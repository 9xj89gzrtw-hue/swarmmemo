package services

// Late settlements (C534). A seller may answer a paid call with 2xx yet
// report no successful settlement: PAYMENT-RESPONSE success false, or no
// settlement header at all. Our EIP-3009 authorization stays valid until its
// validBefore, so the seller can still submit it later; refunding the agent
// at once would let a hostile seller collect our USDC while its callers pay
// nothing. Such a call is charged as usual and its payment row is left
// "unknown" (reason settlement_unconfirmed; response_too_large for a
// discarded answer), counting in the caps. Once the authorization has
// expired, reconcileLate reads the token's authorizationState(our wallet,
// nonce) over the configured chain reader (WORK_USDC_RPC_URL): used, the row
// becomes "paid" (reason settled_late, with the transaction when its
// AuthorizationUsed event is found); unused, it can never move money, so the
// row becomes "failed" (reason settlement_expired_unused, out of the caps)
// and the agent's charge is paid back through the meter (Reimburser), in the
// same transaction as the state change and at most once per hold.

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"swarmmemo/internal/allowance"
)

const (
	// x402LateEvery is how often the worker looks for expired unconfirmed
	// payments; x402LateBatch bounds one look, x402LateDeadline its time.
	x402LateEvery    = 5 * 60
	x402LateBatch    = 8
	x402LateDeadline = time.Minute
	// x402LateMargin is how long past validBefore a payment is left before
	// it is read back: the chain's block clock may trail ours.
	x402LateMargin = 120
	// Reasons a read-back payment row ends with.
	x402ReasonSettledLate    = "settled_late"
	x402ReasonExpiredUnused  = "settlement_expired_unused"
	x402ReimburseDescription = "x402 payment expired unused: the seller never settled it"
)

// lateSettlements is the provider's read-back state.
type lateSettlements struct {
	chain   *USDCChain
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	meter   Meter // the engine's (bindEngine)
	next    atomic.Int64
	running atomic.Bool
}

func (x *x402) bindEngine(e *Engine) { x.late.meter = e.cfg.Meter }

// workLate starts a read-back in the background when one is due; Work calls
// it every pass. It never holds the worker across the chain's RPC.
func (x *x402) workLate(now int64) {
	if !x.lateReady() || now < x.late.next.Load() || !x.late.running.CompareAndSwap(false, true) {
		return
	}
	x.late.next.Store(now + x402LateEvery)
	go func() {
		defer x.late.running.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), x402LateDeadline)
		defer cancel()
		_, _ = x.reconcileLate(ctx, now, time.Now().Unix())
	}()
}

// lateReady reports whether payments can be read back: a chain reader for
// the relay's own network, and a meter that can pay a charge back.
func (x *x402) lateReady() bool {
	if x.cfg == nil || x.db == nil || x.cfg.Signer == nil || x.late.chain == nil || x.late.chain.Network != x.cfg.Network {
		return false
	}
	_, ok := x.late.meter.(Reimburser)
	return ok
}

// reconcileLate reads back at most x402LateBatch unconfirmed payments whose
// authorization expired before chainNow minus the margin (the chain's
// clock, as validBefore), and settles each as above; now is the store's
// clock, for the ledger. It returns how many rows it settled. An RPC failure
// stops the pass: the rows wait for the next.
func (x *x402) reconcileLate(ctx context.Context, now, chainNow int64) (int, error) {
	if !x.lateReady() {
		return 0, nil
	}
	type row struct{ id, account, requestKey, nonce string }
	rows, err := queryAll(ctx, x.db, func(r *sql.Rows) (row, error) {
		var v row
		return v, r.Scan(&v.id, &v.account, &v.requestKey, &v.nonce)
	}, `SELECT id, account, request_key, nonce FROM x402_payments WHERE state='unknown' AND reason IN (?,'response_too_large')
 AND network=? AND asset=? AND valid_before<? ORDER BY valid_before, id LIMIT ?`,
		x402ReasonUnconfirmed, x.late.chain.Network, x.late.chain.Asset.String(), chainNow-x402LateMargin, x402LateBatch)
	if err != nil {
		return 0, err
	}
	payer := x.cfg.Signer.Address()
	n := 0
	for _, r := range rows {
		used, err := x.late.chain.AuthorizationUsed(ctx, x.late.dial, payer, r.nonce)
		if err != nil {
			return n, err
		}
		if used {
			hash, _ := x.late.chain.AuthorizationTx(ctx, x.late.dial, payer, r.nonce) // best effort
			res, err := x.db.ExecContext(ctx, `UPDATE x402_payments SET state='paid', reason=CASE WHEN reason='response_too_large' THEN reason ELSE ? END,
 transaction_hash=CASE WHEN ?<>'' THEN ? ELSE transaction_hash END, finished_at=? WHERE id=? AND state='unknown'`,
				x402ReasonSettledLate, hash, hash, now, r.id)
			if err != nil {
				return n, err
			}
			if k, _ := res.RowsAffected(); k == 1 {
				n++
			}
			continue
		}
		done, err := x.refundUnused(ctx, r.id, r.account, r.requestKey, now)
		if e := (*allowance.Err)(nil); errors.As(err, &e) {
			continue // the ledger refused for now (its grant slice is empty): the row waits, the rest go on
		}
		if err != nil {
			return n, err
		}
		if done {
			n++
		}
	}
	return n, nil
}

// refundUnused marks an expired, unused payment failed and pays the agent's
// charge back, in one transaction: the state change guards the refund, and
// the meter pays a hold back at most once, so a second pass does nothing.
func (x *x402) refundUnused(ctx context.Context, id, account, requestKey string, now int64) (bool, error) {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE x402_payments SET state='failed', reason=?, finished_at=? WHERE id=? AND state='unknown' AND reason IN (?,'response_too_large')`,
		x402ReasonExpiredUnused, now, id, x402ReasonUnconfirmed)
	if err != nil {
		return false, err
	}
	if k, err := res.RowsAffected(); err != nil || k != 1 {
		return false, err
	}
	var hold string
	err = tx.QueryRowContext(ctx, "SELECT hold_id FROM service_calls WHERE service='x402' AND account=? AND request_key=?", account, requestKey).Scan(&hold)
	switch {
	case err == sql.ErrNoRows: // no call record: nothing was charged
	case err != nil:
		return false, err
	case hold != "":
		if _, err = x.late.meter.(Reimburser).Reimburse(ctx, tx, hold, x402ReimburseDescription, now); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}
