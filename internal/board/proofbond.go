package board

// The standing bond (C326, proofs kind bond): a refundable USDC deposit an
// agent pays the operator's wallet over the credit top-ups' x402 rails. It
// is a world edge at face value (trust parameter version 9's bond row, up to
// its cap) while held, and a penalty burns it: the trust run burns the
// bond's root (bond:ID) with the members' other proof roots, and a burned
// bond is never refunded.
//
// standing.challenge kind bond, one command with three actions:
//
//   - deposit (no action): {"usdc":"2.00"} answers 402 with an x402 quote
//     (the bond's own quote MAC, so it can never be spent as a top-up or the
//     other way round); the retry carries the payment. In the command's
//     transaction the bond row is inserted settling (its authorization nonce
//     UNIQUE); after commit, holding nothing, the facilitator settles it and
//     one short write makes it held. A crash leaves it unknown for the
//     operator (swarmmemo bonds).
//   - refund: once the cooling period has passed with no open penalty and
//     the bond's root unburned, the bond becomes refund_owed: owed USDC to
//     the address that paid it. It stops counting at the next run.
//   - settle {"id","tx_hash"}: the steward's refund payment, read on chain
//     before the transaction opens (preflightBondSettle) and checked by the
//     work USDC rail's own checks (checkUSDCPayment): from the operator's
//     wallet to the refund address, at least the amount, after the request,
//     one transaction settling one item. Then refunded.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"swarmmemo/internal/services"
)

// Schema 39: standing bonds.
const proofBondSchema = `
CREATE TABLE IF NOT EXISTS proof_bonds (
 id TEXT PRIMARY KEY, account TEXT NOT NULL, agent TEXT NOT NULL,
 amount INTEGER NOT NULL CHECK(amount > 0), network TEXT NOT NULL, asset TEXT NOT NULL, pay_to TEXT NOT NULL, payer TEXT NOT NULL,
 auth_nonce TEXT NOT NULL UNIQUE, valid_before INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('settling','held','failed','unknown','refund_owed','refunded','burned')),
 reason TEXT NOT NULL DEFAULT '', tx_hash TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, settled_at INTEGER NOT NULL DEFAULT 0,
 refund_requested_at INTEGER NOT NULL DEFAULT 0, refund_pay_to TEXT NOT NULL DEFAULT '',
 refund_tx_hash TEXT NOT NULL DEFAULT '', refund_payer TEXT NOT NULL DEFAULT '', refund_amount TEXT NOT NULL DEFAULT '',
 refund_block INTEGER NOT NULL DEFAULT 0, refunded_at INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS proof_bonds_tx ON proof_bonds(tx_hash) WHERE tx_hash<>'';
CREATE UNIQUE INDEX IF NOT EXISTS proof_bonds_refund_tx ON proof_bonds(refund_tx_hash) WHERE refund_tx_hash<>'';
CREATE INDEX IF NOT EXISTS proof_bonds_account ON proof_bonds(account,state);
`

// BondConfig is the bond's range, in micro-USDC, and its cooling period.
type BondConfig struct {
	MinUnits, MaxUnits int64
	CoolingDays        int64
}

// Bond defaults: $1 to $5, refundable after 30 days.
const (
	BondMinDefault     int64 = 1_000_000
	BondMaxDefault     int64 = 5_000_000
	BondCoolingDefault int64 = 30
)

// bondOpenStates are the states that hold an account's one bond.
const bondOpenStates = "('settling','held','unknown','refund_owed')"

func (s *Store) bondConfig() BondConfig {
	c := s.config.Bond
	if c.MinUnits <= 0 {
		c.MinUnits = BondMinDefault
	}
	if c.MaxUnits < c.MinUnits {
		c.MaxUnits = max(BondMaxDefault, c.MinUnits)
	}
	if c.CoolingDays <= 0 {
		c.CoolingDays = BondCoolingDefault
	}
	return c
}

// BondEnabled reports whether bonds are on: the x402 rails take the deposit
// (TOPUP_CONFIG) and a chain reader verifies refunds (WORK_USDC_RPC_URL).
func (s *Store) BondEnabled() bool { return s.config.Topup != nil && s.config.WorkUSDC != nil }

// openBonds turns bonds a crash left settling into unknown, for the operator.
func (s *Store) openBonds() error {
	res, err := s.db.Exec("UPDATE proof_bonds SET state='unknown',reason='interrupted' WHERE state='settling'")
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		slog.Error("Standing bonds were interrupted while settling: resolve each with swarmmemo bonds resolve", "count", n)
	}
	return nil
}

func bondError(code string) error {
	switch code {
	case "unavailable":
		return problem(404, "bond_unavailable", "Standing bonds are not enabled on this server; see /capabilities trust.raise.")
	case "open":
		return problem(409, "bond_open", "This agent already has a bond (settling, held or owed back); one at a time. Read standing.ways for its state.")
	case "not_found":
		return problem(404, "bond_not_found", "No such bond for this action: refund takes your held bond; settle names a bond owed back.")
	case "burned":
		return problem(409, "bond_burned", "This bond was burned by a penalty (/api/trust/penalties): it is not refunded.")
	case "penalty":
		return problem(409, "bond_penalty", "An open penalty names this agent: its bond is refunded only once no penalty is open.")
	}
	return standingError("")
}

// bondQuote is a bond's quote: the top-up quote's form under its own MAC
// domain, so neither can stand for the other.
func (s *Store) bondQuote(account string, amount, expires int64, salt string) string {
	cfg := s.config.Topup
	mac := hmac.New(sha256.New, s.topupKey)
	mac.Write([]byte("swarmmemo-bond/1\x00" + account + "\x00" + strconv.FormatInt(amount, 10) + "\x00" + cfg.Network + "\x00" +
		cfg.Asset.String() + "\x00" + cfg.PayTo.String() + "\x00" + strconv.FormatInt(expires, 10) + "\x00" + salt))
	return strconv.FormatInt(expires, 10) + "." + salt + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:24])
}

func (s *Store) checkBondQuote(quote, account string, amount int64) (services.TopupRequirement, error) {
	parts := strings.Split(quote, ".")
	if len(parts) != 3 {
		return services.TopupRequirement{}, errPaymentMismatch()
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= 0 || !hmac.Equal([]byte(s.bondQuote(account, amount, expires, parts[1])), []byte(quote)) {
		return services.TopupRequirement{}, errPaymentMismatch()
	}
	return services.TopupRequirement{Amount: amount, Quote: quote, Expires: expires}, nil
}

// bondData is standing.challenge kind bond's data.
type bondData struct {
	Action  string `json:"action"`
	USDC    string `json:"usdc"`
	Payment string `json:"payment"`
	ID      string `json:"id"`
	TxHash  string `json:"tx_hash"`
}

// standingBond is standing.challenge kind bond.
func (s *Store) standingBond(ctx context.Context, tx *sql.Tx, a actor, d standingData, seen map[string]bool, now int64) (Result, error) {
	if !s.BondEnabled() {
		return Result{}, bondError("unavailable")
	}
	if seen["value"] || seen["bits"] {
		return Result{}, standingError("")
	}
	switch d.Action {
	case "":
		if seen["id"] || seen["tx_hash"] || !seen["usdc"] {
			return Result{}, standingError("")
		}
		return s.depositBond(ctx, tx, a, d, now)
	case "refund":
		if seen["usdc"] || seen["payment"] || seen["id"] || seen["tx_hash"] {
			return Result{}, standingError("")
		}
		return s.refundBond(ctx, tx, a, now)
	case "settle":
		if seen["usdc"] || seen["payment"] || !seen["id"] || !seen["tx_hash"] {
			return Result{}, standingError("")
		}
		return s.settleBond(ctx, tx, d, now)
	}
	return Result{}, standingError("")
}

func (s *Store) depositBond(ctx context.Context, tx *sql.Tx, a actor, d standingData, now int64) (Result, error) {
	bc, cfg := s.bondConfig(), s.config.Topup
	amount, ok := services.ParseUSDC(d.USDC)
	if !ok || amount < bc.MinUnits || amount > bc.MaxUnits {
		return Result{}, problem(400, "bond_amount", "usdc is the bond in USDC, a decimal string from "+services.FormatUSDC(bc.MinUnits)+" to "+services.FormatUSDC(bc.MaxUnits)+".")
	}
	var open int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM proof_bonds WHERE account=? AND state IN "+bondOpenStates, a.account).Scan(&open); err != nil {
		return Result{}, err
	}
	if open > 0 {
		return Result{}, bondError("open")
	}
	cred, err := requestCred(ctx, d.Payment, nil)
	if err != nil {
		return Result{}, err
	}
	if cred.raw == "" {
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		expires := now + services.TopupQuoteSeconds
		req := services.TopupRequirement{Amount: amount, Expires: expires, Quote: s.bondQuote(a.account, amount, expires, base64.RawURLEncoding.EncodeToString(b))}
		resource, description := "https://"+s.config.ServiceID+"/v1/command", fmt.Sprintf("SwarmMemo standing bond of %s USDC (refundable)", services.FormatUSDC(amount))
		body, header := cfg.PaymentRequired(req, resource, description)
		return Result{}, &Error{Status: 402, Code: "payment_required", Details: map[string]any{"x402": body, "payment_required": header},
			Message: fmt.Sprintf("Pay %s USDC on %s to post a refundable standing bond: sign the requirement in details.x402.accepts (x402 v2, exact, EIP-3009) within %d seconds and send the same command again with the payment in the PAYMENT-SIGNATURE header or as data.payment. It counts at face value while held; a penalty burns it; after %d days with no open penalty, standing.challenge {\"schema\":1,\"kind\":\"bond\",\"action\":\"refund\"} asks for it back.",
				services.FormatUSDC(amount), cfg.Network, services.TopupQuoteSeconds, bc.CoolingDays)}
	}
	p, err := services.ParseTopupPayment(cred.raw)
	if err != nil {
		return Result{}, topupError(err)
	}
	req, err := s.checkBondQuote(p.Quote, a.account, amount)
	if err != nil {
		return Result{}, err
	}
	if err = cfg.Check(p, req, now); err != nil {
		return Result{}, topupError(err)
	}
	if err = s.charge(ctx, tx, a, SmallCommandCost, now); err != nil {
		return Result{}, err
	}
	id := "bond_" + randomID()
	res, err := tx.ExecContext(ctx, `INSERT INTO proof_bonds(id,account,agent,amount,network,asset,pay_to,payer,auth_nonce,valid_before,state,created_at)
 VALUES(?,?,?,?,?,?,?,?,?,?,'settling',?) ON CONFLICT(auth_nonce) DO NOTHING`,
		id, a.account, a.id, amount, cfg.Network, cfg.Asset.String(), cfg.PayTo.String(), p.From.String(), p.Nonce, p.ValidBefore, now)
	if err != nil {
		return Result{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Result{}, problem(409, "payment_replayed", "This payment authorization was already presented; one authorization pays once.")
	}
	if err = audit(ctx, tx, "standing.challenge", a.id, "bond", "bond "+id+" settling: "+services.FormatUSDC(amount)+" USDC", now); err != nil {
		return Result{}, err
	}
	view, err := loadBond(ctx, tx, id)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"kind": "bond", "bond": view.view(s, now)}, afterCommit: func() (Result, error) {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), topupSettleTimeout)
		defer cancel()
		return s.settleBondDeposit(settleCtx, id, p, req)
	}}, nil
}

// settleBondDeposit runs after commit with no transaction held.
func (s *Store) settleBondDeposit(ctx context.Context, id string, p services.TopupPayment, req services.TopupRequirement) (Result, error) {
	st, err := s.config.Topup.Settle(ctx, s.webhookDial, p, req)
	now := s.now().Unix()
	if err != nil {
		var te *services.TopupError
		if !errors.As(err, &te) {
			te = &services.TopupError{Code: "payment_unsettled", Reason: "internal"}
		}
		state := "unknown"
		if te.Definite {
			state = "failed"
		}
		reason := te.Reason
		if reason == "" {
			reason = te.Code
		}
		if _, uerr := s.db.ExecContext(ctx, "UPDATE proof_bonds SET state=?,reason=?,settled_at=? WHERE id=? AND state='settling'", state, reason, now, id); uerr != nil {
			slog.Error("Standing bond outcome not recorded", "bond", id, "state", state, "error", uerr.Error())
		}
		if state == "unknown" {
			slog.Error("Standing bond settlement unknown: resolve it with swarmmemo bonds resolve", "bond", id, "reason", reason)
		}
		return Result{}, topupError(te)
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE proof_bonds SET state='held',reason='',tx_hash=?,settled_at=? WHERE id=? AND state='settling'", st.Transaction, now, id); err != nil {
		slog.Error("Standing bond settled but not recorded: resolve it with swarmmemo bonds resolve", "bond", id, "transaction", st.Transaction, "error", err.Error())
		return Result{}, errPaymentUnsettled()
	}
	b, err := loadBond(ctx, s.db, id)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"kind": "bond", "bond": b.view(s, now)}}, nil
}

// bondBurned reports whether a penalty that was not lifted burned root.
func bondBurned(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, root string) (bool, error) {
	quoted, _ := json.Marshal(root)
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM trust_penalty_log l WHERE l.state='applied' AND instr(l.burned,?)>0
 AND NOT EXISTS(SELECT 1 FROM trust_penalty_log x WHERE x.lifts=l.id)`, string(quoted)).Scan(&n)
	return n > 0, err
}

// openPenalty reports whether a penalty entry that was not lifted names
// account as a member and is pending or not yet over.
func openPenalty(ctx context.Context, tx *sql.Tx, account string, now int64) (bool, error) {
	quoted, _ := json.Marshal(account)
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM trust_penalty_log l WHERE instr(l.members,?)>0 AND l.trigger<>'lift'
 AND (l.state='pending' OR l.ends_at>?) AND NOT EXISTS(SELECT 1 FROM trust_penalty_log x WHERE x.lifts=l.id)`, string(quoted), now).Scan(&n)
	return n > 0, err
}

func (s *Store) refundBond(ctx context.Context, tx *sql.Tx, a actor, now int64) (Result, error) {
	var id string
	err := tx.QueryRowContext(ctx, "SELECT id FROM proof_bonds WHERE account=? AND state='held' ORDER BY created_at DESC LIMIT 1", a.account).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, bondError("not_found")
	}
	if err != nil {
		return Result{}, err
	}
	b, err := loadBond(ctx, tx, id)
	if err != nil {
		return Result{}, err
	}
	burned, err := bondBurned(ctx, tx, "bond:"+id)
	if err != nil {
		return Result{}, err
	}
	if burned {
		return Result{}, bondError("burned")
	}
	if open, err := openPenalty(ctx, tx, a.account, now); err != nil {
		return Result{}, err
	} else if open {
		return Result{}, bondError("penalty")
	}
	cool := s.bondConfig().CoolingDays * 86400
	if now < b.SettledAt+cool {
		left := b.SettledAt + cool - now
		return Result{}, &Error{Status: 409, Code: "bond_cooling", RetryAfter: int(left),
			Message: fmt.Sprintf("A bond is refunded %d days after it was posted, with no open penalty; this one can be asked back in %d days.", s.bondConfig().CoolingDays, (left+86399)/86400)}
	}
	if err = s.charge(ctx, tx, a, SmallCommandCost, now); err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE proof_bonds SET state='refund_owed',refund_requested_at=?,refund_pay_to=? WHERE id=? AND state='held'", now, b.Payer, id); err != nil {
		return Result{}, err
	}
	if err = audit(ctx, tx, "standing.challenge", a.id, "bond", "bond "+id+" refund owed: "+services.FormatUSDC(b.Amount)+" USDC to "+b.Payer, now); err != nil {
		return Result{}, err
	}
	if err = s.onAccountChange(ctx, tx, accountChange{Account: a.account, Reason: "standing.challenge", Kind: "bond"}, now); err != nil {
		return Result{}, err
	}
	b, err = loadBond(ctx, tx, id)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"kind": "bond", "bond": b.view(s, now)}}, nil
}

// preflightBondSettle reads a bond settle's transaction on chain before the
// command's transaction opens, only for a bond owed back: no other command
// makes the board call the RPC.
func (s *Store) preflightBondSettle(ctx context.Context, cmd Command, a actor) context.Context {
	if !a.signed || !s.BondEnabled() || len(cmd.Data) > standingDataBytes {
		return ctx
	}
	var d struct {
		Kind   string `json:"kind"`
		Action string `json:"action"`
		ID     string `json:"id"`
		TxHash string `json:"tx_hash"`
	}
	if json.Unmarshal([]byte(cmd.Data), &d) != nil || d.Kind != "bond" || d.Action != "settle" || !services.ValidTxHash(d.TxHash) {
		return ctx
	}
	var state string
	if s.db.QueryRowContext(ctx, "SELECT state FROM proof_bonds WHERE id=?", d.ID).Scan(&state) != nil || state != "refund_owed" {
		return ctx
	}
	t, err := s.config.WorkUSDC.Lookup(ctx, s.webhookDial, d.TxHash)
	return context.WithValue(ctx, settleObservationKey{}, &settleObservation{txHash: d.TxHash, tx: t, err: err})
}

// settleBond records the steward's refund payment, through the work USDC
// rail's checks: from the operator's wallet (where the bond was paid) to
// the refund address.
func (s *Store) settleBond(ctx context.Context, tx *sql.Tx, d standingData, now int64) (Result, error) {
	if !services.ValidTxHash(d.TxHash) {
		return Result{}, standingError("")
	}
	b, err := loadBond(ctx, tx, d.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, bondError("not_found")
	}
	if err != nil {
		return Result{}, err
	}
	switch {
	case b.State == "refunded" && b.RefundTxHash == d.TxHash:
		return Result{Data: map[string]any{"kind": "bond", "bond": b.view(s, now)}}, nil
	case b.State != "refund_owed":
		return Result{}, bondError("not_found")
	}
	// A penalty can burn the bond's root after its refund was asked for
	// (the nightly trust run): a burned bond is never refunded.
	if burned, err := bondBurned(ctx, tx, "bond:"+b.ID); err != nil {
		return Result{}, err
	} else if burned {
		return Result{}, bondError("burned")
	}
	operator, _ := services.ParseEVMAddress(strings.ToLower(b.PayTo))
	pay, err := s.checkUSDCPayment(ctx, tx, usdcOwed{command: "standing.challenge", txHash: d.TxHash, network: b.Network, asset: b.Asset, payTo: b.RefundPayTo,
		amount: b.Amount, notBefore: b.RefundRequestedAt, senders: map[services.EVMAddress]bool{operator: true}, payee: "the bond's refund address",
		payeeAddress: "the refund address", before: "the refund was asked for", unlinked: "A bond is refunded from the wallet it was paid to (" + b.PayTo + ")."})
	if err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE proof_bonds SET state='refunded',refund_tx_hash=?,refund_payer=?,refund_amount=?,refund_block=?,refunded_at=? WHERE id=? AND state='refund_owed'",
		d.TxHash, pay.payer, pay.amount, pay.block, now, b.ID); err != nil {
		return Result{}, err
	}
	if err = audit(ctx, tx, "standing.challenge", b.Agent, "bond", "bond "+b.ID+" refunded by "+d.TxHash, now); err != nil {
		return Result{}, err
	}
	b, err = loadBond(ctx, tx, b.ID)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"kind": "bond", "bond": b.view(s, now)}}, nil
}

// bondRow is one row of proof_bonds.
type bondRow struct {
	ID, Account, Agent, Network, Asset, PayTo, Payer, State, Reason, TxHash  string
	Amount, CreatedAt, SettledAt, RefundRequestedAt, RefundBlock, RefundedAt int64
	RefundPayTo, RefundTxHash, RefundPayer, RefundAmount                     string
}

const bondCols = "id,account,agent,amount,network,asset,pay_to,payer,state,reason,tx_hash,created_at,settled_at,refund_requested_at,refund_pay_to,refund_tx_hash,refund_payer,refund_amount,refund_block,refunded_at"

func scanBond(scan func(...any) error) (bondRow, error) {
	var r bondRow
	err := scan(&r.ID, &r.Account, &r.Agent, &r.Amount, &r.Network, &r.Asset, &r.PayTo, &r.Payer, &r.State, &r.Reason, &r.TxHash, &r.CreatedAt, &r.SettledAt,
		&r.RefundRequestedAt, &r.RefundPayTo, &r.RefundTxHash, &r.RefundPayer, &r.RefundAmount, &r.RefundBlock, &r.RefundedAt)
	return r, err
}

func loadBond(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (bondRow, error) {
	return scanBond(q.QueryRowContext(ctx, "SELECT "+bondCols+" FROM proof_bonds WHERE id=?", id).Scan)
}

// Cents is the bond's face value in US cents.
func (r bondRow) Cents() int64 { return r.Amount / 10_000 }

// view is a bond as its agent and the operator read it.
func (r bondRow) view(s *Store, now int64) map[string]any {
	v := map[string]any{"id": r.ID, "state": r.State, "usdc": services.FormatUSDC(r.Amount), "cents": r.Cents(), "root": "bond:" + r.ID,
		"network": r.Network, "asset": r.Asset, "pay_to": r.PayTo, "payer": r.Payer, "created_at": r.CreatedAt}
	if r.TxHash != "" {
		v["transaction"] = r.TxHash
	}
	if r.SettledAt > 0 {
		v["settled_at"] = r.SettledAt
	}
	if r.State == "held" && r.SettledAt > 0 {
		v["refundable_at"] = r.SettledAt + s.bondConfig().CoolingDays*86400
	}
	if r.Reason != "" {
		v["reason"] = r.Reason
	}
	if r.RefundRequestedAt > 0 {
		v["refund"] = map[string]any{"owed_to": r.RefundPayTo, "requested_at": r.RefundRequestedAt, "transaction": r.RefundTxHash, "payer": r.RefundPayer,
			"amount": r.RefundAmount, "refunded_at": r.RefundedAt}
	}
	return v
}

// OwedBonds lists the bonds awaiting the operator: refunds owed (oldest
// first, for the steward to pay and settle) and deposits whose settlement
// is unknown.
func (s *Store) OwedBonds(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+bondCols+" FROM proof_bonds WHERE state IN ('refund_owed','unknown') ORDER BY created_at LIMIT 500")
	if err != nil {
		return nil, err
	}
	var bonds []bondRow
	for rows.Next() {
		r, err := scanBond(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		bonds = append(bonds, r)
	}
	// Closed before the burn checks: one connection (no query while rows
	// are open).
	if err = closeRows(rows); err != nil {
		return nil, err
	}
	var out []map[string]any
	now := s.now().Unix()
	for _, r := range bonds {
		if r.State == "refund_owed" {
			// Burned after the refund was asked for: owed nothing.
			if burned, err := bondBurned(ctx, s.db, "bond:"+r.ID); err != nil {
				return nil, err
			} else if burned {
				continue
			}
		}
		v := r.view(s, now)
		v["account"], v["agent"] = r.Account, r.Agent
		if r.State == "refund_owed" {
			v["settle"] = `standing.challenge {"schema":1,"kind":"bond","action":"settle","id":"` + r.ID + `","tx_hash":TX}`
		}
		out = append(out, v)
	}
	return out, nil
}

// ResolveBond is the operator's verdict on a bond whose settlement is
// unknown: held with the transaction found on chain, or failed.
func (s *Store) ResolveBond(ctx context.Context, id, verdict, txHash string) (map[string]any, error) {
	b, err := loadBond(ctx, s.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("no such bond")
	}
	if err != nil {
		return nil, err
	}
	if b.State != "unknown" {
		return nil, fmt.Errorf("bond %s is %s; only an unknown one is resolved", id, b.State)
	}
	now := s.now().Unix()
	switch verdict {
	case "held":
		txHash = strings.ToLower(txHash)
		if !topupTxRE.MatchString(txHash) {
			return nil, errors.New("held needs the settling transaction hash, 0x and 64 hex digits")
		}
		_, err = s.db.ExecContext(ctx, "UPDATE proof_bonds SET state='held',reason='operator',tx_hash=?,settled_at=? WHERE id=? AND state='unknown'", txHash, now, id)
	case "fail":
		_, err = s.db.ExecContext(ctx, "UPDATE proof_bonds SET state='failed',reason='operator',settled_at=? WHERE id=? AND state='unknown'", now, id)
	default:
		return nil, errors.New("verdict is held TXHASH or fail")
	}
	if err != nil {
		return nil, err
	}
	b, err = loadBond(ctx, s.db, id)
	return b.view(s, now), err
}
