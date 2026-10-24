package board

import (
	"context"
	"database/sql"
	"errors"
)

// hiddenByAuthor marks a message its own author withdrew (message.withdraw).
// Neither the room nor the operator restores it: the author took it back.
const hiddenByAuthor = "author"

// withdrawMessage is message.withdraw (C544): a signed author hides its own
// message, every version of it, with the public reason WithdrawnReason. It
// is the same removal a room's moderator makes (setHidden): the text stays
// in the database, reads show the tombstone, the public record keeps the
// signed command, and nothing is deleted. The author is the account that
// posted it; a worker key withdraws only what it posted itself.
func (s *Store) withdrawMessage(ctx context.Context, tx *sql.Tx, c Command, a actor, now int64) (Result, error) {
	if err := requireSigned(a); err != nil {
		return Result{}, err
	}
	var room, author, account, origin string
	var hidden bool
	err := tx.QueryRowContext(ctx, "SELECT room,author,account,origin,hidden FROM events WHERE id=?", c.MessageID).Scan(&room, &author, &account, &origin, &hidden)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, ErrMessageNotFound()
	}
	if err != nil {
		return Result{}, err
	}
	r, err := roomAccess(ctx, tx, room, a)
	if err != nil {
		return Result{}, ErrMessageNotFound()
	}
	if account != a.account || (a.grant != nil && author != a.id) {
		return Result{}, problem(403, "not_author", "Only the message's author can withdraw it; a room's owner or moderator hides it with room.hide.")
	}
	if origin == "" {
		origin = c.MessageID
	}
	// Every version goes, as every version of an edited message is one
	// message; a version already hidden stays as it is.
	rows, err := tx.QueryContext(ctx, "SELECT id,hidden FROM events WHERE id=? OR origin=? ORDER BY seq", origin, origin)
	if err != nil {
		return Result{}, err
	}
	var ids []string
	chainHidden := false
	for rows.Next() {
		var id string
		var h bool
		if err = rows.Scan(&id, &h); err != nil {
			rows.Close()
			return Result{}, err
		}
		chainHidden = chainHidden || h
		if !h {
			ids = append(ids, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Result{}, err
	}
	if hidden || chainHidden {
		return Result{}, problem(409, "already_hidden", "This message is already hidden or withdrawn.")
	}
	if err = s.charge(ctx, tx, a, SmallCommandCost, now); err != nil {
		return Result{}, err
	}
	for _, id := range ids {
		if err = setHidden(ctx, tx, id, r.Visibility, true, WithdrawnReason, hiddenByAuthor, now); err != nil {
			return Result{}, err
		}
	}
	// The room's public log records it beside every hide and restore, with
	// the author's signed command.
	if err = writeLog(ctx, tx, signedLog(c, a, r.Name, "withdraw", c.MessageID, WithdrawnReason, ""), now); err != nil {
		return Result{}, err
	}
	return Result{Data: map[string]any{"room": r.Name, "message_id": c.MessageID, "hidden": true, "reason": WithdrawnReason, "withdrawn": ids}}, nil
}
