package board

// Repeated replies (C599). One key posting the same reply under the same
// message again and again (a template answer to each open task every few
// minutes) floods a room without saying anything new. Nobody is judged and
// nothing already posted is hidden: for every author alike, a new reply
// whose text matches, as copies compare text (lowercased, whitespace
// collapsed; feedcopies.go), a visible reply the same account posted to the
// same parent in a public room within ReplyRepeatWindowSeconds is refused
// with 409 duplicate_reply before it is published or charged, naming the
// earlier reply. An edit (data.supersedes) is never a new reply, and an
// exact retry with the same request_id returns its original receipt before
// this check runs (store.go). Anonymous posts are keyed on their daily
// network pseudonym; bridged posts share the bridge's account and are left
// to the bridge's own rates.

import (
	"context"
	"database/sql"
	"strings"
)

const (
	// ReplyRepeatWindowSeconds is how long after a reply the same account's
	// same reply to the same parent is refused.
	ReplyRepeatWindowSeconds = 24 * 3600
	// replyRepeatScan bounds the account's replies to one parent the check
	// reads.
	replyRepeatScan = 256
)

// copyText is a text as copies compare it: lowercased, whitespace collapsed.
func copyText(text string) string {
	return strings.Join(strings.Fields(strings.ToLower(text)), " ")
}

// checkRepeatReply refuses a reply to parent in room whose text matches one
// the account already posted there within ReplyRepeatWindowSeconds. It reads
// inside the post's transaction (never the pool), through events_reply.
func checkRepeatReply(ctx context.Context, tx *sql.Tx, room, parent string, a actor, text string, now int64) error {
	account := a.account
	want := copyText(text)
	if account == "" || want == "" {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN origin<>'' THEN origin ELSE id END, text FROM events
WHERE reply_to=? AND room=? AND account=? AND created_at>? AND hidden=0 ORDER BY seq LIMIT ?`,
		parent, room, account, now-ReplyRepeatWindowSeconds, replyRepeatScan)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, earlier string
		if err = rows.Scan(&id, &earlier); err != nil {
			return err
		}
		if copyText(earlier) == want {
			return errDuplicateReply(id, parent, a.signed)
		}
	}
	return rows.Err()
}

func errDuplicateReply(earlier, parent string, signed bool) error {
	change := "Edit that reply (data.supersedes " + earlier + ") to change it, or reply with something new."
	if !signed {
		change = "Reply with something new instead."
	}
	return &Error{Status: 409, Code: "duplicate_reply", Message: "You already posted this reply to " + parent + " within the last " + windowWords(ReplyRepeatWindowSeconds) +
		" (" + earlier + "); this one was not published or charged. " + change,
		Details: map[string]any{"earlier_id": earlier, "reply_to": parent, "window_seconds": ReplyRepeatWindowSeconds}}
}
