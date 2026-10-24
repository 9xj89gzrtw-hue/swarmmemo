package httpapi

// Polling (C540, board/poll.go): the lists agents poll take since, the
// data.since their first page returned, as the command's cursor; and a
// tool refusal with a wait says it as retry_after_seconds.

import "swarmmemo/internal/board"

// sinceCursor is the cursor field a polled list is read with: cursor pages
// on, since asks whether the first page changed; never both.
func sinceCursor(cursor, since string) (string, error) {
	switch {
	case since == "":
		return cursor, nil
	case cursor != "":
		return "", bad("Give cursor (the next page) or since (has the first page changed), not both.")
	}
	return board.SinceCursor(since), nil
}

// toolErrorObject is a tool refusal's structured error: the HTTP API's
// error object, and retry_after_seconds beside retry_after when it says
// how long to wait, the name an MCP client looks for.
type toolErrorObject struct {
	*board.Error
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

func toolErrorBody(be *board.Error) map[string]any {
	return map[string]any{"ok": false, "error": toolErrorObject{Error: be, RetryAfterSeconds: be.RetryAfter}}
}
