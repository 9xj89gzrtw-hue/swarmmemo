package board

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// A sealed known answer (C587): the requester of a check task commits to
// the answer it expects at work.create, as answer_commit, the lowercase hex
// SHA-256 of salt + "\n" + answer, so a worker can't be fed the answer and
// an accept can be audited afterwards. Once the work is closed the requester
// reveals answer and salt with work.reveal; the board recomputes the hash and
// publishes the answer only when it matches. Both are kept in the signed
// commands themselves (work_transitions.payload: the create at sequence 1,
// the reveal as its own transition), so they need no column.

// WorkReveal is the requester's command that opens its sealed answer once
// the work is closed.
const WorkReveal = "work.reveal"

// WorkAnswerNoteMax is the longest answer_commit_note, in characters;
// WorkAnswerBytesMax the longest revealed answer and WorkAnswerSaltBytesMax
// the longest salt, in UTF-8 bytes.
const (
	WorkAnswerNoteMax      = 80
	WorkAnswerBytesMax     = 2048
	WorkAnswerSaltBytesMax = 256
)

// WorkAnswerCommitFormat is the commit's format in words, for docs and
// refusals.
const WorkAnswerCommitFormat = `answer_commit is the lowercase hex SHA-256 of salt + "\n" + answer (UTF-8)`

// WorkKnownAnswer is a work item's sealed known answer as reads show it:
// the commit and its note from the signed create; once revealed, the answer
// and salt the requester's work.reveal signed, Verified (always true: the
// board stores no reveal that does not match) and when.
type WorkKnownAnswer struct {
	Commit     string `json:"commit"`
	Note       string `json:"note,omitempty"`
	State      string `json:"state"` // sealed or revealed
	Answer     string `json:"answer,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Verified   bool   `json:"verified,omitempty"`
	RevealedAt int64  `json:"revealed_at,omitempty"`
}

// Known-answer states.
const (
	WorkAnswerSealed   = "sealed"
	WorkAnswerRevealed = "revealed"
)

// WorkAnswerCommit is the commit of answer under salt: hex
// sha256(salt + "\n" + answer).
func WorkAnswerCommit(salt, answer string) string {
	sum := sha256.Sum256([]byte(salt + "\n" + answer))
	return hex.EncodeToString(sum[:])
}

func invalidAnswerCommit() error {
	return problem(400, "invalid_work_data", WorkAnswerCommitFormat+": 64 lowercase hex digits. answer_commit_note, optional and only with answer_commit, says what the answer is in one printable line of at most 80 characters.")
}

func invalidReveal(msg string) error {
	return problem(400, "invalid_work_data", msg+" "+WorkReveal+` data is {"schema":1,"generation":G,"answer":A,"salt":S}: answer 1–`+fmt.Sprint(WorkAnswerBytesMax)+` UTF-8 bytes, salt 1–`+fmt.Sprint(WorkAnswerSaltBytesMax)+` bytes without a newline, exactly the ones the commit hashed.`)
}

// checkWorkAnswerData checks the known-answer fields work data carries.
func checkWorkAnswerData(d workData, seen map[string]bool) error {
	if seen["answer_commit"] && !fingerprintRE.MatchString(d.AnswerCommit) {
		return invalidAnswerCommit()
	}
	if seen["answer_commit_note"] && (!seen["answer_commit"] || !validWorkNoteLine(d.AnswerCommitNote, WorkAnswerNoteMax)) {
		return invalidAnswerCommit()
	}
	if seen["answer"] && (d.Answer == "" || len(d.Answer) > WorkAnswerBytesMax || strings.ContainsRune(d.Answer, 0)) {
		return invalidReveal("answer is not valid.")
	}
	if seen["salt"] && (d.Salt == "" || len(d.Salt) > WorkAnswerSaltBytesMax || strings.ContainsAny(d.Salt, "\n\x00")) {
		return invalidReveal("salt is not valid.")
	}
	return nil
}

// workCommandData is the data string of a stored signed command payload.
func workCommandData(payload string) (string, error) {
	var envelope struct {
		Command struct {
			Data string `json:"data"`
		} `json:"command"`
	}
	err := json.Unmarshal([]byte(payload), &envelope)
	return envelope.Command.Data, err
}

// loadWorkKnownAnswer is a work item's known answer, or nil when its create
// committed none.
func loadWorkKnownAnswer(ctx context.Context, tx rowQuerier, id string) (*WorkKnownAnswer, error) {
	var commit, note string
	err := tx.QueryRowContext(ctx, `SELECT coalesce(json_extract(d,'$.answer_commit'),''),coalesce(json_extract(d,'$.answer_commit_note'),'')
 FROM (SELECT CASE WHEN json_valid(json_extract(payload,'$.command.data')) THEN json_extract(payload,'$.command.data') END AS d
 FROM work_transitions WHERE work_id=? AND sequence=1 AND operation='work.create')`, id).Scan(&commit, &note)
	if errors.Is(err, sql.ErrNoRows) || err == nil && commit == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k := &WorkKnownAnswer{Commit: commit, Note: note, State: WorkAnswerSealed}
	var payload string
	var at int64
	err = tx.QueryRowContext(ctx, `SELECT payload,accepted_at FROM work_transitions WHERE work_id=? AND operation=? ORDER BY sequence LIMIT 1`, id, WorkReveal).Scan(&payload, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := workCommandData(payload)
	var d struct{ Answer, Salt string }
	if err != nil || json.Unmarshal([]byte(data), &d) != nil || WorkAnswerCommit(d.Salt, d.Answer) != commit {
		return nil, fmt.Errorf("board: work %s has an unreadable reveal", id)
	}
	k.State, k.Answer, k.Salt, k.Verified, k.RevealedAt = WorkAnswerRevealed, d.Answer, d.Salt, true, at
	return k, nil
}

// workAnswerClosed says whether a work item is closed for a reveal: accepted,
// cancelled or past its deadline, or a standing task whose results_max is
// all accepted, so no seat can open again.
func workAnswerClosed(ctx context.Context, tx *sql.Tx, w workRow, state string, standing *workStanding, now int64) (bool, error) {
	switch state {
	case "accepted", "cancelled", "expired", "review_lapsed":
		return true, nil
	}
	if standing == nil || standing.ResultsMax == 0 {
		return false, nil
	}
	n, err := readStandingCounts(ctx, tx, w.ID, "", now)
	return err == nil && n.accepted >= standing.ResultsMax, err
}

// checkWorkReveal admits the requester's reveal of w's sealed answer, or
// says it was already revealed with these very values (done: nothing to
// record again).
func checkWorkReveal(ctx context.Context, tx *sql.Tx, w workRow, state string, standing *workStanding, d workData, now int64) (done bool, err error) {
	k, err := loadWorkKnownAnswer(ctx, tx, w.ID)
	if err != nil {
		return false, err
	}
	if k == nil {
		return false, problem(409, "work_state_conflict", "This work has no sealed answer to reveal: answer_commit is set only at work.create.")
	}
	if k.State == WorkAnswerRevealed {
		if k.Answer == d.Answer && k.Salt == d.Salt {
			return true, nil
		}
		return false, problem(409, "work_state_conflict", "This work's answer is already revealed and verified; a reveal is made once.")
	}
	closed, err := workAnswerClosed(ctx, tx, w, state, standing, now)
	if err != nil {
		return false, err
	}
	if !closed {
		return false, problem(409, "work_state_conflict", "The answer stays sealed until the work closes: accepted, cancelled or past its deadline (a standing task: past its deadline or with every result its results_max allows accepted). Reveal it then.")
	}
	if WorkAnswerCommit(d.Salt, d.Answer) != k.Commit {
		return false, problem(400, "reveal_mismatch", "sha256(salt + \"\\n\" + answer) is not this work's answer_commit, so nothing was revealed. Send the exact answer and salt the commit hashed (UTF-8, no added whitespace).")
	}
	return false, nil
}
