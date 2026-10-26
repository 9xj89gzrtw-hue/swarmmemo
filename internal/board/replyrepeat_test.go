package board

// The same reply to the same message again within the window is refused,
// for every author alike (C599).

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRepeatReplyRefused(t *testing.T) {
	s := openTest(t, Config{})
	base := time.Unix(testTime, 0)
	s.now = func() time.Time { return base }
	asker, flood, other := keyFor(111), keyFor(112), keyFor(113)
	taskA := postAs(t, s, asker, Command{Room: "bounties", Text: "Task A", RequestID: "task-a"})
	taskB := postAs(t, s, asker, Command{Room: "bounties", Text: "Task B", RequestID: "task-b"})
	template := "I can do this. DM me for details."
	firstCmd := signed(flood, Command{Operation: "post", Room: "bounties", ReplyTo: taskA, Text: template, RequestID: "r1", Timestamp: base.Unix()})
	first := run(t, s, firstCmd).Receipt.ID

	refused := func(c Command, source string) *Error {
		t.Helper()
		_, err := s.Execute(testContext, c, source)
		var e *Error
		if !errors.As(err, &e) || e.Code != "duplicate_reply" || e.Status != 409 {
			t.Fatalf("want 409 duplicate_reply, got %v", err)
		}
		return e
	}
	post := func(key byte, c Command) Command {
		c.Operation = "post"
		c.Timestamp = s.now().Unix()
		return signed(keyFor(key), c)
	}
	// Fifteen minutes later: the same text, whitespace and case changed.
	s.now = func() time.Time { return base.Add(15 * time.Minute) }
	e := refused(post(112, Command{Room: "bounties", ReplyTo: taskA, Text: "  i can do this.\n DM me for details. ", RequestID: "r2"}), "test-origin")
	if !strings.Contains(e.Message, first) || !strings.Contains(e.Message, "24 hours") || e.Details.(map[string]any)["earlier_id"] != first {
		t.Fatalf("problem does not name the earlier copy: %+v", e)
	}
	// An exact retry of the first still returns its receipt.
	retry := run(t, s, firstCmd)
	if retry.Receipt.ID != first || !retry.Receipt.Duplicate {
		t.Fatalf("request_id retry: %+v", retry.Receipt)
	}
	// Another parent, other text, another key: accepted.
	postAs(t, s, flood, Command{Room: "bounties", ReplyTo: taskB, Text: template, RequestID: "r3"})
	postAs(t, s, flood, Command{Room: "bounties", ReplyTo: taskA, Text: "Update: a draft is ready.", RequestID: "r4"})
	postAs(t, s, other, Command{Room: "bounties", ReplyTo: taskA, Text: template, RequestID: "r5"})
	// An edit of the first keeping its text is not a new reply.
	postAs(t, s, flood, Command{Room: "bounties", ReplyTo: taskA, Text: template, Data: `{"schema":1,"supersedes":"` + first + `"}`, RequestID: "r6"})
	// Still refused after the edit, naming the message (not the version).
	e = refused(post(112, Command{Room: "bounties", ReplyTo: taskA, Text: template, RequestID: "r7"}), "test-origin")
	if e.Details.(map[string]any)["earlier_id"] != first {
		t.Fatalf("after an edit the problem names %v, want %s", e.Details, first)
	}
	// After the window (from the edit, the latest copy): accepted again.
	s.now = func() time.Time { return base.Add(time.Duration(ReplyRepeatWindowSeconds)*time.Second + time.Hour) }
	postAs(t, s, flood, Command{Room: "bounties", ReplyTo: taskA, Text: template, RequestID: "r8"})

	// Anonymous: keyed on the network pseudonym.
	s.now = func() time.Time { return base }
	anon := Command{Operation: "post", Room: "bounties", ReplyTo: taskB, Text: "anon template", RequestID: "a1"}
	if _, err := s.Execute(testContext, anon, "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	anon.RequestID = "a2"
	refused(anon, "198.51.100.7")
	anon.RequestID = "a3"
	if _, err := s.Execute(testContext, anon, "203.0.113.9"); err != nil {
		t.Fatalf("another network's same reply: %v", err)
	}
}
