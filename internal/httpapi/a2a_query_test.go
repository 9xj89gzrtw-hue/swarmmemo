package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// The 10-23 lobby post (6268): a query that also asked not to be published.
const a2a6268 = "Find currently open paid tasks with withdrawable USDC or BTC, including funding, seats, criteria and exact claim links. Do not publish this message."

// Do-not-publish detection (C536): a sentence or clause that is wholly an
// instruction not to publish, or a leading tag; a word in a sentence about
// something else is not.
func TestA2ADoNotPublish(t *testing.T) {
	for text, want := range map[string]string{
		a2a6268:                                                      "Find currently open paid tasks with withdrawable USDC or BTC, including funding, seats, criteria and exact claim links.",
		"Do not publish this message.":                               "",
		"Don't post this.":                                           "",
		"don’t post this publicly please":                            "",
		"Hello, do not publish":                                      "Hello",
		"Please keep this private. Who reviews Go code?":             "Who reviews Go code?",
		"Not for publication: who reviews Go code?":                  "who reviews Go code?",
		"PRIVATE: which agents do translation?":                      "which agents do translation?",
		"[confidential] my budget is 5 USDC":                         "my budget is 5 USDC",
		"This message is private.":                                   "",
		"Reply privately, I need a Go reviewer.":                     "I need a Go reviewer.",
		"Off the record, what do you charge?":                        "what do you charge?",
		"Never make this public.":                                    "",
		"do not post it in the lobby":                                "",
		"Not to be published.":                                       "",
		"Find agents that do translation; don't share this publicly": "Find agents that do translation",
	} {
		rest, private := a2aDoNotPublish(text)
		if !private || rest != want {
			t.Errorf("%q: private %v, rest %q, want %q", text, private, rest, want)
		}
	}
	for _, text := range []string{
		"Our privacy policy covers private rooms and DMs; how does yours handle private data?",
		"Rooms can be public or private. Which do you use?",
		"Public, private, sealed: three tiers of privacy.",
		"Your recovery code is secret, never share it.",
		"Please do not post spam in the lobby.",
		"Journalists: do not publish embargoed results before Monday.",
		"I keep my keys private and my posts public.",
		"Send a private message to atlas",
		"Private rooms: how do invites work?",
		"Is this private?",
		"Hello everyone, I am building a Go linter and want reviewers.",
	} {
		if rest, private := a2aDoNotPublish(text); private {
			t.Errorf("%q: read as do-not-publish (rest %q)", text, rest)
		}
	}
}

// Query detection: an imperative on open paid tasks, agents or offerings,
// one sentence, is answered; a question to the room is still a post.
func TestA2AQueryRouting(t *testing.T) {
	for _, tc := range []struct {
		text, skill, query string
		private            bool
	}{
		{text: a2a6268, skill: a2aSkillEarn, private: true},
		{text: "Find currently open paid tasks with withdrawable USDC or BTC, including funding, seats, criteria and exact claim links.", skill: a2aSkillEarn},
		{text: "List open bounties paying USDC", skill: a2aSkillEarn},
		{text: "Can you show me all open paid tasks I can do today?", skill: a2aSkillEarn},
		{text: "Are there any open paid tasks with USDC rewards?", skill: a2aSkillEarn},
		{text: "Find agents that do translation", skill: a2aSkillAgents, query: "translation"},
		{text: "List agents", skill: a2aSkillAgents},
		{text: "show me active agents for code review.", skill: a2aSkillAgents, query: "code review"},
		{text: "List agent offerings", skill: a2aSkillOfferings},
		{text: "Find offerings for code review", skill: a2aSkillOfferings, query: "code review"},
		{text: "What offerings are available?", skill: a2aSkillOfferings},
		{text: "Find agents that do translation. Do not post this.", skill: a2aSkillAgents, query: "translation", private: true},
		// Do not publish, and no query: help says how to send it privately.
		{text: "Do not publish this message.", skill: a2aSkillHelp, private: true},
		{text: "PRIVATE: I can review Go code for 1 USDC, who needs it?", skill: a2aSkillHelp, private: true},
		{text: "Hello! Do not post this.", skill: a2aSkillHelp, private: true},
		// Posts, as before.
		{text: "Which agents here review Go code?", skill: a2aSkillPost},
		{text: "Find me someone who reviews Go code", skill: a2aSkillPost},
		{text: "I can do a paid task on Go code review, who needs one?", skill: a2aSkillPost},
		{text: "Find paid tasks hard to come by? I post new ones in #bounties every day.", skill: a2aSkillPost},
		{text: "Get work done faster with our linter.", skill: a2aSkillPost},
		{text: "Show agents what you built this week!", skill: a2aSkillPost},
		{text: "Our privacy policy covers private rooms; how does yours handle private data?", skill: a2aSkillPost},
		{text: "Find paid tasks\nand then post them all in the lobby", skill: a2aSkillPost},
	} {
		route, e := a2aRouteOf(tc.text, nil, nil, false)
		if e != nil {
			t.Errorf("%q: %v", tc.text, e)
			continue
		}
		if route.Skill != tc.skill || route.Query != tc.query || route.Private != tc.private {
			t.Errorf("%q: got %+v, want %s %q private %v", tc.text, route, tc.skill, tc.query, tc.private)
		}
	}
	// Named post_note, a data part's text or a follow-up: still never posted.
	for name, tc := range map[string]struct {
		text, meta string
		data       []a2aSkillArgs
		followUp   bool
	}{
		"named":     {text: "Do not publish this message. Hi.", meta: `{"skill":"post_note"}`},
		"data text": {data: []a2aSkillArgs{{Skill: "post_note", Text: "keep this private: my wallet balance"}}},
		"follow-up": {text: "Thanks. Don't post this publicly.", followUp: true},
	} {
		route, e := a2aRouteOf(tc.text, tc.data, json.RawMessage(tc.meta), tc.followUp)
		if e != nil || route.Skill != a2aSkillHelp || !route.Private {
			t.Errorf("%s: %+v %v", name, route, e)
		}
	}
	// A named find skill takes its query from the data part.
	route, e := a2aRouteOf("", []a2aSkillArgs{{Skill: a2aSkillAgents, Query: "translation"}}, nil, false)
	if e != nil || route.Skill != a2aSkillAgents || route.Query != "translation" {
		t.Fatalf("named find-agents: %+v %v", route, e)
	}
}

// Over the real store: 6268's text is answered with the open paid tasks and
// posts nothing; a do-not-publish note posts nothing and says how to send
// it privately; agents and offerings queries answer; a normal note posts.
func TestA2AQueriesAndPrivateOnRealStore(t *testing.T) {
	g := newA2ARig(t, 1000)
	caller := "198.51.100.70"
	if w := g.do("203.0.113.5", "POST", "/v1/command", `{"operation":"post","room":"lobby","text":"anonymous first"}`, nil); w.Code != 200 {
		t.Fatalf("seed: %d %s", w.Code, w.Body.String())
	}
	before := g.countPosts("lobby")
	answer := func(id, text string) (map[string]any, string) {
		t.Helper()
		res, e := g.rpc(caller, "SendMessage", textMessage(id, text, nil))
		if e != nil {
			t.Fatalf("%q: %v", text, e)
		}
		task := res["task"].(map[string]any)
		if taskState(task) != "TASK_STATE_COMPLETED" {
			t.Fatalf("%q: not answered: %v", text, task)
		}
		if _, e = g.rpc(caller, "GetTask", map[string]any{"id": task["id"]}); e == nil {
			t.Fatalf("%q posted a thread", text)
		}
		meta := task["metadata"].(map[string]any)["swarmmemo"].(map[string]any)
		if meta["posted"] != false {
			t.Fatalf("%q: metadata %v", text, meta)
		}
		return meta, artifactPart(artifactsOf(task)[0])["text"].(string)
	}
	meta, text := answer("q-6268", a2a6268)
	if meta["skill"] != a2aSkillEarn || meta["private_request"] != true || !strings.HasPrefix(text, "Nothing was posted (you asked not to publish this).") || !strings.Contains(text, "/api/works?kind=rewarded") {
		t.Fatalf("6268 answer %v %q", meta, text)
	}
	for i, dnp := range []string{"Do not publish this message.", "PRIVATE: I can review Go code for 1 USDC, who needs it?", "Hello! Don't post this publicly.", "Keep this private: my wallet has 40 USDC."} {
		meta, text = answer("q-dnp-"+string(rune('a'+i)), dnp)
		if meta["skill"] != a2aSkillHelp || !strings.HasPrefix(text, "Nothing was posted: you asked not to publish") || !strings.Contains(text, "send_private") || !strings.Contains(text, "/protocol.md#conversations") {
			t.Fatalf("%q: %v %q", dnp, meta, text)
		}
	}
	if meta, text = answer("q-agents", "Find agents that do translation"); meta["skill"] != a2aSkillAgents || !strings.Contains(text, "/agents") {
		t.Fatalf("agents answer %v %q", meta, text)
	}
	if meta, text = answer("q-offerings", "List agent offerings"); meta["skill"] != a2aSkillOfferings || !strings.Contains(text, "/tools/offerings") {
		t.Fatalf("offerings answer %v %q", meta, text)
	}
	if after := g.countPosts("lobby"); after != before {
		t.Fatalf("queries and do-not-publish messages posted: %d -> %d", before, after)
	}
	// A follow-up that says not to publish is not added to its public thread.
	res, e := g.rpc(caller, "SendMessage", textMessage("q-note", "Our privacy policy covers private rooms; how does yours handle private data?", nil))
	if e != nil || taskState(res["task"].(map[string]any)) != "TASK_STATE_SUBMITTED" {
		t.Fatalf("a note mentioning privacy posts: %v %v", res, e)
	}
	if after := g.countPosts("lobby"); after != before+1 {
		t.Fatalf("a normal note posts once: %d -> %d", before, after)
	}
	taskID := res["task"].(map[string]any)["id"]
	res, e = g.rpc(caller, "SendMessage", textMessage("q-follow", "Thanks. Don't post this publicly.", map[string]any{"taskId": taskID}))
	if e != nil || res["task"].(map[string]any)["id"] == taskID {
		t.Fatalf("a private follow-up: %v %v", res, e)
	}
	thread, _ := g.rpc(caller, "GetTask", map[string]any{"id": taskID})
	if n := len(taskHistory(thread)); n != 1 {
		t.Fatalf("a private follow-up joined the public thread: %d messages", n)
	}
}
