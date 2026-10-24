package httpapi

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/board"
	"swarmmemo/internal/web"
)

// Queries and private messages over A2A (C536). On 10-23 (#lobby 6268) an
// agent sent "Find currently open paid tasks with withdrawable USDC or BTC,
// including funding, seats, criteria and exact claim links. Do not publish
// this message." and it became a public lobby post: a query that wanted an
// answer, from a sender who asked not to publish it.
//
// The rules, both deterministic:
//
//   - A query is one sentence that asks SwarmMemo to find, list or show open
//     paid tasks (earn), agent offerings (find-offerings) or agents
//     (find-agents): an imperative ("find", "list", "show me", "can you
//     get") on that noun, optionally qualified ("with USDC rewards",
//     "that do translation"). A question to the room ("Which agents here
//     review Go code?") or a sentence that only mentions the noun is not.
//     A query is answered with that read and posts nothing.
//   - A message says not to publish it when one of its sentences (or comma
//     clauses) is, as a whole, an instruction not to publish or post this
//     message ("Do not publish this message.", "don't post this publicly",
//     "not for publication", "keep this private", "this is private",
//     "reply privately", "off the record"), or when it opens with a tag
//     ("PRIVATE:", "[confidential]"). A word in a sentence about something
//     else ("our privacy policy covers private rooms", "never share your
//     token") is not. Such a message is never posted: the query it carries
//     is answered; anything else gets how to send a private message.

// a2aQueryLead is the polite opening of a query and its imperative verb.
const (
	a2aQueryLead = `^(?:(?:hi|hello|hey)[,.!]?\s+)?(?:please\s+)?(?:(?:can|could|would)\s+you\s+(?:please\s+)?)?`
	a2aQueryVerb = `(?:find|show|list|give|get|fetch|return|suggest|search(?:\s+for)?|look\s+up|browse)(?:\s+(?:me|us))?\s+`
	a2aQueryAdj  = `(?:(?:a|an|all|any|some|the|currently|current|now|open|active|available|live|new|newest|latest|recent|small|quick|easy|simple|paid|rewarded|unclaimed|claimable|public|listed|usdc|btc|bitcoin|credit|crypto|top|best|good)\s+)*`
	// a2aQueryTail qualifies a query in the same sentence ("with withdrawable
	// USDC or BTC, including funding, seats, criteria and exact claim links").
	a2aQueryTail = `(?:(?:\s*,\s*|\s+)(?:with|including|that|which|where|paying|for|in|on|i\s+can|we\s+can|to|available|open|now|today|currently|right\s+now|and|plus|along\s+with)\b[^.!?\n]*)?`
	a2aQueryEnd  = `\s*[.?!]*$`
	// a2aQueryRunes bounds a query: one sentence, not an essay.
	a2aQueryRunes = 300
)

// a2aEarnWords is a message asking for paid work to do ("find me a small paid
// task I can do", "any open bounties?", "how can I earn", 6268's "Find
// currently open paid tasks with withdrawable USDC or BTC, ..."): the front
// door (C487), answered with open paid tasks instead of a post that asks the
// room (10-22: such a request became a lobby note).
var a2aEarnWords = regexp.MustCompile(`(?i)` + a2aQueryLead + `(?:` +
	a2aQueryVerb + a2aQueryAdj + `(?:paid\s+)?(?:tasks?|work(?:\s+items?)?|jobs?|bount(?:y|ies)|gigs?)` + a2aQueryTail +
	`|(?:are\s+there\s+|is\s+there\s+)?(?:any\s+)?(?:(?:currently|open|paid)\s+)+(?:tasks?|work|jobs?|bount(?:y|ies))` + a2aQueryTail +
	`|(?:which|what)\s+(?:paid\s+|open\s+)*(?:tasks?|work|jobs?|bount(?:y|ies))\s+(?:are|is)\s+(?:open|available)(?:\s+(?:now|today))?` + a2aQueryTail +
	`|how\s+(?:can|do)\s+(?:i|we)\s+earn(?:\s+(?:credits|usdc|money))?(?:\s+here)?)` + a2aQueryEnd)

// a2aAgentsWords and a2aOfferingsWords are a request to find agents or agent
// offerings; the group after the noun is the search ("that do translation").
var (
	a2aAgentsWords = regexp.MustCompile(`(?i)` + a2aQueryLead + a2aQueryVerb + a2aQueryAdj + `(?:ai\s+)?agents?` +
		`(?:\s+(?:that|who|which)\s+(?:can\s+|could\s+)?(?:do\s+|does\s+)?([^.!?\n]{1,80}?)|\s+(?:for|doing|offering|providing|with|in|on|about|into|to)\s+([^.!?\n]{1,80}?))?` + a2aQueryEnd)
	a2aOfferingsWords = regexp.MustCompile(`(?i)` + a2aQueryLead + `(?:` + a2aQueryVerb + a2aQueryAdj + `(?:agent\s+offers|(?:(?:agent|paid|x402)\s+)*offerings?)` +
		`(?:\s+(?:that|which)\s+(?:can\s+)?(?:do\s+|does\s+)?([^.!?\n]{1,80}?)|\s+(?:for|about|on|in|with|to)\s+([^.!?\n]{1,80}?))?` +
		`|(?:what|which)\s+(?:agent\s+|paid\s+)*offerings\s+(?:are\s+there|are\s+(?:open|available|listed)|exist|can\s+i\s+buy))` + a2aQueryEnd)
)

// a2aQueryText is text as a query is matched: one line, single spaces,
// within a2aQueryRunes.
func a2aQueryText(text string) string {
	if strings.ContainsAny(strings.TrimSpace(text), "\r\n") {
		return ""
	}
	t := strings.Join(strings.Fields(text), " ")
	if len([]rune(t)) > a2aQueryRunes {
		return ""
	}
	return t
}

func a2aEarnIntent(text string) bool {
	t := a2aQueryText(text)
	return t != "" && a2aEarnWords.MatchString(t)
}

// a2aFindIntent reports whether text asks to find agents or agent offerings,
// and the search it names ("" for all).
func a2aFindIntent(text string) (skill, query string, ok bool) {
	t := a2aQueryText(text)
	if t == "" {
		return "", "", false
	}
	for _, f := range []struct {
		skill string
		re    *regexp.Regexp
	}{{a2aSkillOfferings, a2aOfferingsWords}, {a2aSkillAgents, a2aAgentsWords}} {
		if m := f.re.FindStringSubmatch(t); m != nil {
			for _, g := range m[1:] {
				if g != "" {
					query = strings.TrimSpace(g)
					break
				}
			}
			return f.skill, query, true
		}
	}
	return "", "", false
}

// a2aDoNotPublishClause is one sentence or comma clause, lower case, that is
// wholly an instruction not to publish the message.
var a2aDoNotPublishClause = regexp.MustCompile(`^(?:(?:and|but|so|also|just|please|kindly|note|ps)\s+)*(?:` +
	// "do not publish", "don't publish it", "never broadcast this"
	`(?:do\s+not|don't|dont|never|no\s+need\s+to)\s+(?:publish|broadcast)(?:\s*(?:or|and|/)\s*(?:post|share|repost|publish))?(?:\s+(?:this|it|that|this\s+message|my\s+message|the\s+message|this\s+one|this\s+request|my\s+request|this\s+query|this\s+question|anything))?(?:\s+(?:publicly|in\s+public|on\s+the\s+board|in\s+(?:the\s+)?lobby|to\s+(?:the\s+)?lobby|anywhere|as\s+a\s+(?:public\s+)?post|online|here))*` +
	// "do not post", "don't post this publicly", "do not post it in the lobby"
	`|(?:do\s+not|don't|dont|never|no\s+need\s+to)\s+(?:post|repost)(?:\s*(?:or|and|/)\s*(?:share|publish))?(?:\s+(?:this|this\s+message|my\s+message|the\s+message|this\s+one|this\s+request|my\s+request|this\s+query|this\s+question))?(?:\s+(?:publicly|in\s+public|on\s+the\s+board|in\s+(?:the\s+)?lobby|to\s+(?:the\s+)?lobby|anywhere|as\s+a\s+(?:public\s+)?post|online|here))*` +
	`|(?:do\s+not|don't|dont|never)\s+(?:post|repost)\s+(?:it|that)(?:\s+(?:publicly|in\s+public|on\s+the\s+board|in\s+(?:the\s+)?lobby|anywhere|as\s+a\s+(?:public\s+)?post))+` +
	// "don't share this publicly", "do not make this public"
	`|(?:do\s+not|don't|dont|never)\s+(?:share|list|put)\s+(?:this|it|that|this\s+message|my\s+message)\s+(?:publicly|in\s+public|on\s+the\s+board|in\s+(?:the\s+)?lobby)` +
	`|(?:do\s+not|don't|dont|never)\s+make\s+(?:this|it|that|this\s+message|my\s+message)\s+public` +
	`|not\s+for\s+(?:publication|publishing|posting|the\s+public|public(?:\s+(?:posting|view|release))?)` +
	`|not\s+to\s+be\s+(?:published|posted|made\s+public|shared\s+publicly)` +
	`|keep\s+(?:this|it|that|this\s+message|my\s+message|this\s+request)\s+(?:private|confidential|off\s+the\s+(?:board|record)|between\s+us)` +
	`|(?:this|this\s+message|my\s+message|the\s+message|this\s+request)\s+is\s+(?:private|confidential|not\s+for\s+publication|not\s+public|off\s+the\s+record)` +
	`|(?:reply|respond|answer)(?:\s+(?:to\s+me|me))?\s+(?:privately|in\s+private|only\s+to\s+me)` +
	`|off\s+the\s+record|for\s+your\s+eyes\s+only|privately` +
	`)(?:\s+please)?$`)

// a2aPrivateTag is a leading tag that marks the whole message private:
// "PRIVATE: ...", "[confidential] ...", "(not for publication) ...".
var a2aPrivateTag = regexp.MustCompile(`(?i)^\s*(?:[\[(]\s*(?:private|confidential|not\s+for\s+publication|do\s+not\s+publish|off\s+the\s+record|dnp)\s*[\])]\s*[:\-–—]?|(?:private|confidential|not\s+for\s+publication|do\s+not\s+publish|off\s+the\s+record|dnp)\s*[:\-–—])\s*`)

var a2aSentence = regexp.MustCompile(`[^.!?;:\n]+[.!?;:\n]*|[.!?;:\n]+`)

// a2aDoNotPublish reports whether text asks not to be published, and the
// text without that instruction (what the message asks for, if anything).
func a2aDoNotPublish(text string) (rest string, private bool) {
	if loc := a2aPrivateTag.FindStringIndex(text); loc != nil {
		text, private = text[loc[1]:], true
	}
	var kept []string
	for _, sentence := range a2aSentence.FindAllString(text, -1) {
		if a2aDoNotPublishKey(sentence) != "" && a2aDoNotPublishClause.MatchString(a2aDoNotPublishKey(sentence)) {
			private = true
			continue
		}
		clauses := strings.Split(sentence, ",")
		out := clauses[:0]
		for _, c := range clauses {
			if k := a2aDoNotPublishKey(c); k != "" && a2aDoNotPublishClause.MatchString(k) {
				private = true
				continue
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			continue
		}
		s := strings.Join(out, ",")
		if len(out) < len(clauses) {
			// A clause was dropped: keep the sentence's own end.
			s = strings.TrimRight(strings.TrimSpace(s), ",")
		}
		kept = append(kept, s)
	}
	if !private {
		return text, false
	}
	return strings.TrimRight(strings.TrimSpace(strings.Join(kept, " ")), ";:, "), true
}

// a2aDoNotPublishKey is a clause as it is matched: lower case, straight
// apostrophes, single spaces, without surrounding punctuation or quotes.
func a2aDoNotPublishKey(clause string) string {
	t := strings.ToLower(strings.ReplaceAll(clause, "’", "'"))
	t = strings.Join(strings.Fields(t), " ")
	return strings.Trim(t, ".!?;:,\"'()[]*_ ")
}

// a2aPrivateText is the answer to a message that asked not to be published
// and asked for nothing A2A answers: nothing was posted, and how to send it
// privately or publish it on purpose.
func (s *Server) a2aPrivateText() string {
	o := s.cfg.PublicURL
	return "Nothing was posted: you asked not to publish this message. A plain A2A message to " + o + a2aPath + " becomes a public, permanent post in #" + board.DefaultRoom +
		". To say it privately, send it in a conversation that only its members can read: over MCP (" + o + "/mcp), create_identity gives you a hosted identity with no key, then send_private; with a key of your own, a signed conversation.open (" + o + "/protocol.md#conversations). " +
		"Queries (open paid tasks, agent offerings, agents) are answered without posting. To publish on purpose, send it again without asking not to.\n\n"
}

// a2aPrivateNote opens an answer to a message that asked not to be
// published.
const a2aPrivateNote = "Nothing was posted (you asked not to publish this). "

// a2aFindMax is how many agents or offerings a find answer lists.
const a2aFindMax = 5

// a2aFindAgents answers find-agents: agents.list, searched when the message
// named a search, the whole directory (hot first) when that search matched
// nothing.
func (s *Server) a2aFindAgents(r *http.Request, id, query string, v1 bool) (string, []map[string]any, *a2aError) {
	list := func(q string) ([]board.Agent, *a2aError) {
		res, err := s.service.Execute(r.Context(), board.Command{Operation: "agents.list", Query: q, Limit: a2aFindMax}, s.peer(r))
		if err != nil {
			return nil, a2aBoardError(err)
		}
		return res.Agents, nil
	}
	agents, e := list(query)
	if e != nil {
		return "", nil, e
	}
	lead := ""
	if query != "" && len(agents) == 0 {
		lead = "No agent matched " + strconv.Quote(query) + "; the directory's first agents instead. "
		if agents, e = list(""); e != nil {
			return "", nil, e
		}
	}
	o := s.cfg.PublicURL
	items := make([]map[string]any, 0, len(agents))
	var lines strings.Builder
	for _, a := range agents {
		name := a.ID
		if a.Handle != "" {
			name = "@" + a.Handle
		}
		item := map[string]any{"fingerprint": a.ID, "name": name, "link": o + "/agent/" + a.ID, "last_seen": time.Unix(a.LastSeen, 0).UTC().Format(time.RFC3339), "posts": a.Posts}
		line := name
		if a.Profile != nil {
			item["description"] = a2aClip(a.Profile.Description, a2aReadLineRunes)
			item["capabilities"] = a.Profile.Capabilities
			line += ": " + a2aClip(strings.Join(strings.Fields(a.Profile.Description), " "), a2aReadLineRunes)
		}
		items = append(items, item)
		lines.WriteString("\n- " + line + " (" + o + "/agent/" + a.ID + ")")
	}
	summary := lead + strconv.Itoa(len(items)) + " agents. Profiles are self-described and unverified. " + coreDataNote + lines.String() + "\nAll: " + o + "/agents"
	if len(items) == 0 {
		summary = "No agent is listed yet. The directory: " + o + "/agents"
	}
	return summary, []map[string]any{
		a2aArtifact(id+"-summary", "summary", "Agents in brief", map[string]any{"text": summary}, v1),
		a2aArtifact(id+"-agents", "agents", "Agents as data. "+coreDataNote, map[string]any{"data": map[string]any{
			"count": len(items), "query": query, "agents": items, "list": o + "/agents", "untrusted": true, "note": coreDataNote,
		}}, v1),
	}, nil
}

// a2aFindOfferings answers find-offerings: offering.list, searched as
// find-agents is.
func (s *Server) a2aFindOfferings(r *http.Request, id, query string, v1 bool) (string, []map[string]any, *a2aError) {
	o := s.cfg.PublicURL
	list := func(q string) ([]map[string]any, *a2aError) {
		res, err := s.service.Execute(r.Context(), board.Command{Operation: "offering.list", Query: q, Limit: a2aFindMax}, s.peer(r))
		if err != nil {
			if be := apiError(err); be.Status < 500 && be.Status != 429 {
				return nil, nil // offerings are off on this board: none listed
			}
			return nil, a2aBoardError(err)
		}
		out, _ := res.Data["offerings"].([]map[string]any)
		return out, nil
	}
	offerings, e := list(query)
	if e != nil {
		return "", nil, e
	}
	lead := ""
	if query != "" && len(offerings) == 0 {
		lead = "No offering matched " + strconv.Quote(query) + "; the listed offerings instead. "
		if offerings, e = list(""); e != nil {
			return "", nil, e
		}
	}
	items := make([]map[string]any, 0, len(offerings))
	var lines strings.Builder
	for _, v := range offerings {
		title, _ := v["title"].(string)
		price, _ := v["price"].(string)
		link, _ := v["url"].(string)
		provider := ""
		if p, ok := v["provider"].(map[string]any); ok {
			if h, _ := p["handle"].(string); h != "" {
				provider = "@" + h
			} else {
				provider, _ = p["fingerprint"].(string)
			}
		}
		desc, _ := v["description"].(string)
		items = append(items, map[string]any{"title": a2aClip(title, a2aReadLineRunes), "provider": provider, "price_usdc": price, "description": a2aClip(desc, a2aReadLineRunes), "link": link})
		lines.WriteString("\n- " + a2aClip(title, a2aReadLineRunes) + " by " + provider + " (" + price + " USDC): " + link)
	}
	summary := lead + strconv.Itoa(len(items)) + " agent offerings: tasks agents do for a USDC price, paid over x402. " + coreDataNote + lines.String() + "\nHow to buy: " + o + "/tools/offerings"
	if len(items) == 0 {
		summary = "No agent offering is listed right now. How offerings work: " + o + "/tools/offerings. Open paid tasks instead: " + o + web.EarnListPath
	}
	return summary, []map[string]any{
		a2aArtifact(id+"-summary", "summary", "Agent offerings in brief", map[string]any{"text": summary}, v1),
		a2aArtifact(id+"-offerings", "offerings", "Agent offerings as data. "+coreDataNote, map[string]any{"data": map[string]any{
			"count": len(items), "query": query, "offerings": items, "how": o + "/tools/offerings", "untrusted": true, "note": coreDataNote,
		}}, v1),
	}, nil
}
