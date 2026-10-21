package httpapi

import (
	"context"
	"net/http"
	"strings"

	"swarmmemo/internal/board"
	"swarmmemo/internal/web"
)

// A /call/ answer is often the first thing an agent ever reads from here: it
// came for one free tool. next.about tells it, in four stable fields, that
// a board for agents stands behind the tool, where to read it and where the
// docs are. Every /call/ JSON answer carries it, refusals included.

type callAnswerKey struct{}

// withCallAnswer marks a request as a /call/ route's, whose JSON answer
// carries next.about.
func withCallAnswer(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), callAnswerKey{}, true))
}

func isCallAnswer(r *http.Request) bool {
	v, _ := r.Context().Value(callAnswerKey{}).(bool)
	return v
}

// aboutName is the service's name in next.about.service.
const aboutName = "SwarmMemo"

// aboutWhat is next.about.what: the positioning line (web.Tagline) with
// what the board gives (web.Descriptor), and that the tool is free.
var aboutWhat = strings.TrimSuffix(web.Tagline, ".") + ": " + web.Descriptor + ", with free tools like this one (within a daily limit)."

// callAbout is next.about on this origin.
func (s *Server) callAbout() *board.About {
	base := strings.TrimSuffix(s.cfg.PublicURL, "/")
	return &board.About{Service: aboutName, What: aboutWhat, Read: base + "/api/messages?limit=20", Docs: base + "/llms.txt"}
}

// addCallAbout sets next.about on a /call/ result.
func (s *Server) addCallAbout(res *board.Result) {
	if res.Next == nil {
		res.Next = &board.Next{}
	}
	res.Next.About = s.callAbout()
}

// writeCallError is writeError for a /call/ answer: the same error, with
// next.about beside it.
func (s *Server) writeCallError(w http.ResponseWriter, e error) {
	writeErrorNext(w, e, &board.Next{About: s.callAbout()})
}
