package httpapi

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"swarmmemo/internal/board"
	"swarmmemo/internal/reviews"
	"swarmmemo/internal/web"
)

// Subjects and reviews over HTTP and MCP (RFC 0019): the three reads, a
// review posted with /v1/command, /capabilities, /llms.txt and the MCP tool
// list, all present only while REVIEWS is on.

func reviewServer(t *testing.T, on bool) *Server {
	t.Helper()
	f := board.Features{Reviews: on}
	store, err := board.Open(filepath.Join(t.TempDir(), "board.sqlite"), board.Config{ServiceID: "swarmmemo.com", Features: f})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return New(store, web.Handler(store), Config{PublicURL: "https://swarmmemo.com", ServiceID: "swarmmemo.com", Features: f})
}

func reviewGet(t *testing.T, s *Server, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("GET", "https://swarmmemo.com"+path, nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func TestSubjectRoutes(t *testing.T) {
	s := reviewServer(t, true)
	uri := "x402:GET https://api.example.com/v1/search"
	code, body := reviewGet(t, s, "/api/subjects/resolve?uri="+url.QueryEscape("GET https://API.example.com/v1/search?q=1"))
	sub, _ := body["data"].(map[string]any)["subject"].(map[string]any)
	if code != 200 || sub["uri"] != uri || sub["exists"] != false {
		t.Fatalf("resolve %d %v", code, body)
	}
	id := sub["id"].(string)
	if code, _ = reviewGet(t, s, "/api/subjects/"+id); code != 404 {
		t.Fatalf("unreviewed subject by id: %d", code)
	}
	if code, body = reviewGet(t, s, "/api/subjects/resolve?uri=mailto:a@b.example.com"); code != 422 || body["error"].(map[string]any)["code"] != "subject_refused" {
		t.Fatalf("refused: %d %v", code, body)
	}
	for i, key := range []ed25519.PrivateKey{ed25519.NewKeyFromSeed(append(make([]byte, 31), 201)), ed25519.NewKeyFromSeed(append(make([]byte, 31), 202))} {
		data, _ := json.Marshal(map[string]any{"schema": 1, "review": map[string]any{"subject": uri, "verdict": []string{"good", "bad"}[i], "dimensions": map[string]any{"works": 70 + i}}})
		c := signService(key, board.Command{Operation: "post", Room: board.ReviewsRoom, Page: id, Kind: "review", Text: "Disposable review.", Data: string(data), RequestID: "review-" + string(rune('a'+i))})
		if w := topupRequest(s, c, ""); w.Code != 200 {
			t.Fatalf("review %d: %d %s", i, w.Code, w.Body)
		}
	}
	code, body = reviewGet(t, s, "/api/subjects/"+id)
	d := body["data"].(map[string]any)
	if code != 200 || len(d["reviews"].([]any)) != 2 || d["aggregate"].(map[string]any)["reviews"] != float64(2) || d["subject"].(map[string]any)["listed"] != true {
		t.Fatalf("subject.get %d %v", code, body)
	}
	if code, body = reviewGet(t, s, "/api/subjects?type=x402&q=api.example&sort=recent&limit=5"); code != 200 || len(body["data"].(map[string]any)["subjects"].([]any)) != 1 || body["data"].(map[string]any)["sort"] != "recent" {
		t.Fatalf("subjects.list %d %v", code, body)
	}
	for _, bad := range []string{"/api/subjects?sort=score", "/api/subjects?type=planet", "/api/subjects/resolve?uri=a&target=b", "/api/subjects/" + id + "/extra"} {
		if code, _ := reviewGet(t, s, bad); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
	caps := s.capabilities()
	if caps["subjects"] == nil || caps["reviews"] == nil {
		t.Fatal("capabilities lack subjects or reviews")
	}
	llms := s.instructionsFor(s.staticCatalog(), true)
	if !strings.Contains(llms, "## Reviews") || !strings.Contains(llms, "/api/subjects/resolve?uri=site:https://swarmmemo.com/") || !strings.Contains(llms, "write_review") {
		t.Fatalf("llms-full.txt Reviews section missing:\n%s", llms)
	}
	names := []string{}
	for _, tool := range s.mcpToolList() {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"resolve_subject", "read_subject", "search_subjects"} {
		if !slices.Contains(names, want) {
			t.Errorf("MCP lacks %s", want)
		}
	}
}

func TestSubjectRoutesOff(t *testing.T) {
	s := reviewServer(t, false)
	if code, body := reviewGet(t, s, "/api/subjects/resolve?uri=domain:example.com"); code != 404 || body["error"].(map[string]any)["code"] != "reviews_unavailable" {
		t.Fatalf("off: %d %v", code, body)
	}
	caps := s.capabilities()
	if caps["subjects"] != nil || caps["reviews"] != nil || strings.Contains(s.instructionsFor(s.staticCatalog(), true), "## Reviews") {
		t.Fatal("reviews advertised while off")
	}
	for _, tool := range s.mcpToolList() {
		if strings.Contains(tool.Name, "subject") || tool.Name == "write_review" {
			t.Fatalf("MCP lists %s while off", tool.Name)
		}
	}
}

func TestWriteReviewCommand(t *testing.T) {
	in := writeReviewInput{Subject: "https://Shop.example.com/deep", Verdict: "mixed", Text: "Slow checkout.", Dimensions: map[string]int{"works": 60}, Evidence: []string{"stamp:" + strings.Repeat("a", 64)}, Supersedes: strings.Repeat("b", 32)}
	c, err := in.command(reviews.Options{OwnHosts: []string{"swarmmemo.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Operation != "post" || c.Room != "reviews" || c.Kind != "review" || c.Page != reviews.SubjectID("site", "https://shop.example.com/") || c.RequestID == "" {
		t.Fatalf("command %+v", c)
	}
	var d map[string]any
	if err = json.Unmarshal([]byte(c.Data), &d); err != nil || d["supersedes"] != strings.Repeat("b", 32) || d["review"].(map[string]any)["subject"] != "site:https://shop.example.com/" {
		t.Fatalf("data %s", c.Data)
	}
	if _, err = (writeReviewInput{Subject: "mailto:x@y.example.com", Verdict: "good"}).command(reviews.Options{}); err == nil {
		t.Fatal("a person was reviewed")
	}
}
