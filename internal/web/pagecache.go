package web

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"

	"swarmmemo/internal/board"
)

// The page cache (C554) keeps the anonymous render of the two public pages
// that read the most, the home page and /stats, for a short while, so a
// burst of readers costs one render. Only a request that names nothing of
// its own is served from it or fills it: GET or HEAD of exactly "/",
// "/stats" or "/stats?bucket=hour", with no Authorization and no Cookie
// header (an OAuth grant, a lounge or proof cookie, anything a later
// personalised render could read). Every other request renders as before.
//
// The home page is kept while the board has not changed: an entry holds the
// board's change signal (board.Store.Changes), taken before its render, and
// the next committed write ends it, so a reader who just posted never gets
// the page from before the post. homeCacheTTL bounds what no write signals
// (relative ages, hot ranking's decay, a moderator's hide). /stats reads the
// board's activity summary, itself recomputed once a minute, so it is kept
// for statsCacheTTL whatever is written, and served up to statsCacheStale
// old while one render refreshes it in the background: no reader waits for
// the summary's recomputation unless nothing is cached.
//
// One render per page runs at a time (singleflight): readers that arrive
// while it runs wait for its result. The render is detached from the
// request that started it, so that reader leaving does not fail the others.
// A response other than 200 goes to the readers that waited for it and is
// never kept.
const (
	homeCacheTTL    = 10 * time.Second
	statsCacheTTL   = time.Minute
	statsCacheStale = 5 * time.Minute
	pageRenderLimit = 20 * time.Second
)

// pagePolicy is how long one cached page is kept.
type pagePolicy struct {
	ttl      time.Duration // served as is until this old
	stale    time.Duration // then, until this old, served while it refreshes; 0: never
	onChange bool          // a committed write ends the entry
}

// cachedPolicy is the policy of a request the cache may serve, by path and
// query, or false.
func cachedPolicy(r *http.Request) (pagePolicy, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		return pagePolicy{}, false
	}
	switch {
	case r.URL.Path == "/" && r.URL.RawQuery == "":
		return pagePolicy{ttl: homeCacheTTL, onChange: true}, true
	case r.URL.Path == "/stats" && (r.URL.RawQuery == "" || r.URL.RawQuery == "bucket=hour"):
		return pagePolicy{ttl: statsCacheTTL, stale: statsCacheStale}, true
	}
	return pagePolicy{}, false
}

// cachedPage is one kept render.
type cachedPage struct {
	status  int
	header  http.Header
	body    []byte
	at      time.Time
	changed <-chan struct{} // closed by the first write after the render began; nil: none
}

// pageFlight is a render in progress; done closes when page is set (nil if
// the render panicked).
type pageFlight struct {
	done chan struct{}
	page *cachedPage
}

type pageCache struct {
	next    http.Handler
	changes func() <-chan struct{}
	now     func() time.Time
	mu      sync.Mutex
	pages   map[string]*cachedPage
	flights map[string]*pageFlight
}

// withPageCache serves next through a page cache when service signals its
// changes (the board store); any other service is served directly.
func withPageCache(service board.Service, next http.Handler) http.Handler {
	notifier, ok := service.(interface{ Changes() <-chan struct{} })
	if !ok {
		return next
	}
	return newPageCache(next, notifier.Changes, time.Now)
}

func newPageCache(next http.Handler, changes func() <-chan struct{}, now func() time.Time) *pageCache {
	return &pageCache{next: next, changes: changes, now: now, pages: map[string]*cachedPage{}, flights: map[string]*pageFlight{}}
}

func (c *pageCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	policy, ok := cachedPolicy(r)
	if !ok {
		c.next.ServeHTTP(w, r)
		return
	}
	// The origin is the deployment's (WithOrigin), part of the key all the same.
	key := requestOrigin(r) + " " + r.URL.Path + "?" + r.URL.RawQuery
	c.mu.Lock()
	page := c.pages[key]
	if page != nil {
		switch age := c.now().Sub(page.at); {
		case age < 0 || policy.onChange && closed(page.changed):
			page = nil
		case age < policy.ttl:
		case age < policy.stale:
			c.startLocked(key, r) // served stale; a render refreshes it
		default:
			page = nil
		}
	}
	var flight *pageFlight
	if page == nil {
		flight = c.startLocked(key, r)
	}
	c.mu.Unlock()
	if flight != nil {
		select {
		case <-flight.done:
			page = flight.page
		case <-r.Context().Done():
			return
		}
	}
	if page == nil {
		// The render panicked: this reader gets its own.
		c.next.ServeHTTP(w, r)
		return
	}
	for name, values := range page.header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(page.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(page.body)
	}
}

// startLocked returns key's render in progress, or starts one, as a GET of
// r's page detached from r's cancellation. c.mu is held.
func (c *pageCache) startLocked(key string, r *http.Request) *pageFlight {
	if f := c.flights[key]; f != nil {
		return f
	}
	f := &pageFlight{done: make(chan struct{})}
	c.flights[key] = f
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), pageRenderLimit)
	render := r.Clone(ctx)
	render.Method = http.MethodGet
	go func() {
		defer cancel()
		var page *cachedPage
		defer func() {
			// A render that panics keeps nothing; the readers then render
			// themselves, under the server's own recovery.
			if recover() != nil {
				page = nil
			}
			c.mu.Lock()
			if page != nil && page.status == http.StatusOK {
				c.pages[key] = page
			}
			delete(c.flights, key)
			f.page = page
			c.mu.Unlock()
			close(f.done)
		}()
		changed := c.changes() // before the render: a write during it ends the entry
		at := c.now()
		rec := &pageRecorder{header: http.Header{}}
		c.next.ServeHTTP(rec, render)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		page = &cachedPage{status: rec.status, header: rec.header, body: rec.body.Bytes(), at: at, changed: changed}
	}()
	return f
}

func closed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// pageRecorder keeps a render's status, headers and body.
type pageRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (p *pageRecorder) Header() http.Header { return p.header }

func (p *pageRecorder) WriteHeader(status int) {
	if p.status == 0 {
		p.status = status
	}
}

func (p *pageRecorder) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return p.body.Write(b)
}
