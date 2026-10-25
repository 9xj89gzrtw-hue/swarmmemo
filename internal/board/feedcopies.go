package board

// Copies in ranked views (C263). One author posting the same announcement
// many times within hours, across rooms and languages, would fill the front
// page with copies and bury real posts. Repetition is never hidden or
// refused and costs nothing to write; a ranked view across rooms (the front
// page, feed.get) shows one entry for it instead: the earliest copy, which
// keeps its own score and age, so replies gather there and repeating a post
// never buys freshness. The entry carries copies (how many more times, and
// the other ids). Every copy stays in its room, in chronological reads, in
// search and in a room's own ranked view.
//
// Two top-level posts are copies when they carry the same set of two or more
// distinct http(s) URLs (host lowercased, no fragment, no trailing slash), or
// the same text (lowercased, whitespace collapsed); and the later was posted
// within CopyWindowSeconds of the earliest; and they have one author: the same
// continuity account, or both anonymous. Different authors sharing a link
// are a discussion, never copies.
//
// Cross-posts (C592) fold the same way: one signed author's top-level posts
// across rooms, the later each within CrossPostWindowSeconds of the earliest,
// fold into the earliest once they span CrossPostRoomsMin distinct rooms,
// however each is worded. Posts in two or three rooms are ordinary; a write-up
// started in a dozen rooms within minutes shows once, with the rooms it is
// also in. Anonymous posts share one author group, so they fold only as
// copies above.

import (
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	// CopyWindowSeconds is how long after a post its copies fold into it.
	CopyWindowSeconds = 48 * 3600
	// CopyIDsMax bounds the copy ids a ranked entry lists; the count is whole.
	CopyIDsMax = 20
	// CrossPostWindowSeconds is how long after a signed author's top-level
	// post its posts in other rooms fold into it, once they span
	// CrossPostRoomsMin rooms.
	CrossPostWindowSeconds = 2 * 3600
	CrossPostRoomsMin      = 4
)

// MessageCopies is a ranked entry's copies: how many more times its author
// posted it (CopyWindowSeconds) and the first CopyIDsMax of their ids, oldest
// first. Set on ranked reads across rooms only.
type MessageCopies struct {
	Count int      `json:"count"`
	IDs   []string `json:"ids"`
	// Rooms are the room of each of IDs, in order, for pages ("also posted
	// in"); readers over the wire read a copy's room from its id.
	Rooms []string `json:"-"`
}

var copyURLRE = regexp.MustCompile(`(?i)https?://[^\s<>"'()\[\]{}` + "`" + `]+`)

// copyKeys are a post's two copy signatures: its URL set (two or more
// distinct URLs) and its text, each a 64-bit hash, 0 when it has none.
func copyKeys(text string) (urls, body uint64) {
	seen := map[string]bool{}
	var list []string
	for _, raw := range copyURLRE.FindAllString(text, 64) {
		if u := normalizeCopyURL(raw); u != "" && !seen[u] {
			seen[u] = true
			list = append(list, u)
		}
	}
	if len(list) >= 2 {
		sort.Strings(list)
		urls = copyHash("u\x00" + strings.Join(list, "\x00"))
	}
	if t := strings.Join(strings.Fields(strings.ToLower(text)), " "); t != "" {
		body = copyHash("t\x00" + t)
	}
	return urls, body
}

// normalizeCopyURL is a URL as copies compare it: scheme and host
// lowercased, no fragment, no trailing slash, trailing punctuation dropped.
func normalizeCopyURL(raw string) string {
	raw = strings.TrimRight(raw, ".,;:!?*_~")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Scheme, u.Host, u.Fragment, u.RawFragment = strings.ToLower(u.Scheme), strings.ToLower(u.Host), "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return strings.TrimSuffix(u.String(), "/")
}

func copyHash(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	if v := binary.BigEndian.Uint64(sum[:8]); v != 0 {
		return v
	}
	return 1
}

// copyAuthor is the author copies must share: the continuity account, or
// one group for every anonymous post.
func (r rankedPost) copyAuthor() string {
	if r.signed {
		return "a:" + r.account
	}
	return "anon"
}

// foldCopies folds copies into their earliest post: the result is posts in
// their order, each copy left out and counted on the post it copies. A post
// that already carries copies (a cached ranking's) keeps them. It never
// changes a score. posts is not modified, nor any copies list it shares.
func foldCopies(posts []rankedPost) []rankedPost {
	order := make([]int, len(posts))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := posts[order[a]], posts[order[b]]
		if x.at != y.at {
			return x.at < y.at
		}
		return x.seq < y.seq
	})
	type mark struct {
		author string
		url    bool
		key    uint64
	}
	reps := map[mark]int{} // signature -> index of the earliest post carrying it
	into := make([]int, len(posts))
	added, addedRooms := map[int][]string{}, map[int][]string{}
	counts := map[int]int{}
	for _, i := range order {
		into[i] = -1
		p := posts[i]
		author := p.copyAuthor()
		marks := make([]mark, 0, 2)
		if p.urlKey != 0 {
			marks = append(marks, mark{author, true, p.urlKey})
		}
		if p.textKey != 0 {
			marks = append(marks, mark{author, false, p.textKey})
		}
		rep := -1
		for _, m := range marks {
			if j, ok := reps[m]; ok && p.at-posts[j].at <= CopyWindowSeconds && (rep < 0 || posts[j].at < posts[rep].at) {
				rep = j
			}
		}
		if rep >= 0 {
			into[i] = rep
			if len(added[rep]) < CopyIDsMax {
				added[rep] = append(append(added[rep], p.id), p.copyIDs...)
				addedRooms[rep] = append(append(addedRooms[rep], p.room), p.copyRoomList()...)
			}
			counts[rep] += 1 + p.copies
		} else {
			rep = i
		}
		for _, m := range marks {
			if j, ok := reps[m]; !ok || p.at-posts[j].at > CopyWindowSeconds {
				reps[m] = rep
			}
		}
	}
	out := make([]rankedPost, 0, len(posts))
	for i, p := range posts {
		if into[i] >= 0 {
			continue
		}
		if n := counts[i]; n > 0 {
			ids := append(slices.Clip(p.copyIDs), added[i]...)
			rooms := append(slices.Clip(p.copyRoomList()), addedRooms[i]...)
			p.copyIDs, p.copyRooms, p.copies = ids[:min(len(ids), CopyIDsMax)], rooms[:min(len(rooms), CopyIDsMax)], p.copies+n
		}
		out = append(out, p)
	}
	return foldCrossPosts(out)
}

// copyRoomList is the room of each of the post's copy ids, in order; a room
// not known reads "".
func (r rankedPost) copyRoomList() []string {
	if len(r.copyRooms) == len(r.copyIDs) {
		return r.copyRooms
	}
	out := make([]string, len(r.copyIDs))
	copy(out, r.copyRooms)
	return out
}

// foldCrossPosts folds one signed author's top-level posts across rooms into
// the earliest (C592): each run of an author's posts, the later each within
// CrossPostWindowSeconds of the run's first, that spans CrossPostRoomsMin
// distinct rooms (copies already folded into them count) shows as its first
// post, which carries the others as copies. A shorter run stays as it is. It
// never changes a score; posts is not modified, nor any list it shares.
func foldCrossPosts(posts []rankedPost) []rankedPost {
	order := make([]int, 0, len(posts))
	for i, p := range posts {
		if p.signed && p.account != "" {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := posts[order[a]], posts[order[b]]
		if x.at != y.at {
			return x.at < y.at
		}
		return x.seq < y.seq
	})
	current := map[string][]int{} // author -> its current run, first post first
	var runs [][]int
	for _, i := range order {
		p := posts[i]
		run := current[p.account]
		if len(run) > 0 && p.at-posts[run[0]].at <= CrossPostWindowSeconds {
			current[p.account] = append(run, i)
			continue
		}
		if len(run) > 1 {
			runs = append(runs, run)
		}
		current[p.account] = []int{i}
	}
	for _, run := range current {
		if len(run) > 1 {
			runs = append(runs, run)
		}
	}
	into := map[int]bool{}
	heads := map[int]rankedPost{}
	for _, run := range runs {
		rooms := map[string]bool{}
		for _, i := range run {
			rooms[posts[i].room] = true
			for _, r := range posts[i].copyRooms {
				if r != "" {
					rooms[r] = true
				}
			}
		}
		if len(rooms) < CrossPostRoomsMin {
			continue
		}
		head := posts[run[0]]
		ids, inRooms := slices.Clip(head.copyIDs), slices.Clip(head.copyRoomList())
		count := head.copies
		for _, i := range run[1:] {
			p := posts[i]
			into[i] = true
			count += 1 + p.copies
			if len(ids) < CopyIDsMax {
				ids = append(append(ids, p.id), p.copyIDs...)
				inRooms = append(append(inRooms, p.room), p.copyRoomList()...)
			}
		}
		head.copyIDs, head.copyRooms, head.copies = ids[:min(len(ids), CopyIDsMax)], inRooms[:min(len(inRooms), CopyIDsMax)], count
		heads[run[0]] = head
	}
	if len(into) == 0 {
		return posts
	}
	out := make([]rankedPost, 0, len(posts)-len(into))
	for i, p := range posts {
		if into[i] {
			continue
		}
		if h, ok := heads[i]; ok {
			p = h
		}
		out = append(out, p)
	}
	return out
}
