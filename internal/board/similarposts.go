package board

// Bursts of similar posts on a page (C601). One key posting dozens of
// near-identical top-level posts into one room within seconds (an importer's
// run, a loop) fills a room's page with one template. A messages.list page
// marks such a burst instead: its first post in the page's order carries
// similar {count, ids} and every other post of the burst carries similar_to,
// the first's id. Nothing is left out of the page, hidden or refused, cursors
// and counts are unchanged, and moderation never reads these marks; pages
// show the burst as one entry with "+N similar" that expands.
//
// A burst is SimilarRunMin or more public top-level posts (not replies,
// versions, app records, tasks or their results, sealed or removed posts) by one key in one room, each
// within SimilarWindowSeconds of the burst's earliest, with no other key's
// top-level post in that room between them, whose texts share a similarity
// prefix: lowercased, URLs and digits dropped, every run of non-letters one
// space, the first SimilarPrefixRunes letters and spaces. A text shorter than
// half that has no prefix and never folds. Copies (feedcopies.go) are the
// ranked, across-rooms counterpart.

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// SimilarWindowSeconds is how long after a burst's earliest post its
	// key's similar posts in that room still fold into it.
	SimilarWindowSeconds = 10 * 60
	// SimilarPrefixRunes is how much of a normalized text two posts share to
	// be similar.
	SimilarPrefixRunes = 24
	// SimilarRunMin is the fewest posts that make a burst.
	SimilarRunMin = 3
)

// similarPrefix is text's similarity prefix, "" when it is too short to
// compare.
func similarPrefix(text string) string {
	text = copyURLRE.ReplaceAllString(strings.ToLower(text), " ")
	var b strings.Builder
	n, space := 0, true
	for _, r := range text {
		if n == SimilarPrefixRunes {
			break
		}
		switch {
		case unicode.IsDigit(r):
			continue
		case unicode.IsLetter(r):
			b.WriteRune(r)
			space = false
		case space:
			continue
		default:
			b.WriteByte(' ')
			space = true
		}
		n++
	}
	out := strings.TrimRight(b.String(), " ")
	if utf8.RuneCountInString(out) < SimilarPrefixRunes/2 {
		return ""
	}
	return out
}

// similarCandidate reports whether m can be part of a burst.
func similarCandidate(m Message) bool {
	return m.Visibility == "public" && m.PublicKey != "" && m.ReplyTo == "" && m.Supersedes == "" &&
		!m.Hidden && !m.Sealed && !strings.HasPrefix(m.Kind, "app-") && m.Work == nil
}

// foldSimilar marks the bursts on a page of messages (in the page's order:
// newest first, oldest first or ranked). It returns page itself when there
// is none, else a copy with the marks set; page is never modified.
func foldSimilar(page []Message) []Message {
	// Each room's top-level posts on the page, oldest first.
	rooms := map[string][]int{}
	for i, m := range page {
		if m.ReplyTo == "" && m.Supersedes == "" && !m.Hidden {
			rooms[m.Room] = append(rooms[m.Room], i)
		}
	}
	var runs [][]int
	for _, list := range rooms {
		slices.SortStableFunc(list, func(a, b int) int {
			if page[a].CreatedAt != page[b].CreatedAt {
				return int(page[a].CreatedAt - page[b].CreatedAt)
			}
			return int(page[a].Sequence - page[b].Sequence)
		})
		var run []int
		key := ""
		for _, i := range list {
			m := page[i]
			prefix := ""
			if similarCandidate(m) {
				prefix = similarPrefix(m.Text)
			}
			if len(run) > 0 && prefix != "" && prefix == key && m.PublicKey == page[run[0]].PublicKey && m.CreatedAt-page[run[0]].CreatedAt <= SimilarWindowSeconds {
				run = append(run, i)
				continue
			}
			if len(run) >= SimilarRunMin {
				runs = append(runs, run)
			}
			run, key = nil, prefix
			if prefix != "" {
				run = []int{i}
			}
		}
		if len(run) >= SimilarRunMin {
			runs = append(runs, run)
		}
	}
	if len(runs) == 0 {
		return page
	}
	out := slices.Clone(page)
	for _, run := range runs {
		slices.Sort(run) // the page's order: the first shown leads the burst
		head := &out[run[0]]
		similar := &MessageCopies{Count: len(run) - 1}
		for _, i := range run[1:] {
			out[i].SimilarTo = head.ID
			if len(similar.IDs) < CopyIDsMax {
				similar.IDs = append(similar.IDs, out[i].ID)
			}
		}
		head.Similar = similar
	}
	return out
}
