package web

import "swarmmemo/internal/board"

// copiesShown bounds the rooms a ranked entry's "also posted in" line names;
// the rest are counted (+N).
const copiesShown = 3

// copyLink is one room a ranked entry is also posted in, linking the first
// copy there.
type copyLink struct{ Room, ID string }

// copiesLine is a ranked entry's folded copies and cross-posts (C263, C592)
// as its "also posted in #a, #b (+N)" line: the first copy in each of up to
// copiesShown other rooms, and how many copies the line does not link.
// Copies with no known room (an older cached ranking) only count.
type copiesLine struct {
	Links []copyLink
	More  int
}

func copiesLineOf(c *board.MessageCopies) copiesLine {
	var out copiesLine
	if c == nil {
		return out
	}
	seen := map[string]bool{}
	for i, id := range c.IDs {
		if i >= len(c.Rooms) || len(out.Links) == copiesShown {
			break
		}
		if room := c.Rooms[i]; room != "" && !seen[room] {
			seen[room] = true
			out.Links = append(out.Links, copyLink{Room: room, ID: id})
		}
	}
	out.More = max(c.Count-len(out.Links), 0)
	return out
}

// foldSimilar draws a burst of one key's similar posts (board similarposts.go,
// C601) as one entry: each post marked similar_to leaves the list and is
// listed under its burst's first post instead, behind "+N similar", by that
// post's id. A marked post whose first is not on the page stays as it is.
func foldSimilar(events []board.Message) ([]board.Message, map[string][]*board.Message) {
	heads := map[string]bool{}
	for _, e := range events {
		if e.Similar != nil {
			heads[e.ID] = true
		}
	}
	if len(heads) == 0 {
		return events, nil
	}
	kept := make([]board.Message, 0, len(events))
	similar := map[string][]*board.Message{}
	for _, e := range events {
		if heads[e.SimilarTo] {
			similar[e.SimilarTo] = append(similar[e.SimilarTo], &e)
			continue
		}
		kept = append(kept, e)
	}
	return kept, similar
}
