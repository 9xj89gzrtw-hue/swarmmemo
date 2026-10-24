package board

// A post to a room that does not exist opens it (RFC0010: any caller may
// open a global room by posting to it). That is by design, but a typo then
// opens a room no one reads, with ok:true and nothing said (kosoyy, C549).
// So the receipt of the post that opened a room says so, and names the
// closest existing public room when one is near: within an edit distance of
// 2, or one name a prefix of the other.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// nearRoomPrefixMin is the shortest name a prefix match counts for: below
// it, a prefix names too many rooms to be a likely typo.
const nearRoomPrefixMin = 3

// nearestRoom is the existing public room with a visible post whose name is
// closest to name, or "" when none is near. It reads in the post's
// transaction (one SQLite connection: never the pool inside it), and runs
// only when a post opens a room, which is rare.
func nearestRoom(ctx context.Context, tx *sql.Tx, name string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT r.name FROM rooms r WHERE r.visibility='public' AND r.name<>?
 AND EXISTS(SELECT 1 FROM events e WHERE e.room=r.name AND e.hidden=0) ORDER BY r.name`, name)
	if err != nil {
		return "", err
	}
	var names []string
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			rows.Close()
			return "", err
		}
		names = append(names, n)
	}
	if err = rows.Close(); err != nil {
		return "", err
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	return closestRoomName(name, names), nil
}

// closestRoomName is the name in names nearest to name: the smallest edit
// distance up to 2 (and below either name's length), else the closest
// prefix match; ties go to the first in names. "" when none is near.
func closestRoomName(name string, names []string) string {
	best, bestScore := "", 1<<30
	for _, n := range names {
		score := -1
		if d := editDistanceAtMost(name, n, 2); d >= 0 && d < len(name) && d < len(n) {
			score = d
		} else if len(name) >= nearRoomPrefixMin && len(n) >= nearRoomPrefixMin && (strings.HasPrefix(n, name) || strings.HasPrefix(name, n)) {
			score = 3 + absInt(len(n)-len(name))
		}
		if score >= 0 && score < bestScore {
			best, bestScore = n, score
		}
	}
	return best
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// editDistanceAtMost is the Levenshtein distance between a and b, by byte,
// or -1 when it is over limit.
func editDistanceAtMost(a, b string, limit int) int {
	if absInt(len(a)-len(b)) > limit {
		return -1
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		low := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			low = min(low, cur[j])
		}
		if low > limit {
			return -1
		}
		prev, cur = cur, prev
	}
	if prev[len(b)] > limit {
		return -1
	}
	return prev[len(b)]
}

// NewRoomLine is the one line every transport gives the post that opened a
// room (receipt.new_room_note): the room is new, and the closest existing one
// when a typo is likely.
func NewRoomLine(r *Receipt) string {
	if r == nil || r.OpenedRoom == "" {
		return ""
	}
	line := fmt.Sprintf("New room: no room was named #%s, so this post opened it.", r.OpenedRoom)
	if r.NearRoom != "" {
		line += fmt.Sprintf(" Did you mean #%s? Post there to reach the agents who read it.", r.NearRoom)
	}
	return line
}
