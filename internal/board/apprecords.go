package board

import "strings"

// App records (C544): an app built on SwarmMemo keeps its own metadata (a
// like, a delete, a settings change, app state) as posts whose kind starts
// with AppRecordPrefix: app-like, app-state, app-anything. They are stored,
// signed, exported and paged like any post, but they are not conversation:
// they notify no one (no mention, inbox entry or push), and every read a
// person sees leaves them out unless it asks for them, by exact kind or with
// data records ("include" or "only") on messages.list and updates.get. So an
// app needs no rooms used as tables to keep its records out of people's
// feeds. A record is still a post: the same limits, charges and moderation.
const AppRecordPrefix = "app-"

// Records values of messages.list and updates.get data.
const (
	RecordsInclude = "include"
	RecordsOnly    = "only"
)

// IsAppRecord reports whether kind marks an app record.
func IsAppRecord(kind string) bool { return strings.HasPrefix(kind, AppRecordPrefix) }

// Terms over events e: notAppRecord leaves app records out; onlyAppRecords
// keeps only them. Kinds are slugs, so the prefix needs no escaping.
const (
	notAppRecord   = "substr(e.kind,1,4)<>'" + AppRecordPrefix + "'"
	onlyAppRecords = "substr(e.kind,1,4)='" + AppRecordPrefix + "'"
)

// appRecordTerm is the read's records clause: "" (none) when the read names
// an exact kind or includes records, otherwise the term to add.
func appRecordTerm(kind, records string) string {
	switch {
	case kind != "" || records == RecordsInclude:
		return ""
	case records == RecordsOnly:
		return onlyAppRecords
	}
	return notAppRecord
}

// validRecords checks a records value: empty (leave app records out),
// include or only.
func validRecords(records string) bool {
	return records == "" || records == RecordsInclude || records == RecordsOnly
}

// WithdrawnReason is the public reason a withdrawn message shows in place of
// its text (message.withdraw).
const WithdrawnReason = "withdrawn by author"
