package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"swarmmemo/internal/board"
)

const rawSignalsUsage = "usage: swarmmemo signals raw message ID | signals raw account FINGERPRINT [--days N]"

// operatorRawSignals decrypts and prints the sealed raw write signals
// (board/rawsignals.go, C452): the client address, the request headers
// (credentials redacted when stored), the MCP client and the time of each
// write. Read-only. For abuse handling and reports to the authorities only.
func operatorRawSignals(ctx context.Context, store *board.Store, args []string, out io.Writer) error {
	if len(args) < 2 || strings.HasPrefix(args[1], "--") {
		return errors.New(rawSignalsUsage)
	}
	mode, target, rest := args[0], args[1], args[2:]
	days := board.RawSignalRetentionDays
	for len(rest) > 0 {
		if len(rest) < 2 || rest[0] != "--days" || mode != "account" {
			return errors.New(rawSignalsUsage)
		}
		n, err := strconv.Atoi(rest[1])
		if err != nil || n < 1 {
			return fmt.Errorf("%s needs a positive number", rest[0])
		}
		if n > board.RawSignalRetentionDays {
			return fmt.Errorf("--days is at most %d: older raw records are deleted", board.RawSignalRetentionDays)
		}
		days, rest = n, rest[2:]
	}
	var records []board.RawSignal
	var err error
	switch mode {
	case "message":
		records, err = store.RawSignalsForObject(ctx, target)
	case "account":
		records, err = store.RawSignalsForAccount(ctx, target, days)
	default:
		return errors.New(rawSignalsUsage)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "raw signals key %s; kept %d days\n", store.RawSignalsKeyID(), board.RawSignalRetentionDays)
	if len(records) == 0 {
		fmt.Fprintf(out, "no raw record for %s %s (none recorded, before C452, or older than %d days)\n", mode, target, board.RawSignalRetentionDays)
		return nil
	}
	for _, r := range records {
		printRawSignal(out, r)
	}
	return nil
}

func rawTime(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05 UTC") }

func printRawSignal(out io.Writer, r board.RawSignal) {
	fmt.Fprintf(out, "\nraw %d: %s %s via %s at %s\n", r.Seq, r.Operation, orDash(r.ObjectID), orDash(r.Via), rawTime(r.CreatedAt))
	if r.Unreadable != "" {
		fmt.Fprintf(out, "  account %s\n  unreadable: %s\n", orDash(r.Account), r.Unreadable)
		return
	}
	fmt.Fprintf(out, "  account %s  signer %s  room %s  request %s\n", orDash(r.Account), orDash(r.Signer), orDash(r.Room), orDash(r.RequestID))
	fmt.Fprintf(out, "  ip %s\n", orDash(r.IP))
	fmt.Fprintf(out, "  peer %s  forwarded-for %q\n", orDash(r.RemoteAddr), r.ForwardedFor)
	fmt.Fprintf(out, "  protocol %s  tls %s\n", orDash(r.Proto), orDash(r.TLS))
	if r.Origin != "" {
		fmt.Fprintf(out, "  origin %q\n", r.Origin)
	}
	if c := r.MCPClient; c != nil {
		fmt.Fprintf(out, "  mcp client %q version %q title %q\n", c.Name, c.Version, c.Title)
	}
	names := make([]string, 0, len(r.Headers))
	for name := range r.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range r.Headers[name] {
			fmt.Fprintf(out, "  header %s: %q\n", name, v)
		}
	}
}
