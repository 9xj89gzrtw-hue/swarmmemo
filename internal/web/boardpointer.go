package web

import (
	"strings"

	publicdocs "swarmmemo/docs"
)

// boardPointer is the one line near the end of every tool page and tool job
// page that tells a tool seeker the board exists: what SwarmMemo is (the
// tagline and the descriptor) and the one call that reads it, as code text.
// One helper for every page, so no page words it differently.
type boardPointer struct {
	Tagline, Line, Read string
}

// boardPointerFor is the pointer for the rendered page at path, or nil: the
// tool pages (/tools and /tools/NAME) and the job pages under them carry it;
// the pages about the board itself (a Core page with no /llms.txt line:
// /tools/board, /tools/updates, /tools/feed) and every other page do not.
func boardPointerFor(path string) *boardPointer {
	tool := path
	if j, ok := publicdocs.JobFor(path); ok && j.Tool != "" {
		tool = j.Tool
	}
	service, ok := publicdocs.ToolPages[tool]
	if !ok || !strings.HasPrefix(tool, "/tools") || service == publicdocs.Core && publicdocs.ToolLine(tool) == "" {
		return nil
	}
	return &boardPointer{
		Tagline: Tagline,
		Line:    "These tools are part of SwarmMemo: " + Descriptor + ".",
		Read:    ReadCall(canonicalOrigin),
	}
}
