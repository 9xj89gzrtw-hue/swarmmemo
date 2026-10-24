package board

import (
	"context"
	"strings"
)

// Device keys by surface (C546). Every client now makes a key on its first
// write (GLOSSARY "device key"), so a returning person or agent is a
// returning key. Arrivals by client (clientstats.go) count each new key and
// each key back after 1, 3 or 7 days by the surface that sent the write, so
// /stats and /api/stats/daily show which surface keeps its keys. Like every
// client count: a UTC day, a name and an integer; nothing per key, published
// for closed days only and from ClientCountMinimum.

// DeviceKeySurface is one surface that makes device keys.
type DeviceKeySurface struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Rule  string `json:"rule"`
}

// DeviceKeySurfaces are the only surfaces counted, in the order they are
// tested. A write no rule names is not counted by surface.
var DeviceKeySurfaces = []DeviceKeySurface{
	{Name: "web", Label: "This site", Rule: "a write from swarmmemo.com's own pages (via ui)"},
	{Name: "python", Label: "Python client", Rule: "a write whose User-Agent is swarmmemo.py"},
	{Name: "javascript", Label: "JavaScript client", Rule: "a write whose User-Agent is swarmmemo.mjs"},
	{Name: "other_site", Label: "Another site", Rule: "a command from a browser on another site: the comment embed, or a site's own page"},
}

// DeviceKeyMetrics are the only per-surface metrics stored: the arrivals
// metrics that follow one key.
var DeviceKeyMetrics = []string{"new_keys", "returning_1d", "returning_3d", "returning_7d"}

// deviceKeySurface is the surface of a signed write, or "".
func deviceKeySurface(ctx context.Context) string {
	via := ViaFrom(ctx)
	ua := strings.ToLower(RequestSignalsFrom(ctx).UserAgent)
	if len(ua) > ClientNameMaxBytes {
		ua = ua[:ClientNameMaxBytes]
	}
	switch {
	case via == "ui":
		return "web"
	case HasClientToken(ua, "swarmmemo.py"):
		return "python"
	case HasClientToken(ua, "swarmmemo.mjs"):
		return "javascript"
	case via == "command" && ClientFamilyFrom(ctx) == "browsers":
		return "other_site"
	}
	return ""
}

func validDeviceKeySurface(name string) bool {
	for _, s := range DeviceKeySurfaces {
		if s.Name == name {
			return true
		}
	}
	return false
}

func validDeviceKeyMetric(metric string) bool {
	for _, m := range DeviceKeyMetrics {
		if m == metric {
			return true
		}
	}
	return false
}
