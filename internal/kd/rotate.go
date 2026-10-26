package kd

import (
	"sort"
	"strings"
)

// RotateItem is one entry on the rotation list.
type RotateItem struct {
	Rank        int    `json:"rank"`
	Provider    string `json:"provider"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Masked      string `json:"masked,omitempty"`
	Path        string `json:"path,omitempty"` // for stores
	Reason      string `json:"reason"`
	Action      string `json:"action,omitempty"`
	RotateURL   string `json:"rotate_url,omitempty"`
	GuideURL    string `json:"guide_url,omitempty"`
	Places      int    `json:"places,omitempty"`
	tier        int
	sub         int // the tier the item would have without an incident
}

func inLogs(k Key) bool {
	for _, l := range k.Locations {
		if l.Category == "agent-log" || l.Category == "shell-history" {
			return true
		}
	}
	return false
}

// Rotation orders keys and stores by how urgent they are:
//  1. exposed by a matched incident
//  2. copied into an AI agent log or shell history, where stealers look first
//  3. code, publishing, cloud and payment credentials, which reach other people
//  4. AI provider keys, which cost money when stolen
//  5. anything else
//
// Inside tier 1 the items keep the order of tiers 2 to 5. Within a tier,
// keys found in more places come first.
func Rotation(keys []Key, stores []Store, exposedBy string) []RotateItem {
	var out []RotateItem
	for _, k := range keys {
		p := provider(k.Provider)
		it := RotateItem{Provider: k.Provider, Name: p.Name, Fingerprint: k.Fingerprint, Masked: k.Masked,
			RotateURL: p.Rotate, GuideURL: p.Guide, Places: len(k.Locations)}
		switch {
		case inLogs(k):
			it.tier, it.Reason = 2, "copied into an agent log or shell history"
		case p.Kind == "code" || p.Kind == "publish" || p.Kind == "cloud" || p.Kind == "payments":
			it.tier, it.Reason = 3, "reaches code, packages, cloud or payments"
		case p.Kind == "ai":
			it.tier, it.Reason = 4, "AI provider key"
		default:
			it.tier, it.Reason = 5, "unknown provider"
		}
		it.sub = it.tier
		if exposedBy != "" {
			it.tier = 1
			if inLogs(k) {
				it.Reason = "exposed by " + exposedBy + "; also in an agent log or shell history"
			} else {
				it.Reason = "exposed by " + exposedBy
			}
		}
		out = append(out, it)
	}
	for _, s := range stores {
		p := provider(s.Provider)
		it := RotateItem{Provider: s.Provider, Name: s.What, Path: s.Path, Action: s.Action,
			RotateURL: p.Rotate, GuideURL: p.Guide, tier: 3, sub: 3, Reason: "credential file"}
		if s.Provider == "" {
			it.Provider = "other"
		}
		if exposedBy != "" {
			it.tier, it.Reason = 1, "exposed by "+exposedBy
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.tier != b.tier {
			return a.tier < b.tier
		}
		if a.sub != b.sub {
			return a.sub < b.sub
		}
		if a.Places != b.Places {
			return a.Places > b.Places
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Fingerprint+a.Path < b.Fingerprint+b.Path
	})
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// Tilde shortens a path under home for display.
func Tilde(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}
