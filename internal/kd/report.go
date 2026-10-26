package kd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON prints any value as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func where(k Key, home string, max int) string {
	var parts []string
	seen := map[string]bool{}
	for _, l := range k.Locations {
		s := Tilde(l.Path, home)
		if l.Line > 0 {
			s = fmt.Sprintf("%s:%d", s, l.Line)
		}
		s += " (" + l.Source + ")"
		if seen[s] {
			continue
		}
		seen[s] = true
		parts = append(parts, s)
	}
	if len(parts) > max {
		extra := len(parts) - max
		parts = append(parts[:max], fmt.Sprintf("and %d more", extra))
	}
	return strings.Join(parts, "\n      ")
}

func writeRotation(w io.Writer, items []RotateItem, home string) {
	fmt.Fprintf(w, "Rotation list, most urgent first (%d)\n", len(items))
	if len(items) == 0 {
		fmt.Fprintln(w, "  nothing to rotate")
	}
	for _, it := range items {
		if it.Path != "" {
			fmt.Fprintf(w, "  %2d. %s  %s\n      why: %s\n      do: %s\n", it.Rank, it.Name, Tilde(it.Path, home), it.Reason, it.Action)
		} else {
			fmt.Fprintf(w, "  %2d. %s  %s  fp %s\n      why: %s\n", it.Rank, it.Name, it.Masked, it.Fingerprint, it.Reason)
		}
		if it.RotateURL != "" {
			fmt.Fprintf(w, "      rotate: %s\n", it.RotateURL)
		}
		if it.GuideURL != "" {
			fmt.Fprintf(w, "      guide:  %s\n", it.GuideURL)
		}
	}
}

// ScanReport is the JSON shape of `keydrift scan --json`.
type ScanReport struct {
	*Inventory
	Rotation []RotateItem `json:"rotation"`
}

// WriteScanText prints the inventory and rotation list.
func WriteScanText(w io.Writer, inv *Inventory, rot []RotateItem) {
	home := inv.Home
	fmt.Fprintf(w, "keydrift %s\n", inv.Version)
	var roots []string
	for _, r := range inv.Roots {
		roots = append(roots, Tilde(r, home))
	}
	fmt.Fprintf(w, "home: %s   walked: %s   files read: %d\n\n", home, strings.Join(roots, ", "), inv.Scanned)

	fmt.Fprintf(w, "Keys (%d). Values are never shown; fp is an HMAC with your local salt.\n", len(inv.Keys))
	if len(inv.Keys) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, k := range inv.Keys {
		guess := ""
		if k.RuleOrigin == "keydrift" {
			guess = ", guessed from the variable name"
		}
		fmt.Fprintf(w, "  %s  %s  fp %s  [%s%s]\n      %s\n", provider(k.Provider).Name, k.Masked, k.Fingerprint, k.Rule, guess, where(k, home, 4))
	}
	if len(inv.Stores) > 0 {
		fmt.Fprintf(w, "\nCredential files (%d)\n", len(inv.Stores))
		for _, s := range inv.Stores {
			fmt.Fprintf(w, "  %s  %s\n", Tilde(s.Path, home), s.What)
		}
	}
	if len(inv.CIRefs) > 0 {
		fmt.Fprintf(w, "\nSecret names used by CI (%d). Names only; update these after you rotate.\n", len(inv.CIRefs))
		for _, c := range inv.CIRefs {
			fmt.Fprintf(w, "  %s  %s:%d\n", c.Name, Tilde(c.Path, home), c.Line)
		}
	}
	if len(inv.Skipped) > 0 {
		fmt.Fprintf(w, "\nCould not read (%d)\n", len(inv.Skipped))
		for _, s := range inv.Skipped {
			fmt.Fprintf(w, "  %s: %s\n", Tilde(s.Path, home), s.Reason)
		}
	}
	fmt.Fprintln(w)
	writeRotation(w, rot, home)
}

// WriteDiffText prints a diff.
func WriteDiffText(w io.Writer, changes []Change, home, from, to string) {
	fmt.Fprintf(w, "keydrift diff %s -> %s\n\n", from, to)
	if len(changes) == 0 {
		fmt.Fprintln(w, "No changes.")
		return
	}
	label := map[string]string{
		"new-key":       "NEW KEY",
		"new-location":  "KEY IN A NEW PLACE",
		"gone-location": "KEY GONE FROM A PLACE",
		"gone-key":      "KEY GONE",
	}
	for _, c := range changes {
		fmt.Fprintf(w, "%s  %s  %s  fp %s\n", label[c.Kind], provider(c.Provider).Name, c.Masked, c.Fingerprint)
		for _, l := range c.Locations {
			fmt.Fprintf(w, "    %s (%s)\n", Tilde(l.Path, home), l.Source)
		}
	}
}

// WriteMatchText prints the result of one incident match.
func WriteMatchText(w io.Writer, r MatchResult, rot []RotateItem, home string) {
	in := r.Incident
	fmt.Fprintf(w, "%s: %s (%s)\n", in.ID, in.Title, in.Date)
	for _, s := range in.Sources {
		fmt.Fprintf(w, "  source: %s %s\n", s.Name, s.URL)
	}
	fmt.Fprintln(w)
	if !r.Applies {
		fmt.Fprintln(w, "No evidence of this incident on this machine.")
		return
	}
	fmt.Fprintf(w, "Evidence (%d)\n", len(r.Evidence))
	for _, h := range r.Evidence {
		fmt.Fprintf(w, "  %s: %s\n", h.What, Tilde(h.Path, home))
	}
	fmt.Fprintf(w, "\nWhat counts as exposed (%s)\n  %s\n", r.Scope, r.Note)
	if len(r.ExposedPaths) > 0 {
		fmt.Fprintf(w, "\nFiles from the advisory's list that exist here (%d)\n", len(r.ExposedPaths))
		for _, p := range r.ExposedPaths {
			fmt.Fprintf(w, "  %s\n", Tilde(p, home))
		}
	}
	fmt.Fprintln(w)
	writeRotation(w, rot, home)
	if len(in.Actions) > 0 {
		fmt.Fprintln(w, "\nAlso")
		for _, a := range in.Actions {
			fmt.Fprintf(w, "  - %s\n", a)
		}
	}
}
