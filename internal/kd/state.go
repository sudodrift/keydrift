package kd

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// StateDir is $XDG_STATE_HOME/keydrift or ~/.local/state/keydrift.
func StateDir(home string, env func(string) string) string {
	if x := env("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "keydrift")
	}
	return filepath.Join(home, ".local", "state", "keydrift")
}

// LoadSalt reads the local HMAC salt, creating it (32 random bytes, mode
// 0600) on first use. It refuses a salt file that others can read, because
// anyone with the salt can test guesses against the fingerprints.
func LoadSalt(dir string) ([]byte, error) {
	p := filepath.Join(dir, "salt")
	st, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(salt); err != nil {
			f.Close()
			return nil, err
		}
		return salt, f.Close()
	}
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %v; run chmod 600 %s", p, st.Mode().Perm(), p)
	}
	salt, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("%s is shorter than 16 bytes", p)
	}
	return salt, nil
}

// Snapshot is what `keydrift snapshot` writes. It holds fingerprints, masked
// prefixes and file paths, never values.
type Snapshot struct {
	Tool    string  `json:"tool"`
	Version string  `json:"version"`
	Taken   string  `json:"taken"`
	Home    string  `json:"home"`
	SaltID  string  `json:"salt_id"`
	Keys    []Key   `json:"keys"`
	CIRefs  []CIRef `json:"ci_refs"`
}

// NewSnapshot turns an inventory into a snapshot.
func NewSnapshot(inv *Inventory, salt []byte, now time.Time) *Snapshot {
	return &Snapshot{Tool: "keydrift", Version: inv.Version, Taken: now.UTC().Format(time.RFC3339),
		Home: inv.Home, SaltID: SaltID(salt), Keys: inv.Keys, CIRefs: inv.CIRefs}
}

// SaltID names a salt without revealing it, so diff can refuse to compare
// snapshots made with different salts.
func SaltID(salt []byte) string { return Fingerprint(salt, "keydrift salt id")[:8] }

// ReadSnapshot loads a snapshot file.
func ReadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s is not a keydrift snapshot: %v", path, err)
	}
	if s.Tool != "keydrift" {
		return nil, fmt.Errorf("%s is not a keydrift snapshot", path)
	}
	return &s, nil
}

// Change is one line of a diff.
type Change struct {
	Kind        string     `json:"kind"` // new-key, gone-key, new-location, gone-location
	Fingerprint string     `json:"fingerprint"`
	Provider    string     `json:"provider"`
	Masked      string     `json:"masked"`
	Locations   []Location `json:"locations"`
}

// Diff compares two snapshots. Locations are compared by path, so a key that
// moved lines inside the same file is not a change.
func Diff(old, cur *Snapshot) []Change {
	idx := func(s *Snapshot) map[string]Key {
		m := map[string]Key{}
		for _, k := range s.Keys {
			m[k.Fingerprint] = k
		}
		return m
	}
	o, c := idx(old), idx(cur)
	paths := func(k Key) map[string]Location {
		m := map[string]Location{}
		for _, l := range k.Locations {
			if _, ok := m[l.Path]; !ok {
				m[l.Path] = l
			}
		}
		return m
	}
	var out []Change
	for fp, k := range c {
		ok, had := o[fp]
		if !had {
			out = append(out, Change{"new-key", fp, k.Provider, k.Masked, uniqueLocs(k.Locations)})
			continue
		}
		op, cp := paths(ok), paths(k)
		var added, removed []Location
		for p, l := range cp {
			if _, ok := op[p]; !ok {
				added = append(added, l)
			}
		}
		for p, l := range op {
			if _, ok := cp[p]; !ok {
				removed = append(removed, l)
			}
		}
		if len(added) > 0 {
			out = append(out, Change{"new-location", fp, k.Provider, k.Masked, sortLocs(added)})
		}
		if len(removed) > 0 {
			out = append(out, Change{"gone-location", fp, k.Provider, k.Masked, sortLocs(removed)})
		}
	}
	for fp, k := range o {
		if _, ok := c[fp]; !ok {
			out = append(out, Change{"gone-key", fp, k.Provider, k.Masked, uniqueLocs(k.Locations)})
		}
	}
	rank := map[string]int{"new-key": 0, "new-location": 1, "gone-location": 2, "gone-key": 3}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func sortLocs(l []Location) []Location {
	sort.Slice(l, func(i, j int) bool { return l[i].Path < l[j].Path })
	return l
}

func uniqueLocs(l []Location) []Location {
	seen := map[string]bool{}
	var out []Location
	for _, x := range l {
		if !seen[x.Path] {
			seen[x.Path] = true
			out = append(out, x)
		}
	}
	return sortLocs(out)
}
