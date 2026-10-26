package kd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Options for a scan.
type Options struct {
	Home    string
	Roots   []string // folders walked for env and CI files; default: home
	Salt    []byte
	Version string
}

const (
	chunkSize   = 8 << 20
	overlapSize = 8 << 10
	maxFileSize = 512 << 20
)

type scanner struct {
	salt  []byte
	keys  map[string]*Key
	inv   *Inventory
	seenL map[string]bool
}

// Fingerprint is the HMAC-SHA256 of a value under the local salt, shortened
// to 16 hex characters.
func Fingerprint(salt []byte, value string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// Mask shows only a fixed, public prefix (or two characters for long values
// without one) and the length.
func Mask(prefix, value string) string {
	switch {
	case prefix != "" && strings.HasPrefix(value, prefix):
		return fmt.Sprintf("%s... (%d chars)", prefix, len(value))
	case awsPrefix.MatchString(value):
		return fmt.Sprintf("%s... (%d chars)", value[:4], len(value))
	case stripePrefix.MatchString(value):
		return fmt.Sprintf("%s... (%d chars)", stripePrefix.FindString(value), len(value))
	case len(value) >= 16:
		return fmt.Sprintf("%s... (%d chars)", value[:2], len(value))
	}
	return fmt.Sprintf("... (%d chars)", len(value))
}

var (
	awsPrefix    = regexp.MustCompile(`^(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)`)
	stripePrefix = regexp.MustCompile(`^(?:sk|rk)_(?:test|live|prod)_`)
)

func (s *scanner) add(value string, r Rule, loc Location) {
	value = strings.TrimRight(value, `"',;`)
	if len(value) < 8 {
		return
	}
	fp := Fingerprint(s.salt, value)
	k, ok := s.keys[fp]
	if !ok {
		k = &Key{Fingerprint: fp, Provider: r.Provider, Rule: r.ID, RuleOrigin: r.Origin,
			Masked: Mask(r.Prefix, value), Length: len(value)}
		s.keys[fp] = k
	} else if k.RuleOrigin == "keydrift" && r.Origin == "betterleaks" {
		// A format rule beats a name guess for the same value.
		k.Provider, k.Rule, k.RuleOrigin, k.Masked = r.Provider, r.ID, r.Origin, Mask(r.Prefix, value)
	}
	id := fp + "|" + loc.Path + "|" + fmt.Sprint(loc.Line)
	if s.seenL[id] {
		return
	}
	s.seenL[id] = true
	k.Locations = append(k.Locations, loc)
}

// scanFile runs every rule over a file, in chunks so large databases fit.
func (s *scanner) scanFile(t target) {
	st, err := os.Stat(t.path)
	if err != nil {
		s.inv.Skipped = append(s.inv.Skipped, Skipped{t.path, err.Error()})
		return
	}
	if st.Size() > maxFileSize {
		s.inv.Skipped = append(s.inv.Skipped, Skipped{t.path, "larger than 512 MiB"})
		return
	}
	f, err := os.Open(t.path)
	if err != nil {
		s.inv.Skipped = append(s.inv.Skipped, Skipped{t.path, err.Error()})
		return
	}
	defer f.Close()
	s.inv.Scanned++

	// Matches are handled by absolute offset. A match that ends near the end
	// of a chunk is left for the next chunk, which starts with the last
	// overlapSize bytes of this one, so a key split by a chunk border is
	// always seen whole.
	var carry []byte
	var dataStart int64   // absolute offset of data[0]
	var linesBefore int   // newlines before data[0]
	var processedTo int64 // matches ending at or before this were handled
	buf := make([]byte, chunkSize)
	for {
		n, rerr := io.ReadFull(f, buf)
		final := rerr != nil
		if n == 0 && final && len(carry) == 0 {
			break
		}
		data := append(append([]byte{}, carry...), buf[:n]...)
		dataEnd := dataStart + int64(len(data))
		limit := dataEnd
		if !final {
			limit = dataEnd - overlapSize/2
		}
		lower := bytes.ToLower(data)
		for _, r := range allRules {
			if !r.wanted(lower) {
				continue
			}
			for _, m := range r.re.FindAllSubmatchIndex(data, -1) {
				end := dataStart + int64(m[1])
				if end <= processedTo || end > limit {
					continue
				}
				vs, ve := m[0], m[1]
				if len(m) >= 4 && m[2] >= 0 {
					vs, ve = m[2], m[3]
				}
				line := linesBefore + bytes.Count(data[:vs], []byte{'\n'}) + 1
				s.add(string(data[vs:ve]), r, Location{t.path, line, t.source, t.category})
			}
		}
		processedTo = limit
		if final {
			break
		}
		keep := overlapSize
		if keep > len(data) {
			keep = len(data)
		}
		linesBefore += bytes.Count(data[:len(data)-keep], []byte{'\n'})
		dataStart += int64(len(data) - keep)
		carry = append([]byte{}, data[len(data)-keep:]...)
	}
	s.structured(t)
}

// structured handles files whose secrets have no recognizable format.
func (s *scanner) structured(t target) {
	base := filepath.Base(t.path)
	switch {
	case t.source == "Docker config":
		data, err := os.ReadFile(t.path)
		if err != nil {
			return
		}
		var cfg struct {
			Auths       map[string]map[string]string `json:"auths"`
			CredsStore  string                       `json:"credsStore"`
			CredHelpers map[string]string            `json:"credHelpers"`
		}
		if json.Unmarshal(data, &cfg) != nil {
			return
		}
		regs := make([]string, 0, len(cfg.Auths))
		for r := range cfg.Auths {
			regs = append(regs, r)
		}
		sort.Strings(regs)
		for _, reg := range regs {
			a := cfg.Auths[reg]
			for _, field := range []string{"auth", "identitytoken"} {
				v := a[field]
				if v == "" {
					continue
				}
				line := lineOfBytes(data, v)
				r := Rule{ID: "docker-" + field, Provider: "docker", Origin: "structured"}
				s.add(v, r, Location{t.path, line, t.source + " (" + reg + ")", t.category})
			}
		}
		if cfg.CredsStore != "" || len(cfg.CredHelpers) > 0 {
			s.inv.Stores = append(s.inv.Stores, Store{t.path, "Docker logins kept in a credential helper (not read)", "docker",
				"run docker logout for each registry and revoke the tokens at the registry"})
		}
	case base == "application_default_credentials.json" || base == "adc.json":
		data, err := os.ReadFile(t.path)
		if err != nil {
			return
		}
		var c map[string]any
		if json.Unmarshal(data, &c) != nil {
			return
		}
		for _, field := range []string{"refresh_token", "private_key"} {
			if v, ok := c[field].(string); ok && v != "" {
				r := Rule{ID: "gcloud-" + strings.ReplaceAll(field, "_", "-"), Provider: "gcloud", Origin: "structured"}
				first := strings.SplitN(v, "\n", 2)[0]
				s.add(v, r, Location{t.path, lineOfBytes(data, first), t.source, t.category})
			}
		}
	}
}

func lineOfBytes(data []byte, needle string) int {
	i := bytes.Index(data, []byte(needle))
	if i < 0 {
		return 0
	}
	return bytes.Count(data[:i], []byte{'\n'}) + 1
}

var (
	ghSecretRef = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
	envVarRef   = regexp.MustCompile(`\$\{?([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PAT)[A-Z0-9_]*)\}?`)
)

// scanCI reads only variable names from CI files.
func (s *scanner) scanCI(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		s.inv.Skipped = append(s.inv.Skipped, Skipped{path, err.Error()})
		return
	}
	s.inv.Scanned++
	re := envVarRef
	if strings.Contains(filepath.ToSlash(path), ".github/workflows/") {
		re = ghSecretRef
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if name == "GITHUB_TOKEN" || seen[name] {
				continue
			}
			seen[name] = true
			s.inv.CIRefs = append(s.inv.CIRefs, CIRef{Name: name, Path: path, Line: i + 1, Provider: providerByName(name)})
		}
	}
}

// Scan reads every known place under home and the roots. It returns the
// inventory; raw values never leave this function.
func Scan(o Options) (*Inventory, error) {
	if len(o.Salt) < 16 {
		return nil, fmt.Errorf("salt is missing or too short")
	}
	home, err := filepath.Abs(o.Home)
	if err != nil {
		return nil, err
	}
	roots := o.Roots
	if len(roots) == 0 {
		roots = []string{home}
	}
	var absRoots []string
	for _, r := range roots {
		a, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if st, err := os.Stat(a); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("%s is not a folder", r)
		}
		absRoots = append(absRoots, a)
	}
	inv := &Inventory{Tool: "keydrift", Version: o.Version, Home: home, Roots: absRoots,
		Keys: []Key{}, Stores: []Store{}, CIRefs: []CIRef{}}
	s := &scanner{salt: o.Salt, keys: map[string]*Key{}, inv: inv, seenL: map[string]bool{}}

	seen := map[string]bool{}
	var targets []target
	for _, g := range fixedGlobs {
		for _, p := range globHome(home, g.pattern) {
			if !seen[p] {
				seen[p] = true
				targets = append(targets, target{p, g.source, g.category})
			}
		}
	}
	walked, ci := walkRoots(absRoots, home)
	for _, t := range walked {
		if !seen[t.path] {
			seen[t.path] = true
			targets = append(targets, t)
		}
	}
	for _, t := range targets {
		s.scanFile(t)
		if t.category == "env-file" {
			inv.envFiles = append(inv.envFiles, t.path)
		}
	}
	for _, p := range ci {
		s.scanCI(p)
	}
	for _, g := range storeGlobs {
		for _, p := range globHome(home, g.pattern) {
			if strings.HasSuffix(p, ".pub") {
				continue
			}
			inv.Stores = append(inv.Stores, Store{p, g.what, g.provider, g.action})
		}
	}

	for _, k := range s.keys {
		inv.Keys = append(inv.Keys, *k)
	}
	sort.Slice(inv.Keys, func(i, j int) bool {
		a, b := inv.Keys[i], inv.Keys[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return a.Fingerprint < b.Fingerprint
	})
	return inv, nil
}
