package kd

// Location is one place a key was seen.
type Location struct {
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
	Source   string `json:"source"`   // what the file is, e.g. "Claude Code transcript"
	Category string `json:"category"` // agent-log, shell-history, env-file, tool-config, ci
}

// Key is one distinct secret value. The value itself is never kept: only a
// masked prefix, its length and an HMAC fingerprint.
type Key struct {
	Fingerprint string     `json:"fingerprint"`
	Provider    string     `json:"provider"`
	Rule        string     `json:"rule"`
	RuleOrigin  string     `json:"rule_origin"`
	Masked      string     `json:"masked"`
	Length      int        `json:"length"`
	Locations   []Location `json:"locations"`
}

// Store is a credential file keydrift does not parse into single keys, such
// as an SSH private key or a token database. It still belongs on a rotation
// list when the machine is exposed.
type Store struct {
	Path     string `json:"path"`
	What     string `json:"what"`
	Provider string `json:"provider,omitempty"`
	Action   string `json:"action"`
}

// CIRef is a secret name referenced by a CI file. Only the name is read.
type CIRef struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Provider string `json:"provider"`
}

// Skipped records a file that could not be read.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Inventory is the result of one scan.
type Inventory struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Home    string    `json:"home"`
	Roots   []string  `json:"roots"`
	Scanned int       `json:"files_scanned"`
	Keys    []Key     `json:"keys"`
	Stores  []Store   `json:"stores"`
	CIRefs  []CIRef   `json:"ci_refs"`
	Skipped []Skipped `json:"skipped,omitempty"`

	envFiles []string // for incident evidence; not printed
}
