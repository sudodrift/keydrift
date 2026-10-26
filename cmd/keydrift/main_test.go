package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sudodrift/keydrift/internal/fakehome"
)

type env map[string]string

func (e env) get(k string) string { return e[k] }

func setup(t *testing.T, withKeys bool) (string, env) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o700)
	if withKeys {
		if err := fakehome.Write(home, false); err != nil {
			t.Fatal(err)
		}
	}
	return dir, env{"HOME": home, "XDG_STATE_HOME": filepath.Join(dir, "state"), "PATH": filepath.Join(dir, "nobin")}
}

func call(e env, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, e.get)
	return code, out.String(), errb.String()
}

func TestUsageAndVersion(t *testing.T) {
	_, e := setup(t, false)
	if c, _, _ := call(e); c != 2 {
		t.Errorf("no args: exit %d, want 2", c)
	}
	if c, _, _ := call(e, "frobnicate"); c != 2 {
		t.Errorf("unknown command: exit %d, want 2", c)
	}
	if c, out, _ := call(e, "version"); c != 0 || !strings.HasPrefix(out, "keydrift ") {
		t.Errorf("version: exit %d %q", c, out)
	}
}

func TestScanExitCodes(t *testing.T) {
	_, clean := setup(t, false)
	if c, out, errs := call(clean, "scan"); c != 0 {
		t.Errorf("clean home: exit %d, want 0\n%s%s", c, out, errs)
	}
	_, dirty := setup(t, true)
	c, out, _ := call(dirty, "scan", "--json")
	if c != 1 {
		t.Errorf("home with keys: exit %d, want 1", c)
	}
	var rep struct {
		Keys     []json.RawMessage `json:"keys"`
		Rotation []json.RawMessage `json:"rotation"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Keys) == 0 || len(rep.Rotation) <= len(rep.Keys) {
		t.Errorf("JSON has %d keys and %d rotation items", len(rep.Keys), len(rep.Rotation))
	}
	for _, v := range fakehome.Keys() {
		if strings.Contains(out, v) {
			t.Fatal("raw key value in JSON output")
		}
	}
}

func TestSnapshotDiff(t *testing.T) {
	dir, e := setup(t, true)
	base := filepath.Join(dir, "base.json")
	if c, _, errs := call(e, "snapshot", "-o", base); c != 0 {
		t.Fatalf("snapshot: exit %d %s", c, errs)
	}
	st, _ := os.Stat(base)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("snapshot mode %v, want 0600", st.Mode().Perm())
	}
	if c, out, _ := call(e, "diff", base); c != 0 || !strings.Contains(out, "No changes.") {
		t.Errorf("diff with no change: exit %d\n%s", c, out)
	}
	k := fakehome.Keys()["OPENAI2"]
	os.WriteFile(filepath.Join(e["HOME"], ".zsh_history"), []byte(": 1:0;export OPENAI_API_KEY="+k+"\n"), 0o600)
	c, out, _ := call(e, "diff", base)
	if c != 1 || !strings.Contains(out, "NEW KEY") || !strings.Contains(out, "~/.zsh_history") {
		t.Errorf("diff with a new key: exit %d\n%s", c, out)
	}
	// Only removals: exit 0.
	now := filepath.Join(dir, "now.json")
	call(e, "snapshot", "-o", now)
	os.Remove(filepath.Join(e["HOME"], ".zsh_history"))
	if c, out, _ := call(e, "diff", now); c != 0 || !strings.Contains(out, "KEY GONE") {
		t.Errorf("diff with only a removal: exit %d\n%s", c, out)
	}
	// Snapshots from another salt cannot be compared.
	_, other := setup(t, true)
	if c, _, errs := call(other, "diff", base); c != 2 || !strings.Contains(errs, "different salts") {
		t.Errorf("diff across salts: exit %d %s", c, errs)
	}
}

func TestMatchCommand(t *testing.T) {
	_, e := setup(t, true)
	if c, out, _ := call(e, "match", "list"); c != 0 || strings.Count(out, "\n") != 5 {
		t.Errorf("match list: exit %d\n%s", c, out)
	}
	if c, _, _ := call(e, "match", "nope"); c != 2 {
		t.Errorf("unknown incident: exit %d, want 2", c)
	}
	if c, out, _ := call(e, "match", "zeabur-2026-10"); c != 1 || !strings.Contains(out, "zbpack.json") {
		t.Errorf("zeabur: exit %d\n%s", c, out)
	}
	_, clean := setup(t, false)
	if c, out, _ := call(clean, "match", "railway-2026-10"); c != 0 || !strings.Contains(out, "No evidence") {
		t.Errorf("railway on a clean home: exit %d\n%s", c, out)
	}
	c, out, _ := call(e, "match", "all", "--json")
	var res []map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res) != 5 || c != 1 {
		t.Errorf("match all --json: exit %d, %d results, err %v", c, len(res), err)
	}
}

func TestLooseSaltIsAnError(t *testing.T) {
	_, e := setup(t, false)
	call(e, "scan")
	salt := filepath.Join(e["XDG_STATE_HOME"], "keydrift", "salt")
	if err := os.Chmod(salt, 0o640); err != nil {
		t.Fatal(err)
	}
	if c, _, errs := call(e, "scan"); c != 2 || !strings.Contains(errs, "chmod 600") {
		t.Errorf("loose salt: exit %d %s", c, errs)
	}
}
