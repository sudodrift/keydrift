// Command keydrift lists the API keys and tokens on a machine, tells you
// which ones an incident touched, and gives you a rotation list. It reads
// files only. It never prints or stores a key's value and never sends
// anything over the network.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sudodrift/keydrift/incidents"
	"github.com/sudodrift/keydrift/internal/kd"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) }

const usage = `usage: keydrift <command> [flags]

Commands:
  scan                   list keys, credential files and CI secret names, plus a rotation list
  snapshot [-o FILE]     save the scan as JSON (fingerprints only)
  diff OLD [NEW]         compare two snapshots, or a snapshot with a fresh scan
  match INCIDENT|all     check the machine against an incident in the catalog
  match list             list the incidents in the catalog
  version                print the version

Common flags: --json, --home DIR, --root DIR (repeatable), --state DIR
Exit codes: 0 nothing found, 1 something found, 2 error.
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type common struct {
	json  bool
	home  string
	roots multi
	state string
	out   string
	cat   string
}

func flags(name string, c *common, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("keydrift "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&c.json, "json", false, "print JSON")
	fs.StringVar(&c.home, "home", "", "home folder to read (default $HOME)")
	fs.Var(&c.roots, "root", "folder to walk for env and CI files (default: home; repeatable)")
	fs.StringVar(&c.state, "state", "", "state folder for the salt (default $XDG_STATE_HOME/keydrift)")
	if name == "snapshot" {
		fs.StringVar(&c.out, "o", "", "write the snapshot to this file (default stdout)")
	}
	if name == "match" {
		fs.StringVar(&c.cat, "catalog", "", "read incidents from this folder instead of the built-in catalog")
	}
	return fs
}

// parse allows flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func run(args []string, stdout, stderr io.Writer, env func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "keydrift", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan", "snapshot", "diff", "match":
	default:
		fmt.Fprintf(stderr, "keydrift: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	var c common
	fs := flags(cmd, &c, stderr)
	pos, err := parse(fs, rest)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if c.home == "" {
		c.home = env("HOME")
		if c.home == "" {
			fmt.Fprintln(stderr, "keydrift: HOME is not set; use --home")
			return 2
		}
	}
	if abs, err := filepath.Abs(c.home); err == nil {
		c.home = abs
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "keydrift:", err)
		return 2
	}
	stateDir := c.state
	if stateDir == "" {
		stateDir = kd.StateDir(c.home, env)
	}
	salt, err := kd.LoadSalt(stateDir)
	if err != nil {
		return fail(err)
	}
	scan := func() (*kd.Inventory, error) {
		return kd.Scan(kd.Options{Home: c.home, Roots: c.roots, Salt: salt, Version: version})
	}

	switch cmd {
	case "scan":
		if len(pos) != 0 {
			return fail(errors.New("scan takes no arguments; use --root to add folders"))
		}
		inv, err := scan()
		if err != nil {
			return fail(err)
		}
		rot := kd.Rotation(inv.Keys, inv.Stores, "")
		if c.json {
			if err := kd.WriteJSON(stdout, kd.ScanReport{Inventory: inv, Rotation: rot}); err != nil {
				return fail(err)
			}
		} else {
			kd.WriteScanText(stdout, inv, rot)
		}
		if len(inv.Keys)+len(inv.Stores) > 0 {
			return 1
		}
		return 0

	case "snapshot":
		if len(pos) != 0 {
			return fail(errors.New("snapshot takes no arguments"))
		}
		inv, err := scan()
		if err != nil {
			return fail(err)
		}
		snap := kd.NewSnapshot(inv, salt, time.Now())
		w := stdout
		if c.out != "" {
			f, err := os.OpenFile(c.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return fail(err)
			}
			defer f.Close()
			w = f
		}
		if err := kd.WriteJSON(w, snap); err != nil {
			return fail(err)
		}
		if c.out != "" {
			fmt.Fprintf(stderr, "wrote %s: %d keys\n", c.out, len(snap.Keys))
		}
		return 0

	case "diff":
		if len(pos) < 1 || len(pos) > 2 {
			return fail(errors.New("usage: keydrift diff OLD.json [NEW.json]"))
		}
		old, err := kd.ReadSnapshot(pos[0])
		if err != nil {
			return fail(err)
		}
		var cur *kd.Snapshot
		to := "now"
		if len(pos) == 2 {
			if cur, err = kd.ReadSnapshot(pos[1]); err != nil {
				return fail(err)
			}
			to = pos[1]
		} else {
			inv, err := scan()
			if err != nil {
				return fail(err)
			}
			cur = kd.NewSnapshot(inv, salt, time.Now())
		}
		if old.SaltID != cur.SaltID {
			return fail(errors.New("the snapshots were made with different salts, so their fingerprints cannot be compared"))
		}
		changes := kd.Diff(old, cur)
		if c.json {
			if err := kd.WriteJSON(stdout, map[string]any{"from": pos[0], "to": to, "changes": changes}); err != nil {
				return fail(err)
			}
		} else {
			kd.WriteDiffText(stdout, changes, c.home, pos[0], to)
		}
		for _, ch := range changes {
			if ch.Kind == "new-key" || ch.Kind == "new-location" {
				return 1
			}
		}
		return 0

	case "match":
		var cat []kd.Incident
		if c.cat != "" {
			cat, err = kd.LoadCatalog(os.DirFS(c.cat))
		} else {
			cat, err = kd.LoadCatalog(incidents.FS)
		}
		if err != nil {
			return fail(err)
		}
		if len(pos) != 1 {
			return fail(errors.New("usage: keydrift match INCIDENT|all|list"))
		}
		if pos[0] == "list" {
			for _, in := range cat {
				fmt.Fprintf(stdout, "%-22s %s  %s\n", in.ID, in.Date, in.Title)
			}
			return 0
		}
		var chosen []kd.Incident
		for _, in := range cat {
			if pos[0] == "all" || in.ID == pos[0] {
				chosen = append(chosen, in)
			}
		}
		if len(chosen) == 0 {
			return fail(fmt.Errorf("no incident %q; run keydrift match list", pos[0]))
		}
		inv, err := scan()
		if err != nil {
			return fail(err)
		}
		type out struct {
			kd.MatchResult
			Rotation []kd.RotateItem `json:"rotation"`
		}
		var results []out
		code := 0
		for i, in := range chosen {
			r := kd.Match(in, inv, kd.MatchOptions{Home: inv.Home, PathEnv: env("PATH")})
			var rot []kd.RotateItem
			if r.Applies {
				code = 1
				rot = kd.Rotation(r.Exposed, r.ExposedStores, in.ID)
			}
			results = append(results, out{r, rot})
			if !c.json {
				if i > 0 {
					fmt.Fprintln(stdout, "\n"+strings.Repeat("=", 60)+"\n")
				}
				kd.WriteMatchText(stdout, r, rot, inv.Home)
			}
		}
		if c.json {
			if err := kd.WriteJSON(stdout, results); err != nil {
				return fail(err)
			}
		}
		return code
	}
	return 2
}
