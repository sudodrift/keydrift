package kd

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Incident is one entry of the catalog in incidents/.
type Incident struct {
	ID       string   `yaml:"id" json:"id"`
	Title    string   `yaml:"title" json:"title"`
	Date     string   `yaml:"date" json:"date"`
	Summary  string   `yaml:"summary" json:"summary"`
	Sources  []Source `yaml:"sources" json:"sources"`
	Evidence Evidence `yaml:"evidence" json:"-"`
	Exposure Exposure `yaml:"exposure" json:"-"`
	Actions  []string `yaml:"actions" json:"actions"`
}

type Source struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

type Evidence struct {
	PythonPackages []struct {
		Name     string   `yaml:"name"`
		Versions []string `yaml:"versions"`
	} `yaml:"python_packages"`
	Binaries struct {
		Names []string `yaml:"names"`
		MD5   []string `yaml:"md5"`
	} `yaml:"binaries"`
	TmpDirs          []string `yaml:"tmp_dirs"`
	Files            []string `yaml:"files"`
	LinkedProjectMap []struct {
		File string `yaml:"file"`
		Key  string `yaml:"key"`
	} `yaml:"linked_project_maps"`
	ProjectFiles     []string `yaml:"project_files"`
	ProjectFileGlobs []string `yaml:"project_file_globs"`
	EnvNames         []string `yaml:"env_names"`
}

type Exposure struct {
	Scope string   `yaml:"scope"` // all-keys, paths, project-folders, ai-keys
	Paths []string `yaml:"paths"`
	Note  string   `yaml:"note"`
}

// LoadCatalog reads every *.yaml in fsys and checks each entry.
func LoadCatalog(fsys fs.FS) ([]Incident, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	var out []Incident
	for _, n := range names {
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		var in Incident
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&in); err != nil {
			return nil, fmt.Errorf("%s: %v", n, err)
		}
		if in.ID == "" || in.ID+".yaml" != n {
			return nil, fmt.Errorf("%s: id must match the file name", n)
		}
		if len(in.Sources) == 0 {
			return nil, fmt.Errorf("%s: at least one source is required", n)
		}
		switch in.Exposure.Scope {
		case "all-keys", "paths", "project-folders", "ai-keys":
		default:
			return nil, fmt.Errorf("%s: unknown exposure scope %q", n, in.Exposure.Scope)
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// MatchOptions tells Match where to look. Empty fields get defaults.
type MatchOptions struct {
	Home    string
	Roots   []string
	PyRoots []string // where to look for installed Python packages
	BinDirs []string // where to look for binaries
	TmpDirs []string
	PathEnv string
}

// Hit is one piece of evidence.
type Hit struct {
	What string `json:"what"`
	Path string `json:"path"`
}

// MatchResult is the answer for one incident.
type MatchResult struct {
	Incident       Incident `json:"incident"`
	Applies        bool     `json:"applies"`
	Evidence       []Hit    `json:"evidence"`
	ProjectFolders []string `json:"project_folders,omitempty"`
	Scope          string   `json:"exposure_scope"`
	Note           string   `json:"exposure_note"`
	Exposed        []Key    `json:"exposed_keys"`
	ExposedStores  []Store  `json:"exposed_stores"`
	ExposedPaths   []string `json:"listed_paths_present,omitempty"`
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

func defaultPyRoots(home string) []string {
	return []string{home, "/usr/lib", "/usr/local/lib", "/usr/lib64", "/opt",
		"/Library/Frameworks/Python.framework", "/opt/homebrew/lib"}
}

func defaultBinDirs(home, pathEnv string) []string {
	dirs := filepath.SplitList(pathEnv)
	dirs = append(dirs, filepath.Join(home, ".local", "bin"), filepath.Join(home, "go", "bin"),
		filepath.Join(home, "bin"), filepath.Join(home, "Downloads"), "/usr/local/bin", "/opt/homebrew/bin")
	return dirs
}

// findPythonPackage looks for <name>-<version>.dist-info / .egg-info folders
// and conda-meta/<name>-<version>-*.json files. It never runs Python.
func findPythonPackage(roots []string, name string, versions []string) []Hit {
	want := map[string]bool{}
	for _, v := range versions {
		want[strings.ToLower(name+"-"+v+".dist-info")] = true
		want[strings.ToLower(name+"-"+v+".egg-info")] = true
	}
	var hits []Hit
	seen := map[string]bool{}
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			n := strings.ToLower(d.Name())
			if d.IsDir() {
				if n == ".git" || n == "node_modules" || n == "proc" && root == "/" {
					return filepath.SkipDir
				}
				if want[n] && !seen[p] {
					seen[p] = true
					hits = append(hits, Hit{"installed Python package " + d.Name(), p})
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Base(filepath.Dir(p)) == "conda-meta" {
				for _, v := range versions {
					if strings.HasPrefix(n, strings.ToLower(name+"-"+v+"-")) && strings.HasSuffix(n, ".json") && !seen[p] {
						seen[p] = true
						hits = append(hits, Hit{"conda package " + d.Name(), p})
					}
				}
			}
			return nil
		})
	}
	return hits
}

func md5File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Match checks one incident against this machine and the inventory.
func Match(in Incident, inv *Inventory, o MatchOptions) MatchResult {
	home := o.Home
	res := MatchResult{Incident: in, Scope: in.Exposure.Scope, Note: strings.TrimSpace(in.Exposure.Note),
		Evidence: []Hit{}, Exposed: []Key{}, ExposedStores: []Store{}}
	ev := in.Evidence

	pyRoots := o.PyRoots
	if len(pyRoots) == 0 {
		pyRoots = defaultPyRoots(home)
	}
	for _, pkg := range ev.PythonPackages {
		res.Evidence = append(res.Evidence, findPythonPackage(pyRoots, pkg.Name, pkg.Versions)...)
	}

	if len(ev.Binaries.Names) > 0 {
		bad := map[string]bool{}
		for _, m := range ev.Binaries.MD5 {
			bad[strings.ToLower(m)] = true
		}
		dirs := o.BinDirs
		if len(dirs) == 0 {
			dirs = defaultBinDirs(home, o.PathEnv)
		}
		seen := map[string]bool{}
		for _, d := range dirs {
			for _, n := range ev.Binaries.Names {
				for _, p := range regularOnly([]string{filepath.Join(d, n)}) {
					if seen[p] {
						continue
					}
					seen[p] = true
					if sum, err := md5File(p); err == nil && bad[sum] {
						res.Evidence = append(res.Evidence, Hit{"binary with a known bad MD5 " + sum, p})
					}
				}
			}
		}
	}

	tmps := o.TmpDirs
	if len(tmps) == 0 {
		tmps = []string{"/tmp"}
		if t := os.Getenv("TMPDIR"); t != "" {
			tmps = append(tmps, t)
		}
	}
	for _, t := range tmps {
		for _, g := range ev.TmpDirs {
			m, _ := filepath.Glob(filepath.Join(t, g))
			for _, p := range m {
				if st, err := os.Stat(p); err == nil && st.IsDir() {
					res.Evidence = append(res.Evidence, Hit{"folder left by the stealer", p})
				}
			}
		}
	}

	for _, f := range ev.Files {
		p := expandHome(f, home)
		if _, err := os.Stat(p); err == nil {
			res.Evidence = append(res.Evidence, Hit{"file present", p})
		}
	}

	folders := map[string]bool{}
	for _, lm := range ev.LinkedProjectMap {
		data, err := os.ReadFile(expandHome(lm.File, home))
		if err != nil {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		var projects map[string]json.RawMessage
		if json.Unmarshal(m[lm.Key], &projects) != nil {
			continue
		}
		for p := range projects {
			if filepath.IsAbs(p) {
				folders[filepath.Clean(p)] = true
				res.Evidence = append(res.Evidence, Hit{"folder linked in " + lm.File, p})
			}
		}
	}
	if len(ev.ProjectFiles)+len(ev.ProjectFileGlobs) > 0 {
		for _, root := range inv.Roots {
			filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				rel, _ := filepath.Rel(root, p)
				if d.IsDir() {
					if p != root && (skipDirs[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= maxWalkDepth) {
						return filepath.SkipDir
					}
					return nil
				}
				hit := false
				for _, n := range ev.ProjectFiles {
					hit = hit || d.Name() == n
				}
				for _, g := range ev.ProjectFileGlobs {
					ok, _ := filepath.Match(g, d.Name())
					hit = hit || ok
				}
				if hit {
					folders[filepath.Dir(p)] = true
					res.Evidence = append(res.Evidence, Hit{"project config " + d.Name(), p})
				}
				return nil
			})
		}
	}
	if len(ev.EnvNames) > 0 {
		names := map[string]bool{}
		for _, n := range ev.EnvNames {
			names[n] = true
		}
		for _, r := range inv.CIRefs {
			if names[r.Name] {
				res.Evidence = append(res.Evidence, Hit{"CI uses " + r.Name, r.Path})
			}
		}
		for _, t := range inv.envFiles {
			data, err := os.ReadFile(t)
			if err != nil {
				continue
			}
			for n := range names {
				if strings.Contains(string(data), n) {
					res.Evidence = append(res.Evidence, Hit{"env file mentions " + n, t})
					folders[filepath.Dir(t)] = true
				}
			}
		}
	}
	for f := range folders {
		res.ProjectFolders = append(res.ProjectFolders, f)
	}
	sort.Strings(res.ProjectFolders)
	res.Applies = len(res.Evidence) > 0
	if !res.Applies {
		return res
	}

	switch in.Exposure.Scope {
	case "all-keys":
		res.Exposed = append(res.Exposed, inv.Keys...)
		res.ExposedStores = append(res.ExposedStores, inv.Stores...)
	case "ai-keys":
		for _, k := range inv.Keys {
			if provider(k.Provider).Kind == "ai" {
				res.Exposed = append(res.Exposed, k)
			}
		}
	case "paths":
		var paths []string
		for _, p := range in.Exposure.Paths {
			ep := expandHome(p, home)
			paths = append(paths, ep)
			if _, err := os.Stat(ep); err == nil {
				res.ExposedPaths = append(res.ExposedPaths, ep)
			}
		}
		for _, k := range inv.Keys {
			if anyLocWithin(k, paths) {
				res.Exposed = append(res.Exposed, k)
			}
		}
		for _, s := range inv.Stores {
			for _, p := range paths {
				if within(s.Path, p) {
					res.ExposedStores = append(res.ExposedStores, s)
					break
				}
			}
		}
	case "project-folders":
		for _, k := range inv.Keys {
			if anyLocWithin(k, res.ProjectFolders) {
				res.Exposed = append(res.Exposed, k)
			}
		}
	}
	return res
}

func anyLocWithin(k Key, dirs []string) bool {
	for _, l := range k.Locations {
		for _, d := range dirs {
			if within(l.Path, d) {
				return true
			}
		}
	}
	return false
}
