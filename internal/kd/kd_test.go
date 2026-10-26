package kd

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sudodrift/keydrift/incidents"
	"github.com/sudodrift/keydrift/internal/fakehome"
)

var testSalt = bytes.Repeat([]byte{7}, 32)

func fakeHome(t *testing.T, litellm bool) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := fakehome.Write(home, litellm); err != nil {
		t.Fatal(err)
	}
	return home
}

func scanHome(t *testing.T, home string) *Inventory {
	t.Helper()
	inv, err := Scan(Options{Home: home, Salt: testSalt, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return Rule{}
}

func TestRulesFindEachFakeKey(t *testing.T) {
	k := fakehome.Keys()
	cases := map[string]string{
		"ANTHROPIC":  "anthropic-api-key",
		"OPENAI":     "openai-api-key",
		"GEMINI":     "gcp-api-key",
		"GROQ":       "groq-api-key",
		"XAI":        "xai-api-key",
		"OPENROUTER": "openrouter-api-key",
		"HF":         "huggingface-access-token",
		"TOGETHER":   "togetherai-api-key",
		"GITHUB":     "github-pat",
		"GHO":        "github-oauth",
		"AWSID":      "aws-access-token",
		"STRIPE":     "stripe-access-token",
		"NPM":        "npm-access-token",
		"PYPI":       "pypi-upload-token",
	}
	for name, id := range cases {
		r := ruleByID(t, id)
		line := "something " + k[name] + " more\n"
		if !r.re.MatchString(line) {
			t.Errorf("%s: rule %s did not match the fake key", name, id)
		}
	}
	// Keys with no fixed shape need their variable name next to them.
	named := map[string]string{
		"MISTRAL_API_KEY=" + k["MISTRAL"]:     "mistral-api-key",
		"DEEPSEEK_API_KEY=" + k["DEEPSEEK"]:   "deepseek-api-key",
		"FIREWORKS_API_KEY=" + k["FIREWORKS"]: "name-fireworks",
	}
	for line, id := range named {
		if !ruleByID(t, id).re.MatchString(line + "\n") {
			t.Errorf("rule %s did not match %q", id, line[:20])
		}
	}
}

func TestRulesIgnorePlaceholders(t *testing.T) {
	lines := []string{
		"OPENAI_API_KEY=your-key-here",
		"FIREWORKS_API_KEY=",
		"FIREWORKS_API_KEY=${FIREWORKS_API_KEY}",
		"sk-ant-api03-short",
		"ghp_tooShort",
		"export PATH=/usr/local/bin:$PATH",
	}
	for _, l := range lines {
		for _, r := range Rules() {
			if r.re.MatchString(l + "\n") {
				t.Errorf("rule %s matched placeholder %q", r.ID, l)
			}
		}
	}
}

func TestEveryRuleHasAProvider(t *testing.T) {
	for _, r := range Rules() {
		if len(r.Keywords) == 0 {
			t.Errorf("rule %s has no keywords", r.ID)
		}
		p, ok := Providers[r.Provider]
		if !ok {
			t.Errorf("rule %s: provider %q is not in Providers", r.ID, r.Provider)
			continue
		}
		if p.Rotate == "" {
			t.Errorf("provider %s has no rotate link", r.Provider)
		}
	}
}

func TestScanFindsKeysAndNeverKeepsValues(t *testing.T) {
	home := fakeHome(t, false)
	inv := scanHome(t, home)
	if len(inv.Keys) != 20 {
		t.Errorf("found %d keys, want 20", len(inv.Keys))
	}
	byProv := map[string]int{}
	for _, k := range inv.Keys {
		byProv[k.Provider]++
	}
	for _, p := range []string{"anthropic", "openai", "google", "groq", "xai", "openrouter", "huggingface",
		"mistral", "deepseek", "together", "fireworks", "github", "aws", "stripe", "npm", "pypi", "docker", "gcloud"} {
		if byProv[p] == 0 {
			t.Errorf("no key found for %s", p)
		}
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, ScanReport{Inventory: inv, Rotation: Rotation(inv.Keys, inv.Stores, "")}); err != nil {
		t.Fatal(err)
	}
	WriteScanText(&buf, inv, Rotation(inv.Keys, inv.Stores, ""))
	snap := NewSnapshot(inv, testSalt, time.Now())
	if err := WriteJSON(&buf, snap); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for name, v := range fakehome.Keys() {
		if strings.Contains(out, v) {
			t.Errorf("output holds the raw %s value", name)
		}
		// Not even a long piece of it.
		if len(v) > 24 && strings.Contains(out, v[len(v)-16:]) {
			t.Errorf("output holds the end of the %s value", name)
		}
	}
	if strings.Contains(out, "ZmFrZXVzZXI6ZmFrZXBhc3M=") {
		t.Error("output holds the Docker auth value")
	}
}

func TestSameKeyInTwoPlacesIsOneKey(t *testing.T) {
	inv := scanHome(t, fakeHome(t, false))
	for _, k := range inv.Keys {
		if k.Provider == "anthropic" {
			if len(k.Locations) != 2 {
				t.Fatalf("anthropic key has %d locations, want 2", len(k.Locations))
			}
			return
		}
	}
	t.Fatal("anthropic key not found")
}

func TestStoresAndCINames(t *testing.T) {
	home := fakeHome(t, false)
	inv := scanHome(t, home)
	stores := map[string]bool{}
	for _, s := range inv.Stores {
		stores[Tilde(s.Path, home)] = true
	}
	for _, p := range []string{"~/.ssh/id_ed25519", "~/.railway/config.json", "~/.config/gcloud/credentials.db"} {
		if !stores[p] {
			t.Errorf("store %s not listed", p)
		}
	}
	if stores["~/.ssh/id_ed25519.pub"] {
		t.Error("public key listed as a credential file")
	}
	names := map[string]bool{}
	for _, c := range inv.CIRefs {
		names[c.Name] = true
	}
	for _, n := range []string{"OPENAI_API_KEY", "STRIPE_SECRET_KEY", "DEPLOY_TOKEN"} {
		if !names[n] {
			t.Errorf("CI name %s not found", n)
		}
	}
	if names["GITHUB_TOKEN"] {
		t.Error("GITHUB_TOKEN should be skipped; GitHub makes it per run")
	}
}

func TestDockerCredsStoreIsAStore(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".docker"), 0o700)
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"auths":{"ghcr.io":{}},"credsStore":"desktop"}`), 0o600)
	inv := scanHome(t, home)
	if len(inv.Keys) != 0 {
		t.Errorf("found %d keys in a config that only names a helper", len(inv.Keys))
	}
	found := false
	for _, s := range inv.Stores {
		if strings.HasSuffix(s.Path, "config.json") && s.Provider == "docker" {
			found = true
		}
	}
	if !found {
		t.Error("credsStore not listed as a store")
	}
}

func TestKeyAcrossChunkBorder(t *testing.T) {
	home := t.TempDir()
	key := fakehome.Keys()["GITHUB"]
	data := bytes.Repeat([]byte("x"), chunkSize+1024)
	for i := 1; i < len(data); i += 100 {
		data[i] = '\n'
	}
	at := chunkSize - len(key)/2
	copy(data[at-1:], " "+key+" ")
	if err := os.WriteFile(filepath.Join(home, ".bash_history"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	inv := scanHome(t, home)
	if len(inv.Keys) != 1 || inv.Keys[0].Provider != "github" {
		t.Fatalf("got %d keys, want the one GitHub key across the border", len(inv.Keys))
	}
	if n := len(inv.Keys[0].Locations); n != 1 {
		t.Errorf("key counted %d times", n)
	}
	if l := inv.Keys[0].Locations[0].Line; l != bytes.Count(data[:at], []byte("\n"))+1 {
		t.Errorf("line %d is wrong", l)
	}
}

func TestMaskAndFingerprint(t *testing.T) {
	v := fakehome.Keys()["ANTHROPIC"]
	m := Mask("sk-ant-api03-", v)
	if m != "sk-ant-api03-... (108 chars)" {
		t.Errorf("mask = %q", m)
	}
	if got := Mask("", "abc"); strings.Contains(got, "abc") {
		t.Errorf("short value leaked: %q", got)
	}
	a, b := Fingerprint(testSalt, v), Fingerprint(bytes.Repeat([]byte{8}, 32), v)
	if len(a) != 16 || a == b {
		t.Errorf("fingerprints %q %q: want 16 hex chars that depend on the salt", a, b)
	}
	if Fingerprint(testSalt, v) != a {
		t.Error("fingerprint is not stable")
	}
}

func TestSaltIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s1, err := LoadSalt(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "salt"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("salt mode %v, want 0600", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("state folder mode %v, want 0700", dst.Mode().Perm())
	}
	s2, err := LoadSalt(dir)
	if err != nil || !bytes.Equal(s1, s2) {
		t.Fatal("salt changed between runs")
	}
	os.Chmod(filepath.Join(dir, "salt"), 0o644)
	if _, err := LoadSalt(dir); err == nil {
		t.Error("a salt readable by others was accepted")
	}
}

func TestDiffKinds(t *testing.T) {
	home := fakeHome(t, false)
	old := NewSnapshot(scanHome(t, home), testSalt, time.Now())
	k := fakehome.Keys()
	os.WriteFile(filepath.Join(home, "code", "blog", ".env"), []byte("ANTHROPIC_API_KEY="+k["ANTHROPIC"]+"\n"), 0o600)
	os.WriteFile(filepath.Join(home, ".zsh_history"), []byte(": 1:0;export X="+k["OPENAI2"]+"\n"), 0o600)
	os.Remove(filepath.Join(home, ".pypirc"))
	os.Remove(filepath.Join(home, ".local", "share", "opencode", "auth.json"))
	cur := NewSnapshot(scanHome(t, home), testSalt, time.Now())
	got := map[string]string{}
	for _, c := range Diff(old, cur) {
		got[c.Kind] = c.Provider
	}
	want := map[string]string{"new-key": "openai", "new-location": "anthropic", "gone-key": "pypi", "gone-location": "anthropic"}
	for kind, prov := range want {
		if got[kind] != prov {
			t.Errorf("%s: got %q, want %q", kind, got[kind], prov)
		}
	}
	if len(Diff(old, old)) != 0 {
		t.Error("a snapshot differs from itself")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	inv := scanHome(t, fakeHome(t, false))
	p := filepath.Join(t.TempDir(), "s.json")
	f, _ := os.Create(p)
	WriteJSON(f, NewSnapshot(inv, testSalt, time.Now()))
	f.Close()
	s, err := ReadSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Keys) != len(inv.Keys) || s.SaltID != SaltID(testSalt) {
		t.Errorf("round trip lost data")
	}
}

func TestCatalogLoads(t *testing.T) {
	cat, err := LoadCatalog(incidents.FS)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"litellm-1.107.0", "opencode-2026-10", "ovhcloud-cli-2026-10", "railway-2026-10", "zeabur-2026-10"}
	if len(cat) != len(want) {
		t.Fatalf("%d incidents, want %d", len(cat), len(want))
	}
	for i, in := range cat {
		if in.ID != want[i] {
			t.Errorf("incident %d is %s, want %s", i, in.ID, want[i])
		}
		for _, s := range in.Sources {
			if !strings.HasPrefix(s.URL, "https://") {
				t.Errorf("%s: source %q is not an https link", in.ID, s.URL)
			}
		}
		if len(in.Actions) == 0 {
			t.Errorf("%s has no actions", in.ID)
		}
	}
}

func TestCatalogRejectsBadEntries(t *testing.T) {
	bad := map[string]string{
		"unknown field": "id: x\ntitle: t\nsources: [{name: a, url: https://a}]\nexposure: {scope: all-keys}\nbogus: 1\n",
		"no sources":    "id: x\ntitle: t\nexposure: {scope: all-keys}\n",
		"bad scope":     "id: x\ntitle: t\nsources: [{name: a, url: https://a}]\nexposure: {scope: some}\n",
	}
	for name, body := range bad {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "x.yaml"), []byte(body), 0o600)
		if _, err := LoadCatalog(os.DirFS(dir)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "y.yaml"), []byte("id: x\ntitle: t\nsources: [{name: a, url: https://a}]\nexposure: {scope: all-keys}\n"), 0o600)
	if _, err := LoadCatalog(os.DirFS(dir)); err == nil {
		t.Error("id that does not match the file name was accepted")
	}
}

func incident(t *testing.T, id string) Incident {
	t.Helper()
	cat, err := LoadCatalog(incidents.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range cat {
		if in.ID == id {
			return in
		}
	}
	t.Fatalf("no incident %s", id)
	return Incident{}
}

func match(t *testing.T, id, home string, o MatchOptions) MatchResult {
	t.Helper()
	inv := scanHome(t, home)
	o.Home = home
	if o.PyRoots == nil {
		o.PyRoots = []string{home}
	}
	if o.BinDirs == nil {
		o.BinDirs = []string{filepath.Join(home, "nothing")}
	}
	if o.TmpDirs == nil {
		o.TmpDirs = []string{filepath.Join(home, "nothing")}
	}
	return Match(incident(t, id), inv, o)
}

func TestMatchLiteLLM(t *testing.T) {
	r := match(t, "litellm-1.107.0", fakeHome(t, true), MatchOptions{})
	if !r.Applies || len(r.Exposed) != 20 {
		t.Errorf("applies=%v exposed=%d, want true and every key", r.Applies, len(r.Exposed))
	}
	clean := match(t, "litellm-1.107.0", fakeHome(t, false), MatchOptions{})
	if clean.Applies {
		t.Error("matched without the bad version installed")
	}
}

func TestMatchRailwayUsesLinkedFolders(t *testing.T) {
	home := fakeHome(t, false)
	r := match(t, "railway-2026-10", home, MatchOptions{})
	if !r.Applies {
		t.Fatal("railway did not match")
	}
	for _, k := range r.Exposed {
		for _, l := range k.Locations {
			if !strings.HasPrefix(l.Path, filepath.Join(home, "code", "shop")) && k.Provider != "openai" {
				t.Errorf("%s key outside the linked folder counted as exposed: %s", k.Provider, l.Path)
			}
		}
	}
	got := map[string]bool{}
	for _, k := range r.Exposed {
		got[k.Provider] = true
	}
	if !got["stripe"] || got["google"] {
		t.Errorf("exposed providers %v: want stripe from code/shop and not the blog's Google key", got)
	}
}

func TestMatchZeaburUsesZbpackFolders(t *testing.T) {
	r := match(t, "zeabur-2026-10", fakeHome(t, false), MatchOptions{})
	if !r.Applies || len(r.Exposed) != 1 || r.Exposed[0].Provider != "google" {
		t.Errorf("applies=%v exposed=%d, want the one key in code/blog", r.Applies, len(r.Exposed))
	}
}

func TestMatchOpenCodeOnlyAIKeys(t *testing.T) {
	r := match(t, "opencode-2026-10", fakeHome(t, false), MatchOptions{})
	if !r.Applies {
		t.Fatal("opencode did not match")
	}
	for _, k := range r.Exposed {
		if provider(k.Provider).Kind != "ai" {
			t.Errorf("non-AI key %s counted as exposed", k.Provider)
		}
	}
}

func TestMatchOVHByMD5AndPaths(t *testing.T) {
	home := fakeHome(t, false)
	r := match(t, "ovhcloud-cli-2026-10", home, MatchOptions{})
	if r.Applies {
		t.Fatal("matched with no evidence")
	}
	// The real bad binaries are malware, so the test uses its own file and
	// adds that file's MD5 to a copy of the incident. Match only reads the
	// file; nothing is run.
	bin := filepath.Join(home, "bin")
	os.MkdirAll(bin, 0o700)
	body := []byte("fake ovhcloud binary for tests\n")
	os.WriteFile(filepath.Join(bin, "ovhcloud"), body, 0o600)
	sum := md5.Sum(body)
	in := incident(t, "ovhcloud-cli-2026-10")
	in.Evidence.Binaries.MD5 = append(in.Evidence.Binaries.MD5, hex.EncodeToString(sum[:]))
	tmp := t.TempDir()
	os.Mkdir(filepath.Join(tmp, "envchecker-1761000000"), 0o700)
	inv := scanHome(t, home)
	r = Match(in, inv, MatchOptions{Home: home, PyRoots: []string{home}, BinDirs: []string{bin}, TmpDirs: []string{tmp}})
	if !r.Applies || len(r.Evidence) != 2 {
		t.Fatalf("applies=%v evidence=%v", r.Applies, r.Evidence)
	}
	got := map[string]bool{}
	for _, k := range r.Exposed {
		got[k.Provider] = true
	}
	if !got["aws"] || !got["docker"] || !got["npm"] {
		t.Errorf("exposed %v: want the AWS, Docker and npm keys from the listed files", got)
	}
	if got["stripe"] {
		t.Error("a key in a project .env counted as exposed by OVH")
	}
	stores := map[string]bool{}
	for _, s := range r.ExposedStores {
		stores[Tilde(s.Path, home)] = true
	}
	if !stores["~/.ssh/id_ed25519"] {
		t.Error("SSH key not listed as exposed")
	}
}

func TestRotationOrder(t *testing.T) {
	inv := scanHome(t, fakeHome(t, false))
	rot := Rotation(inv.Keys, inv.Stores, "")
	if rot[0].Provider != "anthropic" {
		t.Errorf("first item %s, want the Anthropic key found in two places including history", rot[0].Provider)
	}
	last := 0
	for i, it := range rot {
		if it.Rank != i+1 {
			t.Errorf("rank %d at %d", it.Rank, i)
		}
		if it.tier < last {
			t.Errorf("tier order broken at %d", i)
		}
		last = it.tier
		if it.RotateURL == "" && it.Action == "" {
			t.Errorf("%s has no rotate link and no action", it.Name)
		}
	}
	b, _ := json.Marshal(rot)
	if strings.Contains(string(b), "tier") {
		t.Error("internal tier leaked into JSON")
	}
}
