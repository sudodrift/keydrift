// Package fakehome writes a fake home folder full of fake keys, for tests and
// for the README demo. The keys are built here at run time from a filler
// string, so no file in this repository holds a string that looks like a
// real key. None of them work anywhere.
package fakehome

import (
	"os"
	"path/filepath"
	"strings"
)

// fill repeats a filler made of the allowed characters to length n. The
// variant letter makes keys of the same kind differ.
func fill(n int, alphabet string, variant byte) string {
	const filler = "FAKEKEYDRIFTTESTVALUE"
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		c := filler[i%len(filler)]
		if i%7 == 3 {
			c = variant
		}
		if !strings.ContainsRune(alphabet, rune(c)) {
			c = alphabet[i%len(alphabet)]
		}
		b.WriteByte(c)
	}
	return b.String()
}

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	hexlow  = "0123456789abcdef"
	b32     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Keys returns the fake keys by placeholder name.
func Keys() map[string]string {
	return map[string]string{
		"ANTHROPIC":  "sk-ant-" + "api03-" + fill(93, alnum, 'A') + "AA",
		"OPENAI":     "sk-" + "proj-" + fill(74, alnum, 'B') + "T3Blbk" + "FJ" + fill(74, alnum, 'C'),
		"GEMINI":     "AI" + "za" + fill(35, alnum, 'D'),
		"GROQ":       "gsk" + "_" + fill(52, alnum, 'E'),
		"XAI":        "xai" + "-" + fill(80, alnum, 'F'),
		"OPENROUTER": "sk-or-" + "v1-" + fill(64, hexlow, 'a'),
		"HF":         "hf" + "_" + fill(34, letters, 'G'),
		"MISTRAL":    fill(32, upper, 'H'),
		"DEEPSEEK":   "sk-" + fill(32, hexlow, 'b'),
		"TOGETHER":   "tgp" + "_v1_" + fill(43, alnum, 'I'),
		"FIREWORKS":  "fw" + "_" + fill(24, alnum, 'J'),
		"GITHUB":     "gh" + "p_" + fill(36, alnum, 'K'),
		"GHO":        "gh" + "o_" + fill(36, alnum, 'L'),
		"AWSID":      "AK" + "IA" + fill(16, b32, 'M'),
		"AWSSECRET":  fill(40, alnum, 'N'),
		"STRIPE":     "sk" + "_live_" + fill(24, alnum, 'O'),
		"NPM":        "npm" + "_" + fill(36, alnum, 'P'),
		"PYPI":       "pypi-" + "AgEIcHlwaS5vcmc" + fill(60, alnum, 'Q'),
		"OPENAI2":    "sk-" + "proj-" + fill(74, alnum, 'R') + "T3Blbk" + "FJ" + fill(74, alnum, 'S'),
		"GCLOUDRT":   "1//" + fill(60, alnum, 'T'),
	}
}

// Files returns the fake home's files. Paths are relative to home; @@NAME@@
// is replaced with Keys()[NAME] and @@HOME@@ with the home path.
var Files = map[string]string{
	".bash_history": "ls\nexport OPENAI_API_KEY=@@OPENAI@@\n" +
		"curl https://api.anthropic.com/v1/messages -H 'x-api-key: @@ANTHROPIC@@'\ngit status\n",
	".claude/projects/-home-dev-code-shop/5f1c.jsonl":              `{"type":"user","message":{"role":"user","content":"why does GROQ_API_KEY=@@GROQ@@ return 401?"}}` + "\n",
	".codex/sessions/2026/10/20/rollout-2026-10-20T10-00-00.jsonl": `{"type":"message","content":"push with @@GITHUB@@"}` + "\n",
	".gemini/tmp/7d1e/chats/session-2026-10-21.json":               `{"messages":[{"text":"HF token is @@HF@@"}]}` + "\n",
	".aider.chat.history.md":                                       "#### set OPENROUTER_API_KEY to @@OPENROUTER@@\n",
	".docker/config.json":                                          `{"auths":{"registry.example.invalid":{"auth":"ZmFrZXVzZXI6ZmFrZXBhc3M="}}}` + "\n",
	".aws/credentials":                                             "[default]\naws_access_key_id = @@AWSID@@\naws_secret_access_key = @@AWSSECRET@@\n",
	".config/gcloud/application_default_credentials.json":          `{"type":"authorized_user","client_id":"fake.apps.example.invalid","refresh_token":"@@GCLOUDRT@@"}` + "\n",
	".config/gcloud/credentials.db":                                "not a real database\n",
	".config/gh/hosts.yml":                                         "github.com:\n    user: fakeuser\n    oauth_token: @@GHO@@\n",
	".npmrc":                                                       "//registry.npmjs.org/:_authToken=@@NPM@@\n",
	".pypirc":                                                      "[pypi]\nusername = __token__\npassword = @@PYPI@@\n",
	".ssh/id_ed25519":                                              "not a real private key\n",
	".ssh/id_ed25519.pub":                                          "ssh-ed25519 FAKE fake@example.invalid\n",
	".railway/config.json":                                         `{"projects":{"@@HOME@@/code/shop":{"projectPath":"@@HOME@@/code/shop","project":"fake-project-id"}},"user":{}}` + "\n",
	".local/share/opencode/auth.json":                              `{"anthropic":{"type":"api","key":"@@ANTHROPIC@@"}}` + "\n",
	"code/shop/.env": "OPENAI_API_KEY=@@OPENAI@@\nSTRIPE_SECRET_KEY=@@STRIPE@@\nXAI_API_KEY=@@XAI@@\n" +
		"MISTRAL_API_KEY=@@MISTRAL@@\nDEEPSEEK_API_KEY=@@DEEPSEEK@@\nFIREWORKS_API_KEY=@@FIREWORKS@@\n" +
		"TOGETHER_API_KEY=@@TOGETHER@@\nDATABASE_URL=postgres://localhost/shop\nOPENAI_MODEL=gpt-5\n",
	"code/shop/.env.example": "OPENAI_API_KEY=your-key-here\nSTRIPE_SECRET_KEY=\n",
	"code/shop/railway.json": `{"build":{"builder":"NIXPACKS"}}` + "\n",
	"code/shop/.github/workflows/deploy.yml": "on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n" +
		"      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n      STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}\n" +
		"      GH: ${{ secrets.GITHUB_TOKEN }}\n",
	"code/blog/zbpack.json":     `{"build_command":"npm run build"}` + "\n",
	"code/blog/.env.production": "GEMINI_API_KEY=@@GEMINI@@\n",
	"code/blog/.gitlab-ci.yml":  "deploy:\n  script:\n    - curl -H \"Authorization: Bearer $DEPLOY_TOKEN\" https://deploy.example.invalid\n",
	"code/ml/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA": "Name: litellm\nVersion: 1.107.0\n",
	"code/ml/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info/RECORD":   "",
}

// Write creates the fake home at dir. With litellm false, the litellm
// 1.107.0 install is left out.
func Write(dir string, litellm bool) error {
	keys := Keys()
	for rel, body := range Files {
		if !litellm && strings.Contains(rel, "litellm-1.107.0") {
			continue
		}
		for name, v := range keys {
			body = strings.ReplaceAll(body, "@@"+name+"@@", v)
		}
		body = strings.ReplaceAll(body, "@@HOME@@", dir)
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}
