package kd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// target is one file to scan for keys.
type target struct {
	path     string
	source   string
	category string
}

// Fixed places under home where AI tools and shells keep logs, history and
// state. The list starts from what MEDUSA's `secrets scan` reads, checked
// against each tool's own docs where they say anything. docs/sources.md has
// the details and the paths we could not confirm.
type fixedGlob struct {
	pattern  string // relative to home; ** matches any depth
	source   string
	category string
}

var fixedGlobs = []fixedGlob{
	// Claude Code
	{".claude/projects/**/*.jsonl", "Claude Code transcript", "agent-log"},
	{".claude/history.jsonl", "Claude Code history", "agent-log"},
	{".claude/settings.json", "Claude Code settings", "tool-config"},
	{".claude.json", "Claude Code user config", "tool-config"},
	// Codex
	{".codex/history.jsonl", "Codex history", "agent-log"},
	{".codex/sessions/**/*.jsonl", "Codex session", "agent-log"},
	{".codex/history/**/*", "Codex history", "agent-log"},
	{".codex/auth.json", "Codex login", "tool-config"},
	{".codex/config.toml", "Codex config", "tool-config"},
	// Gemini CLI
	{".gemini/tmp/*/chats/**/*", "Gemini CLI session", "agent-log"},
	{".gemini/history/**/*", "Gemini CLI history", "agent-log"},
	// Aider (default file names in home; files in projects are found by the walk)
	{".aider.chat.history.md", "Aider chat history", "agent-log"},
	{".aider.input.history", "Aider input history", "agent-log"},
	{".aider.llm.history", "Aider LLM log", "agent-log"},
	// Cursor and VS Code (Linux paths, then macOS paths)
	{".config/Cursor/User/workspaceStorage/**/state.vscdb", "Cursor workspace state", "agent-log"},
	{".config/Cursor/User/workspaceStorage/**/*chat*.json", "Cursor chat", "agent-log"},
	{".config/Cursor/User/globalStorage/state.vscdb", "Cursor global state", "agent-log"},
	{".config/Code/User/workspaceStorage/**/chatSessions/*.json", "VS Code Copilot chat", "agent-log"},
	{".config/Code/User/globalStorage/state.vscdb", "VS Code global state", "agent-log"},
	{"Library/Application Support/Cursor/User/workspaceStorage/**/state.vscdb", "Cursor workspace state", "agent-log"},
	{"Library/Application Support/Cursor/User/globalStorage/state.vscdb", "Cursor global state", "agent-log"},
	{"Library/Application Support/Code/User/workspaceStorage/**/chatSessions/*.json", "VS Code Copilot chat", "agent-log"},
	// Zed and Claude Desktop
	{".local/share/zed/conversations/*", "Zed conversation", "agent-log"},
	{".config/Claude/*.json", "Claude Desktop state", "agent-log"},
	{".config/Claude/*.log", "Claude Desktop log", "agent-log"},
	{"Library/Application Support/Claude/*.json", "Claude Desktop state", "agent-log"},
	// Continue, Sourcegraph Cody and Hermes (paths from the OVHcloud advisory)
	{".config/Code/User/globalStorage/continue.continue/index/index.sqlite", "Continue index", "agent-log"},
	{".config/Cursor/User/globalStorage/continue.continue/index/index.sqlite", "Continue index", "agent-log"},
	{".config/Code/User/globalStorage/sourcegraph.cody-ai/chat/chat-history.db", "Cody chat history", "agent-log"},
	{".config/Cursor/User/globalStorage/sourcegraph.cody-ai/chat/chat-history.db", "Cody chat history", "agent-log"},
	{".hermes/sessions/**/*", "Hermes session", "agent-log"},
	{".hermes/.hermes_history", "Hermes history", "agent-log"},
	// OpenCode
	{".local/share/opencode/auth.json", "OpenCode provider keys", "tool-config"},
	{".local/share/opencode/opencode.db", "OpenCode database", "agent-log"},
	{".config/opencode/opencode.db", "OpenCode database", "agent-log"},
	// Shell and REPL history
	{".bash_history", "bash history", "shell-history"},
	{".zsh_history", "zsh history", "shell-history"},
	{".local/share/fish/fish_history", "fish history", "shell-history"},
	{".python_history", "Python REPL history", "shell-history"},
	{".node_repl_history", "Node REPL history", "shell-history"},
	{".psql_history", "psql history", "shell-history"},
	{".mysql_history", "MySQL history", "shell-history"},
	{".irb_history", "irb history", "shell-history"},
	{".rediscli_history", "redis-cli history", "shell-history"},
	{".sqlite_history", "sqlite history", "shell-history"},
	// Tool configs that hold tokens
	{".docker/config.json", "Docker config", "tool-config"},
	{".aws/credentials", "AWS credentials", "tool-config"},
	{".aws/config", "AWS config", "tool-config"},
	{".config/gcloud/application_default_credentials.json", "gcloud application default credentials", "tool-config"},
	{".config/gcloud/legacy_credentials/*/adc.json", "gcloud legacy credentials", "tool-config"},
	{".config/gh/hosts.yml", "GitHub CLI login", "tool-config"},
	{".npmrc", "npm config", "tool-config"},
	{".pypirc", "PyPI config", "tool-config"},
	{".netrc", "netrc", "tool-config"},
	{".git-credentials", "git credential store", "tool-config"},
}

// Credential files listed as stores: present or not, never parsed into keys.
var storeGlobs = []struct{ pattern, what, provider, action string }{
	{".ssh/id_*", "SSH private key", "", "make a new key pair and remove the old public key from every server and from GitHub or GitLab"},
	{".kube/config", "Kubernetes config", "", "rotate the cluster credentials or tokens it holds"},
	{".config/gcloud/credentials.db", "gcloud credential database", "gcloud", "run gcloud auth revoke, then log in again"},
	{".config/gcloud/access_tokens.db", "gcloud access token cache", "gcloud", "run gcloud auth revoke, then log in again"},
	{".azure/msal_token_cache.json", "Azure CLI token cache", "", "run az logout and revoke sessions in Entra ID"},
	{".terraform.d/credentials.tfrc.json", "Terraform credentials", "", "revoke the token in HCP Terraform and log in again"},
	{".config/doctl/config.yaml", "DigitalOcean CLI config", "", "revoke the token in the DigitalOcean control panel"},
	{".dockercfg", "old Docker config", "docker", "log out and revoke the registry token"},
	{".claude/.credentials.json", "Claude Code login", "anthropic", "log out of Claude Code and log in again"},
	{".codex/auth.json", "Codex login", "openai", "log out of Codex and log in again"},
	{".config/zeabur/cli.yaml", "Zeabur CLI login", "", "log out of the Zeabur CLI and log in again"},
	{".railway/config.json", "Railway CLI login", "", "log out of the Railway CLI and log in again"},
}

// Directories the walk never enters.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".cache": true, ".npm": true, ".cargo": true, ".rustup": true,
	".venv": true, "venv": true, "__pycache__": true, ".local": true, ".config": true, "Library": true,
	".claude": true, ".codex": true, ".gemini": true, ".hermes": true, "snap": true, ".Trash": true, ".vscode-server": true,
	".cursor-server": true, "go": true, ".m2": true, ".gradle": true, ".pyenv": true, ".nvm": true,
}

const maxWalkDepth = 8

// globHome expands a pattern relative to home. "**" matches zero or more
// folders.
func globHome(home, pattern string) []string {
	if !strings.Contains(pattern, "**") {
		m, _ := filepath.Glob(filepath.Join(home, pattern))
		return regularOnly(m)
	}
	i := strings.Index(pattern, "**")
	bases, _ := filepath.Glob(filepath.Join(home, pattern[:i]))
	rest := strings.TrimPrefix(pattern[i+2:], "/")
	segs := strings.Split(rest, "/")
	var out []string
	for _, base := range bases {
		filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			// match the last len(segs) path segments against rest
			rel, _ := filepath.Rel(base, p)
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) < len(segs) {
				return nil
			}
			tail := strings.Join(parts[len(parts)-len(segs):], "/")
			if ok, _ := filepath.Match(rest, tail); ok {
				out = append(out, p)
			}
			return nil
		})
	}
	return regularOnly(out)
}

func regularOnly(ps []string) []string {
	var out []string
	for _, p := range ps {
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}

func isEnvFile(name string) bool {
	switch {
	case name == ".env", name == ".envrc", name == ".dev.vars":
		return true
	case strings.HasPrefix(name, ".env."):
		return true
	case strings.HasSuffix(name, ".env") && len(name) > 4:
		return true
	}
	return false
}

// walkRoots finds env files, project .npmrc files, Aider history files and
// CI files under the given roots.
func walkRoots(roots []string, home string) (targets []target, ci []string) {
	seen := map[string]bool{}
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			depth := strings.Count(rel, string(filepath.Separator))
			if d.IsDir() {
				if p != root && (skipDirs[d.Name()] || depth >= maxWalkDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || seen[p] {
				return nil
			}
			name := d.Name()
			dir := filepath.Base(filepath.Dir(p))
			switch {
			case isEnvFile(name):
				targets = append(targets, target{p, "env file", "env-file"})
			case name == ".npmrc" && filepath.Dir(p) != home:
				targets = append(targets, target{p, "npm config", "tool-config"})
			case strings.HasPrefix(name, ".aider.") && strings.Contains(name, "history") && filepath.Dir(p) != home:
				targets = append(targets, target{p, "Aider history", "agent-log"})
			case (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) && dir == "workflows" &&
				filepath.Base(filepath.Dir(filepath.Dir(p))) == ".github":
				ci = append(ci, p)
			case name == ".gitlab-ci.yml":
				ci = append(ci, p)
			default:
				return nil
			}
			seen[p] = true
			return nil
		})
	}
	return targets, ci
}
