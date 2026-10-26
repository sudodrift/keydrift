package kd

import (
	"bytes"
	"regexp"
	"strings"
)

// Rule finds one kind of credential in text.
type Rule struct {
	ID       string
	Provider string // key into Providers
	Origin   string // "betterleaks", "keydrift" (name based) or "structured"
	Prefix   string // fixed prefix that is safe to show when masking
	Keywords []string
	re       *regexp.Regexp
}

// keywords lets the scanner skip a rule when none of its words appear in a
// chunk, the same idea as the keywords list in Gitleaks and Betterleaks
// configs. Lower case; the chunk is lower-cased before the check.
var keywords = map[string][]string{
	"anthropic-admin-api-key":            {"sk-ant-admin01-"},
	"anthropic-api-key":                  {"sk-ant-api03-"},
	"openai-api-key":                     {"t3blbkfj"},
	"gcp-gemini-api":                     {"aq.ab8rn6"},
	"gcp-api-key":                        {"aiza"},
	"groq-api-key":                       {"gsk_"},
	"xai-api-key":                        {"xai-"},
	"openrouter-api-key":                 {"sk-or-v1-"},
	"huggingface-access-token":           {"hf_"},
	"huggingface-organization-api-token": {"api_org_"},
	"mistral-api-key":                    {"mistral"},
	"deepseek-api-key":                   {"deepseek"},
	"togetherai-api-key":                 {"tgp_v1_"},
	"github-pat":                         {"ghp_"},
	"github-fine-grained-pat":            {"github_pat_"},
	"github-oauth":                       {"gho_"},
	"github-app-token":                   {"ghu_", "ghs_"},
	"github-refresh-token":               {"ghr_"},
	"aws-access-token":                   {"a3t", "akia", "asia", "abia", "acca"},
	"stripe-access-token":                {"_test_", "_live_", "_prod_"},
	"npm-access-token":                   {"npm_"},
	"pypi-upload-token":                  {"pypi-ageichlwas5vcmc"},
}

// The regular expressions marked "betterleaks" are copied from the default
// Betterleaks config (config/betterleaks.toml, commit d778712d3d0f,
// 2026-10-26), Copyright (c) 2026 Zachary Rice, MIT License. See
// third_party/betterleaks/LICENSE. The only change is a leading (?m) so that
// "$" also matches at the end of a line when keydrift scans a whole file.
//
// The rules marked "keydrift" are ours. They match by variable name for
// providers whose keys have no fixed format, so their provider guess is only
// as good as the name.
var betterleaksRules = []struct{ id, provider, prefix, re string }{
	{"anthropic-admin-api-key", "anthropic", "sk-ant-admin01-", `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"anthropic-api-key", "anthropic", "sk-ant-api03-", `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"openai-api-key", "openai", "sk-", `\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"gcp-gemini-api", "google", "AQ.", `\b(AQ\.Ab8RN6[A-Za-z0-9_-]{44})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"gcp-api-key", "google", "AIza", `\b(AIza[\w-]{35})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"groq-api-key", "groq", "gsk_", `(?i)\b(gsk_[A-Z0-9]{52})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"xai-api-key", "xai", "xai-", `(?i)\b(xai-[A-Za-z0-9_-]{70,120})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"openrouter-api-key", "openrouter", "sk-or-v1-", `(?i)\b(sk-or-v1-[0-9a-f]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"huggingface-access-token", "huggingface", "hf_", `\b(hf_(?i:[a-z]{34}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"huggingface-organization-api-token", "huggingface", "api_org_", `\b(api_org_(?i:[a-z]{34}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"mistral-api-key", "mistral", "", `(?i)(?:mistral)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"deepseek-api-key", "deepseek", "sk-", `(?i)(?:deepseek)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(sk-[a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"togetherai-api-key", "together", "tgp_v1_", `(?i)\b(tgp_v1_[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"github-pat", "github", "ghp_", `ghp_[0-9a-zA-Z]{36}`},
	{"github-fine-grained-pat", "github", "github_pat_", `github_pat_\w{82}`},
	{"github-oauth", "github", "gho_", `gho_[0-9a-zA-Z]{36}`},
	{"github-app-token", "github", "gh", `(?:ghu|ghs)_[0-9a-zA-Z]{36}`},
	{"github-refresh-token", "github", "ghr_", `ghr_[0-9a-zA-Z]{36}`},
	{"aws-access-token", "aws", "", `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`},
	{"stripe-access-token", "stripe", "", `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"npm-access-token", "npm", "npm_", `(?i)\b(npm_[a-z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`},
	{"pypi-upload-token", "pypi", "pypi-", `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`},
}

// Name based rules (ours). The value must be at least 20 characters of key
// alphabet so that placeholders such as "changeme" or "${OPENAI_API_KEY}" do
// not match.
var nameRules = []struct{ id, provider, names string }{
	{"name-openai", "openai", `OPENAI_API_KEY|OPENAI_ADMIN_KEY`},
	{"name-anthropic", "anthropic", `ANTHROPIC_API_KEY|ANTHROPIC_ADMIN_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_API_KEY`},
	{"name-google", "google", `GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY`},
	{"name-groq", "groq", `GROQ_API_KEY`},
	{"name-xai", "xai", `XAI_API_KEY|GROK_API_KEY`},
	{"name-openrouter", "openrouter", `OPENROUTER_API_KEY`},
	{"name-huggingface", "huggingface", `HF_TOKEN|HUGGINGFACE_TOKEN|HUGGING_FACE_HUB_TOKEN|HUGGINGFACEHUB_API_TOKEN`},
	{"name-mistral", "mistral", `MISTRAL_API_KEY`},
	{"name-deepseek", "deepseek", `DEEPSEEK_API_KEY`},
	{"name-together", "together", `TOGETHER_API_KEY|TOGETHERAI_API_KEY`},
	{"name-fireworks", "fireworks", `FIREWORKS_API_KEY`},
	{"name-github", "github", `GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT`},
	{"name-aws-secret", "aws", `AWS_SECRET_ACCESS_KEY|aws_secret_access_key`},
	{"name-stripe", "stripe", `STRIPE_SECRET_KEY|STRIPE_API_KEY`},
	{"name-npm", "npm", `NPM_TOKEN|_authToken`},
	{"name-pypi", "pypi", `PYPI_TOKEN|PYPI_API_TOKEN|TWINE_PASSWORD`},
}

var allRules []Rule

func init() {
	for _, r := range betterleaksRules {
		allRules = append(allRules, Rule{ID: r.id, Provider: r.provider, Origin: "betterleaks", Prefix: r.prefix,
			Keywords: keywords[r.id], re: regexp.MustCompile(`(?m)` + r.re)})
	}
	for _, r := range nameRules {
		// NAME = value, NAME: value, "NAME": "value", export NAME=value,
		// and the npmrc form //host/:_authToken=value.
		re := `(?m)(?:^|[^A-Za-z0-9_])(?:` + r.names + `)["']?\s*(?:=|:)\s*["']?([A-Za-z0-9_\-./+=]{20,})`
		var kw []string
		for _, n := range strings.Split(r.names, "|") {
			kw = append(kw, strings.ToLower(n))
		}
		allRules = append(allRules, Rule{ID: r.id, Provider: r.provider, Origin: "keydrift", Keywords: kw, re: regexp.MustCompile(re)})
	}
}

// Rules returns the rule list (for docs and tests).
func Rules() []Rule { return allRules }

// wanted reports whether any keyword of r appears in lower.
func (r Rule) wanted(lower []byte) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	for _, k := range r.Keywords {
		if bytes.Contains(lower, []byte(k)) {
			return true
		}
	}
	return false
}
