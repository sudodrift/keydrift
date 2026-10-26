package kd

// Provider describes where to rotate or revoke one kind of credential.
type Provider struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // ai, code, publish, cloud, payments
	Rotate string `json:"rotate_url"`
	// Guide is a howtorotate.com tutorial when one exists for the provider.
	Guide string `json:"guide_url,omitempty"`
}

// Every URL here was opened on 2026-10-26; see docs/sources.md.
var Providers = map[string]Provider{
	"openai":      {"openai", "OpenAI", "ai", "https://platform.openai.com/api-keys", "https://howtorotate.com/docs/tutorials/openai/"},
	"anthropic":   {"anthropic", "Anthropic", "ai", "https://platform.claude.com/settings/keys", ""},
	"google":      {"google", "Google (Gemini, GCP API keys)", "ai", "https://aistudio.google.com/app/apikey", "https://howtorotate.com/docs/tutorials/gcp/"},
	"groq":        {"groq", "Groq", "ai", "https://console.groq.com/keys", "https://howtorotate.com/docs/tutorials/groq/"},
	"xai":         {"xai", "xAI", "ai", "https://console.x.ai/team/default/api-keys", ""},
	"openrouter":  {"openrouter", "OpenRouter", "ai", "https://openrouter.ai/settings/keys", ""},
	"huggingface": {"huggingface", "Hugging Face", "ai", "https://huggingface.co/settings/tokens", ""},
	"mistral":     {"mistral", "Mistral", "ai", "https://console.mistral.ai/api-keys", ""},
	"deepseek":    {"deepseek", "DeepSeek", "ai", "https://platform.deepseek.com/api_keys", ""},
	"together":    {"together", "Together AI", "ai", "https://api.together.ai/settings/api-keys", ""},
	"fireworks":   {"fireworks", "Fireworks AI", "ai", "https://app.fireworks.ai/settings/users/api-keys", ""},
	"github":      {"github", "GitHub", "code", "https://github.com/settings/tokens", "https://howtorotate.com/docs/tutorials/github/"},
	"aws":         {"aws", "AWS", "cloud", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", "https://howtorotate.com/docs/tutorials/aws/"},
	"stripe":      {"stripe", "Stripe", "payments", "https://docs.stripe.com/keys", "https://howtorotate.com/docs/tutorials/stripe/"},
	"npm":         {"npm", "npm", "publish", "https://docs.npmjs.com/revoking-access-tokens", "https://howtorotate.com/docs/tutorials/npm/"},
	"pypi":        {"pypi", "PyPI", "publish", "https://pypi.org/manage/account/token/", ""},
	"docker":      {"docker", "Docker registry login", "publish", "https://docs.docker.com/security/access-tokens/", ""},
	"gcloud":      {"gcloud", "Google Cloud CLI login", "cloud", "https://cloud.google.com/sdk/gcloud/reference/auth/revoke", ""},
	"unknown":     {"unknown", "Unknown provider", "other", "", ""},
}

func provider(id string) Provider {
	if p, ok := Providers[id]; ok {
		return p
	}
	return Providers["unknown"]
}

// providerByName guesses a provider from a variable name, for CI references.
func providerByName(name string) string {
	n := upper(name)
	for _, m := range []struct{ sub, id string }{
		{"OPENROUTER", "openrouter"}, {"OPENAI", "openai"}, {"ANTHROPIC", "anthropic"}, {"CLAUDE", "anthropic"},
		{"GEMINI", "google"}, {"GOOGLE", "google"}, {"GROQ", "groq"}, {"XAI", "xai"}, {"GROK", "xai"},
		{"HUGGING", "huggingface"}, {"HF_", "huggingface"}, {"MISTRAL", "mistral"}, {"DEEPSEEK", "deepseek"},
		{"TOGETHER", "together"}, {"FIREWORKS", "fireworks"}, {"GITHUB", "github"}, {"GH_", "github"},
		{"AWS", "aws"}, {"STRIPE", "stripe"}, {"NPM", "npm"}, {"PYPI", "pypi"}, {"TWINE", "pypi"},
		{"DOCKER", "docker"},
	} {
		if contains(n, m.sub) {
			return m.id
		}
	}
	return "unknown"
}
