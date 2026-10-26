# Sources

Everything keydrift claims about file paths, key formats, incidents and rotation pages comes from the sources below. They were read on October 26, 2026. Where a fact could not be confirmed from a primary source, it is listed under "Not verified" at the end.

## Key patterns

- Betterleaks default config, `config/betterleaks.toml` at commit [d778712](https://github.com/betterleaks/betterleaks/blob/d778712d3d0fc5da7dd44fc751258f3527f808cc/config/betterleaks.toml) (October 26, 2026). MIT License, Copyright (c) 2026 Zachary Rice. The rules in `internal/kd/rules.go` marked "betterleaks" are copied from it with a leading `(?m)` added. The license is kept in `third_party/betterleaks/LICENSE`. Betterleaks has rules for Anthropic, OpenAI, Google, Groq, xAI, OpenRouter, Hugging Face, Mistral, DeepSeek, Together AI, GitHub, AWS, Stripe, npm and PyPI. It has no Fireworks rule, so Fireworks keys are found by variable name only.
- Gitleaks, [config/gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml) at commit 5f6ec56 (MIT, Copyright (c) 2019 Zachary Rice), was compared and has fewer AI provider rules, so Betterleaks was used.
- The keyword lists in `rules.go` follow the same idea as the `keywords` field in both configs: a rule only runs on text that contains one of its words.

## Where keys end up

- MEDUSA, [docs/SECRETS_SCANNER.md](https://github.com/Pantheon-Security/medusa/blob/5f217edf8b09b960a32311982754dd2717a70c9b/docs/SECRETS_SCANNER.md) and [medusa/core/chat_history_discovery.py](https://github.com/Pantheon-Security/medusa/blob/5f217edf8b09b960a32311982754dd2717a70c9b/medusa/core/chat_history_discovery.py), commit 5f217ed. MEDUSA is AGPL-3.0, so no code was copied. keydrift uses its list of agent and shell history paths as a starting point: Claude Code, Claude Desktop, Cursor, Zed, VS Code Copilot, Gemini, Aider, Codex, and the shell and REPL histories.
- Claude Code: [sessions](https://code.claude.com/docs/en/sessions) and [the .claude directory](https://code.claude.com/docs/en/claude-directory) say transcripts are saved under `~/.claude/projects/` as JSONL and cleaned up after `cleanupPeriodDays` (30 by default). [Authentication](https://code.claude.com/docs/en/authentication) says Linux credentials are in `~/.claude/.credentials.json` with mode 0600.
- Codex: the [config reference](https://developers.openai.com/codex/config-reference) documents `history.persistence` writing `history.jsonl` and the file credential store at `CODEX_HOME/auth.json`. The session path `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` is from the Codex source, `codex-rs/rollout/src/recorder.rs`.
- Gemini CLI: [session management](https://geminicli.com/docs/cli/session-management/) says chats are saved under `~/.gemini/tmp/<project_hash>/chats/`.
- Aider: [options](https://aider.chat/docs/config/options.html) gives the defaults `.aider.chat.history.md` and `.aider.input.history`, relative to where Aider runs. That is why keydrift looks for them in home and in every walked folder.
- OpenCode: [providers](https://opencode.ai/docs/providers/) says keys added with `/connect` are stored in `~/.local/share/opencode/auth.json`.
- OVHcloud advisory [GHSA-862f-55f5-vmvw](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw) (published October 20, 2026) lists the files the malware collected: VS Code and Cursor `state.vscdb`, the Continue and Sourcegraph Cody databases, the OpenCode databases, `~/.hermes/sessions` and `~/.hermes/.hermes_history`, `~/.claude`, AWS, gcloud and Azure files, Docker configs, `~/.kube/config`, `~/.ssh`, `~/.netrc`, doctl and Terraform credentials, and `~/.gitconfig`. keydrift reads or lists all of them.
- Railway CLI, [src/config.rs](https://github.com/railwayapp/cli/blob/b62467ef1b5303e3e340283ed96425dcf9612993/src/config.rs), commit b62467e: the CLI keeps its login and a `projects` map keyed by local folder in `~/.railway/config.json`, and reads `RAILWAY_TOKEN` and `RAILWAY_API_TOKEN`. Railway's [config as code](https://docs.railway.com/reference/config-as-code) docs name `railway.toml` and `railway.json`.
- Zeabur CLI, [pkg/config/init.go](https://github.com/zeabur/cli/blob/c32c927c5cb0ed019f99b0e501eac0daf83c1d29/pkg/config/init.go), commit c32c927: the CLI config is `~/.config/zeabur/cli.yaml` with a `token` key. zbpack, [pkg/plan/config.go](https://github.com/zeabur/zbpack/blob/21d54e3d8b909ba17de17be90948ba2abfa89192/pkg/plan/config.go), commit 21d54e3: project config is `zbpack.json` or `zbpack.<service>.json`.

## Incidents

- LiteLLM 1.107.0: [LiteLLM incident post](https://docs.litellm.ai/blog/security-incident-oct-21-2026), [OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144), [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/).
- ovhcloud-cli: [GHSA-862f-55f5-vmvw](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw), which gives the five MD5 sums, the temp folder `envchecker-` followed by 9 or 10 digits that the stealer never deletes, and the path list.
- Railway: [security disclosure](https://blog.railway.com/p/security-disclosure-wednesday-october-21st), [preliminary report](https://blog.railway.com/p/preliminary-report-october-security-incident), [PostgreSQL credential advice](https://blog.railway.com/p/security-disclosure-recommendation-rotate-postgresql-database-credentials).
- Zeabur: [October 2026 security incident](https://zeabur.com/blogs/october-2026-security-incident).
- OpenCode: [statement on X](https://x.com/i/status/2111519637049319818), October 17, 2026.

## Rotation pages

Each provider's page for revoking keys, checked on October 26, 2026. Pages behind a login redirect to it, and two return 403 to scripts; those were taken from the provider's own docs.

| provider | rotate page | howtorotate.com guide |
| --- | --- | --- |
| OpenAI | https://platform.openai.com/api-keys (403 to scripts) | [openai](https://howtorotate.com/docs/tutorials/openai/) |
| Anthropic | https://platform.claude.com/settings/keys | none |
| Google | https://aistudio.google.com/app/apikey, [API key docs](https://cloud.google.com/docs/authentication/api-keys) | [gcp](https://howtorotate.com/docs/tutorials/gcp/) |
| Groq | https://console.groq.com/keys | [groq](https://howtorotate.com/docs/tutorials/groq/) |
| xAI | https://console.x.ai/team/default/api-keys, linked from the [xAI quickstart](https://docs.x.ai/docs/tutorial) | none |
| OpenRouter | https://openrouter.ai/settings/keys | none |
| Hugging Face | https://huggingface.co/settings/tokens, linked from [User access tokens](https://huggingface.co/docs/hub/security-tokens) | none |
| Mistral | https://console.mistral.ai/api-keys | none |
| DeepSeek | https://platform.deepseek.com/api_keys (403 to scripts), linked from the [DeepSeek API docs](https://api-docs.deepseek.com/) | none |
| Together AI | https://api.together.ai/settings/api-keys | none |
| Fireworks AI | https://app.fireworks.ai/settings/users/api-keys, linked from the [Fireworks quickstart](https://docs.fireworks.ai/getting-started/quickstart) | none |
| GitHub | https://github.com/settings/tokens | [github](https://howtorotate.com/docs/tutorials/github/) |
| AWS | [Manage access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) | [aws](https://howtorotate.com/docs/tutorials/aws/) |
| Stripe | [API keys](https://docs.stripe.com/keys) | [stripe](https://howtorotate.com/docs/tutorials/stripe/) |
| npm | [Revoking access tokens](https://docs.npmjs.com/revoking-access-tokens) | [npm](https://howtorotate.com/docs/tutorials/npm/) |
| PyPI | https://pypi.org/manage/account/token/ | none |
| Docker | [Access tokens](https://docs.docker.com/security/access-tokens/) | none |
| gcloud CLI login | [gcloud auth revoke](https://cloud.google.com/sdk/gcloud/reference/auth/revoke) | none |

howtorotate.com returned 404 for Anthropic, Hugging Face, xAI, OpenRouter, Mistral, DeepSeek, Together AI, Fireworks, PyPI and Docker, so no guide is linked for them.

## HasMySecretLeaked

- Protocol: GitGuardian, [HasMySecretLeaked: building a trustless and secure protocol](https://blog.gitguardian.com/hasmysecretleaked-building-a-trustless-and-secure-protocol/). It describes hashing the secret, sending a short prefix of the hash, and getting back encrypted matches.
- The exact parameters (the pepper, the scrypt settings and the payload encryption) appear only in ggshield's code, [ggshield/verticals/hmsl/crypto.py](https://github.com/GitGuardian/ggshield/blob/ccbd1a2d5cf5eea4c69c120a17357aaefbeeff29/ggshield/verticals/hmsl/crypto.py), commit ccbd1a2.
- Terms: GitGuardian [terms of service](https://www.gitguardian.com/legal/terms-of-service), last updated October 20, 2025, forbid making the Services available to any third party and copying "any feature or function of the Services", and give no permission for other clients.
- So keydrift has no `--hmsl` option.

## Not verified

- Cursor's own docs say nothing about where it stores chats. The Cursor paths come from MEDUSA and the OVHcloud advisory only.
- VS Code Copilot `chatSessions` and Claude Desktop paths come from MEDUSA only.
- The Zed conversations folder and the REPL history file names come from MEDUSA only.
- The Codex session path is from the Codex source, not its docs.
- `.npmrc` is on the OVHcloud list only as "NPM configuration", with no path. keydrift assumes `~/.npmrc`.
