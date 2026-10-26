# keydrift

keydrift answers one question after a supply chain or platform incident: which of my keys did it touch?

It reads the places where API keys end up on a developer machine, lists every key it finds without ever showing the value, and turns that into a rotation list with the most urgent key first and a link to the page where you revoke it. It also knows a few recent incidents and can tell you whether this machine shows signs of each one, and which keys that puts at risk.

keydrift only reads files. It does not run any program it finds, it does not call any provider, and it sends nothing over the network.

## What it reads

- **AI agent logs and state.** Claude Code transcripts and history, Codex sessions and history, Gemini CLI chats, Aider chat and input history, Cursor and VS Code chat state, Claude Desktop, Zed conversations, the Continue and Sourcegraph Cody extensions, OpenCode and Hermes. People paste keys into agent chats, and agents echo environment variables into their logs. Several recent stealers went after exactly these files.
- **Shell histories.** bash, zsh and fish, and the Python, Node, psql, MySQL, irb, redis-cli and sqlite histories.
- **Env files** (`.env`, `.env.*`, `*.env`, `.envrc`, `.dev.vars`) under your home folder, or under the folders you give with `--root`.
- **Tool configs.** `~/.docker/config.json`, `~/.aws/credentials` and `config`, gcloud application default credentials, the GitHub CLI `hosts.yml`, `.npmrc`, `.pypirc`, `.netrc` and `.git-credentials`.
- **CI files** (`.github/workflows/*.yml` and `.gitlab-ci.yml`). Only the names of the secrets they use are read, so you know what to update after you rotate.
- **Credential files it cannot look inside**, such as SSH private keys, the gcloud credential databases, the kube config, the Claude Code and Codex login files, and the Railway and Zeabur CLI logins. These are listed with what to do about them.

The full list of paths, and where each one comes from, is in [docs/sources.md](docs/sources.md).

## What it looks for

AI providers first: OpenAI, Anthropic, Google (Gemini and other Google API keys), Groq, xAI, OpenRouter, Hugging Face, Mistral, DeepSeek, Together AI and Fireworks AI. Then GitHub, AWS, Stripe, npm and PyPI, plus Docker registry logins and gcloud refresh tokens.

Most patterns are copied from the default rules of [Betterleaks](https://github.com/betterleaks/betterleaks), the successor to Gitleaks by the same author, with its MIT license notice kept in `third_party/betterleaks/LICENSE`. Keys with no fixed shape, such as Fireworks keys or AWS secret keys, are found by the variable name next to them (`FIREWORKS_API_KEY=...`). The report marks those as "guessed from the variable name".

## How values stay private

- keydrift never prints or stores a value. You see the provider, a short known prefix such as `sk-ant-api03-` (or the first two characters when there is no known prefix), the length, and a fingerprint.
- The fingerprint is HMAC-SHA256 of the value with a random 32 byte salt, cut to 16 hex characters. The salt is created on first run at `$XDG_STATE_HOME/keydrift/salt` (or `~/.local/state/keydrift/salt`) with mode 0600 in a 0700 folder. keydrift refuses to run if the salt file can be read by anyone else. Without the salt, the fingerprint cannot be used to test guesses of the key.
- The same key in two places shows up once, with both places listed.
- Snapshots hold fingerprints, masked prefixes and paths. They are written with mode 0600.

## Install

```sh
git clone https://github.com/sudodrift/keydrift
cd keydrift
make build        # static binary at bin/keydrift, needs Go 1.27
make check        # gofmt, go vet, tests
```

keydrift runs on Linux and macOS. It is not built for Windows, because it relies on Unix file modes to keep the salt private.

## Usage

```
keydrift scan                   list keys, credential files and CI secret names, plus a rotation list
keydrift snapshot -o FILE       save the scan as JSON (fingerprints only)
keydrift diff OLD [NEW]         compare two snapshots, or a snapshot with a fresh scan
keydrift match INCIDENT|all     check the machine against an incident in the catalog
keydrift match list             list the incidents in the catalog
keydrift version
```

Flags for every command: `--json`, `--home DIR`, `--root DIR` (repeatable; folders to walk for env and CI files, default your home folder), `--state DIR` (where the salt lives). `match` also takes `--catalog DIR` to read incident files from a folder instead of the built-in ones.

Exit codes: 0 when nothing was found, 1 when something was found (keys for `scan`, a new key or a key in a new place for `diff`, evidence of the incident for `match`), 2 on an error.

### The rotation list

Items are ordered like this:

1. keys exposed by the incident you matched
2. keys copied into an AI agent log or shell history, the first place stealers look
3. keys and credential files that reach code, packages, cloud accounts or payments (GitHub, npm, PyPI, AWS, Docker, gcloud, Stripe, SSH)
4. other AI provider keys, which cost money when stolen
5. anything else

Within a group, a key found in more places comes first. Each item links the provider's own page for revoking keys and, where [howtorotate.com](https://howtorotate.com) has a guide for that provider, the guide as well.

Revoke at the provider first. Deleting the file or the line does not stop a key that was already copied.

### snapshot and diff

`snapshot` and `diff` work like the other sudodrift tools: take a snapshot when the machine is in a known state, then compare later. `diff` reports four things:

- `NEW KEY`: a fingerprint that was not there before
- `KEY IN A NEW PLACE`: a known key showed up in another file, for example pasted into an agent chat
- `KEY GONE FROM A PLACE` and `KEY GONE`: for your records; these do not change the exit code

Fingerprints only match when both snapshots were made with the same salt, so `diff` refuses to compare snapshots from different salts.

### Incidents

The catalog is a folder of YAML files in [incidents/](incidents/). Each file lists its sources, the evidence to look for and what counts as exposed. It ships with:

| id | what keydrift checks | what counts as exposed |
| --- | --- | --- |
| `litellm-1.107.0` | `litellm-1.107.0.dist-info`, `.egg-info` or conda metadata in your home folder and the usual system Python folders | every key on the machine |
| `ovhcloud-cli-2026-10` | an `ovhcloud` binary whose MD5 is one of the five in the advisory, `envchecker-<digits>` folders in the temp folder | keys and credential files at the paths the advisory lists |
| `railway-2026-10` | `~/.railway/config.json`, the project folders it links, `railway.json` or `railway.toml`, `RAILWAY_TOKEN` in env or CI files | keys in those project folders |
| `zeabur-2026-10` | `~/.config/zeabur/cli.yaml`, `zbpack.json` and `zbpack.*.json` | keys in those project folders |
| `opencode-2026-10` | OpenCode's `auth.json` and `opencode.db` | AI provider keys, and only if OpenCode emailed you |

For Railway and Zeabur the breach was on the platform, so keydrift can only see the copies of your variables that also sit on this machine. Treat every variable you stored on the platform as exposed, whether or not keydrift finds a copy.

To check for an MD5, keydrift reads the file and hashes it. It never runs it.

### Why there is no `--hmsl`

GitGuardian's HasMySecretLeaked checks whether a secret appears in public leaks without sending the secret itself, and adding it was considered. It is left out for two reasons. The protocol is described in a [GitGuardian blog post](https://blog.gitguardian.com/hasmysecretleaked-building-a-trustless-and-secure-protocol/), but the exact hashing parameters are only in the code of GitGuardian's own client, ggshield. And GitGuardian's [terms of service](https://www.gitguardian.com/legal/terms-of-service) give no permission for third party clients while forbidding copying "any feature or function of the Services". If you want that check, use ggshield (`ggshield hmsl check`) directly.

## Demo

This demo runs against a fake home folder. Every key in it was made up by `internal/fakehome` and works nowhere. The output below is pasted from a real run of the static binary built with `make build VERSION=0.1.0`, with `HOME` pointing at the fake home.

```sh
go run ./internal/fakehome/mkfakehome /tmp/keydrift-demo/home
export HOME=/tmp/keydrift-demo/home
cd ~
```

```
$ keydrift scan
keydrift 0.1.0
home: /tmp/keydrift-demo/home   walked: ~   files read: 17

Keys (20). Values are never shown; fp is an HMAC with your local salt.
  Anthropic  sk-ant-api03-... (108 chars)  fp bc52ab9a1bd361a6  [anthropic-api-key]
      ~/.local/share/opencode/auth.json:1 (OpenCode provider keys)
      ~/.bash_history:3 (bash history)
  AWS  FA... (40 chars)  fp 2e34d655cdbb13b0  [name-aws-secret, guessed from the variable name]
      ~/.aws/credentials:3 (AWS credentials)
  AWS  AKIA... (20 chars)  fp 33844031973b8309  [aws-access-token]
      ~/.aws/credentials:2 (AWS credentials)
  DeepSeek  sk-... (35 chars)  fp 0bf2aeeedd9cde1d  [deepseek-api-key]
      ~/code/shop/.env:5 (env file)
  Docker registry login  Zm... (24 chars)  fp 504a7c68129d4cb8  [docker-auth]
      ~/.docker/config.json:1 (Docker config (registry.example.invalid))
  Fireworks AI  fw... (27 chars)  fp b81fb9502633e042  [name-fireworks, guessed from the variable name]
      ~/code/shop/.env:6 (env file)
  Google Cloud CLI login  1/... (63 chars)  fp 08d41241827b70d0  [gcloud-refresh-token]
      ~/.config/gcloud/application_default_credentials.json:1 (gcloud application default credentials)
  GitHub  ghp_... (40 chars)  fp 9ee8c746bddc7fb9  [github-pat]
      ~/.codex/sessions/2026/10/20/rollout-2026-10-20T10-00-00.jsonl:1 (Codex session)
  GitHub  gho_... (40 chars)  fp cb8a2c57eeed71d2  [github-oauth]
      ~/.config/gh/hosts.yml:3 (GitHub CLI login)
  Google (Gemini, GCP API keys)  AIza... (39 chars)  fp d397154df6403455  [gcp-api-key]
      ~/code/blog/.env.production:1 (env file)
  Groq  gsk_... (56 chars)  fp 688841a9a729caf6  [groq-api-key]
      ~/.claude/projects/-home-dev-code-shop/5f1c.jsonl:1 (Claude Code transcript)
  Hugging Face  hf_... (37 chars)  fp 29926b66d890be53  [huggingface-access-token]
      ~/.gemini/tmp/7d1e/chats/session-2026-10-21.json:1 (Gemini CLI session)
  Mistral  FA... (32 chars)  fp a23052bf290149d3  [mistral-api-key]
      ~/code/shop/.env:4 (env file)
  npm  npm_... (40 chars)  fp bd3221d70eab1565  [npm-access-token]
      ~/.npmrc:1 (npm config)
  OpenAI  sk-... (164 chars)  fp 289a330e244b4823  [openai-api-key]
      ~/.bash_history:2 (bash history)
      ~/code/shop/.env:1 (env file)
  OpenRouter  sk-or-v1-... (73 chars)  fp 4e04dab14b3daac1  [openrouter-api-key]
      ~/.aider.chat.history.md:1 (Aider chat history)
  PyPI  pypi-... (80 chars)  fp 9316739a8ed84640  [pypi-upload-token]
      ~/.pypirc:3 (PyPI config)
  Stripe  sk_live_... (32 chars)  fp 00b5cdac0521a6e6  [stripe-access-token]
      ~/code/shop/.env:2 (env file)
  Together AI  tgp_v1_... (50 chars)  fp 18067cf935588b38  [togetherai-api-key]
      ~/code/shop/.env:7 (env file)
  xAI  xai-... (84 chars)  fp 1902c01dcebbc3ca  [xai-api-key]
      ~/code/shop/.env:3 (env file)

Credential files (3)
  ~/.ssh/id_ed25519  SSH private key
  ~/.config/gcloud/credentials.db  gcloud credential database
  ~/.railway/config.json  Railway CLI login

Secret names used by CI (3). Names only; update these after you rotate.
  DEPLOY_TOKEN  ~/code/blog/.gitlab-ci.yml:3
  OPENAI_API_KEY  ~/code/shop/.github/workflows/deploy.yml:6
  STRIPE_SECRET_KEY  ~/code/shop/.github/workflows/deploy.yml:7

Rotation list, most urgent first (23)
   1. Anthropic  sk-ant-api03-... (108 chars)  fp bc52ab9a1bd361a6
      why: copied into an agent log or shell history
      rotate: https://platform.claude.com/settings/keys
   2. OpenAI  sk-... (164 chars)  fp 289a330e244b4823
      why: copied into an agent log or shell history
      rotate: https://platform.openai.com/api-keys
      guide:  https://howtorotate.com/docs/tutorials/openai/
   3. GitHub  ghp_... (40 chars)  fp 9ee8c746bddc7fb9
      why: copied into an agent log or shell history
      rotate: https://github.com/settings/tokens
      guide:  https://howtorotate.com/docs/tutorials/github/
   4. Groq  gsk_... (56 chars)  fp 688841a9a729caf6
      why: copied into an agent log or shell history
      rotate: https://console.groq.com/keys
      guide:  https://howtorotate.com/docs/tutorials/groq/
   5. Hugging Face  hf_... (37 chars)  fp 29926b66d890be53
      why: copied into an agent log or shell history
      rotate: https://huggingface.co/settings/tokens
   6. OpenRouter  sk-or-v1-... (73 chars)  fp 4e04dab14b3daac1
      why: copied into an agent log or shell history
      rotate: https://openrouter.ai/settings/keys
   7. AWS  FA... (40 chars)  fp 2e34d655cdbb13b0
      why: reaches code, packages, cloud or payments
      rotate: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
      guide:  https://howtorotate.com/docs/tutorials/aws/
   8. AWS  AKIA... (20 chars)  fp 33844031973b8309
      why: reaches code, packages, cloud or payments
      rotate: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
      guide:  https://howtorotate.com/docs/tutorials/aws/
   9. Docker registry login  Zm... (24 chars)  fp 504a7c68129d4cb8
      why: reaches code, packages, cloud or payments
      rotate: https://docs.docker.com/security/access-tokens/
  10. GitHub  gho_... (40 chars)  fp cb8a2c57eeed71d2
      why: reaches code, packages, cloud or payments
      rotate: https://github.com/settings/tokens
      guide:  https://howtorotate.com/docs/tutorials/github/
  11. Google Cloud CLI login  1/... (63 chars)  fp 08d41241827b70d0
      why: reaches code, packages, cloud or payments
      rotate: https://cloud.google.com/sdk/gcloud/reference/auth/revoke
  12. PyPI  pypi-... (80 chars)  fp 9316739a8ed84640
      why: reaches code, packages, cloud or payments
      rotate: https://pypi.org/manage/account/token/
  13. Stripe  sk_live_... (32 chars)  fp 00b5cdac0521a6e6
      why: reaches code, packages, cloud or payments
      rotate: https://docs.stripe.com/keys
      guide:  https://howtorotate.com/docs/tutorials/stripe/
  14. npm  npm_... (40 chars)  fp bd3221d70eab1565
      why: reaches code, packages, cloud or payments
      rotate: https://docs.npmjs.com/revoking-access-tokens
      guide:  https://howtorotate.com/docs/tutorials/npm/
  15. Railway CLI login  ~/.railway/config.json
      why: credential file
      do: log out of the Railway CLI and log in again
  16. SSH private key  ~/.ssh/id_ed25519
      why: credential file
      do: make a new key pair and remove the old public key from every server and from GitHub or GitLab
  17. gcloud credential database  ~/.config/gcloud/credentials.db
      why: credential file
      do: run gcloud auth revoke, then log in again
      rotate: https://cloud.google.com/sdk/gcloud/reference/auth/revoke
  18. DeepSeek  sk-... (35 chars)  fp 0bf2aeeedd9cde1d
      why: AI provider key
      rotate: https://platform.deepseek.com/api_keys
  19. Fireworks AI  fw... (27 chars)  fp b81fb9502633e042
      why: AI provider key
      rotate: https://app.fireworks.ai/settings/users/api-keys
  20. Google (Gemini, GCP API keys)  AIza... (39 chars)  fp d397154df6403455
      why: AI provider key
      rotate: https://aistudio.google.com/app/apikey
      guide:  https://howtorotate.com/docs/tutorials/gcp/
  21. Mistral  FA... (32 chars)  fp a23052bf290149d3
      why: AI provider key
      rotate: https://console.mistral.ai/api-keys
  22. Together AI  tgp_v1_... (50 chars)  fp 18067cf935588b38
      why: AI provider key
      rotate: https://api.together.ai/settings/api-keys
  23. xAI  xai-... (84 chars)  fp 1902c01dcebbc3ca
      why: AI provider key
      rotate: https://console.x.ai/team/default/api-keys
exit=1
```

```
$ keydrift scan --json | head -32
{
  "tool": "keydrift",
  "version": "0.1.0",
  "home": "/tmp/keydrift-demo/home",
  "roots": [
    "/tmp/keydrift-demo/home"
  ],
  "files_scanned": 17,
  "keys": [
    {
      "fingerprint": "bc52ab9a1bd361a6",
      "provider": "anthropic",
      "rule": "anthropic-api-key",
      "rule_origin": "betterleaks",
      "masked": "sk-ant-api03-... (108 chars)",
      "length": 108,
      "locations": [
        {
          "path": "/tmp/keydrift-demo/home/.local/share/opencode/auth.json",
          "line": 1,
          "source": "OpenCode provider keys",
          "category": "tool-config"
        },
        {
          "path": "/tmp/keydrift-demo/home/.bash_history",
          "line": 3,
          "source": "bash history",
          "category": "shell-history"
        }
      ]
    },
    {
...
```

Take a snapshot:

```
$ keydrift snapshot -o ~/keys-base.json
wrote /tmp/keydrift-demo/home/keys-base.json: 20 keys
exit=0
```

Then paste a new (fake) Groq key into the shell history, copy the Anthropic key into another project, and delete `.pypirc`:

```sh
printf ': 1761500000:0;export GROQ_API_KEY=gsk_%.52s\n' "$(printf 'NotARealKeyJustForTheDemo%.0s' 1 2 3)" >> ~/.zsh_history
grep -o 'sk-ant-api03-[A-Za-z0-9_-]*' ~/.bash_history | sed 's/^/ANTHROPIC_API_KEY=/' > ~/code/blog/.env
rm ~/.pypirc
```

```
$ keydrift diff ~/keys-base.json
keydrift diff /tmp/keydrift-demo/home/keys-base.json -> now

NEW KEY  Groq  gsk_... (56 chars)  fp 3b28315cacfd4c34
    ~/.zsh_history (zsh history)
KEY IN A NEW PLACE  Anthropic  sk-ant-api03-... (108 chars)  fp bc52ab9a1bd361a6
    ~/code/blog/.env (env file)
KEY GONE  PyPI  pypi-... (80 chars)  fp 9316739a8ed84640
    ~/.pypirc (PyPI config)
exit=1
```

```
$ keydrift match list
litellm-1.107.0        2026-10-21  LiteLLM 1.107.0 on PyPI carried a credential stealer
opencode-2026-10       2026-10-16  OpenCode Console breach of linked AI provider keys
ovhcloud-cli-2026-10   2026-10-19  Swapped ovhcloud-cli release binaries stole local credentials
railway-2026-10        2026-10-21  Railway environment variables decrypted by an attacker
zeabur-2026-10         2026-10-14  Zeabur environment variables read from the platform database
exit=0
```

```
$ keydrift match railway-2026-10
railway-2026-10: Railway environment variables decrypted by an attacker (2026-10-21)
  source: Railway security disclosure https://blog.railway.com/p/security-disclosure-wednesday-october-21st
  source: Railway preliminary report https://blog.railway.com/p/preliminary-report-october-security-incident
  source: Railway advice on rotating PostgreSQL credentials https://blog.railway.com/p/security-disclosure-recommendation-rotate-postgresql-database-credentials

Evidence (3)
  file present: ~/.railway/config.json
  folder linked in ~/.railway/config.json: ~/code/shop
  project config railway.json: ~/code/shop/railway.json

What counts as exposed (project-folders)
  keydrift sees only local copies. Every variable you set in Railway's dashboard counts as exposed, whether or not a copy sits on this machine.

Rotation list, most urgent first (7)
   1. OpenAI  sk-... (164 chars)  fp 289a330e244b4823
      why: exposed by railway-2026-10; also in an agent log or shell history
      rotate: https://platform.openai.com/api-keys
      guide:  https://howtorotate.com/docs/tutorials/openai/
   2. Stripe  sk_live_... (32 chars)  fp 00b5cdac0521a6e6
      why: exposed by railway-2026-10
      rotate: https://docs.stripe.com/keys
      guide:  https://howtorotate.com/docs/tutorials/stripe/
   3. DeepSeek  sk-... (35 chars)  fp 0bf2aeeedd9cde1d
      why: exposed by railway-2026-10
      rotate: https://platform.deepseek.com/api_keys
   4. Fireworks AI  fw... (27 chars)  fp b81fb9502633e042
      why: exposed by railway-2026-10
      rotate: https://app.fireworks.ai/settings/users/api-keys
   5. Mistral  FA... (32 chars)  fp a23052bf290149d3
      why: exposed by railway-2026-10
      rotate: https://console.mistral.ai/api-keys
   6. Together AI  tgp_v1_... (50 chars)  fp 18067cf935588b38
      why: exposed by railway-2026-10
      rotate: https://api.together.ai/settings/api-keys
   7. xAI  xai-... (84 chars)  fp 1902c01dcebbc3ca
      why: exposed by railway-2026-10
      rotate: https://console.x.ai/team/default/api-keys

Also
  - Revoke each key at its provider first. Changing the variable on Railway does not kill the old key.
  - Set the new value on Railway and redeploy; containers read variables only at startup.
  - For Railway Postgres, use Regenerate instead of ALTER USER.
exit=1
```

The fake home has no `ovhcloud` binary:

```
$ keydrift match ovhcloud-cli-2026-10
ovhcloud-cli-2026-10: Swapped ovhcloud-cli release binaries stole local credentials (2026-10-19)
  source: OVHcloud advisory GHSA-862f-55f5-vmvw https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw

No evidence of this incident on this machine.
exit=0
```

Now add the folder pip leaves behind when it installs LiteLLM 1.107.0:

```sh
mkdir -p ~/code/ml/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info
```

```
$ keydrift match litellm-1.107.0
litellm-1.107.0: LiteLLM 1.107.0 on PyPI carried a credential stealer (2026-10-21)
  source: LiteLLM incident post https://docs.litellm.ai/blog/security-incident-oct-21-2026
  source: OSV MAL-2026-2144 https://osv.dev/vulnerability/MAL-2026-2144
  source: Microsoft Security Blog https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/

Evidence (1)
  installed Python package litellm-1.107.0.dist-info: ~/code/ml/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info

What counts as exposed (all-keys)
  The payload ran with your user's rights on every Python start, so treat every key this machine can read as exposed, not only the ones keydrift lists. That includes keys in the environment of running processes.

Rotation list, most urgent first (23)
   1. Anthropic  sk-ant-api03-... (108 chars)  fp bc52ab9a1bd361a6
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://platform.claude.com/settings/keys
   2. OpenAI  sk-... (164 chars)  fp 289a330e244b4823
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://platform.openai.com/api-keys
      guide:  https://howtorotate.com/docs/tutorials/openai/
   3. GitHub  ghp_... (40 chars)  fp 9ee8c746bddc7fb9
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://github.com/settings/tokens
      guide:  https://howtorotate.com/docs/tutorials/github/
   4. Groq  gsk_... (56 chars)  fp 3b28315cacfd4c34
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://console.groq.com/keys
      guide:  https://howtorotate.com/docs/tutorials/groq/
   5. Groq  gsk_... (56 chars)  fp 688841a9a729caf6
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://console.groq.com/keys
      guide:  https://howtorotate.com/docs/tutorials/groq/
   6. Hugging Face  hf_... (37 chars)  fp 29926b66d890be53
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://huggingface.co/settings/tokens
   7. OpenRouter  sk-or-v1-... (73 chars)  fp 4e04dab14b3daac1
      why: exposed by litellm-1.107.0; also in an agent log or shell history
      rotate: https://openrouter.ai/settings/keys
   8. AWS  FA... (40 chars)  fp 2e34d655cdbb13b0
      why: exposed by litellm-1.107.0
...
```

## Limits

- keydrift finds keys that match a known shape or sit next to a known variable name. A key with no prefix under an unusual name is missed.
- It reads files, not running processes. Keys that live only in the environment of a running program, in a password manager or in the OS keychain are not seen.
- Cursor and VS Code keep chat state in SQLite files. keydrift scans those files as raw bytes, which finds keys stored as plain text but not values the app compresses or encrypts.
- Files over 512 MiB are skipped and listed.
- The incident checks find the evidence the sources describe. A clean result is not proof the machine is clean.

## License

MIT, see [LICENSE](LICENSE). The rules copied from Betterleaks keep their MIT notice in `third_party/betterleaks/LICENSE`.
