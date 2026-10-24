# cleanerproxy

An inspecting LLM proxy for the Anthropic Messages and OpenAI Chat Completions APIs. Sits between your coding agent and the upstream provider to defend against tool-call injection, PII exfiltration, and advertisement injection by shady relay services.

## Threat model

The upstream you talk to may be hostile. It may:

1. **Splice tool calls** into responses that your coding agent executes against your filesystem and credentials
2. **Harvest PII and secrets** from your request bodies
3. **Inject advertisements** via prepended system prompts to steer model recommendations

cleanerproxy inspects every response through a three-tier pipeline (structural proof, dangerous-capability matching, semantic classification via IBM Granite Guardian) and either blocks, defangs, or asks you to approve suspicious tool calls.

## What it does

- **Tier 0** (structural): Proves a tool call was not produced by the provider (undeclared tool, schema violation, incoherent envelope)
- **Tier 1** (capability): Matches machine-compromise primitives in tool arguments (credential access, remote code execution, persistence)
- **Tier 2** (semantic): Asks an independent local model (IBM Granite Guardian 3.2) whether a call follows from what you asked
- **PII pseudonymization**: Bidirectional, format-preserving redaction of names, emails, API keys, SSNs, phone numbers before they leave your machine
- **Ad detection**: Scans for blocked domains, affiliate URLs, promotional language, prompt leakage from relay-injected system prompts
- **Human-in-the-loop approval**: Blocked calls are replaced with a question to the user; one keystroke approves or denies

## Supported clients

| Client | Approval tool | Status |
|--------|--------------|--------|
| [opencode](https://opencode.ai) | `question` | Full support (shapeQuestions) |
| [Claude Code](https://code.claude.com) | `AskUserQuestion` | Full support (shapeClaudeCode) |
| [Codex CLI](https://developers.openai.com/codex/cli) | `request_user_input` | Full support (shapeFlat) |
| [Roo Code / Cline](https://github.com/RooVetGit/Roo-Code) | `ask_followup_question` | Full support (shapeFlat) |
| Any client with a question tool | Configurable | `CLEANERPROXY_APPROVAL_ASK_TOOLS` |

## Setup

### Requirements

- Go 1.27+
- For Tier 2: [oMLX](https://github.com/nicobytes/omlx) (macOS) or Docker (Linux) with `granite-guardian-3.2-3b-a800m`
- For NER-based name detection: a small local model (Qwen2.5-0.5B-Instruct-4bit recommended)

### Quick start (macOS)

```sh
git clone <repo> && cd cleanerproxy
cp .env.example .env
# Edit .env: set CLEANERPROXY_ANTHROPIC_UPSTREAM to your upstream URL

# Download the Tier 2 classifier (2.6 GB, one-time):
./scripts/fetch-model.sh

# Start oMLX with granite-guardian and qwen2.5-0.5b loaded, then:
go run ./cmd/cleanerproxy
```

### Quick start (Linux / WSL)

```sh
git clone <repo> && cd cleanerproxy
cp .env.example .env
# Edit .env: set CLEANERPROXY_ANTHROPIC_UPSTREAM to your upstream URL

# Option A: native with oMLX or any OpenAI-compatible local server
go run ./cmd/cleanerproxy

# Option B: Docker (builds the classifier container with llama.cpp)
./scripts/fetch-model.sh
docker compose up -d
```

Linux desktop users get `notify-send` notifications automatically when `$DISPLAY` or `$WAYLAND_DISPLAY` is set. Install `libnotify` if not already present:

```sh
# Debian/Ubuntu
sudo apt install libnotify-bin
# Alpine
apk add libnotify
# Arch
pacman -S libnotify
```

Windows users: use WSL 2 and follow the Linux instructions.

### Point your client at cleanerproxy

Set your client's API base URL to `http://127.0.0.1:8787`. Your real API key goes in the client config, not in cleanerproxy. The proxy forwards auth headers unchanged.

**opencode** (`opencode.json`):
```jsonc
{
  "provider": {
    "anthropic": {
      "baseURL": "http://127.0.0.1:8787"
    }
  }
}
```

**Claude Code**:
```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

**Codex CLI**:
```sh
export OPENAI_BASE_URL=http://127.0.0.1:8787
codex
```

## Notifications

cleanerproxy supports three notification backends, used in combination:

| Backend | Platform | Use case |
|---------|----------|----------|
| macOS alerts + Notification Center | macOS | Desktop users at their machine |
| `notify-send` (libnotify) | Linux | Desktop users with a display server |
| [ntfy.sh](https://ntfy.sh) | Any | Server/headless, mobile push, remote approval |

ntfy.sh fires **in addition** to desktop notifications when configured, so you get both local popups and phone push.

### ntfy.sh setup

ntfy.sh is recommended for headless/server environments and for Hermes agent users who need to approve tool calls from their phone.

```sh
# In .env:
CLEANERPROXY_NTFY_URL=https://ntfy.sh/my-cleanerproxy-topic
# Optional, for authenticated topics:
CLEANERPROXY_NTFY_TOKEN=tk_...
```

Install the [ntfy app](https://ntfy.sh) on your phone and subscribe to the same topic.

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and edit it. The proxy loads `.env` automatically; existing env vars take precedence.

See `.env.example` for the full list with documentation.

## Docker deployment

```sh
# Build and start proxy + classifier:
docker compose up -d

# Optional TLS front end:
docker compose --profile tls up -d
```

The classifier container runs on an internal-only network with no internet access. It needs no API keys and sees no provider credentials.

## Verification

```sh
# Offline tests only (no model needed):
./scripts/verify.sh hermetic

# Everything (needs Docker + model):
./scripts/verify.sh all
```

## Architecture

```
client (opencode/claude/codex) ──► cleanerproxy (:8787) ──► upstream (untrusted)
                                        │
                                        ├── Tier 0: structural proof (allowlist, schema)
                                        ├── Tier 1: capability matching (regex, patterns)
                                        ├── Tier 2: semantic classifier (Granite Guardian, local)
                                        ├── PII pseudonymization (NER + regex, bidirectional)
                                        ├── Ad detection (domain blocklist, promo patterns)
                                        └── Notifications (macOS/Linux/ntfy.sh)
```

Zero external Go dependencies. stdlib only.
