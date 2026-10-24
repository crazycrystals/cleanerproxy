// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	ListenAddr string

	// PassthroughAddr is an optional second listener that runs the full
	// inspection pipeline (Tier 0/1/2, approval, adguard, content-filter,
	// audit) but with pseudonymization DISABLED. Set this when you want to
	// point a client at cleanerproxy without PII redaction — useful when
	// redaction is causing issues. Empty string disables the second listener.
	PassthroughAddr string

	// AnthropicUpstream and OpenAIUpstream are the base URLs this proxy
	// forwards to. In the threat model these are UNTRUSTED: they may be a
	// hostile relay rather than the real provider. That assumption is the
	// entire reason the response-inspection pipeline exists.
	AnthropicUpstream string
	OpenAIUpstream    string

	// PolicyMode: defang | strict | abort-on-proof | abort-all | monitor.
	PolicyMode string

	// Classifier (Tier 2).
	//
	// Backend "guardian" is the default and intended configuration: IBM
	// Granite Guardian, a purpose-trained risk classifier, served locally.
	// Nothing leaves the machine to answer "should this tool call be
	// allowed?".
	//
	// Two inference servers are supported:
	//   - "llama" (default in Docker): llama.cpp with GBNF grammar and
	//     calibrated log-probabilities.
	//   - "omlx": oMLX on macOS, OpenAI-compatible /v1/completions with
	//     hard-label scoring. Preferred for native runs without Docker.
	//
	// Backend "anthropic" prompts a general chat model over the network. It
	// is a fallback for hosts that cannot run local inference, and it leaks
	// tool-call context to a second vendor.
	ClassifierEnabled bool
	ClassifierBackend string
	ClassifierBaseURL string
	ClassifierAPIKey  string
	ClassifierModel   string
	GuardianVariant   string
	GuardianBackend   string // "llama" or "omlx"; only when ClassifierBackend="guardian"
	ClassifyAll       bool
	ClassifyTimeout   time.Duration

	// Tier 2 policy thresholds. Defaults are calibrated against
	// internal/evalset; re-measure with cmd/guardian-eval after changing the
	// model or the variant.
	SemanticBlockConfidence float64
	CorrelateConfidence     float64
	VouchEnabled            bool
	VouchThreshold          float64

	// Audit log.
	AuditPath string
	AuditKey  string // hex-encoded 32-byte key; empty disables encryption

	// Pseudonymization: bidirectional PII/secret redaction. Real values are
	// replaced with format-preserving pseudonyms before the request leaves
	// the machine, and reversed on the response path.
	//
	// ApprovalEnabled turns on human-in-the-loop approval: a blocked call is
	// replaced by a question to the user, asked through a tool the client
	// already declared. Without it, every false positive is terminal, because
	// Tier 1 ignores conversation context and so re-requesting cannot help.
	ApprovalEnabled bool

	// ApprovalChallengeTTL bounds how long the user has to answer a prompt.
	ApprovalChallengeTTL time.Duration

	// ApprovalGrantTTL bounds how long an approval stays usable once given. It
	// only has to cover one model round trip.
	ApprovalGrantTTL time.Duration

	// ApprovalAskTools overrides which client tool names may be used to ask.
	// Empty uses approval.DefaultAskToolNames.
	ApprovalAskTools []string

	PseudonymizeEnabled bool
	PseudonymStatePath  string

	// PseudonymNames is a list of real names to seed the detector with.
	// Without this, only structured patterns (emails, API keys, etc.) are
	// detected. Names require seeding because arbitrary NER is too expensive
	// for inline proxy use.
	PseudonymNames []string

	// PseudonymNEREnabled turns on NER-based name discovery via a local
	// model. When enabled, every request is scanned for person names not
	// in the seed list, so unseen names are caught automatically.
	PseudonymNEREnabled bool

	// PseudonymNERModel is the model ID for NER extraction.
	PseudonymNERModel string

	// PseudonymNERTimeout is the timeout for a single NER call.
	PseudonymNERTimeout time.Duration

	// Desktop notifications: macOS alerts + Notification Center banners,
	// Linux notify-send, and/or ntfy.sh push notifications, with detail
	// files that can be reviewed later.
	NotifyEnabled  bool          // master switch for desktop notifications
	NotifyDir      string        // directory for detail .txt files
	NotifyCooldown time.Duration // min interval between same-category notifications

	// ntfy.sh push notifications: fire alongside desktop notifications, or
	// as the sole notification path on headless/server environments.
	// Recommended for Hermes agent users who need remote approval on mobile.
	NtfyURL   string // full topic URL, e.g. "https://ntfy.sh/my-cleanerproxy"
	NtfyToken string // optional access token for authenticated topics

	// Ad Guard: detect and clean advertisement content injected by shady
	// relay services that prepend adversarial system prompts.
	AdGuardEnabled        bool
	AdGuardBlockedDomains []string // extra domains to block (merged with defaults)

	UpstreamTimeout time.Duration
	MaxRequestBytes int64
}

// Load reads configuration from the environment and applies defaults.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:        env("CLEANERPROXY_LISTEN", ":8787"),
		PassthroughAddr:   env("CLEANERPROXY_PASSTHROUGH_LISTEN", ""),
		AnthropicUpstream: env("CLEANERPROXY_ANTHROPIC_UPSTREAM", "https://api.anthropic.com"),
		OpenAIUpstream:    env("CLEANERPROXY_OPENAI_UPSTREAM", "https://api.openai.com"),
		PolicyMode:        env("CLEANERPROXY_POLICY", "defang"),

		ClassifierEnabled: envBool("CLEANERPROXY_CLASSIFIER_ENABLED", false),
		ClassifierBackend: strings.ToLower(env("CLEANERPROXY_CLASSIFIER_BACKEND", "guardian")),
		ClassifierAPIKey:  os.Getenv("CLEANERPROXY_CLASSIFIER_API_KEY"),
		ClassifierModel:   env("CLEANERPROXY_CLASSIFIER_MODEL", "claude-3-5-haiku-20241022"),
		GuardianVariant:   env("CLEANERPROXY_GUARDIAN_VARIANT", "function_call"),
		GuardianBackend:   strings.ToLower(env("CLEANERPROXY_GUARDIAN_BACKEND", "llama")),
		ClassifyAll:       envBool("CLEANERPROXY_CLASSIFY_ALL", false),

		// 20s, not 8s: Granite Guardian on CPU takes ~2s per call at p50 and
		// needs headroom for a cold prompt cache under concurrent load.
		ClassifyTimeout: envDuration("CLEANERPROXY_CLASSIFY_TIMEOUT", 20*time.Second),

		SemanticBlockConfidence: envFloat("CLEANERPROXY_SEMANTIC_BLOCK_CONFIDENCE", 0.7),
		CorrelateConfidence:     envFloat("CLEANERPROXY_CORRELATE_CONFIDENCE", 0.6),
		VouchEnabled:            envBool("CLEANERPROXY_VOUCH_ENABLED", false),
		VouchThreshold:          envFloat("CLEANERPROXY_VOUCH_THRESHOLD", 0.45),

		AuditPath: env("CLEANERPROXY_AUDIT_PATH", ""),
		AuditKey:  os.Getenv("CLEANERPROXY_AUDIT_KEY"),

		ApprovalEnabled:      envBool("CLEANERPROXY_APPROVAL_ENABLED", true),
		ApprovalChallengeTTL: envDuration("CLEANERPROXY_APPROVAL_CHALLENGE_TTL", 10*time.Minute),
		ApprovalGrantTTL:     envDuration("CLEANERPROXY_APPROVAL_GRANT_TTL", 5*time.Minute),
		ApprovalAskTools:     envList("CLEANERPROXY_APPROVAL_ASK_TOOLS"),

		PseudonymizeEnabled: envBool("CLEANERPROXY_PSEUDONYMIZE", false),
		PseudonymStatePath:  env("CLEANERPROXY_PSEUDONYM_STATE", ""),
		PseudonymNames:      envList("CLEANERPROXY_PSEUDONYM_NAMES"),
		PseudonymNEREnabled: envBool("CLEANERPROXY_PSEUDONYM_NER", false),
		PseudonymNERModel:   env("CLEANERPROXY_PSEUDONYM_NER_MODEL", ""),
		PseudonymNERTimeout: envDuration("CLEANERPROXY_PSEUDONYM_NER_TIMEOUT", 10*time.Second),

		NotifyEnabled:  envBool("CLEANERPROXY_NOTIFY", true),
		NotifyDir:      env("CLEANERPROXY_NOTIFY_DIR", notifyDirDefault()),
		NotifyCooldown: envDuration("CLEANERPROXY_NOTIFY_COOLDOWN", 30*time.Second),

		NtfyURL:   env("CLEANERPROXY_NTFY_URL", ""),
		NtfyToken: os.Getenv("CLEANERPROXY_NTFY_TOKEN"),

		AdGuardEnabled:        envBool("CLEANERPROXY_ADGUARD", false),
		AdGuardBlockedDomains: envList("CLEANERPROXY_ADGUARD_BLOCKED_DOMAINS"),

		UpstreamTimeout: envDuration("CLEANERPROXY_UPSTREAM_TIMEOUT", 10*time.Minute),
		MaxRequestBytes: int64(envInt("CLEANERPROXY_MAX_REQUEST_BYTES", 32<<20)),
	}

	// "off" disables an API surface entirely. Worth supporting explicitly:
	// without it, proxying only Anthropic still leaves /v1/chat/completions as a
	// live forwarder to whatever the OpenAI default happens to be, which is
	// unused attack surface that nothing in the config makes visible.
	if isUpstreamOff(c.AnthropicUpstream) {
		c.AnthropicUpstream = ""
	}
	if isUpstreamOff(c.OpenAIUpstream) {
		c.OpenAIUpstream = ""
	}
	if c.AnthropicUpstream == "" && c.OpenAIUpstream == "" {
		return nil, fmt.Errorf("both upstreams are off; cleanerproxy would serve nothing")
	}

	for name, raw := range map[string]string{
		"CLEANERPROXY_ANTHROPIC_UPSTREAM": c.AnthropicUpstream,
		"CLEANERPROXY_OPENAI_UPSTREAM":    c.OpenAIUpstream,
	} {
		if raw == "" {
			continue // disabled
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("%s: %q is not a valid absolute URL (use \"off\" to disable this API)", name, raw)
		}
	}

	switch c.ClassifierBackend {
	case "guardian":
		switch c.GuardianBackend {
		case "omlx":
			c.ClassifierBaseURL = env("CLEANERPROXY_CLASSIFIER_BASE_URL", "http://127.0.0.1:8001")
		case "llama", "":
			c.ClassifierBaseURL = env("CLEANERPROXY_CLASSIFIER_BASE_URL", "http://guardian:8080")
		default:
			return nil, fmt.Errorf("unknown CLEANERPROXY_GUARDIAN_BACKEND %q (want llama or omlx)", c.GuardianBackend)
		}
	case "anthropic":
		c.ClassifierBaseURL = env("CLEANERPROXY_CLASSIFIER_BASE_URL", "https://api.anthropic.com")
	default:
		return nil, fmt.Errorf("unknown CLEANERPROXY_CLASSIFIER_BACKEND %q (want guardian or anthropic)", c.ClassifierBackend)
	}

	if c.ClassifierEnabled {
		if c.ClassifierBackend == "anthropic" && c.ClassifierAPIKey == "" {
			return nil, fmt.Errorf("CLEANERPROXY_CLASSIFIER_BACKEND=anthropic requires CLEANERPROXY_CLASSIFIER_API_KEY")
		}
		// Refuse to route the classifier through an untrusted *remote*
		// upstream. If the classifier's traffic passes through the same relay
		// we are inspecting, the adversary is being asked to certify its own
		// injected tool calls, and Tier 2 provides exactly zero security.
		//
		// Localhost is exempt: when the upstream is a local model server
		// (e.g. oMLX), the threat is poisoned weights, not a network relay.
		// The classifier is a different model on the same server — different
		// weights, different trust boundary. The sameHost check would reject
		// this legitimate configuration.
		if (c.AnthropicUpstream != "" && sameHost(c.ClassifierBaseURL, c.AnthropicUpstream) && !isLocalhost(c.AnthropicUpstream)) ||
			(c.OpenAIUpstream != "" && sameHost(c.ClassifierBaseURL, c.OpenAIUpstream) && !isLocalhost(c.OpenAIUpstream)) {
			return nil, fmt.Errorf(
				"refusing to start: classifier base URL %q resolves to the same host as an inspected upstream. "+
					"The Tier 2 classifier must use a trust path independent of the proxied upstream, or the "+
					"adversary is grading its own work. Point CLEANERPROXY_CLASSIFIER_BASE_URL at a local model "+
					"or a direct provider endpoint",
				c.ClassifierBaseURL)
		}
	}

	return c, nil
}

// sameHost reports whether two URLs share a host.
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}

// isLocalhost reports whether a URL points to the local machine.
func isLocalhost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envFloat(key string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// envList reads a comma-separated list. Empty entries are dropped so a trailing
// comma cannot produce a tool named "".
func envList(key string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// notifyDirDefault returns a platform-appropriate directory for notification
// detail files:
//   - macOS:  ~/Library/Logs/cleanerproxy/notify
//   - Linux:  $XDG_STATE_HOME/cleanerproxy/notify (or ~/.local/state/cleanerproxy/notify)
//   - other:  $TMPDIR/cleanerproxy-notify
func notifyDirDefault() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "cleanerproxy-notify")
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Logs", "cleanerproxy", "notify")
	case "linux":
		stateDir := os.Getenv("XDG_STATE_HOME")
		if stateDir == "" {
			stateDir = filepath.Join(home, ".local", "state")
		}
		return filepath.Join(stateDir, "cleanerproxy", "notify")
	default:
		return filepath.Join(os.TempDir(), "cleanerproxy-notify")
	}
}

// isUpstreamOff reports whether an upstream is explicitly disabled.
func isUpstreamOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "none", "disabled", "-":
		return true
	}
	return false
}
