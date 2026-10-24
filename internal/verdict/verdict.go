// Package verdict defines the normalized vocabulary shared by every
// inspection tier and by the policy engine.
//
// The central design decision here: tool calls from the Anthropic wire format
// (content blocks of type "tool_use") and from the OpenAI wire format
// (message.tool_calls[] with stringified JSON arguments) are normalized into a
// single ToolCall type before inspection. Inspectors are therefore completely
// API-agnostic, and a detection rule written once applies to both upstreams.
package verdict

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Tier identifies which layer of defense produced a Finding. Tiers are ordered
// by epistemic strength, not by severity: Tier0 findings are deterministic
// proofs of tampering, Tier2 findings are probabilistic judgments.
type Tier int

const (
	// TierStructural covers deterministic invariant violations: a tool name
	// the client never declared, input that fails the declared schema,
	// incoherent stop_reason, duplicate block indices. A Tier0 finding is
	// effectively proof of upstream tampering — the real model cannot emit
	// these. False positive rate is ~0.
	TierStructural Tier = 0

	// TierCapability covers dangerous-capability pattern matches on tool
	// arguments, evaluated independently of conversational relevance:
	// pipe-to-shell, credential-path writes, persistence mechanisms.
	// Deterministic matching, but a legitimate model CAN emit these when the
	// user genuinely asked for them, so these are suspicion, not proof.
	TierCapability Tier = 1

	// TierSemantic covers the probabilistic relevance classifier: is this
	// tool call plausibly derived from what the user actually asked for?
	// Must be backed by a path independent of the untrusted upstream.
	TierSemantic Tier = 2

	// TierCorroboration covers cross-path replay: the same request issued to
	// an independently trusted path did not produce this tool call.
	TierCorroboration Tier = 3
)

func (t Tier) String() string {
	switch t {
	case TierStructural:
		return "tier0-structural"
	case TierCapability:
		return "tier1-capability"
	case TierSemantic:
		return "tier2-semantic"
	case TierCorroboration:
		return "tier3-corroboration"
	}
	return fmt.Sprintf("tier%d-unknown", int(t))
}

// Severity expresses how confident we are that this specific finding
// represents actual malice, and drives policy selection.
type Severity int

const (
	// SeverityInfo is recorded for audit but never blocks.
	SeverityInfo Severity = iota

	// SeveritySuspicious indicates a finding that warrants surfacing to the
	// user but which has a plausible benign explanation.
	SeveritySuspicious

	// SeverityMalicious indicates high confidence of an injected or tampered
	// tool call.
	SeverityMalicious

	// SeverityProof indicates a deterministic invariant violation. The real
	// model could not have produced this response; the upstream tampered
	// with it. Reserved for Tier 0.
	SeverityProof
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeveritySuspicious:
		return "suspicious"
	case SeverityMalicious:
		return "malicious"
	case SeverityProof:
		return "proof"
	}
	return "unknown"
}

// Action is the decision the policy engine reaches for a whole response.
type Action int

const (
	// ActionAllow passes the response through unmodified.
	ActionAllow Action = iota

	// ActionDefang strips the offending tool call and substitutes a synthetic
	// tool_result carrying the block reason, keeping the agent loop intact so
	// the user is informed in-band and the session stays usable.
	ActionDefang

	// ActionAbort terminates the response with an HTTP 5xx (or, mid-stream,
	// an error event followed by connection close).
	ActionAbort
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDefang:
		return "defang"
	case ActionAbort:
		return "abort"
	}
	return "unknown"
}

// ToolCall is the normalized, API-agnostic representation of a single tool
// invocation extracted from an upstream response.
type ToolCall struct {
	// ID is the upstream-assigned call identifier ("toolu_..." on Anthropic,
	// "call_..." on OpenAI). Trivially forgeable; useful only for correlating
	// the defanged result back to the call.
	ID string

	// Name is the tool the upstream is asking the client to run.
	Name string

	// Input is the decoded argument object. For OpenAI this is the result of
	// unmarshalling the stringified `arguments` field; a decode failure is
	// itself recorded as a structural finding rather than silently ignored.
	Input map[string]any

	// RawInput preserves the exact bytes received, because detection rules
	// must be able to match on the literal wire form. Re-marshalling Go maps
	// normalizes away meaningful signal (key order, whitespace padding,
	// unicode escaping) that an attacker may use for evasion.
	RawInput json.RawMessage

	// BlockIndex is the position of this call in the response content, used
	// for structural coherence checks and for surgical rewriting.
	BlockIndex int
}

// ArgText flattens every string value anywhere in the tool input into a single
// searchable corpus.
//
// Rationale: capability rules must not depend on knowing each tool's parameter
// names. A shell command may arrive as {"command": "..."} or {"cmd": "..."} or
// nested as {"input": {"script": "..."}}. Attackers also split payloads across
// multiple fields. Flattening defeats both parameter-name assumptions and
// naive field-splitting evasion.
func (tc ToolCall) ArgText() string {
	var out []string
	collectStrings(tc.Input, &out)
	sort.Strings(out)
	return strings.Join(out, "\n")
}

func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case map[string]any:
		// Keys are collected too: an attacker can smuggle payload fragments
		// into object keys, which a values-only walk would miss.
		for k, e := range t {
			*out = append(*out, k)
			collectStrings(e, out)
		}
	}
}

// Finding is a single detection result.
type Finding struct {
	Tier     Tier     `json:"tier"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`

	// ToolCallID is the call this finding concerns, empty for findings about
	// the response as a whole.
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name,omitempty"`

	// Message is user-facing text. It is embedded verbatim into the defanged
	// tool_result the agent shows the user, so it must be written for a human
	// under time pressure: say what was blocked and why it looked wrong.
	Message string `json:"message"`

	// Evidence is the specific substring or schema path that triggered the
	// rule. Truncated before display to avoid echoing a large hostile payload
	// into the user's terminal.
	Evidence string `json:"evidence,omitempty"`

	// Confidence applies to probabilistic tiers. Deterministic tiers report 1.
	Confidence float64 `json:"confidence"`
}

// Verdict aggregates all findings for one upstream response.
type Verdict struct {
	Findings []Finding `json:"findings"`
}

// Add appends a finding.
func (v *Verdict) Add(f Finding) { v.Findings = append(v.Findings, f) }

// Clean reports whether nothing actionable was found.
func (v *Verdict) Clean() bool {
	for _, f := range v.Findings {
		if f.Severity > SeverityInfo {
			return false
		}
	}
	return true
}

// MaxSeverity returns the highest severity across findings.
func (v *Verdict) MaxSeverity() Severity {
	m := SeverityInfo
	for _, f := range v.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// FindingsFor returns findings concerning a specific tool call.
func (v *Verdict) FindingsFor(id string) []Finding {
	var out []Finding
	for _, f := range v.Findings {
		if f.ToolCallID == id {
			out = append(out, f)
		}
	}
	return out
}

// BlockedCallIDs returns the set of tool call IDs with at least one
// actionable finding.
func (v *Verdict) BlockedCallIDs() map[string]bool {
	out := map[string]bool{}
	for _, f := range v.Findings {
		if f.Severity > SeverityInfo && f.ToolCallID != "" {
			out[f.ToolCallID] = true
		}
	}
	return out
}

// Explain renders findings into the human-readable notice that replaces a
// blocked tool call. This notice is the entire user interface of the proxy.
//
// calls supplies the blocked call so the notice can show WHAT was blocked.
// Passing findings alone produced an unactionable notice: a Tier 2 finding says
// only `this call to "read" does not follow from anything you asked for`, which
// never reveals that the path was ~/.ssh/id_ed25519. Half of all detections are
// Tier 2 only, so half of all notices named no arguments at all and the user
// could neither evaluate nor act on the decision.
func Explain(findings []Finding, calls []ToolCall) string {
	byID := map[string]ToolCall{}
	for _, c := range calls {
		byID[c.ID] = c
	}

	var b strings.Builder
	b.WriteString("BLOCKED BY CLEANERPROXY\n\n")
	b.WriteString("This tool call was not executed. cleanerproxy inspects responses ")
	b.WriteString("from the upstream provider for tool calls that may have been ")
	b.WriteString("injected or tampered with in transit.\n")

	// Group by call, preserving first-seen order, so a response carrying two
	// blocked calls shows each one with its own arguments and reasons rather
	// than merging them into an ambiguous list.
	var order []string
	group := map[string][]Finding{}
	for _, f := range findings {
		if _, seen := group[f.ToolCallID]; !seen {
			order = append(order, f.ToolCallID)
		}
		group[f.ToolCallID] = append(group[f.ToolCallID], f)
	}

	for _, id := range order {
		explainCall(&b, byID[id], group[id])
	}

	b.WriteString("\nWHAT TO DO\n")
	b.WriteString("If you did not ask for this, treat your upstream provider as compromised: ")
	b.WriteString("rotate any credentials that were in this session's context.\n")
	// The previous wording was "if you genuinely intended this action,
	// re-request it explicitly". That is false for Tier 1 findings, which
	// ignore conversation context by design: re-asking produces the identical
	// block, forever. Promising a recovery path that does not exist is worse
	// than admitting there is none.
	b.WriteString("If you did ask for this, re-requesting it will NOT help when the reason above ")
	b.WriteString("is tier1-capability: those rules ignore conversation context on purpose, so the ")
	b.WriteString("block will repeat. Run the command yourself, in your own shell, then tell the ")
	b.WriteString("agent to continue.\n")
	// Showing the payload and suggesting the user run it could turn this
	// warning into the delivery mechanism for the very thing it blocked. Say
	// plainly that recognition is the precondition.
	b.WriteString("Only do that if you RECOGNISE the arguments above as what you asked for. ")
	b.WriteString("They were chosen by the upstream provider, not by you, and cleanerproxy blocked ")
	b.WriteString("them because it could not confirm you wanted them. If you cannot tell, do not run it.\n")
	return b.String()
}

// explainCall writes one blocked call: what it was, then why it was stopped.
func explainCall(b *strings.Builder, call ToolCall, findings []Finding) {
	name := call.Name
	if name == "" && len(findings) > 0 {
		name = findings[0].ToolName
	}
	if name == "" {
		name = "(unnamed tool)"
	}

	b.WriteString("\nBLOCKED CALL\n")
	fmt.Fprintf(b, "  tool: %s\n", SanitizeForDisplay(name))
	if args := strings.TrimSpace(string(call.RawInput)); args != "" {
		// Arguments are attacker-controlled and are about to be printed into a
		// terminal, so they get the same sanitizing as evidence.
		fmt.Fprintf(b, "  arguments: %s\n", truncate(SanitizeForDisplay(args), 600))
	} else {
		b.WriteString("  arguments: (unavailable — the call was withheld before its " +
			"arguments could be fully decoded)\n")
	}

	b.WriteString("\nWHY IT WAS BLOCKED\n")
	for _, f := range findings {
		fmt.Fprintf(b, "- [%s / %s] %s\n", f.Tier, f.Severity, SanitizeForDisplay(f.Message))
		if f.Evidence != "" {
			fmt.Fprintf(b, "  evidence: %s\n", truncate(SanitizeForDisplay(f.Evidence), 300))
		}
		if f.Tier >= TierSemantic {
			fmt.Fprintf(b, "  confidence: %.2f\n", f.Confidence)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("... (%d bytes total, truncated)", len(s))
}

// SanitizeForDisplay neutralizes control sequences in text that will be
// rendered in a user's terminal.
//
// Escape sequences are replaced with a visible marker rather than dropped, so
// that their presence is itself reported: a payload containing terminal
// escapes is strong evidence of intent to deceive the user, and silently
// removing them would hide that signal.
//
// Markers use square brackets rather than angle brackets because
// encoding/json HTML-escapes < and > by default, which would render the
// marker unrecognisable once the notice is serialized onto the wire.
func SanitizeForDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			// Preserved: the notice is multi-line by design.
			b.WriteRune(r)
		case r == 0x1b:
			// ESC introduces ANSI/CSI/OSC sequences.
			b.WriteString("[ESC]")
		case r < 0x20 || r == 0x7f:
			// Remaining C0 controls and DEL, including CR (which can be used
			// to overwrite a printed line) and BEL.
			fmt.Fprintf(&b, "[0x%02X]", r)
		case r >= 0x80 && r <= 0x9f:
			// C1 controls; some terminals interpret these as escapes.
			fmt.Fprintf(&b, "[0x%02X]", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
