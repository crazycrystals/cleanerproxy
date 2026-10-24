package inspect

// Tier 0: deterministic structural invariants.
//
// Everything in this file answers a question with a provable answer, not a
// judgment call. The guiding principle: a response that violates one of these
// invariants could not have been produced by the provider's own serializer, so
// something between the provider and us edited it. That makes these findings
// qualitatively different from the heuristic tiers, and it is why they carry
// SeverityProof and are safe to act on without a model in the loop.
//
// This tier is also the cheapest and runs first. In the common case a clean
// response exits here with a few map lookups and one schema walk.

import (
	"fmt"
	"strings"
	"unicode"

	"cleanerproxy/internal/verdict"
	"cleanerproxy/internal/wire"
)

// Structural implements the Tier 0 inspector.
type Structural struct {
	// StrictIDFormat enables the tool-call ID prefix check. Off by default:
	// the prefixes are trivially forged, so the check catches only careless
	// attackers while risking false positives against provider changes or
	// third-party OpenAI-compatible backends that use their own ID scheme.
	StrictIDFormat bool

	// TokenAccountingRatio is the multiple by which observed content may
	// exceed the upstream's claimed token count before we flag it. Generous
	// by default because tokenization varies by language and content type.
	TokenAccountingRatio float64
}

// NewStructural returns an inspector with calibrated defaults.
func NewStructural() *Structural {
	return &Structural{
		StrictIDFormat:       false,
		TokenAccountingRatio: 3.0,
	}
}

// Inspect evaluates all structural invariants over a response's tool calls and
// metadata, appending findings to v.
func (s *Structural) Inspect(rc *wire.RequestContext, calls []verdict.ToolCall, meta wire.ResponseMeta, v *verdict.Verdict) {
	s.checkToolProvenance(rc, calls, v)
	s.checkSchemas(rc, calls, v)
	s.checkIDs(rc, calls, v)
	s.checkResponseCoherence(calls, meta, v)
}

// checkToolProvenance is the single highest-value check in the entire system.
//
// The client's request enumerates every tool it is capable of executing. That
// list is authoritative and locally known — it did not come from the upstream.
// A tool call naming anything outside it is either unexecutable (harmless but
// proof of tampering) or, worse, an attempt to hit a tool the client has but
// did not offer for this turn. Either way the real model could not have
// produced it, because the real model was only shown the declared set.
//
// False positive rate here is zero by construction.
func (s *Structural) checkToolProvenance(rc *wire.RequestContext, calls []verdict.ToolCall, v *verdict.Verdict) {
	declared := rc.DeclaredNames()

	for _, c := range calls {
		if _, ok := rc.Tool(c.Name); ok {
			continue
		}

		// Undeclared. Before reporting, work out whether this looks like a
		// deliberate evasion attempt, because that changes the user-facing
		// message from "malformed" to "someone is attacking you".
		if near, kind := nearestDeclared(c.Name, declared); near != "" {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.name.confusable",
				Severity:   verdict.SeverityProof,
				ToolCallID: c.ID,
				ToolName:   c.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf(
					"Upstream requested tool %q, which was never declared but differs from the declared tool %q only by %s. "+
						"This is characteristic of a deliberate impersonation attempt, not a malformed response.",
					c.Name, near, kind),
				Evidence: fmt.Sprintf("requested=%q declared=%q codepoints=%s", c.Name, near, codepoints(c.Name)),
			})
			continue
		}

		if len(declared) == 0 {
			// The strongest possible signal: the client offered no tools at
			// all, so there is no interpretation under which the provider
			// would emit a tool call.
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.call.without.declaration",
				Severity:   verdict.SeverityProof,
				ToolCallID: c.ID,
				ToolName:   c.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf(
					"Upstream returned a call to tool %q, but this request declared no tools whatsoever. "+
						"The provider was never given a tool to call. This response was modified in transit.",
					c.Name),
			})
			continue
		}

		v.Add(verdict.Finding{
			Tier:       verdict.TierStructural,
			Rule:       "tool.name.undeclared",
			Severity:   verdict.SeverityProof,
			ToolCallID: c.ID,
			ToolName:   c.Name,
			Confidence: 1.0,
			Message: fmt.Sprintf(
				"Upstream requested tool %q, which this request never declared. The provider could not have "+
					"produced this call because it was never shown that tool.", c.Name),
			Evidence: fmt.Sprintf("declared=[%s]", strings.Join(declared, ", ")),
		})
	}
}

// checkSchemas validates each call's arguments against the schema the client
// declared for that tool. This is the primary defense against argument
// tampering, where the upstream preserves a legitimate call but mutates its
// parameters.
func (s *Structural) checkSchemas(rc *wire.RequestContext, calls []verdict.ToolCall, v *verdict.Verdict) {
	for _, c := range calls {
		tool, ok := rc.Tool(c.Name)
		if !ok {
			continue // already reported by provenance check
		}

		// A tool call whose arguments did not parse as JSON at all is
		// reported by the codec as a decode finding; skip schema work.
		if c.Input == nil && len(c.RawInput) > 0 {
			continue
		}

		violations, understood := ValidateSchema(tool.Schema, c.Input)

		for _, vio := range violations {
			sev := verdict.SeveritySuspicious
			msg := fmt.Sprintf("Argument %s for tool %q violates the declared schema: %s",
				vio.Path, c.Name, vio.Msg)

			if vio.Fatal {
				// Providers constrain tool-argument sampling to the declared
				// schema. A fatal-class violation therefore indicates the
				// object was rewritten after generation.
				sev = verdict.SeverityProof
				msg = fmt.Sprintf(
					"Argument %s for tool %q violates the declared schema in a way constrained decoding prevents: %s. "+
						"The arguments appear to have been rewritten after the provider generated them.",
					vio.Path, c.Name, vio.Msg)
			}

			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.input.schema",
				Severity:   sev,
				ToolCallID: c.ID,
				ToolName:   c.Name,
				Confidence: 1.0,
				Message:    msg,
				Evidence:   vio.String(),
			})
		}

		if !understood {
			// Record that our validation was incomplete. This matters for
			// audit: a clean Tier 0 result on an unvalidatable schema must
			// not be read later as "we checked and it was fine".
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.input.schema.unvalidated",
				Severity:   verdict.SeverityInfo,
				ToolCallID: c.ID,
				ToolName:   c.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf("Schema for tool %q uses keywords outside the validated subset; "+
					"argument validation for this call was partial.", c.Name),
			})
		}
	}
}

// checkIDs enforces uniqueness of tool call identifiers and, optionally,
// provider ID formats.
func (s *Structural) checkIDs(rc *wire.RequestContext, calls []verdict.ToolCall, v *verdict.Verdict) {
	seen := map[string]int{}
	for _, c := range calls {
		if c.ID == "" {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.id.missing",
				Severity:   verdict.SeverityMalicious,
				ToolName:   c.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf("Tool call to %q arrived with no call ID. The client cannot correlate a "+
					"result to it, and the provider always assigns one.", c.Name),
			})
			continue
		}
		seen[c.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			// Duplicate IDs break result correlation and are a known way to
			// smuggle a second call past a client that keys on ID.
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.id.duplicate",
				Severity:   verdict.SeverityProof,
				ToolCallID: id,
				Confidence: 1.0,
				Message: fmt.Sprintf("Tool call ID %q appears %d times in one response. IDs are unique per "+
					"response; duplication indicates an inserted call.", id, n),
			})
		}
	}

	if !s.StrictIDFormat {
		return
	}
	want := "toolu_"
	if rc.Format == wire.FormatOpenAI {
		want = "call_"
	}
	for _, c := range calls {
		if c.ID != "" && !strings.HasPrefix(c.ID, want) {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "tool.id.format",
				Severity:   verdict.SeveritySuspicious,
				ToolCallID: c.ID,
				ToolName:   c.Name,
				Confidence: 0.5,
				Message: fmt.Sprintf("Tool call ID %q does not use the expected %q prefix for the %s API. "+
					"Note that this prefix is trivially forged, so its absence indicates carelessness "+
					"rather than proving anything.", c.ID, want, rc.Format),
			})
		}
	}
}

// checkResponseCoherence validates invariants over the response envelope.
func (s *Structural) checkResponseCoherence(calls []verdict.ToolCall, meta wire.ResponseMeta, v *verdict.Verdict) {
	// A response carrying tool calls must report a stop reason that says so.
	// An upstream that appends a tool_use block to a completed end_turn
	// response commonly forgets to rewrite stop_reason.
	if len(calls) > 0 && meta.StopReason != "" && meta.StopReason != "tool_use" && meta.StopReason != "tool_calls" {
		v.Add(verdict.Finding{
			Tier:       verdict.TierStructural,
			Rule:       "response.stop_reason.incoherent",
			Severity:   verdict.SeverityProof,
			Confidence: 1.0,
			Message: fmt.Sprintf("Response contains %d tool call(s) but reports stop_reason %q. The provider "+
				"always reports a tool-use stop reason when it emits tool calls; this mismatch means the "+
				"tool call was appended after generation completed.", len(calls), meta.StopReason),
			Evidence: fmt.Sprintf("stop_reason=%s tool_calls=%d", meta.StopReason, len(calls)),
		})
	}

	if meta.MessageStartCount > 1 {
		v.Add(verdict.Finding{
			Tier:       verdict.TierStructural,
			Rule:       "response.multiple_envelopes",
			Severity:   verdict.SeverityProof,
			Confidence: 1.0,
			Message: fmt.Sprintf("Stream contained %d message_start events. A single response has exactly one; "+
				"additional envelopes indicate a spliced-in second message.", meta.MessageStartCount),
		})
	}

	// Content block indices must be unique. Reuse lets an attacker overwrite
	// a block a permissive client has already accepted.
	idxSeen := map[int]int{}
	for _, i := range meta.BlockIndices {
		idxSeen[i]++
	}
	for i, n := range idxSeen {
		if n > 1 {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "response.block_index.duplicate",
				Severity:   verdict.SeverityProof,
				Confidence: 1.0,
				Message: fmt.Sprintf("Content block index %d was opened %d times in one response. Indices are "+
					"unique; reuse is a block-overwrite attempt.", i, n),
			})
		}
	}

	// Token accounting. Purely heuristic and deliberately loose: an upstream
	// that injects content usually does not recompute usage, but tokenization
	// ratios vary enough that this can only ever be a soft signal.
	if meta.OutputTokens > 0 && s.TokenAccountingRatio > 0 {
		observed := meta.TextBytes + meta.ToolCallBytes
		// ~4 bytes/token is a reasonable English/code average.
		budget := float64(meta.OutputTokens) * 4.0 * s.TokenAccountingRatio
		if float64(observed) > budget && observed-meta.OutputTokens*4 > 512 {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "response.usage.mismatch",
				Severity:   verdict.SeveritySuspicious,
				Confidence: 0.4,
				Message: fmt.Sprintf("Response carries %d bytes of content but upstream reported only %d output "+
					"tokens. Content may have been appended without updating the usage accounting.",
					observed, meta.OutputTokens),
				Evidence: fmt.Sprintf("observed_bytes=%d claimed_tokens=%d ratio=%.1f",
					observed, meta.OutputTokens, float64(observed)/float64(meta.OutputTokens)),
			})
		}
	}
}

// nearestDeclared reports whether name is a confusable variant of a declared
// tool, and how. This distinguishes a random injected tool name from targeted
// impersonation of a tool the client actually has.
func nearestDeclared(name string, declared []string) (string, string) {
	for _, d := range declared {
		if name == d {
			return "", ""
		}
	}
	for _, d := range declared {
		if strings.EqualFold(name, d) {
			return d, "letter case"
		}
	}
	// Strip characters that render invisibly or near-invisibly and retry.
	// Zero-width joiners and Cyrillic lookalikes are the usual vehicles.
	if f := foldConfusables(name); f != "" {
		for _, d := range declared {
			if f == foldConfusables(d) && name != d {
				return d, "visually confusable or invisible characters"
			}
		}
	}
	// Single edit distance catches transposition and one-character padding.
	for _, d := range declared {
		if editDistanceAtMost1(name, d) {
			return d, "a single character"
		}
	}
	return "", ""
}

// confusableFolds maps common homoglyphs onto their ASCII lookalike. This is
// not a complete Unicode confusables table; it covers the Cyrillic and Greek
// characters that actually appear in impersonation attacks against ASCII
// tool names.
var confusableFolds = map[rune]rune{
	'\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
	'\u0443': 'y', '\u0445': 'x', '\u0455': 's', '\u0456': 'i', '\u0458': 'j',
	'\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03bd': 'v', '\u03ba': 'k',
	'\uff41': 'a', '\uff42': 'b', '\uff43': 'c', // fullwidth forms
}

func foldConfusables(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff':
			// zero-width: drop entirely
			continue
		case unicode.Is(unicode.Cf, r):
			continue
		default:
			if f, ok := confusableFolds[r]; ok {
				b.WriteRune(f)
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
		}
	}
	return b.String()
}

// editDistanceAtMost1 reports whether a and b differ by at most one
// insertion, deletion, or substitution. Cheaper and clearer than a full
// Levenshtein matrix for the only question we ask.
func editDistanceAtMost1(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == lb {
		diff := 0
		for i := range ra {
			if ra[i] != rb[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return diff == 1
	}
	if la > lb {
		ra, rb = rb, ra
		la, lb = lb, la
	}
	if lb-la != 1 {
		return false
	}
	i, j := 0, 0
	skipped := false
	for i < la && j < lb {
		if ra[i] != rb[j] {
			if skipped {
				return false
			}
			skipped = true
			j++
			continue
		}
		i++
		j++
	}
	return true
}

// codepoints renders a string as explicit codepoints so a user staring at two
// visually identical tool names in a terminal can see the difference.
func codepoints(s string) string {
	var parts []string
	for _, r := range s {
		if r < 128 && unicode.IsPrint(r) {
			parts = append(parts, string(r))
		} else {
			parts = append(parts, fmt.Sprintf("U+%04X", r))
		}
	}
	return strings.Join(parts, " ")
}
