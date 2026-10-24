package guard

import (
	"encoding/json"

	"cleanerproxy/internal/approval"
	"cleanerproxy/internal/inspect"
	"cleanerproxy/internal/verdict"
	"cleanerproxy/internal/wire"
)

// Replacement decides what takes the place of a blocked tool call: a real
// question put to the user, or the plain text notice.
//
// Asking is preferred whenever the client declared a tool capable of it, because
// the alternative leaves the user with no way to proceed. Tier 1 rules ignore
// conversation context by design, so re-requesting a legitimately wanted action
// reproduces the identical block indefinitely; before this existed, the only
// remedy was to disable enforcement globally.
func (g *Guard) Replacement(rc *wire.RequestContext, call verdict.ToolCall, findings []verdict.Finding) wire.Replacement {
	notice := verdict.Explain(findings, []verdict.ToolCall{call})

	q, ok := g.question(rc, call, findings)
	if !ok {
		return wire.Replacement{Notice: notice}
	}
	return wire.Replacement{Notice: notice, Question: q}
}

// question builds the injected approval prompt, or reports that none should be
// asked.
func (g *Guard) question(rc *wire.RequestContext, call verdict.ToolCall, findings []verdict.Finding) (*wire.QuestionCall, bool) {
	if g.Approvals == nil || rc == nil {
		return nil, false
	}

	// Tier 0 findings are structural proof: a call to a tool the client never
	// declared, a duplicate block index, an impersonated tool name. They mean
	// the transport is lying, not that a questionable action was proposed, so
	// there is nothing a user could consent to. Asking would invite someone to
	// approve something that is not what it claims to be.
	for _, f := range findings {
		if f.Severity >= verdict.SeverityProof {
			return nil, false
		}
	}

	// ModeStrict and the abort modes deliberately have no override. Someone who
	// selected them asked for refusal, not for a dialogue.
	if g.Mode != ModeDefang {
		return nil, false
	}

	tool, ok := approval.FindAskTool(g.AskToolNames, func(name string) (json.RawMessage, bool) {
		dt, found := rc.Tool(name)
		if !found {
			return nil, false
		}
		return dt.Schema, true
	}, func(schema json.RawMessage, instance any) (int, bool) {
		vs, understood := inspect.ValidateSchema(schema, instance)
		return len(vs), understood
	})
	if !ok {
		return nil, false
	}

	fp := approval.Compute(call.Name, call.RawInput)
	// One open prompt per payload. A hostile upstream that re-sends the same
	// call on every turn would otherwise stack prompts until the user clicks
	// something just to clear them.
	if g.Approvals.Pending(fp) {
		return nil, false
	}

	c, err := g.Approvals.Issue(idPrefix(rc.Format), call.ID, call.Name, call.RawInput, argsPreview(call))
	if err != nil {
		return nil, false
	}

	args := tool.BuildArgs(c, reasons(findings))
	if len(args) == 0 {
		return nil, false
	}
	return &wire.QuestionCall{ID: c.Nonce, Name: tool.Name, Args: args}, true
}

// AnswerApprovals resolves any approval prompts the client has answered, and
// reports the rewrites to apply to the request before it is forwarded.
//
// Answers are read only from requests. Requests originate at the user's client
// and reach cleanerproxy before the upstream is involved, so the upstream cannot
// author one. That asymmetry is what makes an in-band approval safe here: the
// adversary can author a response but not a request, and therefore cannot
// manufacture consent.
func (g *Guard) AnswerApprovals(results []wire.ToolResult) (rewrites map[string]string, granted []*approval.Challenge) {
	if g.Approvals == nil || len(results) == 0 {
		return nil, nil
	}
	rewrites = map[string]string{}
	for _, r := range results {
		if !approval.IsChallengeID(r.ID) {
			continue
		}
		c, approved := g.Approvals.Answer(r.ID, r.Text)
		if c == nil {
			// Unknown, expired, or already answered. Indistinguishable from a
			// fabrication, and all four are treated the same way: ignored.
			continue
		}
		rewrites[r.ID] = approval.ResultForModel(c, approved)
		if approved {
			// Spend the grant here rather than leaving it for a later
			// Evaluate. The caller is about to replay this exact call, so the
			// consent is being used now; leaving it live would let a model
			// proposing the identical call afterwards ride in for free.
			g.Approvals.Consume(c.Fingerprint)
			granted = append(granted, c)
		}
	}
	if len(rewrites) == 0 {
		return nil, nil
	}
	return rewrites, granted
}

func idPrefix(f wire.Format) string {
	if f == wire.FormatOpenAI {
		return "call_"
	}
	return "toolu_"
}

// argsPreview is what the user reads when deciding. Sanitized because it is
// attacker-controlled text about to be rendered by a terminal client, and
// truncated because a prompt nobody reads is a prompt nobody acts on correctly.
func argsPreview(call verdict.ToolCall) string {
	s := verdict.SanitizeForDisplay(string(call.RawInput))
	const max = 600
	if len(s) > max {
		return s[:max] + "... (truncated)"
	}
	return s
}

func reasons(findings []verdict.Finding) []string {
	var out []string
	for _, f := range findings {
		if f.Severity < verdict.SeveritySuspicious {
			continue
		}
		out = append(out, verdict.SanitizeForDisplay(f.Message))
	}
	return out
}
