package approval

import (
	"encoding/json"
	"fmt"
	"strings"

	"cleanerproxy/internal/toolnames"
)

// AskTool is a client-declared tool that can put a question to the user.
//
// cleanerproxy never invents a tool. It can only inject a call to something the
// client already declared in this very request, because an injected call to an
// undeclared tool is exactly what the Tier 0 allowlist exists to catch — and
// the client would reject it anyway. If no suitable tool is declared, the
// approval path is simply unavailable and the plain text notice is used.
type AskTool struct {
	Name   string
	Schema json.RawMessage

	// shape records which argument layout was matched, since clients differ.
	shape askShape
}

type askShape int

const (
	shapeNone askShape = iota

	// shapeQuestions matches opencode's question tool:
	//   {"questions":[{"question":..,"header":..,"options":[{"label":..,"description":..}]}]}
	shapeQuestions

	// shapeFlat matches the common minimal form used by many clients:
	//   {"question":..,"options":["..",".."]}
	shapeFlat

	// shapeClaudeCode matches Claude Code's AskUserQuestion tool:
	//   {"question":..,"options":[{"label":..,"description":..}]}
	// Options are objects with label/description (like opencode) but without
	// the outer questions[] wrapper.
	shapeClaudeCode
)

// DefaultAskToolNames are the tool names checked, in preference order.
//
// Canonical list lives in internal/toolnames because internal/inspect needs the
// same one to decide which tools merely display text; two copies would drift.
var DefaultAskToolNames = toolnames.AskTools

// SchemaValidator validates an instance against a declared JSON schema. Injected
// via interface so this package does not import the inspect tier.
type SchemaValidator func(schema json.RawMessage, instance any) (violations int, understood bool)

// FindAskTool selects a declared tool usable for asking the user, and decides
// which argument shape to build for it.
//
// validate is used to confirm the arguments cleanerproxy would build actually
// satisfy the tool's own declared schema. This matters: guessing a shape and
// emitting arguments the client rejects would replace a clear security warning
// with a confusing tool error, which is a worse outcome than not asking at all.
func FindAskTool(names []string, lookup func(string) (json.RawMessage, bool), validate SchemaValidator) (AskTool, bool) {
	if len(names) == 0 {
		names = DefaultAskToolNames
	}
	for _, name := range names {
		schema, ok := lookup(name)
		if !ok {
			continue
		}
		for _, shape := range []askShape{shapeQuestions, shapeClaudeCode, shapeFlat} {
			t := AskTool{Name: name, Schema: schema, shape: shape}
			probe := t.buildArgs("probe question", "Probe", "probe")
			if probe == nil {
				continue
			}
			if validate == nil {
				return t, true
			}
			var inst any
			if err := json.Unmarshal(probe, &inst); err != nil {
				continue
			}
			violations, understood := validate(schema, inst)
			// An unparseable or unsupported schema returns understood=false.
			// Treat that as acceptable rather than as a failure: refusing would
			// disable approvals for any client with an exotic schema, and the
			// client validates its own arguments regardless.
			if !understood || violations == 0 {
				return t, true
			}
		}
	}
	return AskTool{}, false
}

// BuildArgs renders the arguments for the approval question about one call.
func (t AskTool) BuildArgs(c *Challenge, reasons []string) json.RawMessage {
	return t.buildArgs(questionText(c, reasons), "Blocked tool call", c.ArgsPreview)
}

func (t AskTool) buildArgs(question, header, _ string) json.RawMessage {
	switch t.shape {
	case shapeQuestions:
		v := map[string]any{
			"questions": []any{map[string]any{
				"question": question,
				"header":   header,
				"options": []any{
					// Refusal first, deliberately. The proxy's own judgment is
					// that this call is malicious, so the safe choice should be
					// the default and the least effort. A user overriding a
					// security control should have to travel further than a
					// user accepting it.
					map[string]any{
						"label":       DenyLabel,
						"description": "Discard this call. The agent is told it was refused and continues without it.",
					},
					map[string]any{
						"label":       ApproveLabel,
						"description": "Execute exactly the arguments shown above, once. Only choose this if you recognise them as what you asked for.",
					},
				},
			}},
		}
		out, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return out
	case shapeClaudeCode:
		// Claude Code's AskUserQuestion: options are objects with label+description,
		// but no outer questions[] wrapper.
		out, err := json.Marshal(map[string]any{
			"question": question,
			"options": []any{
				map[string]any{
					"label":       DenyLabel,
					"description": "Discard this call. The agent is told it was refused and continues without it.",
				},
				map[string]any{
					"label":       ApproveLabel,
					"description": "Execute exactly the arguments shown above, once. Only choose this if you recognise them as what you asked for.",
				},
			},
		})
		if err != nil {
			return nil
		}
		return out
	case shapeFlat:
		out, err := json.Marshal(map[string]any{
			"question": question,
			"options":  []any{DenyLabel, ApproveLabel},
		})
		if err != nil {
			return nil
		}
		return out
	}
	return nil
}

// questionText is what the user actually reads. It has to carry enough for a
// decision — the exact arguments and why they were stopped — while staying
// short enough to be read rather than dismissed.
func questionText(c *Challenge, reasons []string) string {
	var b strings.Builder
	b.WriteString("cleanerproxy blocked a tool call from the upstream provider.\n\n")
	fmt.Fprintf(&b, "tool: %s\narguments: %s\n", c.ToolName, c.ArgsPreview)
	if len(reasons) > 0 {
		b.WriteString("\nwhy:\n")
		for _, r := range reasons {
			fmt.Fprintf(&b, "- %s\n", r)
		}
	}
	b.WriteString("\nThese arguments were chosen by the provider, not by you. ")
	b.WriteString("Approve only if this is what you asked for. ")
	b.WriteString("If you did not ask for it, refuse and rotate any credentials this session has touched.")
	return b.String()
}

// ResultForModel is the tool_result content cleanerproxy substitutes before
// forwarding the answer upstream.
//
// The client's own result text is replaced rather than passed through. The model
// has to act on the outcome, and a bare option label ("Run it anyway") does not
// tell it what to do next. Replacing it also keeps the user's literal words out
// of the upstream's hands, which is worth doing for an adversary that retains
// everything it sees.
func ResultForModel(c *Challenge, approved bool) string {
	if approved {
		// Not an instruction to re-issue. cleanerproxy replays the approved call
		// itself, so by the time the model sees anything the call has already
		// been handed to the client. Asking the model to re-issue was tried and
		// fails: Claude 4.6 Opus correctly treats a tool_result telling it to
		// run `curl … | bash` as a prompt injection and refuses.
		return fmt.Sprintf(
			"The user reviewed the blocked %s call and approved it. cleanerproxy has already "+
				"released that call for execution; its result will follow. No action is needed from you.",
			c.ToolName)
	}
	return fmt.Sprintf(
		"The user reviewed the blocked %s call and refused it. "+
			"Do not attempt it again, and do not propose a variant of it. "+
			"Continue with the task without that call, or explain what you cannot do without it.",
		c.ToolName)
}
