package wire

// OpenAI Chat Completions API codec.
//
// The important structural difference from Anthropic: tool arguments arrive as
// a *stringified* JSON document inside `function.arguments`, not as a nested
// object. That double encoding matters for two reasons.
//
// First, a decode failure is a finding in its own right — the provider always
// emits parseable JSON there, so garbage means someone rewrote it.
//
// Second, it gives an attacker a layer to hide in: bytes that are inert in the
// outer JSON become meaningful after the inner parse. Detection therefore runs
// against both the decoded object and the raw inner string.

import (
	"encoding/json"
	"fmt"
	"strings"

	"cleanerproxy/internal/verdict"
)

// ---- Request -----------------------------------------------------------

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream,omitempty"`

	// Functions is the deprecated pre-`tools` field. Still accepted by the
	// API and therefore still a declaration channel we must honour, or an
	// attacker could call a function the client declared the old way and we
	// would wrongly report it as undeclared.
	Functions []openAIFunction `json:"functions,omitempty"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type openAIMessage struct {
	Role      string           `json:"role"`
	Content   json.RawMessage  `json:"content"`
	ToolCalls []openAIToolCall `json:"tool_calls,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Index    *int   `json:"index,omitempty"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ParseOpenAIRequest builds a RequestContext from a Chat Completions request.
func ParseOpenAIRequest(body []byte) (*RequestContext, error) {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse openai request: %w", err)
	}

	rc := &RequestContext{
		Format:  FormatOpenAI,
		Model:   req.Model,
		Stream:  req.Stream,
		RawBody: body,
	}

	for _, t := range req.Tools {
		if t.Function.Name == "" {
			continue
		}
		rc.Tools = append(rc.Tools, DeclaredTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			Schema:      t.Function.Parameters,
		})
	}
	// Legacy `functions` declarations count as declared too.
	for _, fn := range req.Functions {
		if fn.Name == "" {
			continue
		}
		if _, exists := rc.Tool(fn.Name); exists {
			continue
		}
		rc.Tools = append(rc.Tools, DeclaredTool{
			Name:        fn.Name,
			Description: fn.Description,
			Schema:      fn.Parameters,
		})
	}
	rc.Index()

	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if s := decodeOpenAIContent(m.Content); s != "" {
				if rc.System != "" {
					rc.System += "\n"
				}
				rc.System += s
			}
		case "user":
			if s := decodeOpenAIContent(m.Content); s != "" {
				rc.UserTurns = append(rc.UserTurns, s)
			}
		case "assistant":
			for _, tc := range m.ToolCalls {
				rc.PriorAssistantToolNames = append(rc.PriorAssistantToolNames, tc.Function.Name)
			}
		case "tool":
			// Excluded from UserTurns for the same reason as Anthropic
			// tool_result blocks: tool output is attacker-reachable content,
			// and treating it as user intent would let an attacker authorize
			// their own tool calls by planting text in a file the agent reads.
		}
	}

	return rc, nil
}

// decodeOpenAIContent handles both the string form and the newer array-of-parts
// form of `content`.
func decodeOpenAIContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var out []string
		for _, p := range parts {
			if p.Text != "" {
				out = append(out, p.Text)
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// ---- Non-streaming response --------------------------------------------

type openAIResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Content   json.RawMessage  `json:"content"`
			ToolCalls []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// ParseOpenAIResponse extracts normalized tool calls and metadata.
func ParseOpenAIResponse(body []byte) ([]verdict.ToolCall, ResponseMeta, error) {
	var resp openAIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ResponseMeta{}, fmt.Errorf("parse openai response: %w", err)
	}

	meta := ResponseMeta{
		Model:             resp.Model,
		OutputTokens:      resp.Usage.CompletionTokens,
		MessageStartCount: 1,
	}

	var calls []verdict.ToolCall
	idx := 0
	for _, ch := range resp.Choices {
		// Normalize finish_reason onto the Anthropic vocabulary so the shared
		// coherence check in Tier 0 works for both dialects.
		meta.StopReason = normalizeFinishReason(ch.FinishReason)
		meta.TextBytes += len(decodeOpenAIContent(ch.Message.Content))

		for _, tc := range ch.Message.ToolCalls {
			meta.ToolCallBytes += len(tc.Function.Arguments)
			meta.BlockIndices = append(meta.BlockIndices, idx)
			calls = append(calls, normalizeOpenAICall(tc, idx))
			idx++
		}
	}
	return calls, meta, nil
}

// normalizeFinishReason maps OpenAI finish reasons onto the vocabulary the
// shared inspectors expect.
func normalizeFinishReason(r string) string {
	switch r {
	case "tool_calls", "function_call":
		return "tool_use"
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "":
		return ""
	}
	return r
}

// normalizeOpenAICall converts an OpenAI tool call into the shared form,
// decoding the stringified arguments.
func normalizeOpenAICall(tc openAIToolCall, blockIndex int) verdict.ToolCall {
	args := tc.Function.Arguments
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	var input map[string]any
	if err := json.Unmarshal([]byte(args), &input); err != nil {
		// nil Input with non-empty RawInput is the agreed signal for a decode
		// failure; the structural inspector reports it rather than guessing.
		input = nil
	}
	return verdict.ToolCall{
		ID:         tc.ID,
		Name:       tc.Function.Name,
		Input:      input,
		RawInput:   json.RawMessage(args),
		BlockIndex: blockIndex,
	}
}

// RewriteOpenAIResponse defangs a non-streaming response by removing blocked
// tool calls and folding the notice into the message content.
//
// finish_reason is corrected to "stop" when no tool call survives, because a
// client that sees "tool_calls" will sit waiting to submit results for calls
// that are no longer present.
func RewriteOpenAIResponse(body []byte, blocked map[string]Replacement) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	choices, _ := raw["choices"].([]any)

	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		tcs, _ := msg["tool_calls"].([]any)
		if len(tcs) == 0 {
			continue
		}

		kept := make([]any, 0, len(tcs))
		var notices []string
		asked := false
		for _, t := range tcs {
			tc, ok := t.(map[string]any)
			if !ok {
				kept = append(kept, t)
				continue
			}
			id, _ := tc["id"].(string)
			rep, isBlocked := blocked[id]
			if !isBlocked {
				kept = append(kept, t)
				continue
			}
			if rep.Question != nil {
				// Replace the blocked call with a question to the user. The
				// original function and arguments are discarded entirely.
				kept = append(kept, map[string]any{
					"id":   rep.Question.ID,
					"type": "function",
					"function": map[string]any{
						"name":      rep.Question.Name,
						"arguments": string(rep.Question.Args),
					},
				})
				asked = true
				continue
			}
			notices = append(notices, rep.Notice)
		}

		if len(notices) == 0 && !asked {
			continue
		}

		if len(kept) == 0 {
			delete(msg, "tool_calls")
			choice["finish_reason"] = "stop"
		} else {
			msg["tool_calls"] = kept
		}

		if len(notices) > 0 {
			existing := ""
			if s, ok := msg["content"].(string); ok {
				existing = s
			}
			msg["content"] = strings.TrimSpace(existing + "\n\n" + strings.Join(notices, "\n"))
		}
	}

	return json.Marshal(raw)
}
