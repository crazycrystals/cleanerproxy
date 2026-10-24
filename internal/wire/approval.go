package wire

import (
	"encoding/json"
	"strings"
)

// This file handles the request direction of the approval flow: finding the
// user's answer to a cleanerproxy prompt, and replacing that answer with an
// instruction the model can act on before the request is forwarded.
//
// Requests are the trustworthy direction. They originate at the user's client
// and reach cleanerproxy before the upstream is involved, so the upstream cannot
// author one. Everything in the response direction is suspect; a tool_result in
// a request is not.

// ToolResults extracts every tool output carried in a request, so the caller can
// look for answers to its own approval prompts.
func ToolResults(format Format, body []byte) []ToolResult {
	if format == FormatOpenAI {
		return openAIToolResults(body)
	}
	return anthropicToolResults(body)
}

func anthropicToolResults(body []byte) []ToolResult {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	var out []ToolResult
	for _, m := range req.Messages {
		var blocks []anthropicBlock
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "tool_result" || b.ToolUseID == "" {
				continue
			}
			out = append(out, ToolResult{ID: b.ToolUseID, Text: flattenResultContent(b.Content)})
		}
	}
	return out
}

func openAIToolResults(body []byte) []ToolResult {
	var req struct {
		Messages []struct {
			Role       string          `json:"role"`
			ToolCallID string          `json:"tool_call_id"`
			Content    json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	var out []ToolResult
	for _, m := range req.Messages {
		if m.Role != "tool" || m.ToolCallID == "" {
			continue
		}
		out = append(out, ToolResult{ID: m.ToolCallID, Text: flattenResultContent(m.Content)})
	}
	return out
}

// flattenResultContent handles the string form, the array-of-parts form, and the
// bare-JSON form that clients use when a tool returns structured data.
//
// Falls back to the raw text so a shape this does not model still yields
// something to match against. That is safe because matching requires the exact
// approve label and the absence of the deny label: extra surrounding bytes
// cannot turn a refusal into consent.
func flattenResultContent(raw json.RawMessage) string {
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
		var b []string
		for _, p := range parts {
			if p.Text != "" {
				b = append(b, p.Text)
			}
		}
		if len(b) > 0 {
			return strings.Join(b, "\n")
		}
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return strings.Join(list, "\n")
	}
	return string(raw)
}

// RewriteToolResults replaces the content of the identified tool results.
//
// Used to swap the user's literal selection for an explicit instruction. The
// model has to act on the outcome, and a bare option label does not tell it
// what to do; replacing the text also keeps the user's own words out of the
// upstream's hands, which is worth doing against a provider assumed to retain
// everything it sees.
//
// Returns the original body unchanged when there is nothing to rewrite, so the
// common path does not pay for a re-serialization.
func RewriteToolResults(format Format, body []byte, replacements map[string]string) ([]byte, error) {
	if len(replacements) == 0 {
		return body, nil
	}
	if format == FormatOpenAI {
		return rewriteOpenAIToolResults(body, replacements)
	}
	return rewriteAnthropicToolResults(body, replacements)
}

func rewriteAnthropicToolResults(body []byte, replacements map[string]string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	messages, _ := raw["messages"].([]any)
	for _, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, b := range blocks {
			blk, ok := b.(map[string]any)
			if !ok || blk["type"] != "tool_result" {
				continue
			}
			id, _ := blk["tool_use_id"].(string)
			text, found := replacements[id]
			if !found {
				continue
			}
			blk["content"] = text
			// An approval prompt is never an error, and leaving a stale
			// is_error would make the model treat the instruction as a failure.
			delete(blk, "is_error")
		}
	}
	return json.Marshal(raw)
}

func rewriteOpenAIToolResults(body []byte, replacements map[string]string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	messages, _ := raw["messages"].([]any)
	for _, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok || msg["role"] != "tool" {
			continue
		}
		id, _ := msg["tool_call_id"].(string)
		text, found := replacements[id]
		if !found {
			continue
		}
		msg["content"] = text
	}
	return json.Marshal(raw)
}
