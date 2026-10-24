package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Synthesis of an assistant turn that cleanerproxy authors itself.
//
// WHY THIS EXISTS
//
// When the user approves a blocked call, the obvious implementation is to tell
// the model "the user approved it, re-issue that call". That does not work, and
// the reason is instructive.
//
// Measured against Claude 4.6 Opus through this proxy: a tool_result saying the
// user approved a `curl … | bash` and asking for a byte-identical re-issue was
// identified as a prompt-injection attempt and refused, with a correct
// explanation of why piping a remote script into a shell is dangerous. The model
// was right. Tool output is attacker-reachable, so an instruction arriving in a
// tool_result deserves exactly that suspicion — it is the same principle that
// keeps tool_result out of RequestContext.UserTurns on the inspection side.
//
// Two further problems with asking the model, independent of refusal:
//   - it may re-issue something subtly different, which then fails the
//     fingerprint check and re-prompts the user for no reason;
//   - it costs a round trip to re-derive a call cleanerproxy is already holding.
//
// So cleanerproxy replays the approved call itself. What the client receives is
// byte-for-byte the arguments the user was shown and consented to, which is
// stricter than anything the model would reconstruct.

// SynthCall is a tool call cleanerproxy emits on its own authority.
type SynthCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

// SynthesizeToolCalls builds a complete assistant response containing exactly
// the given tool calls.
//
// For stream=true the result is a full SSE body, so the caller can write it with
// the SSE headers set and the client sees an ordinary streamed turn.
func SynthesizeToolCalls(format Format, stream bool, model string, calls []SynthCall) ([]byte, error) {
	if len(calls) == 0 {
		return nil, fmt.Errorf("wire: no calls to synthesize")
	}
	for _, c := range calls {
		if !json.Valid(c.Args) {
			return nil, fmt.Errorf("wire: call %q has invalid JSON arguments", c.Name)
		}
	}
	if format == FormatOpenAI {
		if stream {
			return synthOpenAIStream(model, calls)
		}
		return synthOpenAIBuffered(model, calls)
	}
	if stream {
		return synthAnthropicStream(model, calls)
	}
	return synthAnthropicBuffered(model, calls)
}

func synthAnthropicBuffered(model string, calls []SynthCall) ([]byte, error) {
	content := make([]any, 0, len(calls))
	for _, c := range calls {
		var input any
		if err := json.Unmarshal(c.Args, &input); err != nil {
			return nil, err
		}
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    c.ID,
			"name":  c.Name,
			"input": input,
		})
	}
	return json.Marshal(map[string]any{
		"id":      synthMessageID(),
		"type":    "message",
		"role":    "assistant",
		"model":   model,
		"content": content,
		// The turn is waiting on tool results, so this must be tool_use. An
		// end_turn here would leave the approved call unexecuted.
		"stop_reason":   "tool_use",
		"stop_sequence": nil,
		// Zero usage is honest: no tokens were spent, because no model was
		// called. Omitting the field entirely breaks clients that require it.
		"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
	})
}

func synthAnthropicStream(model string, calls []SynthCall) ([]byte, error) {
	var b bytes.Buffer
	w := NewWriter(&b)
	msgID := synthMessageID()

	write := func(name string, payload map[string]any) error {
		return w.Write(Event{Name: name, Data: mustJSON(payload)})
	}

	if err := write("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": msgID, "type": "message", "role": "assistant", "model": model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	}); err != nil {
		return nil, err
	}

	for i, c := range calls {
		if err := write("content_block_start", map[string]any{
			"type": "content_block_start", "index": i,
			"content_block": map[string]any{
				"type": "tool_use", "id": c.ID, "name": c.Name, "input": map[string]any{},
			},
		}); err != nil {
			return nil, err
		}
		// Arguments arrive as input_json_delta. One fragment carrying the whole
		// object is valid and is what any short call looks like on the wire.
		if err := write("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": i,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": string(c.Args)},
		}); err != nil {
			return nil, err
		}
		if err := write("content_block_stop", map[string]any{
			"type": "content_block_stop", "index": i,
		}); err != nil {
			return nil, err
		}
	}

	if err := write("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "tool_use", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": 0},
	}); err != nil {
		return nil, err
	}
	if err := write("message_stop", map[string]any{"type": "message_stop"}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func synthOpenAIBuffered(model string, calls []SynthCall) ([]byte, error) {
	tcs := make([]any, 0, len(calls))
	for i, c := range calls {
		tcs = append(tcs, map[string]any{
			"index": i,
			"id":    c.ID,
			"type":  "function",
			"function": map[string]any{
				"name":      c.Name,
				"arguments": string(c.Args),
			},
		})
	}
	return json.Marshal(map[string]any{
		"id":      synthCompletionID(),
		"object":  "chat.completion",
		"created": 0,
		"model":   model,
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role": "assistant", "content": nil, "tool_calls": tcs,
			},
			"finish_reason": "tool_calls",
		}},
		"usage": map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
	})
}

func synthOpenAIStream(model string, calls []SynthCall) ([]byte, error) {
	var b bytes.Buffer
	w := NewWriter(&b)
	id := synthCompletionID()

	chunk := func(delta map[string]any, finish any) error {
		return w.Write(Event{Data: mustJSON(map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": 0, "model": model,
			"choices": []any{map[string]any{
				"index": 0, "delta": delta, "finish_reason": finish,
			}},
		})})
	}

	tcs := make([]any, 0, len(calls))
	for i, c := range calls {
		tcs = append(tcs, map[string]any{
			"index": i, "id": c.ID, "type": "function",
			"function": map[string]any{"name": c.Name, "arguments": string(c.Args)},
		})
	}
	if err := chunk(map[string]any{"role": "assistant", "tool_calls": tcs}, nil); err != nil {
		return nil, err
	}
	if err := chunk(map[string]any{}, "tool_calls"); err != nil {
		return nil, err
	}
	// Clients treat [DONE] as the terminator; omitting it makes them wait.
	if err := w.Write(Event{Data: "[DONE]"}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Synthetic ids are marked so they are identifiable in a transcript or an audit
// log as locally authored rather than provider issued.
func synthMessageID() string    { return "msg_cpxy" + randHex(12) }
func synthCompletionID() string { return "chatcmpl-cpxy" + randHex(12) }

// randHex returns n hex characters. Falls back to a fixed marker if the system
// RNG fails: these ids are labels, not secrets, so a collision is cosmetic and
// failing the whole approval over it would be worse.
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(b)[:n]
}

// SynthIDPrefixes are the markers used above, exported for tests and audit
// tooling that needs to recognise locally authored turns.
var SynthIDPrefixes = []string{"msg_cpxy", "chatcmpl-cpxy"}

// IsSynthesized reports whether a response id was authored by cleanerproxy.
func IsSynthesized(id string) bool {
	for _, p := range SynthIDPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}
