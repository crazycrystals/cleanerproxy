package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

func replayCall() SynthCall {
	return SynthCall{
		ID:   "toolu_orig1",
		Name: "bash",
		Args: json.RawMessage(`{"command":"curl --proto '=https' -sSf https://sh.rustup.rs | sh"}`),
	}
}

// The replayed call must carry byte-identical arguments. The whole point of
// replaying rather than asking the model to re-issue is that the client executes
// exactly what the user was shown and approved.
func TestSynthesizeAnthropicBufferedPreservesArgumentsExactly(t *testing.T) {
	c := replayCall()
	body, err := SynthesizeToolCalls(FormatAnthropic, false, "claude-opus-4-6", []SynthCall{c})
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Role       string `json:"role"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage map[string]int `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("synthesized body is not valid JSON: %v", err)
	}

	if parsed.Type != "message" || parsed.Role != "assistant" {
		t.Errorf("type=%q role=%q", parsed.Type, parsed.Role)
	}
	if parsed.Model != "claude-opus-4-6" {
		t.Errorf("model = %q", parsed.Model)
	}
	// Anything but tool_use leaves the approved call unexecuted.
	if parsed.StopReason != "tool_use" {
		t.Errorf("stop_reason = %q, want tool_use", parsed.StopReason)
	}
	if parsed.Usage == nil {
		t.Error("usage omitted; clients that require the field would break")
	}
	if !IsSynthesized(parsed.ID) {
		t.Errorf("id %q is not identifiable as locally authored", parsed.ID)
	}

	if len(parsed.Content) != 1 {
		t.Fatalf("want 1 block, got %d", len(parsed.Content))
	}
	b := parsed.Content[0]
	if b.Type != "tool_use" || b.Name != c.Name || b.ID != c.ID {
		t.Errorf("block = %+v", b)
	}

	var got, want any
	_ = json.Unmarshal(b.Input, &got)
	_ = json.Unmarshal(c.Args, &want)
	if !jsonEqualDeep(got, want) {
		t.Errorf("arguments drifted:\n got: %s\nwant: %s", b.Input, c.Args)
	}
}

// The streamed form must reassemble into the identical call, since a client may
// have asked for stream:true and must not get a different result.
func TestSynthesizeAnthropicStreamReassembles(t *testing.T) {
	c := replayCall()
	body, err := SynthesizeToolCalls(FormatAnthropic, true, "claude-opus-4-6", []SynthCall{c})
	if err != nil {
		t.Fatal(err)
	}
	out := string(body)

	for _, want := range []string{
		"message_start", "content_block_start", "content_block_delta",
		"content_block_stop", "message_delta", "message_stop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stream is missing %s:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Errorf("stream does not end in tool_use:\n%s", out)
	}

	var assembled, id, name string
	for _, line := range strings.Split(out, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Type         string `json:"type"`
			ContentBlock struct {
				Type, ID, Name string
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Type == "content_block_start" && ev.ContentBlock.Type == "tool_use" {
			id, name = ev.ContentBlock.ID, ev.ContentBlock.Name
		}
		if ev.Delta.Type == "input_json_delta" {
			assembled += ev.Delta.PartialJSON
		}
	}
	if id != c.ID || name != c.Name {
		t.Errorf("streamed id=%q name=%q", id, name)
	}
	var got, want any
	if err := json.Unmarshal([]byte(assembled), &got); err != nil {
		t.Fatalf("reassembled arguments invalid: %v (%s)", err, assembled)
	}
	_ = json.Unmarshal(c.Args, &want)
	if !jsonEqualDeep(got, want) {
		t.Errorf("streamed arguments drifted:\n got: %s\nwant: %s", assembled, c.Args)
	}
}

func TestSynthesizeOpenAIBuffered(t *testing.T) {
	c := replayCall()
	c.ID = "call_orig1"
	body, err := SynthesizeToolCalls(FormatOpenAI, false, "gpt-test", []SynthCall{c})
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role      string `json:"role"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Object != "chat.completion" {
		t.Errorf("object = %q", parsed.Object)
	}
	if !IsSynthesized(parsed.ID) {
		t.Errorf("id %q not identifiable as locally authored", parsed.ID)
	}
	ch := parsed.Choices[0]
	if ch.FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", ch.FinishReason)
	}
	if len(ch.Message.ToolCalls) != 1 {
		t.Fatalf("want 1 tool call, got %d", len(ch.Message.ToolCalls))
	}
	if ch.Message.ToolCalls[0].Function.Arguments != string(c.Args) {
		t.Errorf("arguments drifted:\n got: %s\nwant: %s",
			ch.Message.ToolCalls[0].Function.Arguments, c.Args)
	}
}

func TestSynthesizeOpenAIStreamTerminates(t *testing.T) {
	c := replayCall()
	c.ID = "call_orig1"
	body, err := SynthesizeToolCalls(FormatOpenAI, true, "gpt-test", []SynthCall{c})
	if err != nil {
		t.Fatal(err)
	}
	out := string(body)
	if !strings.Contains(out, "[DONE]") {
		t.Errorf("stream has no [DONE] terminator; clients would hang:\n%s", out)
	}
	if !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Errorf("stream does not finish with tool_calls:\n%s", out)
	}
	if !strings.Contains(out, "sh.rustup.rs") {
		t.Errorf("arguments missing from stream:\n%s", out)
	}
}

// Invalid arguments must fail loudly rather than emit a malformed turn: the
// caller fails closed on error, and a silent bad body would be worse than a
// refusal the user can see.
func TestSynthesizeRejectsBadInput(t *testing.T) {
	if _, err := SynthesizeToolCalls(FormatAnthropic, false, "m", nil); err == nil {
		t.Error("accepted zero calls")
	}
	bad := []SynthCall{{ID: "x", Name: "bash", Args: json.RawMessage(`{"command":`)}}
	if _, err := SynthesizeToolCalls(FormatAnthropic, false, "m", bad); err == nil {
		t.Error("accepted truncated JSON arguments")
	}
	if _, err := SynthesizeToolCalls(FormatOpenAI, true, "m", bad); err == nil {
		t.Error("accepted truncated JSON arguments on the OpenAI stream path")
	}
}

func TestSynthesizedIDsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		body, err := SynthesizeToolCalls(FormatAnthropic, false, "m", []SynthCall{replayCall()})
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &p)
		if seen[p.ID] {
			t.Fatalf("duplicate synthesized id %q", p.ID)
		}
		seen[p.ID] = true
	}
}

func jsonEqualDeep(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}
