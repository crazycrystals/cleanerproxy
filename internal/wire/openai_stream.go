package wire

// Streaming quarantine for the OpenAI Chat Completions API.
//
// The quarantine principle is identical to the Anthropic filter, but the wire
// shape forces a different implementation:
//
//   - There are no typed events. Every chunk is an unnamed `data:` JSON object,
//     so the filter must inspect each chunk's contents to decide its fate
//     rather than switching on an event name.
//   - A single chunk can carry both ordinary content and tool-call fragments in
//     the same delta, so chunks cannot simply be forwarded or withheld whole.
//     They must be split: content forwarded, tool fragments retained.
//   - Tool calls are keyed by an integer `index` within `delta.tool_calls`, and
//     the `id` and `name` usually appear only in the first fragment for that
//     index. Later fragments carry arguments alone.
//   - The stream terminates with a literal `data: [DONE]` sentinel rather than
//     a structured event.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"cleanerproxy/internal/verdict"
)

// oaiPending is a quarantined OpenAI tool call under assembly, keyed by the
// index that appears in delta.tool_calls[].index.
type oaiPending struct {
	Index    int
	ID       string
	Name     string
	ArgParts []string

	// firstFragment retains the original id/type/function envelope so a
	// cleared call can be released in the shape the client expects.
	firstFragment map[string]any
}

func (p *oaiPending) args() string {
	var n int
	for _, s := range p.ArgParts {
		n += len(s)
	}
	buf := make([]byte, 0, n)
	for _, s := range p.ArgParts {
		buf = append(buf, s...)
	}
	return string(buf)
}

// OpenAIStreamFilter mediates one streaming Chat Completions response.
type OpenAIStreamFilter struct {
	RC    *RequestContext
	Guard ResponseGuard
	Out   *Writer

	OnVerdict    func(*verdict.Verdict, verdict.Action)
	OnAdDetected func(text string)

	meta    ResponseMeta
	pending map[int]*oaiPending
	order   []int

	// chunkTemplate retains the envelope fields (id, model, created, object)
	// from a real chunk so synthesized chunks are indistinguishable in shape.
	chunkTemplate map[string]any

	heldFinish *Event
	malformed  int
	flushed    bool

	// textAccum accumulates text deltas for post-hoc ad scanning.
	textAccum []byte
}

// NewOpenAIStreamFilter constructs a filter.
func NewOpenAIStreamFilter(rc *RequestContext, g ResponseGuard, out *Writer) *OpenAIStreamFilter {
	return &OpenAIStreamFilter{
		RC:      rc,
		Guard:   g,
		Out:     out,
		pending: map[int]*oaiPending{},
	}
}

// Run consumes the upstream stream and writes the filtered stream to Out.
func (f *OpenAIStreamFilter) Run(upstream io.Reader) error {
	r := NewReader(upstream)

	for {
		ev, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if ferr := f.finish(); ferr != nil {
					return ferr
				}
				return nil
			}
			return err
		}

		// The terminator must be emitted only after quarantined calls have
		// been resolved, or the client sees the stream end before the tool
		// calls arrive.
		if ev.IsDone() {
			if ferr := f.finish(); ferr != nil {
				return ferr
			}
			return f.Out.Write(ev)
		}

		out, err := f.process(ev)
		if err != nil {
			return err
		}
		if out == nil {
			continue // fully withheld
		}
		if err := f.Out.Write(*out); err != nil {
			return err
		}
	}
}

// process returns the event to forward, or nil if it was withheld entirely.
func (f *OpenAIStreamFilter) process(ev Event) (*Event, error) {
	var chunk map[string]any
	if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
		// Withheld for the same reason as the Anthropic filter: an unparseable
		// chunk may carry tool-call fragments we cannot identify, and
		// forwarding it would bypass the quarantine.
		f.malformed++
		return nil, nil
	}

	if f.chunkTemplate == nil {
		f.chunkTemplate = map[string]any{}
		for _, k := range []string{"id", "object", "created", "model", "system_fingerprint"} {
			if v, ok := chunk[k]; ok {
				f.chunkTemplate[k] = v
			}
		}
		f.meta.MessageStartCount = 1
		if m, ok := chunk["model"].(string); ok {
			f.meta.Model = m
		}
	}

	if u, ok := chunk["usage"].(map[string]any); ok {
		if ct, ok := u["completion_tokens"].(float64); ok && ct > 0 {
			f.meta.OutputTokens = int(ct)
		}
	}

	choices, _ := chunk["choices"].([]any)
	if len(choices) == 0 {
		return &ev, nil
	}

	sawFinish := false
	anyContentRemains := false

	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}

		if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
			f.meta.StopReason = normalizeFinishReason(fr)
			sawFinish = true
		}

		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			if choice["finish_reason"] != nil {
				continue
			}
			anyContentRemains = true
			continue
		}

		if s, ok := delta["content"].(string); ok && s != "" {
			f.meta.TextBytes += len(s)
			f.textAccum = append(f.textAccum, s...)
			anyContentRemains = true
		}
		if _, ok := delta["role"]; ok {
			anyContentRemains = true
		}

		// Extract and withhold tool-call fragments, leaving the rest intact.
		if tcs, ok := delta["tool_calls"].([]any); ok && len(tcs) > 0 {
			f.absorbToolCalls(tcs)
			delete(delta, "tool_calls")
		}
	}

	if sawFinish {
		// Hold the terminating chunk until quarantined calls are resolved, so
		// released tool calls precede it.
		cp := ev
		f.heldFinish = &cp
		if err := f.finish(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	if !anyContentRemains {
		// The chunk carried nothing but tool-call fragments; drop it.
		return nil, nil
	}

	// Re-serialize, since tool_calls were stripped out.
	b, err := json.Marshal(chunk)
	if err != nil {
		return &ev, nil
	}
	ev.Data = string(b)
	return &ev, nil
}

// absorbToolCalls accumulates tool-call fragments into the quarantine.
func (f *OpenAIStreamFilter) absorbToolCalls(tcs []any) {
	for _, t := range tcs {
		tc, ok := t.(map[string]any)
		if !ok {
			continue
		}
		idx := 0
		if v, ok := tc["index"].(float64); ok {
			idx = int(v)
		}
		pb, exists := f.pending[idx]
		if !exists {
			pb = &oaiPending{Index: idx, firstFragment: map[string]any{}}
			f.pending[idx] = pb
			f.order = append(f.order, idx)
			// Preserve the envelope from the first fragment for this index.
			for k, v := range tc {
				if k != "function" {
					pb.firstFragment[k] = v
				}
			}
		}
		if id, ok := tc["id"].(string); ok && id != "" {
			pb.ID = id
			pb.firstFragment["id"] = id
		}
		fn, ok := tc["function"].(map[string]any)
		if !ok {
			continue
		}
		if n, ok := fn["name"].(string); ok && n != "" {
			pb.Name = n
		}
		if a, ok := fn["arguments"].(string); ok && a != "" {
			pb.ArgParts = append(pb.ArgParts, a)
		}
	}
}

// finish inspects quarantined calls, releases or replaces them, then emits the
// held terminating chunk.
func (f *OpenAIStreamFilter) finish() error {
	if f.flushed {
		return nil
	}
	f.flushed = true

	v := &verdict.Verdict{}

	if f.malformed > 0 {
		sev := verdict.SeveritySuspicious
		if len(f.order) > 0 {
			sev = verdict.SeverityMalicious
		}
		v.Add(verdict.Finding{
			Tier:       verdict.TierStructural,
			Rule:       "stream.malformed_chunk",
			Severity:   sev,
			Confidence: 1.0,
			Message: fmt.Sprintf("Upstream sent %d stream chunk(s) containing invalid JSON. These were discarded "+
				"rather than forwarded, since an unparseable chunk may carry tool-call fragments that would "+
				"otherwise bypass inspection.", f.malformed),
		})
	}

	sort.Ints(f.order)
	calls := make([]verdict.ToolCall, 0, len(f.order))

	for _, idx := range f.order {
		pb := f.pending[idx]
		args := pb.args()
		if args == "" {
			args = "{}"
		}
		f.meta.ToolCallBytes += len(args)
		f.meta.BlockIndices = append(f.meta.BlockIndices, idx)

		var input map[string]any
		if err := json.Unmarshal([]byte(args), &input); err != nil {
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "stream.tool_call.incomplete",
				Severity:   verdict.SeverityMalicious,
				ToolCallID: pb.ID,
				ToolName:   pb.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf("Tool call to %q was withheld because its assembled arguments are not "+
					"valid JSON (%v). A client assembling partial arguments can be steered into a different "+
					"call than the provider generated.", pb.Name, err),
				Evidence: truncateStr(args, 200),
			})
			input = nil
		}

		calls = append(calls, verdict.ToolCall{
			ID:         pb.ID,
			Name:       pb.Name,
			Input:      input,
			RawInput:   json.RawMessage(args),
			BlockIndex: idx,
		})
	}

	action := verdict.ActionAllow
	if f.Guard != nil && len(calls) > 0 {
		gv, ga := f.Guard.Evaluate(f.RC, calls, f.meta)
		if gv != nil {
			v.Findings = append(v.Findings, gv.Findings...)
		}
		action = ga
	}
	if v.MaxSeverity() >= verdict.SeverityMalicious && action == verdict.ActionAllow {
		action = verdict.ActionDefang
	}

	if f.OnVerdict != nil {
		f.OnVerdict(v, action)
	}

	if action == verdict.ActionAbort {
		_ = f.Out.Write(Event{Data: mustJSON(map[string]any{
			"error": map[string]any{
				"type":    "cleanerproxy_blocked",
				"code":    "cleanerproxy_blocked",
				"message": verdict.Explain(v.Findings, calls),
			},
		})})
		return ErrAborted
	}

	blocked := v.BlockedCallIDs()
	var released []any
	var notices []string

	for _, idx := range f.order {
		pb := f.pending[idx]
		if blocked[pb.ID] || (pb.ID == "" && len(blocked) > 0) {
			rep := Replacement{Notice: verdict.Explain(v.FindingsFor(pb.ID), calls)}
			if f.Guard != nil {
				rep = f.Guard.Replacement(f.RC, callByID(calls, pb.ID), v.FindingsFor(pb.ID))
			}
			if rep.Question != nil {
				// The approval prompt replaces the blocked call in the same
				// tool_calls slot. Its arguments are the prompt, so nothing
				// executable from the original call survives.
				released = append(released, map[string]any{
					"index": idx,
					"id":    rep.Question.ID,
					"type":  "function",
					"function": map[string]any{
						"name":      rep.Question.Name,
						"arguments": string(rep.Question.Args),
					},
				})
				continue
			}
			notices = append(notices, rep.Notice)
			continue
		}
		frag := map[string]any{}
		for k, val := range pb.firstFragment {
			frag[k] = val
		}
		frag["index"] = idx
		frag["function"] = map[string]any{"name": pb.Name, "arguments": pb.args()}
		released = append(released, frag)
	}

	// Released calls are emitted as a single coalesced chunk. Splitting them
	// back into the original fragment boundaries would be pointless: any
	// client must already handle arbitrary fragmentation, and one complete
	// chunk is strictly easier to consume.
	if len(released) > 0 {
		if err := f.emitChunk(map[string]any{"tool_calls": released}, ""); err != nil {
			return err
		}
	}
	for _, n := range notices {
		if err := f.emitChunk(map[string]any{"content": n}, ""); err != nil {
			return err
		}
	}

	if f.heldFinish != nil {
		ev := *f.heldFinish
		if len(f.order) > 0 && len(released) == 0 {
			ev.Data = rewriteFinishReason(ev.Data, "stop")
		}
		if err := f.Out.Write(ev); err != nil {
			return err
		}
		f.heldFinish = nil
	}

	// Post-hoc ad detection on accumulated text.
	if f.OnAdDetected != nil && len(f.textAccum) > 0 {
		f.OnAdDetected(string(f.textAccum))
	}

	return nil
}

// emitChunk writes a synthesized chunk carrying the given delta.
func (f *OpenAIStreamFilter) emitChunk(delta map[string]any, finishReason string) error {
	chunk := map[string]any{}
	for k, v := range f.chunkTemplate {
		chunk[k] = v
	}
	if chunk["object"] == nil {
		chunk["object"] = "chat.completion.chunk"
	}
	choice := map[string]any{"index": 0, "delta": delta}
	if finishReason != "" {
		choice["finish_reason"] = finishReason
	} else {
		choice["finish_reason"] = nil
	}
	chunk["choices"] = []any{choice}
	return f.Out.Write(Event{Data: mustJSON(chunk)})
}

func rewriteFinishReason(data, reason string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return data
	}
	choices, _ := m["choices"].([]any)
	for _, c := range choices {
		if choice, ok := c.(map[string]any); ok {
			if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
				choice["finish_reason"] = reason
			}
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return string(out)
}
