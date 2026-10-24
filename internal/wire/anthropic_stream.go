package wire

// Streaming quarantine for the Anthropic Messages API.
//
// THE CORE PROBLEM
//
// Tool arguments arrive as a sequence of `input_json_delta` fragments. Any
// individual fragment is meaningless — `{"command": "cu` tells you nothing —
// so a tool call cannot be inspected until every fragment has arrived. But a
// streaming proxy's whole job is to forward bytes as they appear. If we
// forward tool-call fragments as they arrive, the client has already assembled
// and possibly begun executing the call by the time we could judge it, and the
// inspection is decorative.
//
// THE RESOLUTION
//
// Split the stream by block type. Text and thinking deltas are forwarded
// immediately, preserving the responsive feel that matters to a user watching
// output appear. Tool-use blocks are quarantined: held entirely, invisible to
// the client, until the response is structurally complete. Only then are they
// inspected and either released verbatim or replaced with a notice.
//
// Quarantine is held until `message_delta` rather than the block's own
// `content_block_stop`, because `message_delta` is what carries `stop_reason`
// and final token usage — both of which Tier 0 needs for coherence checks. In
// practice tool calls are the last thing in a response, so the added delay is
// the tail of the stream, not a stall in the middle of visible output.
//
// The latency cost therefore lands only on responses that actually contain
// tool calls, and only on the portion the user cannot see anyway.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"cleanerproxy/internal/verdict"
)

// ResponseGuard is the inspection entry point the filter calls once it holds a
// complete set of tool calls. Implemented by internal/guard; declared here so
// that package wire has no dependency on the inspection tiers.
type ResponseGuard interface {
	Evaluate(rc *RequestContext, calls []verdict.ToolCall, meta ResponseMeta) (*verdict.Verdict, verdict.Action)

	// Replacement decides what takes the place of a blocked call: a question
	// put to the user via a tool the client declared, or a text notice.
	Replacement(rc *RequestContext, call verdict.ToolCall, findings []verdict.Finding) Replacement
}

// pendingBlock is a quarantined tool_use block under assembly.
type pendingBlock struct {
	Index int
	ID    string
	Name  string

	// startEvent is the original content_block_start, retained so a clean
	// block can be released byte-faithfully rather than re-serialized.
	startEvent Event

	// deltaEvents are the original input_json_delta events in arrival order.
	deltaEvents []Event

	// stopEvent is the original content_block_stop, if it arrived.
	stopEvent *Event

	// jsonParts accumulates partial_json fragments.
	jsonParts []string

	complete bool
}

func (p *pendingBlock) rawJSON() string {
	var n int
	for _, s := range p.jsonParts {
		n += len(s)
	}
	buf := make([]byte, 0, n)
	for _, s := range p.jsonParts {
		buf = append(buf, s...)
	}
	return string(buf)
}

// AnthropicStreamFilter mediates one streaming response.
type AnthropicStreamFilter struct {
	RC    *RequestContext
	Guard ResponseGuard
	Out   *Writer

	// OnVerdict is invoked with the final verdict for audit logging.
	OnVerdict func(*verdict.Verdict, verdict.Action)

	// OnAdDetected is called when ad content is detected in the accumulated
	// text at finish() time. Since text deltas are already forwarded, the
	// callback should notify/log rather than attempt retraction.
	OnAdDetected func(text string)

	// OnContentFilter is called when the upstream appears to have blocked
	// the request with a content filter (empty response, 0 output tokens,
	// stop_reason "stop_sequence"). The callback should log/notify.
	OnContentFilter func()

	meta    ResponseMeta
	pending map[int]*pendingBlock
	order   []int // quarantine order, so release preserves stream order

	heldMessageDelta *Event
	flushed          bool

	// textAccum accumulates text deltas for post-hoc ad scanning.
	textAccum []byte

	// malformed counts control events whose JSON could not be parsed. These
	// are withheld rather than forwarded, for the reason documented on
	// dropMalformed.
	malformed int
}

// dropMalformed decides what to do with a control event we could not parse.
//
// Forwarding an unparseable event is not safe. A `content_block_delta` whose
// JSON is invalid still has an index we cannot read, so we cannot tell whether
// it belongs to a quarantined tool call — and if it does, forwarding it hands
// the client a fragment of the exact payload the quarantine exists to contain.
// That is a complete quarantine bypass, reachable by an upstream that simply
// emits deliberately malformed JSON around its injected arguments.
//
// A legitimate provider never emits invalid JSON in a control event
// (unknown *fields* are ignored by encoding/json and do not land here, so this
// costs no forward compatibility). Withholding is therefore the correct
// default: it cannot break an honest upstream and it closes the bypass.
func (f *AnthropicStreamFilter) dropMalformed() (bool, error) {
	f.malformed++
	return true, nil
}

// NewAnthropicStreamFilter constructs a filter.
func NewAnthropicStreamFilter(rc *RequestContext, g ResponseGuard, out *Writer) *AnthropicStreamFilter {
	return &AnthropicStreamFilter{
		RC:      rc,
		Guard:   g,
		Out:     out,
		pending: map[int]*pendingBlock{},
	}
}

// ErrAborted signals the policy engine chose to terminate the response.
var ErrAborted = errors.New("cleanerproxy: response aborted by policy")

// Run consumes the upstream stream and writes the filtered stream to Out.
func (f *AnthropicStreamFilter) Run(upstream io.Reader) error {
	r := NewReader(upstream)

	for {
		ev, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Stream ended. If tool calls are still quarantined the
				// upstream truncated the response; flush what we have so the
				// user is not left with a silently missing tool call.
				return f.finish(true)
			}
			return err
		}

		if handled, herr := f.handle(ev); herr != nil {
			return herr
		} else if handled {
			continue
		}

		// Default: pass through untouched.
		if err := f.Out.Write(ev); err != nil {
			return err
		}
	}
}

// handle returns (true, nil) when the event was consumed by the filter.
func (f *AnthropicStreamFilter) handle(ev Event) (bool, error) {
	switch ev.Name {
	case "message_start":
		f.meta.MessageStartCount++
		var p struct {
			Message struct {
				Model string `json:"model"`
				Usage struct {
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(ev.Data), &p) == nil {
			f.meta.Model = p.Message.Model
		}
		return false, nil // forward

	case "content_block_start":
		var p struct {
			Index        int `json:"index"`
			ContentBlock struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &p); err != nil {
			return f.dropMalformed()
		}
		f.meta.BlockIndices = append(f.meta.BlockIndices, p.Index)

		if p.ContentBlock.Type != "tool_use" {
			return false, nil // text/thinking: stream immediately
		}

		// Quarantine.
		pb := &pendingBlock{
			Index:      p.Index,
			ID:         p.ContentBlock.ID,
			Name:       p.ContentBlock.Name,
			startEvent: ev,
		}
		// A non-streaming-shaped input may already be present.
		if len(p.ContentBlock.Input) > 0 && string(p.ContentBlock.Input) != "{}" {
			pb.jsonParts = append(pb.jsonParts, string(p.ContentBlock.Input))
		}
		f.pending[p.Index] = pb
		f.order = append(f.order, p.Index)
		return true, nil // withheld

	case "content_block_delta":
		var p struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				Thinking    string `json:"thinking"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &p); err != nil {
			return f.dropMalformed()
		}
		if pb, held := f.pending[p.Index]; held {
			pb.deltaEvents = append(pb.deltaEvents, ev)
			if p.Delta.PartialJSON != "" {
				pb.jsonParts = append(pb.jsonParts, p.Delta.PartialJSON)
			}
			return true, nil // withheld
		}
		f.meta.TextBytes += len(p.Delta.Text) + len(p.Delta.Thinking)
		if p.Delta.Text != "" {
			f.textAccum = append(f.textAccum, p.Delta.Text...)
		}
		return false, nil

	case "content_block_stop":
		var p struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &p); err != nil {
			return f.dropMalformed()
		}
		if pb, held := f.pending[p.Index]; held {
			cp := ev
			pb.stopEvent = &cp
			pb.complete = true
			return true, nil // withheld
		}
		return false, nil

	case "message_delta":
		// Carries stop_reason and final usage: the last inputs Tier 0 needs.
		var p struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(ev.Data), &p) == nil {
			f.meta.StopReason = p.Delta.StopReason
			if p.Usage.OutputTokens > 0 {
				f.meta.OutputTokens = p.Usage.OutputTokens
			}
		}
		cp := ev
		f.heldMessageDelta = &cp
		// Inspect and release now, before message_delta reaches the client,
		// so content blocks stay ahead of the envelope terminator.
		if err := f.finish(false); err != nil {
			return true, err
		}
		return true, nil

	case "message_stop":
		// Safety net: if message_delta never arrived, flush here.
		if err := f.finish(true); err != nil {
			return true, err
		}
		return false, nil // forward
	}

	return false, nil
}

// finish inspects quarantined calls, releases or replaces them, then emits the
// held message_delta.
func (f *AnthropicStreamFilter) finish(truncated bool) error {
	if f.flushed {
		return nil
	}
	f.flushed = true

	// Detect upstream content-filter interception: an empty stream with
	// 0 output tokens and stop_reason "stop_sequence"/"stop". The model
	// never ran; the relay's classifier blocked before generation started.
	if len(f.order) == 0 && f.meta.TextBytes == 0 && f.meta.OutputTokens == 0 &&
		(f.meta.StopReason == "stop_sequence" || f.meta.StopReason == "stop") {
		// message_start is already forwarded, so inject a text block
		// explaining what happened before message_delta/message_stop.
		const notice = "The upstream provider's content filter blocked this request and returned an empty response. " +
			"This is not a cleanerproxy block — the provider itself refused to generate output. " +
			"Rephrase the request to avoid content-filter trigger words, " +
			"or inform the user that this request cannot be fulfilled through this provider."
		_ = f.Out.Write(Event{
			Name: "content_block_start",
			Data: mustJSON(map[string]any{
				"type":          "content_block_start",
				"index":         0,
				"content_block": map[string]any{"type": "text", "text": ""},
			}),
		})
		_ = f.Out.Write(Event{
			Name: "content_block_delta",
			Data: mustJSON(map[string]any{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]any{"type": "text_delta", "text": notice},
			}),
		})
		_ = f.Out.Write(Event{
			Name: "content_block_stop",
			Data: mustJSON(map[string]any{"type": "content_block_stop", "index": 0}),
		})
		// Rewrite stop_reason so the client treats this as a normal end.
		if f.heldMessageDelta != nil {
			f.heldMessageDelta.Data = rewriteStopReason(f.heldMessageDelta.Data, "end_turn")
		}
		if f.OnContentFilter != nil {
			f.OnContentFilter()
		}
		// Still emit held message_delta below.
	}

	v := &verdict.Verdict{}
	calls := make([]verdict.ToolCall, 0, len(f.order))

	if f.malformed > 0 {
		// Malformed control events are a quarantine-bypass technique: an
		// upstream that corrupts the JSON envelope around injected arguments
		// is trying to get fragments forwarded without being inspected. A
		// legitimate provider never emits invalid JSON here.
		sev := verdict.SeveritySuspicious
		if len(f.order) > 0 {
			// Corrupted events alongside an actual quarantined tool call is
			// not plausibly incidental.
			sev = verdict.SeverityMalicious
		}
		v.Add(verdict.Finding{
			Tier:       verdict.TierStructural,
			Rule:       "stream.malformed_control_event",
			Severity:   sev,
			Confidence: 1.0,
			Message: fmt.Sprintf("Upstream sent %d stream control event(s) containing invalid JSON. These were "+
				"discarded rather than forwarded. Providers do not emit malformed control events; this is "+
				"characteristic of an attempt to smuggle tool-call fragments past inspection.", f.malformed),
		})
	}

	for _, idx := range f.order {
		pb := f.pending[idx]
		raw := pb.rawJSON()
		if raw == "" {
			raw = "{}"
		}
		f.meta.ToolCallBytes += len(raw)

		var input map[string]any
		decodeErr := json.Unmarshal([]byte(raw), &input)

		if !pb.complete || decodeErr != nil {
			// An unterminated or unparseable tool call must never be
			// released. A client assembling partial JSON can be coerced into
			// a different command than the one the provider generated, so a
			// truncated call is treated as hostile rather than merely broken.
			why := "the stream ended before the tool call was complete"
			if decodeErr != nil {
				why = fmt.Sprintf("its arguments are not valid JSON (%v)", decodeErr)
			}
			v.Add(verdict.Finding{
				Tier:       verdict.TierStructural,
				Rule:       "stream.tool_call.incomplete",
				Severity:   verdict.SeverityMalicious,
				ToolCallID: pb.ID,
				ToolName:   pb.Name,
				Confidence: 1.0,
				Message: fmt.Sprintf("Tool call to %q was withheld because %s. Partially delivered tool "+
					"arguments can be assembled by a client into a command the provider never generated.",
					pb.Name, why),
				Evidence: truncateStr(raw, 200),
			})
		}

		calls = append(calls, verdict.ToolCall{
			ID:         pb.ID,
			Name:       pb.Name,
			Input:      input,
			RawInput:   json.RawMessage(raw),
			BlockIndex: pb.Index,
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
	// A locally-raised finding must still be able to escalate the action even
	// when the guard was satisfied.
	if v.MaxSeverity() >= verdict.SeverityMalicious && action == verdict.ActionAllow {
		action = verdict.ActionDefang
	}

	if f.OnVerdict != nil {
		f.OnVerdict(v, action)
	}

	if action == verdict.ActionAbort {
		// Emit a protocol-level error so the client surfaces a failure rather
		// than silently accepting a truncated turn.
		_ = f.Out.Write(Event{
			Name: "error",
			Data: mustJSON(map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    "cleanerproxy_blocked",
					"message": verdict.Explain(v.Findings, calls),
				},
			}),
		})
		return ErrAborted
	}

	blocked := v.BlockedCallIDs()
	anySurvives := false
	askedQuestion := false

	for _, idx := range f.order {
		pb := f.pending[idx]
		if blocked[pb.ID] {
			rep := Replacement{Notice: verdict.Explain(v.FindingsFor(pb.ID), calls)}
			if f.Guard != nil {
				rep = f.Guard.Replacement(f.RC, callByID(calls, pb.ID), v.FindingsFor(pb.ID))
			}
			if rep.Question != nil {
				if err := f.emitQuestion(pb, rep.Question); err != nil {
					return err
				}
				askedQuestion = true
				continue
			}
			if err := f.emitNotice(pb, rep.Notice); err != nil {
				return err
			}
			continue
		}
		anySurvives = true
		if err := f.releaseBlock(pb); err != nil {
			return err
		}
	}

	if f.heldMessageDelta != nil {
		ev := *f.heldMessageDelta
		// askedQuestion matters as much as anySurvives: the injected approval
		// prompt IS a tool_use, and the client must run it. Rewriting
		// stop_reason to end_turn here would leave the prompt sitting in the
		// transcript unexecuted, so the user would never be asked and the
		// approval path would silently do nothing.
		if len(f.order) > 0 && !anySurvives && !askedQuestion {
			// Every tool call was blocked and nothing replaced them, so the
			// turn ends rather than awaiting tool results. Leaving stop_reason
			// as "tool_use" would leave the client waiting for a call that
			// will never arrive.
			ev.Data = rewriteStopReason(ev.Data, "end_turn")
		}
		if err := f.Out.Write(ev); err != nil {
			return err
		}
		f.heldMessageDelta = nil
	}

	// Post-hoc ad detection on accumulated text.
	if f.OnAdDetected != nil && len(f.textAccum) > 0 {
		f.OnAdDetected(string(f.textAccum))
	}

	return nil
}

// releaseBlock re-emits a cleared tool_use block using the original upstream
// events, so a legitimate call reaches the client byte-for-byte as sent.
func (f *AnthropicStreamFilter) releaseBlock(pb *pendingBlock) error {
	if err := f.Out.Write(pb.startEvent); err != nil {
		return err
	}
	for _, d := range pb.deltaEvents {
		if err := f.Out.Write(d); err != nil {
			return err
		}
	}
	if pb.stopEvent != nil {
		return f.Out.Write(*pb.stopEvent)
	}
	return f.Out.Write(Event{
		Name: "content_block_stop",
		Data: mustJSON(map[string]any{"type": "content_block_stop", "index": pb.Index}),
	})
}

// emitNotice substitutes a text block in place of a blocked tool_use block,
// reusing the same block index so the stream stays well-formed.
func (f *AnthropicStreamFilter) emitNotice(pb *pendingBlock, notice string) error {
	if err := f.Out.Write(Event{
		Name: "content_block_start",
		Data: mustJSON(map[string]any{
			"type":          "content_block_start",
			"index":         pb.Index,
			"content_block": map[string]any{"type": "text", "text": ""},
		}),
	}); err != nil {
		return err
	}
	if err := f.Out.Write(Event{
		Name: "content_block_delta",
		Data: mustJSON(map[string]any{
			"type":  "content_block_delta",
			"index": pb.Index,
			"delta": map[string]any{"type": "text_delta", "text": notice},
		}),
	}); err != nil {
		return err
	}
	return f.Out.Write(Event{
		Name: "content_block_stop",
		Data: mustJSON(map[string]any{"type": "content_block_stop", "index": pb.Index}),
	})
}

// emitQuestion substitutes an approval question in place of a blocked tool_use
// block, reusing the same block index so the stream stays well-formed.
//
// The original arguments are discarded entirely; only the prompt is emitted, so
// nothing executable from the blocked call reaches the client.
func (f *AnthropicStreamFilter) emitQuestion(pb *pendingBlock, q *QuestionCall) error {
	if err := f.Out.Write(Event{
		Name: "content_block_start",
		Data: mustJSON(map[string]any{
			"type":  "content_block_start",
			"index": pb.Index,
			"content_block": map[string]any{
				"type":  "tool_use",
				"id":    q.ID,
				"name":  q.Name,
				"input": map[string]any{},
			},
		}),
	}); err != nil {
		return err
	}
	// Anthropic streams tool input as input_json_delta fragments; a single
	// fragment carrying the whole object is valid and is what a short call
	// looks like anyway.
	if err := f.Out.Write(Event{
		Name: "content_block_delta",
		Data: mustJSON(map[string]any{
			"type":  "content_block_delta",
			"index": pb.Index,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": string(q.Args)},
		}),
	}); err != nil {
		return err
	}
	return f.Out.Write(Event{
		Name: "content_block_stop",
		Data: mustJSON(map[string]any{"type": "content_block_stop", "index": pb.Index}),
	})
}

// callByID finds a parsed call by its upstream-assigned id.
func callByID(calls []verdict.ToolCall, id string) verdict.ToolCall {
	for _, c := range calls {
		if c.ID == id {
			return c
		}
	}
	return verdict.ToolCall{ID: id}
}

func rewriteStopReason(data, reason string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return data
	}
	d, ok := m["delta"].(map[string]any)
	if !ok {
		d = map[string]any{}
		m["delta"] = d
	}
	d["stop_reason"] = reason
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return string(out)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
