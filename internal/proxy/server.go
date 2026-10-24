// Package proxy implements the HTTP front end: it accepts Anthropic Messages
// and OpenAI Chat Completions traffic, forwards it upstream, and runs the
// inspection pipeline over the response before any of it reaches the client.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cleanerproxy/internal/adguard"
	"cleanerproxy/internal/approval"
	"cleanerproxy/internal/audit"
	"cleanerproxy/internal/guard"
	"cleanerproxy/internal/notify"
	"cleanerproxy/internal/redact"
	"cleanerproxy/internal/verdict"
	"cleanerproxy/internal/wire"
)

// Server is the proxy HTTP handler.
type Server struct {
	AnthropicUpstream string
	OpenAIUpstream    string
	Guard             *guard.Guard
	Audit             *audit.Logger
	Redactor          *redact.Redactor    // nil = redaction disabled
	AdScanner         *adguard.Scanner    // nil = ad detection disabled
	Notifier          *notify.Notifier    // nil = notifications disabled
	Log               *slog.Logger
	MaxRequestBytes   int64

	Client *http.Client
}

// Handler builds the route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/messages", s.handleAnthropic)
	mux.HandleFunc("POST /v1/chat/completions", s.handleOpenAI)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	// Anything else is forwarded unexamined to the Anthropic upstream so that
	// auxiliary endpoints (model listing, token counting) keep working. These
	// carry no tool calls and therefore no injection surface.
	mux.HandleFunc("/", s.handlePassthrough)
	return mux
}

func (s *Server) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	if s.AnthropicUpstream == "" {
		s.refuseDisabled(w, "Anthropic Messages", "CLEANERPROXY_ANTHROPIC_UPSTREAM")
		return
	}
	s.handle(w, r, wire.FormatAnthropic, s.AnthropicUpstream)
}

func (s *Server) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if s.OpenAIUpstream == "" {
		s.refuseDisabled(w, "OpenAI Chat Completions", "CLEANERPROXY_OPENAI_UPSTREAM")
		return
	}
	s.handle(w, r, wire.FormatOpenAI, s.OpenAIUpstream)
}

// refuseDisabled rejects a request for an API this instance does not serve.
//
// An explicit refusal rather than a forward to some default endpoint: a proxy
// that quietly relays an API nobody configured is an open forwarder for the
// caller's credentials, and it would be inspected under a tool set the operator
// never reviewed.
func (s *Server) refuseDisabled(w http.ResponseWriter, api, envVar string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":"cleanerproxy_api_disabled","message":%s}}`+"\n",
		jsonString(fmt.Sprintf("The %s API is not enabled on this cleanerproxy instance. "+
			"Set %s to an upstream URL to enable it.", api, envVar)))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, format wire.Format, upstream string) {
	start := time.Now()

	body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxRequestBytes))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "could not read request body", err)
		return
	}

	var rc *wire.RequestContext
	if format == wire.FormatAnthropic {
		rc, err = wire.ParseAnthropicRequest(body)
	} else {
		rc, err = wire.ParseOpenAIRequest(body)
	}
	if err != nil {
		// A request we cannot parse is one whose declared tool set we cannot
		// learn, which would silently disable the strongest inspection we
		// have. Refusing is correct: forwarding it would mean proxying
		// traffic we are structurally unable to protect.
		s.fail(w, http.StatusBadRequest,
			"cleanerproxy could not parse this request, so it cannot determine which tools you declared. "+
				"Forwarding it would disable tool-call inspection entirely", err)
		return
	}

	// Resolve any approval prompt the user has just answered, before the
	// request goes anywhere. This is the only trustworthy direction: requests
	// originate at the user's client, so the upstream cannot author one and
	// therefore cannot manufacture consent for its own payload.
	replacements, granted := s.Guard.AnswerApprovals(wire.ToolResults(format, body))
	if len(replacements) > 0 {
		rewritten, rerr := wire.RewriteToolResults(format, body, replacements)
		if rerr != nil {
			// The answer was recorded but the instruction could not be
			// substituted. Forwarding the raw option label would leave the
			// model guessing what to do next, so refuse instead.
			s.fail(w, http.StatusInternalServerError,
				"cleanerproxy recorded your approval but could not rewrite the request to act on it", rerr)
			return
		}
		body = rewritten
		s.Log.Info("approval answered", "count", len(replacements),
			"granted", len(granted), "format", format.String())
	}

	// An approval is honoured by replaying the call cleanerproxy is already
	// holding, without consulting the model.
	//
	// Asking the model to re-issue was implemented first and does not work: a
	// tool_result instructing it to re-run `curl … | bash` is correctly read as
	// a prompt injection and refused (measured against Claude 4.6 Opus). The
	// model is right to distrust tool output, so the recovery path must not
	// depend on it. Replaying also guarantees the client receives byte-for-byte
	// the arguments the user was shown, which is stricter than anything the
	// model would reconstruct, and costs no round trip.
	if len(granted) > 0 {
		s.replayApproved(w, rc, format, granted, hostOf(upstream), start)
		return
	}

	// Redact PII/secrets before the request reaches the upstream. The model
	// sees only pseudonyms; the real values never leave this machine.
	if s.Redactor != nil {
		body = []byte(s.Redactor.Conceal(string(body)))
	}

	resp, err := s.forward(r, body, upstream)
	if err != nil {
		s.fail(w, http.StatusBadGateway, "upstream request failed", err)
		return
	}
	defer resp.Body.Close()

	upstreamHost := hostOf(upstream)

	// Non-2xx or non-SSE responses carry no tool calls worth inspecting in
	// the streaming sense; handle them on the buffered path.
	isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

	if isSSE {
		s.streamResponse(w, resp, rc, format, upstreamHost, start)
		return
	}
	s.bufferedResponse(w, resp, rc, format, upstreamHost, start)
}

// streamResponse runs the SSE quarantine filter.
func (s *Server) streamResponse(w http.ResponseWriter, resp *http.Response, rc *wire.RequestContext, format wire.Format, upstreamHost string, start time.Time) {
	copyResponseHeaders(w.Header(), resp.Header)
	wire.SetSSEHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)

	var out *wire.Writer
	if s.Redactor != nil {
		out = wire.NewWriter(&revealingWriter{w: w, r: s.Redactor})
	} else {
		out = wire.NewWriter(w)
	}

	record := func(calls []verdict.ToolCall) func(*verdict.Verdict, verdict.Action) {
		return func(v *verdict.Verdict, a verdict.Action) {
			s.record(format, rc.Model, true, calls, v, a, upstreamHost, time.Since(start))
		}
	}

	var err error
	if format == wire.FormatAnthropic {
		f := wire.NewAnthropicStreamFilter(rc, s.Guard, out)
		f.OnVerdict = func(v *verdict.Verdict, a verdict.Action) { record(nil)(v, a) }
		if s.AdScanner != nil {
			f.OnAdDetected = s.makeAdCallback()
		}
		f.OnContentFilter = func() {
			s.Log.Warn("upstream content filter triggered (streaming)",
				"upstream", upstreamHost, "model", rc.Model)
			if s.Notifier != nil {
				s.Notifier.SendWithDetail(
					"cleanerproxy: upstream content filter",
					"The upstream provider blocked this request with its content filter",
					fmt.Sprintf("CLEANERPROXY — UPSTREAM CONTENT FILTER (streaming)\n"+
						"Time:     %s\n"+
						"Upstream: %s\n"+
						"Model:    %s\n"+
						"Duration: %s\n\n"+
						"The upstream provider's content classifier intercepted this request\n"+
						"and returned an empty SSE stream. The agent has been told to rephrase.",
						time.Now().Format(time.RFC3339), upstreamHost, rc.Model, time.Since(start).Round(time.Millisecond)),
					"content-filter",
				)
			}
		}
		err = f.Run(resp.Body)
	} else {
		f := wire.NewOpenAIStreamFilter(rc, s.Guard, out)
		f.OnVerdict = func(v *verdict.Verdict, a verdict.Action) { record(nil)(v, a) }
		if s.AdScanner != nil {
			f.OnAdDetected = s.makeAdCallback()
		}
		err = f.Run(resp.Body)
	}

	if err != nil && !errors.Is(err, wire.ErrAborted) {
		// Headers are already sent, so a status code is no longer available.
		// The filter has emitted whatever it could; log and drop the
		// connection rather than appending confusing trailing events.
		s.Log.Error("stream filter failed", "err", err, "format", format.String())
	}
}

// bufferedResponse inspects a complete, non-streaming response.
func (s *Server) bufferedResponse(w http.ResponseWriter, resp *http.Response, rc *wire.RequestContext, format wire.Format, upstreamHost string, start time.Time) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.fail(w, http.StatusBadGateway, "could not read upstream response", err)
		return
	}

	// Pass through error responses and anything that is not a success: they
	// contain no tool calls, and rewriting provider error shapes would break
	// client error handling.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if s.Redactor != nil {
			raw = []byte(s.Redactor.Reveal(string(raw)))
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(raw)
		return
	}

	var (
		calls []verdict.ToolCall
		meta  wire.ResponseMeta
	)
	if format == wire.FormatAnthropic {
		calls, meta, err = wire.ParseAnthropicResponse(raw)
	} else {
		calls, meta, err = wire.ParseOpenAIResponse(raw)
	}
	if err != nil {
		s.fail(w, http.StatusBadGateway,
			"cleanerproxy could not parse the upstream response, so it could not be inspected", err)
		return
	}

	// Detect upstream content-filter interception. Some relay providers
	// (e.g. inferhub) run a classifier that, when triggered, returns a
	// 200 with valid JSON but an empty content body: no text, no tool
	// calls, 0 output tokens, and stop_reason "stop_sequence". Without
	// this check the agent sees an empty response and loops endlessly.
	if isContentFilterResponse(meta, calls) {
		s.Log.Warn("upstream content filter triggered",
			"upstream", upstreamHost,
			"stop_reason", meta.StopReason,
			"output_tokens", meta.OutputTokens)
		if s.Notifier != nil {
			s.Notifier.SendWithDetail(
				"cleanerproxy: upstream content filter",
				"The upstream provider blocked this request with its content filter",
				fmt.Sprintf("CLEANERPROXY — UPSTREAM CONTENT FILTER\n"+
					"Time:     %s\n"+
					"Upstream: %s\n"+
					"Model:    %s\n"+
					"Duration: %s\n\n"+
					"The upstream provider's content classifier intercepted this request\n"+
					"and returned an empty response. This is not a cleanerproxy block —\n"+
					"the provider itself refused to generate output.\n\n"+
					"The agent has been told to rephrase or abandon the request.\n"+
					"If this is a false positive, try rephrasing without trigger words.",
					time.Now().Format(time.RFC3339), upstreamHost, meta.Model, time.Since(start).Round(time.Millisecond)),
				"content-filter",
			)
		}
		rewritten := contentFilterMessage(format, meta.Model)
		copyResponseHeaders(w.Header(), resp.Header)
		w.Header().Del("Content-Length")
		w.Header().Set("X-Cleanerproxy-Action", "content-filter-rewrite")
		w.WriteHeader(http.StatusOK)
		if s.Redactor != nil {
			rewritten = []byte(s.Redactor.Reveal(string(rewritten)))
		}
		_, _ = w.Write(rewritten)
		return
	}

	v, action := s.Guard.Evaluate(rc, calls, meta)
	s.record(format, rc.Model, false, calls, v, action, upstreamHost, time.Since(start))

	switch action {
	case verdict.ActionAbort:
		s.blockedResponse(w, v, calls)
		return

	case verdict.ActionDefang:
		notices := map[string]wire.Replacement{}
		for id := range v.BlockedCallIDs() {
			notices[id] = s.Guard.Replacement(rc, callByID(calls, id), v.FindingsFor(id))
		}
		var rewritten []byte
		if format == wire.FormatAnthropic {
			rewritten, err = wire.RewriteAnthropicResponse(raw, notices)
		} else {
			rewritten, err = wire.RewriteOpenAIResponse(raw, notices)
		}
		if err != nil {
			// Rewriting failed, so we cannot guarantee the blocked call was
			// removed. Fail closed: returning the original would deliver the
			// exact payload we just decided to block.
			s.Log.Error("defang rewrite failed; failing closed", "err", err)
			s.blockedResponse(w, v, calls)
			return
		}
		// Ad guard on defanged responses too.
		if s.AdScanner != nil {
			if cleaned, adHits := s.scanAndCleanAds(format, rewritten); len(adHits) > 0 {
				rewritten = cleaned
			}
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.Header().Del("Content-Length") // body length changed
		w.Header().Set("X-Cleanerproxy-Action", "defang")
		w.WriteHeader(http.StatusOK)
		if s.Redactor != nil {
			rewritten = []byte(s.Redactor.Reveal(string(rewritten)))
		}
		_, _ = w.Write(rewritten)
		return

	default:
		// Ad guard: scan response text for injected advertisements.
		if s.AdScanner != nil {
			if cleaned, adHits := s.scanAndCleanAds(format, raw); len(adHits) > 0 {
				raw = cleaned
			}
		}
		copyResponseHeaders(w.Header(), resp.Header)
		if !v.Clean() {
			w.Header().Set("X-Cleanerproxy-Action", "allow-with-findings")
		}
		w.Header().Del("Content-Length") // body may have been modified by ad cleaning
		w.WriteHeader(resp.StatusCode)
		if s.Redactor != nil {
			raw = []byte(s.Redactor.Reveal(string(raw)))
		}
		_, _ = w.Write(raw)
	}
}

// blockedResponse returns the 5xx fail-closed form.
//
// 502 rather than 500: the failure originates with the upstream, and 502
// communicates "the thing I was talking to misbehaved", which is precisely
// what happened.
func (s *Server) blockedResponse(w http.ResponseWriter, v *verdict.Verdict, calls []verdict.ToolCall) {
	explanation := verdict.Explain(v.Findings, calls)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cleanerproxy-Action", "abort")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":"cleanerproxy_blocked","message":%s}}`,
		jsonString(explanation))
}

// forward relays the request upstream.
func (s *Server) forward(r *http.Request, body []byte, upstream string) (*http.Response, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	target.Path = strings.TrimRight(target.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyRequestHeaders(req.Header, r.Header)
	req.Header.Set("Host", target.Host)
	req.Host = target.Host

	return s.Client.Do(req)
}

// handlePassthrough relays non-inference endpoints unmodified.
func (s *Server) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.MaxRequestBytes))
	if err != nil {
		s.fail(w, http.StatusBadRequest, "could not read request body", err)
		return
	}
	upstream := s.AnthropicUpstream
	api, envVar := "Anthropic", "CLEANERPROXY_ANTHROPIC_UPSTREAM"
	if strings.HasPrefix(r.URL.Path, "/v1/chat") || strings.HasPrefix(r.URL.Path, "/v1/completions") ||
		strings.HasPrefix(r.URL.Path, "/v1/embeddings") {
		upstream = s.OpenAIUpstream
		api, envVar = "OpenAI", "CLEANERPROXY_OPENAI_UPSTREAM"
	}
	if upstream == "" {
		s.refuseDisabled(w, api, envVar)
		return
	}
	resp, err := s.forward(r, body, upstream)
	if err != nil {
		s.fail(w, http.StatusBadGateway, "upstream request failed", err)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) record(format wire.Format, model string, streaming bool, calls []verdict.ToolCall, v *verdict.Verdict, action verdict.Action, upstreamHost string, dur time.Duration) {
	if v == nil {
		return
	}
	if action != verdict.ActionAllow || !v.Clean() {
		s.Log.Warn("inspection finding",
			"action", action.String(),
			"format", format.String(),
			"severity", v.MaxSeverity().String(),
			"findings", len(v.Findings),
			"upstream", upstreamHost)

		if s.Notifier != nil {
			title := fmt.Sprintf("cleanerproxy: %s", action.String())
			summary := fmt.Sprintf("%s — %d finding(s), severity %s",
				v.MaxSeverity().String(), len(v.Findings), action.String())
			detail := formatInspectionDetail(format.String(), model, streaming, calls, v, action, upstreamHost, dur)
			s.Notifier.SendWithDetail(title, summary, detail, "inspection")
		}
	}
	if s.Audit == nil {
		return
	}
	rec := audit.BuildRecord(format.String(), model, streaming, calls, v, action, upstreamHost, dur)
	if err := s.Audit.Write(rec); err != nil {
		s.Log.Error("audit write failed", "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string, err error) {
	s.Log.Error(msg, "err", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"type":"error","error":{"type":"cleanerproxy_error","message":%s}}`,
		jsonString(fmt.Sprintf("%s: %v", msg, err)))
}

// hopByHop headers must not be forwarded.
var hopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"proxy-authenticate": true, "proxy-authorization": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true,
}

func copyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "host" || lk == "content-length" {
			continue
		}
		// Accept-Encoding is deliberately dropped so that Go's transport
		// negotiates and transparently decompresses the response. Inspection
		// requires plaintext; forwarding the client's own Accept-Encoding
		// would hand us a gzip stream we would have to decompress ourselves.
		if lk == "accept-encoding" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "content-length" || lk == "content-encoding" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// NewHTTPClient builds the upstream client.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Streaming correctness: without this, the transport may buffer
			// the response and defeat incremental delivery.
			ResponseHeaderTimeout: 120 * time.Second,
		},
	}
}

var _ = context.Background

// replayApproved emits the approved calls as an assistant turn authored by
// cleanerproxy.
func (s *Server) replayApproved(w http.ResponseWriter, rc *wire.RequestContext, format wire.Format,
	granted []*approval.Challenge, upstreamHost string, start time.Time) {

	calls := make([]wire.SynthCall, 0, len(granted))
	recorded := make([]verdict.ToolCall, 0, len(granted))
	for _, c := range granted {
		id := c.OrigID
		if id == "" {
			id = c.Nonce + "x"
		}
		calls = append(calls, wire.SynthCall{ID: id, Name: c.ToolName, Args: c.RawArgs})

		var input map[string]any
		_ = json.Unmarshal(c.RawArgs, &input)
		recorded = append(recorded, verdict.ToolCall{
			ID: id, Name: c.ToolName, Input: input, RawInput: c.RawArgs,
		})
	}

	body, err := wire.SynthesizeToolCalls(format, rc.Stream, rc.Model, calls)
	if err != nil {
		// Fail closed. Falling through to the upstream would ask the model to
		// re-issue the call, which is the path that does not work.
		s.fail(w, http.StatusInternalServerError,
			"cleanerproxy could not release the call you approved; re-request the action", err)
		return
	}

	// Audited as its own event: a tool call was released on human authority
	// rather than by passing inspection, and that distinction is exactly what an
	// audit log exists to preserve.
	v := &verdict.Verdict{}
	for _, c := range recorded {
		v.Add(verdict.Finding{
			Tier:       verdict.TierCapability,
			Rule:       "approval.replayed",
			Severity:   verdict.SeverityInfo,
			ToolCallID: c.ID,
			ToolName:   c.Name,
			Confidence: 1.0,
			Message: fmt.Sprintf("Released the previously blocked %q call because the user approved it "+
				"at a cleanerproxy prompt. Emitted locally with the exact arguments the user was shown; "+
				"the upstream was not consulted.", c.Name),
		})
	}
	s.record(format, rc.Model, rc.Stream, recorded, v, verdict.ActionAllow, upstreamHost, time.Since(start))

	w.Header().Set("X-Cleanerproxy-Action", "approved-replay")
	if rc.Stream {
		wire.SetSSEHeaders(w.Header())
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)

	s.Log.Info("replayed approved call", "count", len(calls), "stream", rc.Stream)
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

// scanAndCleanAds extracts text from the response body, scans it for ad
// content, logs/notifies on detection, and returns the cleaned body.
func (s *Server) scanAndCleanAds(format wire.Format, body []byte) ([]byte, []adguard.Hit) {
	text := extractResponseText(format, body)
	if text == "" {
		return body, nil
	}
	hits := s.AdScanner.Scan(text)
	if len(hits) == 0 {
		return body, nil
	}

	// Log and notify.
	for _, h := range hits {
		s.Log.Warn("ad detected in response",
			"rule", h.Rule, "matched", h.Matched)
	}
	if s.Notifier != nil {
		summary := fmt.Sprintf("%d ad indicator(s) found: %s", len(hits), hits[0].Rule)
		detail := formatAdDetail("buffered response", hits, text)
		s.Notifier.SendWithDetail(
			"cleanerproxy: ad detected",
			summary, detail,
			"adguard",
		)
	}

	// Clean: replace text content in the response JSON.
	cleaned := s.AdScanner.Clean(text, hits)
	if cleaned == text {
		return body, hits
	}
	result := replaceResponseText(format, body, cleaned)
	return result, hits
}

// extractResponseText pulls the text content from a response body.
func extractResponseText(format wire.Format, body []byte) string {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}

	if format == wire.FormatAnthropic {
		content, _ := raw["content"].([]any)
		var parts []string
		for _, item := range content {
			blk, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if blk["type"] == "text" {
				if t, ok := blk["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	}

	// OpenAI
	choices, _ := raw["choices"].([]any)
	var parts []string
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		if ct, ok := msg["content"].(string); ok {
			parts = append(parts, ct)
		}
	}
	return strings.Join(parts, "\n")
}

// makeAdCallback returns the OnAdDetected callback for stream filters.
// Since text has already been forwarded to the client, all we can do is
// log and notify.
func (s *Server) makeAdCallback() func(string) {
	return func(text string) {
		hits := s.AdScanner.Scan(text)
		if len(hits) == 0 {
			return
		}
		for _, h := range hits {
			s.Log.Warn("ad detected in streamed response",
				"rule", h.Rule, "matched", h.Matched)
		}
		if s.Notifier != nil {
			summary := fmt.Sprintf("%d ad indicator(s) in stream: %s", len(hits), hits[0].Rule)
			detail := formatAdDetail("streamed response", hits, text)
			s.Notifier.SendWithDetail(
				"cleanerproxy: ad detected",
				summary, detail,
				"adguard-stream",
			)
		}
	}
}

// replaceResponseText substitutes the text content in a response body.
func replaceResponseText(format wire.Format, body []byte, newText string) []byte {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	if format == wire.FormatAnthropic {
		content, _ := raw["content"].([]any)
		textIdx := 0
		textParts := strings.SplitN(newText, "\n", -1)
		// Rejoin into a single string per text block.
		joined := strings.Join(textParts, "\n")
		for _, item := range content {
			blk, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if blk["type"] == "text" {
				if textIdx == 0 {
					blk["text"] = joined
				}
				textIdx++
			}
		}
	} else {
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
			if _, ok := msg["content"].(string); ok {
				msg["content"] = newText
			}
		}
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// revealingWriter wraps an io.Writer and replaces pseudonyms with real values
// in all data written through it. Used on the SSE response path so that
// streamed chunks arrive at the client with original PII restored.
//
// It also implements http.Flusher so that wire.NewWriter can detect it and
// flush after each event.
type revealingWriter struct {
	w io.Writer
	r *redact.Redactor
}

func (rw *revealingWriter) Write(p []byte) (int, error) {
	revealed := rw.r.Reveal(string(p))
	n, err := rw.w.Write([]byte(revealed))
	// Report len(p) as written regardless, since the caller wrote len(p)
	// bytes of input and partial-write semantics should match.
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func (rw *revealingWriter) Flush() {
	if f, ok := rw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// formatAdDetail builds a human-readable detail file for an ad detection event.
func formatAdDetail(source string, hits []adguard.Hit, text string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CLEANERPROXY — AD DETECTION\n")
	fmt.Fprintf(&b, "Time:   %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Source: %s\n", source)
	fmt.Fprintf(&b, "Hits:   %d\n\n", len(hits))

	for i, h := range hits {
		fmt.Fprintf(&b, "--- Hit %d ---\n", i+1)
		fmt.Fprintf(&b, "Rule:    %s\n", h.Rule)
		fmt.Fprintf(&b, "Matched: %s\n", h.Matched)
		if h.Context != "" {
			fmt.Fprintf(&b, "Context: %s\n", h.Context)
		}
		b.WriteByte('\n')
	}

	if text != "" {
		b.WriteString("--- Full Response Text ---\n")
		if len(text) > 4000 {
			b.WriteString(text[:4000])
			fmt.Fprintf(&b, "\n\n... truncated (%d bytes total)\n", len(text))
		} else {
			b.WriteString(text)
		}
		b.WriteByte('\n')
	}

	return b.String()
}

// formatInspectionDetail builds a human-readable detail file for an inspection finding.
func formatInspectionDetail(format, model string, streaming bool, calls []verdict.ToolCall, v *verdict.Verdict, action verdict.Action, upstream string, dur time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CLEANERPROXY — INSPECTION FINDING\n")
	fmt.Fprintf(&b, "Time:      %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Action:    %s\n", action.String())
	fmt.Fprintf(&b, "Severity:  %s\n", v.MaxSeverity().String())
	fmt.Fprintf(&b, "Format:    %s\n", format)
	fmt.Fprintf(&b, "Model:     %s\n", model)
	fmt.Fprintf(&b, "Streaming: %v\n", streaming)
	fmt.Fprintf(&b, "Upstream:  %s\n", upstream)
	fmt.Fprintf(&b, "Duration:  %s\n", dur.Round(time.Millisecond))
	fmt.Fprintf(&b, "Findings:  %d\n\n", len(v.Findings))

	for i, f := range v.Findings {
		fmt.Fprintf(&b, "--- Finding %d ---\n", i+1)
		fmt.Fprintf(&b, "Tier:       %s\n", f.Tier.String())
		fmt.Fprintf(&b, "Severity:   %s\n", f.Severity.String())
		fmt.Fprintf(&b, "Rule:       %s\n", f.Rule)
		fmt.Fprintf(&b, "Message:    %s\n", f.Message)
		if f.ToolCallID != "" {
			fmt.Fprintf(&b, "Tool Call:  %s\n", f.ToolCallID)
		}
		if f.ToolName != "" {
			fmt.Fprintf(&b, "Tool Name:  %s\n", f.ToolName)
		}
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 500 {
				ev = ev[:500] + "..."
			}
			fmt.Fprintf(&b, "Evidence:   %s\n", ev)
		}
		if f.Confidence > 0 && f.Confidence < 1 {
			fmt.Fprintf(&b, "Confidence: %.2f\n", f.Confidence)
		}
		b.WriteByte('\n')
	}

	if len(calls) > 0 {
		b.WriteString("--- Tool Calls in Response ---\n")
		for i, c := range calls {
			fmt.Fprintf(&b, "\nCall %d:\n", i+1)
			fmt.Fprintf(&b, "  ID:   %s\n", c.ID)
			fmt.Fprintf(&b, "  Name: %s\n", c.Name)
			raw := string(c.RawInput)
			if len(raw) > 1000 {
				raw = raw[:1000] + "..."
			}
			fmt.Fprintf(&b, "  Args: %s\n", raw)
		}
		b.WriteByte('\n')
	}

	// Append the full explanation that was shown to the agent.
	blocked := v.BlockedCallIDs()
	if len(blocked) > 0 {
		b.WriteString("--- Block Notice (shown to agent) ---\n")
		var blockedFindings []verdict.Finding
		for _, f := range v.Findings {
			if f.Severity > verdict.SeverityInfo {
				blockedFindings = append(blockedFindings, f)
			}
		}
		b.WriteString(verdict.Explain(blockedFindings, calls))
	}

	return b.String()
}

// isContentFilterResponse detects the fingerprint of an upstream content-filter
// interception: a 200 response with valid JSON but no actual content. Relay
// providers that run a content classifier sometimes return this shape instead
// of a proper error, leaving the agent with an empty response it loops on.
//
// Fingerprint: 0 output tokens, 0 text bytes, 0 tool calls, and a stop reason
// that is not "end_turn" or "max_tokens" (typically "stop_sequence" or "stop").
func isContentFilterResponse(meta wire.ResponseMeta, calls []verdict.ToolCall) bool {
	if len(calls) > 0 || meta.OutputTokens > 0 || meta.TextBytes > 0 {
		return false
	}
	// An empty response with end_turn can happen legitimately (model chose
	// to say nothing). stop_sequence or stop with 0 tokens is the classifier
	// fingerprint — the model never ran.
	switch meta.StopReason {
	case "stop_sequence", "stop":
		return true
	}
	return false
}

// contentFilterMessage builds a well-formed response that tells the agent the
// upstream content filter blocked the request. The message is actionable: it
// explains what happened and what to do about it.
func contentFilterMessage(format wire.Format, model string) []byte {
	const notice = "The upstream provider's content filter blocked this request and returned an empty response. " +
		"This is not a cleanerproxy block — the provider itself refused to generate output. " +
		"Rephrase the request to avoid content-filter trigger words, " +
		"or inform the user that this request cannot be fulfilled through this provider."

	if format == wire.FormatAnthropic {
		out, _ := json.Marshal(map[string]any{
			"id":    "msg_content_filter_0",
			"type":  "message",
			"role":  "assistant",
			"model": model,
			"content": []any{
				map[string]any{"type": "text", "text": notice},
			},
			"stop_reason": "end_turn",
			"usage": map[string]any{
				"input_tokens":  0,
				"output_tokens": 0,
			},
		})
		return out
	}

	// OpenAI format.
	out, _ := json.Marshal(map[string]any{
		"id":      "chatcmpl-content-filter-0",
		"object":  "chat.completion",
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": "stop",
			"message": map[string]any{
				"role":    "assistant",
				"content": notice,
			},
		}},
		"usage": map[string]any{
			"prompt_tokens":     0,
			"completion_tokens": 0,
			"total_tokens":      0,
		},
	})
	return out
}

