package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cleanerproxy/internal/guard"
)

// An API with no configured upstream must be refused, not forwarded to a
// default. A proxy that quietly relays an API nobody configured is an open
// forwarder for whatever credential the caller presents.
func TestDisabledAPIIsRefusedNotForwarded(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","content":[]}`)
	}))
	defer upstream.Close()

	s := &Server{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    "", // only Anthropic is ported
		Guard:             guard.New(),
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes:   1 << 20,
		Client:            upstream.Client(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	for _, path := range []string{
		"/v1/chat/completions", // the disabled inference route
		"/v1/completions",      // disabled via passthrough
		"/v1/embeddings",       // disabled via passthrough
	} {
		t.Run(path, func(t *testing.T) {
			before := upstreamHits
			resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusNotImplemented {
				t.Errorf("status = %d, want 501; body=%s", resp.StatusCode, raw)
			}
			if upstreamHits != before {
				t.Error("request was forwarded despite the API being disabled")
			}

			var parsed struct {
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(raw, &parsed); err != nil {
				t.Fatalf("refusal is not valid JSON: %v (%s)", err, raw)
			}
			if parsed.Error.Type != "cleanerproxy_api_disabled" {
				t.Errorf("error type = %q", parsed.Error.Type)
			}
			// The operator has to be able to act on this without reading source.
			if !strings.Contains(parsed.Error.Message, "CLEANERPROXY_OPENAI_UPSTREAM") {
				t.Errorf("message does not name the setting to change: %q", parsed.Error.Message)
			}
		})
	}
}

// The enabled API must keep working normally alongside a disabled one.
func TestEnabledAPIStillWorksWhenOtherIsDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("upstream path = %q, want /v1/messages", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn"}`)
	}))
	defer upstream.Close()

	s := &Server{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    "",
		Guard:             guard.New(),
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes:   1 << 20,
		Client:            upstream.Client(),
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "hello") {
		t.Errorf("response not relayed: %s", raw)
	}
}
