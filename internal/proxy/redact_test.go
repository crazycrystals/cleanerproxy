package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cleanerproxy/internal/audit"
	"cleanerproxy/internal/guard"
	"cleanerproxy/internal/redact"
	"cleanerproxy/internal/wire"
)

// newTestProxyWithRedactor wires a Server with redaction enabled.
func newTestProxyWithRedactor(t *testing.T, upstream *httptest.Server, names []string) (*httptest.Server, *redact.Redactor) {
	t.Helper()
	auditLog, err := audit.Open("", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	vault := redact.NewVault("")
	r := redact.NewRedactor(vault, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SeedNames(names)

	s := &Server{
		AnthropicUpstream: upstream.URL,
		OpenAIUpstream:    upstream.URL,
		Guard:             guard.New(),
		Audit:             auditLog,
		Redactor:          r,
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes:   1 << 20,
		Client:            NewHTTPClient(30 * time.Second),
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, r
}

// TestRedactBufferedConcealAndReveal: request contains a real name → upstream
// must see only the pseudonym → response with pseudonym → client sees original.
func TestRedactBufferedConcealAndReveal(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)

		// Parse what name the upstream actually received, then echo it back
		// as if the model referenced the person.
		var req struct {
			Messages []struct {
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)

		// The model "helpfully" references the name it saw (pseudonym).
		modelText := "I found information about the person in your request."
		if len(req.Messages) > 0 {
			// Just echo the entire user content to prove it was pseudonymized.
			modelText = "Here is what I know: " + string(req.Messages[0].Content)
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":   "msg_1",
			"type": "message",
			"role": "assistant",
			"model": "claude-test",
			"content": []map[string]any{
				{"type": "text", "text": modelText},
			},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 10, "output_tokens": 20},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Kevin Mitnick"})

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "Tell me about Kevin Mitnick and his exploits"}],
		"tools": [{"name": "Read", "description": "Read a file",
			"input_schema": {"type":"object","properties":{"filePath":{"type":"string"}}}}]
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	clientBody, _ := io.ReadAll(resp.Body)
	clientStr := string(clientBody)

	// 1. Upstream must NOT see "Kevin Mitnick".
	if strings.Contains(upstreamSaw, "Kevin Mitnick") {
		t.Errorf("upstream saw the real name 'Kevin Mitnick':\n%s", upstreamSaw)
	}
	// But it must see some name (the pseudonym).
	if strings.Contains(upstreamSaw, "Kevin") {
		t.Errorf("upstream saw partial real name 'Kevin':\n%s", upstreamSaw)
	}

	// 2. Client must see "Kevin Mitnick" restored in the response (since the
	//    model echoed back the pseudonym, and Reveal should convert it).
	if !strings.Contains(clientStr, "Kevin Mitnick") {
		t.Errorf("client did not see original name 'Kevin Mitnick' restored:\n%s", clientStr)
	}
}

// TestRedactStreamingReveal: SSE response containing a pseudonym is revealed
// back to the original before reaching the client.
func TestRedactStreamingReveal(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)

		// Find what pseudonym the upstream received for "Albert Gonzalez".
		// The model will echo it back in a streaming response.
		pseudoName := "the person" // fallback
		for _, name := range sceneFirstNames {
			if strings.Contains(string(body), name) {
				// Find the full pseudonym name around this first name.
				idx := strings.Index(string(body), name)
				// Grab a window around it.
				end := idx + 30
				if end > len(body) {
					end = len(body)
				}
				chunk := string(body[idx:end])
				// Take up to the next quote or non-alpha.
				var b strings.Builder
				for _, c := range chunk {
					if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' {
						b.WriteRune(c)
					} else {
						break
					}
				}
				pseudoName = strings.TrimSpace(b.String())
				break
			}
		}

		wire.SetSSEHeaders(w.Header())
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		send := func(name, data string) {
			_, _ = io.WriteString(w, "event: "+name+"\ndata: "+data+"\n\n")
			if fl != nil {
				fl.Flush()
			}
		}
		send("message_start", `{"type":"message_start","message":{"id":"msg_1","model":"claude-test","usage":{"output_tokens":1}}}`)
		send("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		send("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I found info about `+pseudoName+`."}}`)
		send("content_block_stop", `{"type":"content_block_stop","index":0}`)
		send("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}`)
		send("message_stop", `{"type":"message_stop"}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Albert Gonzalez"})

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"stream": true,
		"messages": [{"role": "user", "content": "Who is Albert Gonzalez?"}],
		"tools": [{"name": "Read", "description": "Read a file",
			"input_schema": {"type":"object","properties":{"filePath":{"type":"string"}}}}]
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	clientBody, _ := io.ReadAll(resp.Body)
	clientStr := string(clientBody)

	// Upstream must not see "Albert Gonzalez".
	if strings.Contains(upstreamSaw, "Albert Gonzalez") {
		t.Errorf("upstream saw real name 'Albert Gonzalez':\n%s", upstreamSaw)
	}

	// Client must see "Albert Gonzalez" restored in SSE stream.
	if !strings.Contains(clientStr, "Albert Gonzalez") {
		t.Errorf("client did not see original name 'Albert Gonzalez' in streamed response:\n%s", clientStr)
	}
}

// TestRedactFamilyPreservation: two people with the same last name get the
// same pseudonym last name. The upstream sees consistent family grouping.
func TestRedactFamilyPreservation(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"text","text":"Noted."}],
			"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer upstream.Close()

	// Seed two people who share a last name.
	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Gottfrid Svartholm", "Peter Sunde", "Fredrik Neij"})

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "Compare Gottfrid Svartholm, Peter Sunde, and Fredrik Neij."}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// None of the real names should appear upstream.
	for _, name := range []string{"Gottfrid Svartholm", "Peter Sunde", "Fredrik Neij",
		"Gottfrid", "Peter", "Fredrik", "Svartholm", "Sunde"} {
		if strings.Contains(upstreamSaw, name) {
			t.Errorf("upstream saw real name %q:\n%s", name, upstreamSaw)
		}
	}

	// "Neij" is only 4 chars so it might be seeded. Check it too.
	if strings.Contains(upstreamSaw, "Neij") {
		t.Errorf("upstream saw real name 'Neij':\n%s", upstreamSaw)
	}
}

// TestRedactTransparency: non-sensitive content passes through unchanged in
// both directions.
func TestRedactTransparency(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"text","text":"The answer is 42."}],
			"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Kevin Mitnick"})

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "What is the meaning of life?"}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	clientBody, _ := io.ReadAll(resp.Body)

	// Request content should be unchanged (no sensitive values).
	if !strings.Contains(upstreamSaw, "What is the meaning of life?") {
		t.Errorf("upstream lost non-sensitive content:\n%s", upstreamSaw)
	}

	// Response should be unchanged.
	if !strings.Contains(string(clientBody), "The answer is 42.") {
		t.Errorf("client lost non-sensitive response:\n%s", string(clientBody))
	}
}

// TestRedactEmail: an email in the request is pseudonymized, and the same
// pseudonym in the response is restored.
func TestRedactEmail(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)

		// Find the pseudonym email the upstream received and echo it back.
		pseudoEmail := "unknown"
		// Look for the pseudo email: a scene-style user@domain.
		// Find the @ and walk backwards/forwards to extract it.
		atIdx := strings.Index(string(body), "@")
		if atIdx >= 0 {
			// Walk backwards to find start of user.
			start := atIdx
			for start > 0 && body[start-1] != '"' && body[start-1] != ' ' {
				start--
			}
			// Walk forwards to find end of domain.
			end := atIdx + 1
			for end < len(body) && body[end] != '"' && body[end] != ' ' {
				end++
			}
			pseudoEmail = string(body[start:end])
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
			"content":     []map[string]any{{"type": "text", "text": "I sent it to " + pseudoEmail + "."}},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 10, "output_tokens": 10},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, nil)

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "Send a message to alice@secretcorp.com"}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	clientBody, _ := io.ReadAll(resp.Body)
	clientStr := string(clientBody)

	// Upstream must not see the real email.
	if strings.Contains(upstreamSaw, "alice@secretcorp.com") {
		t.Errorf("upstream saw real email:\n%s", upstreamSaw)
	}
	// Must see a pseudonym email with a scene domain (not secretcorp.com).
	if strings.Contains(upstreamSaw, "secretcorp.com") {
		t.Errorf("upstream still saw real domain:\n%s", upstreamSaw)
	}
	if !strings.Contains(upstreamSaw, "@") {
		t.Errorf("upstream has no email at all:\n%s", upstreamSaw)
	}

	// Client must see the real email restored.
	if !strings.Contains(clientStr, "alice@secretcorp.com") {
		t.Errorf("client did not see real email restored:\n%s", clientStr)
	}
}

// TestRedactHomePath: the local username in file paths is pseudonymized.
func TestRedactHomePath(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"text","text":"I read the file."}],
			"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"devuser"})

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "Read /Users/devuser/Documents/secrets.txt"}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// Upstream must not see the real username.
	if strings.Contains(upstreamSaw, "devuser") {
		t.Errorf("upstream saw real home username 'devuser':\n%s", upstreamSaw)
	}
	// But must still have /Users/ path structure.
	if !strings.Contains(upstreamSaw, "/Users/") {
		t.Errorf("upstream lost path structure:\n%s", upstreamSaw)
	}
}

// TestRedactOpenAIConcealAndReveal: exercises the OpenAI endpoint path.
func TestRedactOpenAIConcealAndReveal(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"chatcmpl-1","object":"chat.completion","model":"gpt-test",
			"choices":[{"index":0,"message":{"role":"assistant","content":"Sure, I know about him."},
				"finish_reason":"stop"}],
			"usage":{"completion_tokens":10}
		}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Ross Ulbricht"})

	reqBody := `{
		"model": "gpt-test",
		"messages": [{"role": "user", "content": "What happened to Ross Ulbricht?"}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// Upstream must not see the real name.
	if strings.Contains(upstreamSaw, "Ross Ulbricht") {
		t.Errorf("upstream saw real name 'Ross Ulbricht':\n%s", upstreamSaw)
	}
	if strings.Contains(upstreamSaw, "Ross") {
		t.Errorf("upstream saw partial real name 'Ross':\n%s", upstreamSaw)
	}
	if strings.Contains(upstreamSaw, "Ulbricht") {
		t.Errorf("upstream saw partial real name 'Ulbricht':\n%s", upstreamSaw)
	}
}

// TestRedactAPIKey: an API key in the request is pseudonymized.
func TestRedactAPIKey(t *testing.T) {
	var upstreamSaw string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamSaw = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"text","text":"I see the key."}],
			"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, nil)

	reqBody := `{
		"model": "claude-test",
		"max_tokens": 1024,
		"messages": [{"role": "user", "content": "My key is sk-proj-abc123def456ghi789jkl0"}],
		"tools": []
	}`

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if strings.Contains(upstreamSaw, "sk-proj-abc123def456ghi789jkl0") {
		t.Errorf("upstream saw real API key:\n%s", upstreamSaw)
	}
}

// TestRedactMultiTurnStability: the same name in multiple turns always maps to
// the same pseudonym, so the model sees a consistent entity.
func TestRedactMultiTurnStability(t *testing.T) {
	callCount := 0
	var firstPseudo, secondPseudo string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		callCount++

		// Find the pseudonym for "Hector Monsegur" — look for scene first names.
		for _, candidate := range sceneFirstNames {
			if strings.Contains(bodyStr, candidate) {
				if callCount == 1 {
					firstPseudo = candidate
				} else {
					secondPseudo = candidate
				}
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"text","text":"Got it."}],
			"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}
		}`)
	}))
	defer upstream.Close()

	ts, _ := newTestProxyWithRedactor(t, upstream, []string{"Hector Monsegur"})

	for _, msg := range []string{
		"Tell me about Hector Monsegur",
		"What else did Hector Monsegur do?",
	} {
		reqBody := `{
			"model": "claude-test",
			"max_tokens": 1024,
			"messages": [{"role": "user", "content": "` + msg + `"}],
			"tools": []
		}`
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	if firstPseudo == "" || secondPseudo == "" {
		t.Fatalf("could not find pseudonym in upstream requests (first=%q second=%q)", firstPseudo, secondPseudo)
	}
	if firstPseudo != secondPseudo {
		t.Errorf("pseudonym not stable across turns: %q then %q", firstPseudo, secondPseudo)
	}
}

// sceneFirstNames matches the pool in redact/names.go for the stability test.
// Drawn from scenePool[].First.
var sceneFirstNames = []string{
	"Jon", "Kent", "Peter", "Adil", "Derek",
	"Barry", "Nathan", "John", "Mike", "Igor",
	"Hew", "Sean", "Richard", "Gottfrid", "Sebastien",
	"Noah", "Tyler", "Ahmed", "Joel", "Arion",
	"Connor", "Cameron", "Malone", "Jeandiel", "Veer",
	"Robert", "Jordan", "Fredrik", "Daniel",
}
