// Package audit writes an append-only record of every inspection verdict.
//
// The log is the one place in this system where real encryption is both
// possible and worthwhile. Unlike conversation content — which the upstream
// model must be able to read, and therefore cannot be meaningfully encrypted
// end-to-end — audit records are written and read only by the operator. They
// also contain exactly the sensitive material an attacker would want: the
// commands that were attempted, file paths, and fragments of prompts.
//
// AES-256-GCM is used because it is in the standard library. ChaCha20-Poly1305
// would be a marginally better choice on hardware without AES-NI, but it lives
// in golang.org/x/crypto and this module's dependency policy is stdlib-only.
package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"cleanerproxy/internal/verdict"
)

// Record is one inspection outcome.
type Record struct {
	Timestamp time.Time         `json:"ts"`
	Format    string            `json:"format"`
	Model     string            `json:"model"`
	Streaming bool              `json:"streaming"`
	Action    string            `json:"action"`
	Findings  []verdict.Finding `json:"findings,omitempty"`

	// ToolCalls records name and argument digest for every inspected call.
	ToolCalls []CallRecord `json:"tool_calls,omitempty"`

	UpstreamHost string `json:"upstream_host,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
}

// CallRecord summarizes one inspected tool call.
type CallRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Args    string `json:"args"`
	Blocked bool   `json:"blocked"`
}

// Logger appends records to a file, optionally encrypted.
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	aead cipher.AEAD

	// Fallback is used when no path is configured, so that findings are still
	// visible rather than silently discarded.
	Fallback io.Writer
}

// Open prepares a logger. An empty path disables file logging and routes
// records to fallback. A 64-character hex key enables encryption.
func Open(path, hexKey string, fallback io.Writer) (*Logger, error) {
	l := &Logger{Fallback: fallback}

	if hexKey != "" {
		key, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("audit key must be hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("audit key must be 32 bytes (64 hex chars), got %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		l.aead = aead
	}

	if path != "" {
		// 0600: the log contains attempted commands and prompt fragments.
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		l.f = f
	}

	return l, nil
}

// Close releases the file handle.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

// Encrypted reports whether records are encrypted at rest.
func (l *Logger) Encrypted() bool { return l.aead != nil }

// Write appends one record.
func (l *Logger) Write(r Record) error {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return err
	}

	line := plain
	if l.aead != nil {
		nonce := make([]byte, l.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ct := l.aead.Seal(nonce, nonce, plain, nil)
		// Prefix marks the format so a reader can tell encrypted lines from
		// plaintext ones if the key was enabled partway through a file's life.
		line = []byte("enc:" + base64.StdEncoding.EncodeToString(ct))
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	w := l.Fallback
	if l.f != nil {
		w = l.f
	}
	if w == nil {
		return nil
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// Decrypt reverses Write for a single line, for the read-side tool.
func Decrypt(line, hexKey string) ([]byte, error) {
	if len(line) < 4 || line[:4] != "enc:" {
		return []byte(line), nil // plaintext record
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(line[4:])
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ct[:aead.NonceSize()], ct[aead.NonceSize():]
	return aead.Open(nil, nonce, body, nil)
}

// BuildRecord assembles a Record from an inspection outcome.
func BuildRecord(format, model string, streaming bool, calls []verdict.ToolCall, v *verdict.Verdict, action verdict.Action, upstreamHost string, dur time.Duration) Record {
	r := Record{
		Format:       format,
		Model:        model,
		Streaming:    streaming,
		Action:       action.String(),
		UpstreamHost: upstreamHost,
		DurationMS:   dur.Milliseconds(),
	}
	if v != nil {
		r.Findings = v.Findings
	}
	blocked := map[string]bool{}
	if v != nil {
		blocked = v.BlockedCallIDs()
	}
	for _, c := range calls {
		args := string(c.RawInput)
		if len(args) > 2000 {
			args = args[:2000] + "...(truncated)"
		}
		r.ToolCalls = append(r.ToolCalls, CallRecord{
			ID:      c.ID,
			Name:    c.Name,
			Args:    args,
			Blocked: blocked[c.ID],
		})
	}
	return r
}
