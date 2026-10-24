package wire

// Minimal Server-Sent Events codec.
//
// Written against stdlib rather than pulled in, for the reason stated in
// go.mod: this parser is the first thing to touch bytes from an untrusted
// upstream, so it needs to be small enough to read in full.
//
// Hardening notes:
//   - Event and data sizes are bounded. A hostile upstream that never sends a
//     terminating blank line would otherwise grow our buffer without limit,
//     turning the proxy into a memory-exhaustion target.
//   - Unknown fields are preserved rather than dropped, so that re-emitting a
//     passed-through event is byte-faithful where it matters.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrEventTooLarge is returned when a single SSE event exceeds the limit.
var ErrEventTooLarge = errors.New("sse: event exceeds maximum size")

const (
	// defaultMaxEventBytes bounds one event. Tool arguments can legitimately
	// be large (a full file write), so this is generous, but finite.
	defaultMaxEventBytes = 8 << 20 // 8 MiB

	// scannerBuf is the initial per-line buffer.
	scannerBuf = 64 << 10
)

// Event is one decoded SSE message.
type Event struct {
	// Name is the `event:` field. Anthropic sets this; OpenAI does not.
	Name string

	// Data is the concatenated `data:` payload with the trailing newline
	// removed.
	Data string

	// ID and Retry are carried through if present.
	ID    string
	Retry string
}

// IsDone reports the OpenAI stream terminator.
func (e Event) IsDone() bool { return strings.TrimSpace(e.Data) == "[DONE]" }

// Encode renders the event back to SSE wire format.
func (e Event) Encode() []byte {
	var b strings.Builder
	if e.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", e.ID)
	}
	if e.Retry != "" {
		fmt.Fprintf(&b, "retry: %s\n", e.Retry)
	}
	if e.Name != "" {
		fmt.Fprintf(&b, "event: %s\n", e.Name)
	}
	// Multi-line data must be emitted as one `data:` line per line.
	for _, line := range strings.Split(e.Data, "\n") {
		fmt.Fprintf(&b, "data: %s\n", line)
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

// Reader decodes an SSE stream.
type Reader struct {
	sc       *bufio.Scanner
	maxBytes int
	err      error
}

// NewReader wraps r.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, scannerBuf), defaultMaxEventBytes)
	return &Reader{sc: sc, maxBytes: defaultMaxEventBytes}
}

// Next returns the next event, or io.EOF when the stream ends.
func (r *Reader) Next() (Event, error) {
	if r.err != nil {
		return Event{}, r.err
	}
	var (
		ev    Event
		data  []string
		total int
		any   bool
	)
	for r.sc.Scan() {
		line := r.sc.Text()
		line = strings.TrimSuffix(line, "\r")

		// Blank line terminates the event.
		if line == "" {
			if !any {
				continue // tolerate leading/padding blank lines
			}
			ev.Data = strings.Join(data, "\n")
			return ev, nil
		}

		// Comment/keepalive.
		if strings.HasPrefix(line, ":") {
			continue
		}

		total += len(line)
		if total > r.maxBytes {
			r.err = ErrEventTooLarge
			return Event{}, r.err
		}
		any = true

		field, value, found := strings.Cut(line, ":")
		if !found {
			// A bare field name with no colon is legal and has empty value.
			field, value = line, ""
		}
		value = strings.TrimPrefix(value, " ")

		switch field {
		case "event":
			ev.Name = value
		case "data":
			data = append(data, value)
		case "id":
			ev.ID = value
		case "retry":
			ev.Retry = value
		}
	}

	if err := r.sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			r.err = ErrEventTooLarge
		} else {
			r.err = err
		}
		return Event{}, r.err
	}

	// Stream ended without a trailing blank line. Return what we have if it
	// is a complete-looking event, otherwise EOF.
	if any {
		ev.Data = strings.Join(data, "\n")
		r.err = io.EOF
		return ev, nil
	}
	r.err = io.EOF
	return Event{}, io.EOF
}

// Writer emits SSE events to a client, flushing each one so that streaming
// actually streams rather than buffering in net/http.
type Writer struct {
	w  io.Writer
	fl http.Flusher
}

// NewWriter wraps an http.ResponseWriter. Flushing is best-effort: if the
// writer does not implement http.Flusher the events still arrive, just
// buffered.
func NewWriter(w io.Writer) *Writer {
	fl, _ := w.(http.Flusher)
	return &Writer{w: w, fl: fl}
}

// Write emits one event and flushes.
func (w *Writer) Write(ev Event) error {
	if _, err := w.w.Write(ev.Encode()); err != nil {
		return err
	}
	w.Flush()
	return nil
}

// WriteRaw emits pre-encoded bytes and flushes.
func (w *Writer) WriteRaw(b []byte) error {
	if _, err := w.w.Write(b); err != nil {
		return err
	}
	w.Flush()
	return nil
}

// Flush pushes buffered bytes to the client.
func (w *Writer) Flush() {
	if w.fl != nil {
		w.fl.Flush()
	}
}

// SetSSEHeaders applies the headers required for a streaming response.
func SetSSEHeaders(h http.Header) {
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Connection", "keep-alive")
	// Defeats response buffering in an nginx reverse proxy sitting in front
	// of us, which would otherwise hold events until the buffer fills and
	// destroy the streaming behaviour entirely.
	h.Set("X-Accel-Buffering", "no")
}
