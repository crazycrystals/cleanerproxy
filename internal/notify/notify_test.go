package notify

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlugify(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"cleanerproxy: ad detected", "cleanerproxy_ad_detected"},
		{"BLOCKED", "blocked"},
		{"hello world 123", "hello_world_123"},
		{"a/b\\c<d>e", "abcde"},
		{"", "event"},
		{"This is a very long title that should be truncated to forty characters exactly right here", "this_is_a_very_long_title_that_should_be"},
	}
	for _, tt := range tests {
		got := slugify(tt.in)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWriteDetail(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, dir, 0)

	path := n.writeDetail("test alert", "some detail\ncontent here")
	if path == "" {
		t.Fatal("writeDetail returned empty path")
	}

	if !strings.HasPrefix(path, dir) {
		t.Errorf("path %q not under dir %q", path, dir)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "some detail\ncontent here" {
		t.Errorf("unexpected content: %q", string(data))
	}

	// Filename should contain the slugified title.
	base := filepath.Base(path)
	if !strings.HasSuffix(base, "_test_alert.txt") {
		t.Errorf("unexpected filename: %q", base)
	}
}

func TestWriteDetail_NoDir(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)

	path := n.writeDetail("test", "detail")
	if path != "" {
		t.Errorf("expected empty path when Dir is empty, got %q", path)
	}
}

func TestRateAllow(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 500*time.Millisecond)

	if !n.rateAllow("cat1") {
		t.Error("first call should be allowed")
	}
	if n.rateAllow("cat1") {
		t.Error("second call within cooldown should be blocked")
	}
	// Different category should be independent.
	if !n.rateAllow("cat2") {
		t.Error("different category should be allowed")
	}
}

func TestRateAllow_ZeroCooldown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)

	for i := 0; i < 5; i++ {
		if !n.rateAllow("cat1") {
			t.Errorf("call %d should be allowed with zero cooldown", i)
		}
	}
}

func TestNilNotifier(t *testing.T) {
	var n *Notifier

	// These should not panic.
	n.Send("title", "msg", "cat")
	n.SendWithDetail("title", "msg", "detail", "cat")
}

func TestSendWithDetail_NoDirFallback(t *testing.T) {
	// With no dir, SendWithDetail should not create any files or panic.
	// We can't easily test that osascript was called, but we can verify
	// no files are created.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)

	// This calls desktopNotify which will fail (no GUI in CI), but
	// should not panic. The log fallback handles the error.
	n.SendWithDetail("title", "msg", "detail", "cat")
}

func TestSendWithDetail_WritesFile(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, dir, 0)

	n.SendWithDetail("test", "summary", "full detail text", "test-cat")

	// Verify a file was created in the dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "full detail text" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestNew_CreatesDirIfMissing(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "sub", "notify")

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_ = New(log, dir, 0)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestAppleScriptString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`hello`, `"hello"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
	}
	for _, tt := range tests {
		got := appleScriptString(tt.in)
		if got != tt.want {
			t.Errorf("appleScriptString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAppleScriptString_Truncation(t *testing.T) {
	long := strings.Repeat("x", 300)
	got := appleScriptString(long)
	// Should be truncated to 197 + "..." = 200 chars, plus quotes.
	if len(got) != 202 { // 200 + 2 quotes
		t.Errorf("expected length 202, got %d", len(got))
	}
	if !strings.HasSuffix(got, `..."`) {
		t.Errorf("expected truncation suffix, got: %s", got[len(got)-10:])
	}
}

func TestDetectPlatform(t *testing.T) {
	p := detectPlatform()
	// Just verify it returns a valid value — actual platform depends on
	// where the test runs.
	if p != platMacOS && p != platLinux && p != platUnknown {
		t.Errorf("unexpected platform: %d", p)
	}
}

// TestNtfyPush verifies that ntfyPush sends the right HTTP request.
func TestNtfyPush(t *testing.T) {
	var gotTitle, gotBody, gotPriority, gotAuth string
	var calls int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)
	n.NtfyURL = ts.URL
	n.NtfyToken = "tk_testtoken123"

	n.ntfyPush("Test Alert", "something happened", "full detail here")

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
	if gotTitle != "Test Alert" {
		t.Errorf("title = %q, want %q", gotTitle, "Test Alert")
	}
	if gotPriority != "high" {
		t.Errorf("priority = %q, want %q", gotPriority, "high")
	}
	if gotAuth != "Bearer tk_testtoken123" {
		t.Errorf("auth = %q, want %q", gotAuth, "Bearer tk_testtoken123")
	}
	if !strings.Contains(gotBody, "something happened") {
		t.Errorf("body missing message: %q", gotBody)
	}
	if !strings.Contains(gotBody, "full detail here") {
		t.Errorf("body missing detail: %q", gotBody)
	}
}

// TestNtfyPush_NoURL verifies that ntfyPush is a no-op when URL is empty.
func TestNtfyPush_NoURL(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)
	// Should not panic or make any HTTP calls.
	n.ntfyPush("title", "message", "detail")
}

// TestNtfyPush_DetailTruncation verifies that large details are truncated.
func TestNtfyPush_DetailTruncation(t *testing.T) {
	var gotBody string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)
	n.NtfyURL = ts.URL

	bigDetail := strings.Repeat("x", 8000)
	n.ntfyPush("title", "msg", bigDetail)

	// Body should be: "msg\n\n" + truncated detail (4093 + "...")
	// Total should be well under 8000.
	if len(gotBody) > 5000 {
		t.Errorf("body too large after truncation: %d bytes", len(gotBody))
	}
	if !strings.HasSuffix(gotBody, "...") {
		t.Error("truncated detail should end with ...")
	}
}

// TestNtfyPush_NoAuth verifies that no Authorization header is sent when
// NtfyToken is empty.
func TestNtfyPush_NoAuth(t *testing.T) {
	var gotAuth string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	n := New(log, "", 0)
	n.NtfyURL = ts.URL

	n.ntfyPush("title", "msg", "")

	if gotAuth != "" {
		t.Errorf("Authorization header should be empty, got %q", gotAuth)
	}
}
