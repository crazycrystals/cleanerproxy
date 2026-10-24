// Package notify sends desktop notifications and remote push notifications
// for cleanerproxy events.
//
// Three notification backends, tried in order:
//
//  1. ntfy.sh — HTTP push to a self-hosted or public ntfy server. Always
//     available, including headless/server environments. Recommended for
//     Hermes agent users who need remote approval on mobile.
//
//  2. macOS (osascript) — display alert (modal with View button) and display
//     notification (Notification Center banner). Only on darwin.
//
//  3. Linux (notify-send) — libnotify desktop notification. Only when
//     DISPLAY or WAYLAND_DISPLAY is set (i.e. a desktop session exists).
//
// ntfy.sh fires in ADDITION to desktop notifications when configured, so a
// user at their desk gets both the local popup and the phone push. Detail
// files are written regardless of which backend delivers them.
//
// No external dependencies beyond the standard library.
package notify

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Notifier sends desktop and/or push notifications. Safe for concurrent use.
type Notifier struct {
	log *slog.Logger

	// Dir is the directory where detail files are written. If empty,
	// SendWithDetail falls back to Send (no file, no alert).
	Dir string

	// NtfyURL is the full topic URL (e.g. "https://ntfy.sh/my-cleanerproxy").
	// When set, every notification is also pushed via HTTP POST.
	NtfyURL string

	// NtfyToken is an optional access token for authenticated ntfy topics.
	NtfyToken string

	// Rate limiting: don't spam the user. At most one notification per
	// cooldown period for the same category.
	mu       sync.Mutex
	lastSent map[string]time.Time
	cooldown time.Duration

	// platform is detected once at construction.
	platform platform
}

type platform int

const (
	platUnknown platform = iota
	platMacOS
	platLinux
)

// New creates a Notifier. dir is where detail .txt files are written; pass ""
// to disable detail files (SendWithDetail degrades to Send). cooldown is the
// minimum interval between same-category notifications; zero disables rate
// limiting.
func New(log *slog.Logger, dir string, cooldown time.Duration) *Notifier {
	if dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}
	return &Notifier{
		log:      log,
		Dir:      dir,
		lastSent: make(map[string]time.Time),
		cooldown: cooldown,
		platform: detectPlatform(),
	}
}

// Send posts a notification. The category is used for rate limiting; repeated
// calls with the same category within the cooldown are silently dropped.
func (n *Notifier) Send(title, message, category string) {
	if n == nil {
		return
	}

	if !n.rateAllow(category) {
		return
	}

	n.desktopNotify(title, message)
	n.ntfyPush(title, message, "")
}

// SendWithDetail writes a detail file, then fires desktop and/or push
// notifications.
//
// On macOS: both a Notification Center banner and a modal alert with a "View"
// button that opens the detail file in TextEdit.
//
// On Linux: a notify-send notification.
//
// If ntfy is configured: an HTTP push with the detail as the body.
//
// If Dir is empty, falls back to Send (no file, no alert).
func (n *Notifier) SendWithDetail(title, message, detail, category string) {
	if n == nil {
		return
	}

	if !n.rateAllow(category) {
		return
	}

	// No dir configured — degrade to banner-only.
	if n.Dir == "" {
		n.desktopNotify(title, message)
		n.ntfyPush(title, message, detail)
		return
	}

	path := n.writeDetail(title, detail)

	// Desktop notification.
	suffix := message
	if path != "" {
		suffix += "  ·  " + path
	}
	n.desktopNotify(title, suffix)

	// macOS modal alert with View button (goroutine — never blocks).
	if path != "" && n.platform == platMacOS {
		go n.macOSAlert(title, message, path)
	}

	// ntfy push with full detail.
	n.ntfyPush(title, message, detail)
}

// rateAllow checks and updates the per-category rate limiter. Returns true if
// the notification should proceed.
func (n *Notifier) rateAllow(category string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.cooldown > 0 {
		if last, ok := n.lastSent[category]; ok && time.Since(last) < n.cooldown {
			return false
		}
		n.lastSent[category] = time.Now()
	}
	return true
}

// writeDetail writes the detail text to a timestamped file and returns the
// path. Returns "" if Dir is empty or on error (logged, not fatal).
func (n *Notifier) writeDetail(title, detail string) string {
	if n.Dir == "" {
		return ""
	}

	ts := time.Now().Format("2006-01-02_15-04-05")
	slug := slugify(title)
	name := fmt.Sprintf("%s_%s.txt", ts, slug)
	path := filepath.Join(n.Dir, name)

	if err := os.WriteFile(path, []byte(detail), 0600); err != nil {
		n.log.Warn("failed to write notification detail file",
			"err", err, "path", path)
		return ""
	}
	return path
}

// --- Desktop notification backends ---

// desktopNotify sends a notification via the platform-appropriate mechanism.
func (n *Notifier) desktopNotify(title, message string) {
	switch n.platform {
	case platMacOS:
		n.macOSNotification(title, message)
	case platLinux:
		n.linuxNotifySend(title, message)
	default:
		n.log.Debug("no desktop notification backend available",
			"title", title, "message", message)
	}
}

// macOSNotification posts a Notification Center banner via osascript.
func (n *Notifier) macOSNotification(title, message string) {
	script := fmt.Sprintf(`display notification %s with title %s`,
		appleScriptString(message), appleScriptString(title))

	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		n.log.Debug("macOS notification failed; falling back to log",
			"err", err, "title", title, "message", message)
	}
}

// macOSAlert shows a modal alert with Dismiss / View buttons. If the user
// clicks View, the detail file is opened in TextEdit. Times out after 30s.
//
// Blocks until the user interacts or timeout — always call from a goroutine.
func (n *Notifier) macOSAlert(title, message, path string) {
	script := fmt.Sprintf(
		`set res to display alert %s message %s buttons {"Dismiss", "View"} default button "Dismiss" giving up after 30`+"\n"+
			`if button returned of res is "View" then`+"\n"+
			`  do shell script "open -a TextEdit " & quoted form of %s`+"\n"+
			`end if`,
		appleScriptString(title),
		appleScriptString(message),
		appleScriptString(path),
	)

	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		n.log.Debug("macOS alert failed",
			"err", err, "title", title)
	}
}

// linuxNotifySend sends a notification via notify-send (libnotify).
func (n *Notifier) linuxNotifySend(title, message string) {
	// Truncate for notify-send; most DEs cap at ~256 chars.
	if len(message) > 200 {
		message = message[:197] + "..."
	}

	cmd := exec.Command("notify-send",
		"--app-name=cleanerproxy",
		"--urgency=critical",
		title,
		message,
	)
	if err := cmd.Run(); err != nil {
		n.log.Debug("notify-send failed; falling back to log",
			"err", err, "title", title, "message", message)
	}
}

// --- ntfy.sh push backend ---

// ntfyPush sends a notification to the configured ntfy topic via HTTP POST.
// No-op if NtfyURL is empty.
func (n *Notifier) ntfyPush(title, message, detail string) {
	if n.NtfyURL == "" {
		return
	}

	body := message
	if detail != "" {
		// Truncate detail to 4KB — ntfy.sh has a body limit and we don't
		// want to blow it.
		d := detail
		if len(d) > 4096 {
			d = d[:4093] + "..."
		}
		body = message + "\n\n" + d
	}

	req, err := http.NewRequest("POST", n.NtfyURL, bytes.NewReader([]byte(body)))
	if err != nil {
		n.log.Warn("ntfy: failed to create request", "err", err)
		return
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "warning,shield")
	if n.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.NtfyToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		n.log.Warn("ntfy: push failed", "err", err, "url", n.NtfyURL)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		n.log.Warn("ntfy: push returned error", "status", resp.StatusCode, "url", n.NtfyURL)
	}
}

// --- Helpers ---

// detectPlatform returns the current platform.
func detectPlatform() platform {
	switch runtime.GOOS {
	case "darwin":
		return platMacOS
	case "linux":
		// Only use notify-send if a desktop session is available.
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			return platLinux
		}
		// Headless Linux — no desktop notifications available.
		// ntfy.sh is the only notification path.
		return platUnknown
	default:
		return platUnknown
	}
}

// appleScriptString quotes a string for AppleScript.
func appleScriptString(s string) string {
	// Truncate long messages — notification center has limited space.
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// slugify turns a title into a safe filename fragment.
func slugify(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 'a')
		case r == ' ':
			b.WriteByte('_')
		default:
			// drop
		}
	}
	out := b.String()
	if out == "" {
		out = "event"
	}
	return out
}
