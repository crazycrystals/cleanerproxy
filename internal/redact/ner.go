package redact

// NER-based person name and username extraction via a local LLM (oMLX).
//
// Called on each request to detect person names and system usernames that
// aren't in the seed list. Results are cached in the vault so each unique
// text span is only NER'd once.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// NERConfig holds the configuration for the local NER model.
type NERConfig struct {
	// BaseURL is the oMLX server URL (e.g. "http://127.0.0.1:8001").
	BaseURL string

	// Model is the model ID for NER extraction.
	Model string

	// APIKey is the oMLX API key.
	APIKey string

	// Timeout for the NER call.
	Timeout time.Duration
}

// NERExtractor extracts person names and usernames from text using a local LLM.
type NERExtractor struct {
	cfg    NERConfig
	client *http.Client
}

// NewNERExtractor creates a new NER extractor.
func NewNERExtractor(cfg NERConfig) *NERExtractor {
	return &NERExtractor{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

const nerSystemPrompt = `Extract person names and the FIRST directory after /Users/ or /home/ (the login username) from the text. Return ONLY a JSON array of quoted strings. No duplicates. No explanation.

Extract:
- Person names (first, last, or full names of real humans)
- The login username from paths: ONLY the component immediately after /Users/ or /home/ (e.g. from /Users/alice/projects/myapp, extract ONLY "alice")

Do NOT extract:
- Subdirectories, project names, folder names, or repository names (e.g. from /Users/alice/projects/myapp, do NOT extract "projects" or "myapp")
- Company names, product names, brand names
- Programming terms, tool names, package names, binary names
- Generic words like "user", "admin", "root", "nobody"
- Anything that looks like a software project, command, or config file

Example: "Ask John Smith about /Users/devuser/projects/cleanerproxy/config.go"
Output: ["John Smith", "devuser"]

Example: "Reading /home/alice/devel/myproject/src/main.go"
Output: ["alice"]

Example: "The server runs Linux as root."
Output: []`

// Extract returns person names and usernames found in the text.
func (n *NERExtractor) Extract(ctx context.Context, text string) ([]string, error) {
	// Truncate very long texts -- NER only needs enough context to find names,
	// and the full conversation can be enormous.
	if len(text) > 8000 {
		text = text[:8000]
	}

	reqBody := map[string]any{
		"model": n.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": nerSystemPrompt},
			{"role": "user", "content": text},
		},
		"temperature": 0.0,
		"max_tokens":  512,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ner: marshal request: %w", err)
	}

	url := strings.TrimRight(n.cfg.BaseURL, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ner: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.APIKey)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ner: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ner: read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ner: status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the OpenAI-compatible response.
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("ner: parse response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, nil
	}

	content := strings.TrimSpace(result.Choices[0].Message.Content)

	// The model may wrap the JSON in markdown code fences. Strip them.
	content = stripCodeFences(content)

	// Some models include thinking tags. Strip those too.
	if idx := strings.Index(content, "["); idx >= 0 {
		content = content[idx:]
	}
	if idx := strings.LastIndex(content, "]"); idx >= 0 {
		content = content[:idx+1]
	}

	var names []string
	if err := json.Unmarshal([]byte(content), &names); err != nil {
		// Fallback: the model may return unquoted names like [John McAffrey].
		// Try to salvage by adding quotes.
		names = parseUnquotedArray(content)
		if len(names) == 0 {
			return nil, nil
		}
	}

	// Deduplicate and filter. A 0.5B model can hallucinate -- reject anything
	// that obviously isn't a person name or username.
	seen := make(map[string]bool)
	var filtered []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		// Normalize casing: NER models may return "john mcaffrey" preserving
		// user input casing. Title-case multi-word names so the plausibility
		// filter (which requires uppercase initials) doesn't reject them.
		name = titleCaseWords(name)
		if !isPlausibleName(name) {
			continue
		}
		if !seen[name] {
			seen[name] = true
			filtered = append(filtered, name)
		}
	}

	return filtered, nil
}

// isPlausibleName rejects NER hallucinations that are obviously not person
// names or usernames. A 0.5B model will sometimes return entire sentences,
// instructions, project names, or other garbage.
func isPlausibleName(s string) bool {
	// Too short or too long.
	if len(s) < 2 || len(s) > 50 {
		return false
	}
	// Contains newlines -- not a name.
	if strings.ContainsAny(s, "\n\r\t") {
		return false
	}
	// More than 4 words -- not a name or username.
	words := strings.Fields(s)
	if len(words) > 4 {
		return false
	}
	// Single word: stricter filtering.
	if len(words) == 1 {
		lower := strings.ToLower(words[0])
		// Reject known generic/tech terms.
		for _, generic := range genericTerms {
			if lower == generic {
				return false
			}
		}
		// Reject if it contains dots, slashes, or other non-name punctuation
		// (looks like a path, URL, or package name).
		if strings.ContainsAny(words[0], "./\\:") {
			return false
		}
		// Must be alphanumeric/hyphens/underscores (name or username shape).
		for _, r := range words[0] {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '\'') {
				return false
			}
		}
		return true
	}
	// Multi-word: each word must start with an uppercase letter (name shape).
	for _, w := range words {
		clean := strings.NewReplacer("-", "", "'", "", "\u2019", "").Replace(w)
		if len(clean) == 0 {
			continue
		}
		first := clean[0]
		if first < 'A' || first > 'Z' {
			return false
		}
	}
	return true
}

// titleCaseWords uppercases the first letter of each word. Single words are
// left as-is so that usernames like "crystals" aren't mangled.
func titleCaseWords(s string) string {
	words := strings.Fields(s)
	if len(words) <= 1 {
		return s
	}
	for i, w := range words {
		runes := []rune(w)
		if len(runes) > 0 {
			runes[0] = unicode.ToUpper(runes[0])
		}
		words[i] = string(runes)
	}
	return strings.Join(words, " ")
}

// genericTerms are common words that NER might return but are not identifying.
// This includes system users, common English words, directory/project names,
// programming terms, and tool names that a small model might confuse for
// person names or usernames.
var genericTerms = []string{
	// System users.
	"user", "admin", "root", "nobody", "daemon", "system", "guest",
	"operator", "default", "test", "dev", "staff", "wheel", "sudo",
	// Common English words.
	"the", "and", "for", "with", "from", "this", "that", "what",
	"how", "who", "when", "where", "which", "about",
	// Common directory/path names that are NOT usernames.
	"devel", "develop", "projects", "workspace", "repos", "src",
	"source", "code", "build", "dist", "bin", "lib", "var", "tmp",
	"opt", "etc", "usr", "local", "share", "include", "config",
	"conf", "data", "logs", "log", "cache", "temp", "backup",
	"documents", "downloads", "desktop", "pictures", "music",
	"videos", "public", "private", "work", "sites", "www",
	"applications", "library", "contents", "resources", "frameworks",
	// Programming/tech terms that look like single-word names.
	"proxy", "server", "client", "handler", "router", "middleware",
	"controller", "service", "manager", "factory", "builder",
	"parser", "scanner", "reader", "writer", "buffer", "stream",
	"socket", "channel", "worker", "monitor", "watcher", "helper",
	"utils", "util", "tools", "tool", "plugin", "module", "package",
	"internal", "external", "vendor", "node_modules", "target",
	"output", "input", "assets", "static", "public", "templates",
	// Common project/tool names that are not people.
	"nginx", "docker", "redis", "postgres", "mysql", "mongo",
	"grafana", "prometheus", "kubernetes", "terraform", "ansible",
	"jenkins", "gitlab", "github", "bitbucket", "heroku",
	"opencode", "cleanerproxy", "guardian", "sentinel", "evilproxy",
	// Go/programming language terms.
	"main", "init", "setup", "run", "start", "stop", "close",
	"open", "read", "write", "delete", "update", "create",
	"cmd", "pkg", "api", "app", "web",
}

// isGenericTerm reports whether a lowercased string matches a known
// non-identifying term. Used by both NER filtering and SeedNames.
func isGenericTerm(lower string) bool {
	for _, g := range genericTerms {
		if lower == g {
			return true
		}
	}
	return false
}

// stripCodeFences removes markdown ```json ... ``` wrappers.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove opening fence (```json or just ```)
		if idx := strings.Index(s, "\n"); idx >= 0 {
			s = s[idx+1:]
		}
		// Remove closing fence
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	return strings.TrimSpace(s)
}

// parseUnquotedArray handles model output like [John McAffrey, Jane Doe]
// where strings aren't quoted.
func parseUnquotedArray(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip quotes if present.
		p = strings.Trim(p, `"'`)
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pathSegmentRe matches Unix-style absolute paths.
var pathSegmentRe = regexp.MustCompile(`(?:/Users/|/home/)([^/\s]+)(/[^\s"'` + "`" + `]+)?`)

// extractPathContext returns the set of username path segments (the component
// immediately after /Users/ or /home/) and all OTHER path segments from the
// text. This allows us to distinguish the actual username from subdirectory
// names that a naive NER model might also extract.
func extractPathContext(text string) (usernames map[string]bool, nonUserSegments map[string]bool) {
	usernames = make(map[string]bool)
	nonUserSegments = make(map[string]bool)

	matches := pathSegmentRe.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		username := m[1]
		usernames[strings.ToLower(username)] = true

		// Parse the rest of the path after the username.
		if len(m) > 2 && m[2] != "" {
			rest := m[2] // e.g. "/devel/cleanerproxy/internal/foo.go"
			parts := strings.Split(rest, "/")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				// Strip file extensions for directory-name matching.
				if dot := strings.LastIndex(p, "."); dot > 0 {
					p = p[:dot]
				}
				lower := strings.ToLower(p)
				if lower != "" {
					nonUserSegments[lower] = true
				}
			}
		}
	}
	return
}

// isNonUserPathSegment returns true if a candidate NER name matches a
// path segment that is NOT a username (i.e. it's a subdirectory, project
// name, or filename).
func isNonUserPathSegment(name string, usernames, nonUserSegments map[string]bool) bool {
	lower := strings.ToLower(name)
	// If it's a known username, allow it.
	if usernames[lower] {
		return false
	}
	// If it appears as a non-username path segment, reject it.
	return nonUserSegments[lower]
}
