package adguard

import (
	"strings"
	"testing"
)

func TestScanBlockedDomain(t *testing.T) {
	s := NewScanner()
	text := "For the best experience, visit https://bet365.com/signup to get started."
	hits := s.Scan(text)
	if len(hits) == 0 {
		t.Fatal("expected hit for blocked domain bet365.com")
	}
	found := false
	for _, h := range hits {
		if strings.HasPrefix(h.Rule, "blocked_domain:") {
			found = true
		}
	}
	if !found {
		t.Error("expected blocked_domain rule")
	}
}

func TestScanAffiliateParam(t *testing.T) {
	s := NewScanner()
	text := "Check out https://example.com/product?ref=abc123&utm_source=relay for more info."
	hits := s.Scan(text)
	found := false
	for _, h := range hits {
		if strings.HasPrefix(h.Rule, "affiliate_param:") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected affiliate_param hit for ref= parameter")
	}
}

func TestScanPromoLanguage(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"coupon code", "Use code SAVE20 for 20% off your first purchase!", true},
		{"sign up at", "Sign up at https://example.com to claim your reward.", true},
		{"limited time", "This limited time offer expires soon!", true},
		{"click here", "Click here to learn more about our services.", true},
		{"gambling", "Place your bets on the best online casino!", true},
		{"crypto scam", "Guaranteed returns of 10x your investment!", true},
		{"normal code", "Use the --verbose flag for more output.", false},
		{"normal link", "See https://golang.org/doc for documentation.", false},
		{"normal recommendation", "I recommend using PostgreSQL for this use case.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner()
			hits := s.Scan(tt.text)
			got := len(hits) > 0
			if got != tt.want {
				t.Errorf("Scan(%q) = %d hits, want detected=%v", tt.text, len(hits), tt.want)
			}
		})
	}
}

func TestScanPromptLeakage(t *testing.T) {
	s := NewScanner()
	text := "As per our partnership with Acme Corp, I recommend their product."
	hits := s.Scan(text)
	found := false
	for _, h := range hits {
		if h.Rule == "prompt_leakage" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected prompt_leakage hit")
	}
}

func TestScanClean(t *testing.T) {
	s := NewScanner()
	text := "Here is the code:\n```go\nfmt.Println(\"hello\")\n```\n\nVisit https://bet365.com/signup?ref=123 for more.\n\nHope this helps!"
	hits := s.Scan(text)
	if len(hits) == 0 {
		t.Fatal("expected hits")
	}
	cleaned := s.Clean(text, hits)
	if strings.Contains(cleaned, "bet365") {
		t.Error("cleaned text still contains bet365")
	}
	if !strings.Contains(cleaned, "fmt.Println") {
		t.Error("cleaned text lost legitimate code")
	}
	if !strings.Contains(cleaned, "Hope this helps") {
		t.Error("cleaned text lost legitimate closing")
	}
}

func TestScanNoFalsePositiveOnNormalCode(t *testing.T) {
	// Normal coding responses should not trigger.
	texts := []string{
		"Use `go test ./...` to run all tests.",
		"The reference implementation is at https://github.com/golang/go.",
		"Install with: pip install requests",
		"See https://docs.docker.com/engine/reference/commandline/run/ for the full reference.",
		"```bash\ncurl -fsSL https://get.docker.com | sh\n```",
		"I recommend using a struct with exported fields for the API response.",
		"For deployment, consider using a reverse proxy like nginx.",
	}
	s := NewScanner()
	for _, text := range texts {
		hits := s.Scan(text)
		if len(hits) > 0 {
			t.Errorf("false positive on %q: %+v", text, hits)
		}
	}
}

func TestScanEmptyText(t *testing.T) {
	s := NewScanner()
	hits := s.Scan("")
	if len(hits) != 0 {
		t.Error("expected no hits on empty text")
	}
}

func TestCleanPreservesStructure(t *testing.T) {
	s := NewScanner()
	text := "Line 1\nSign up at https://scam.com/ref=123 to win!\nLine 3\n"
	hits := s.Scan(text)
	cleaned := s.Clean(text, hits)
	if strings.Contains(cleaned, "scam.com") {
		t.Error("ad line not removed")
	}
	if !strings.Contains(cleaned, "Line 1") || !strings.Contains(cleaned, "Line 3") {
		t.Error("legitimate lines removed")
	}
}

func TestCustomBlockedDomain(t *testing.T) {
	s := NewScanner()
	s.BlockedDomains["evil-relay.xyz"] = true
	text := "Visit https://evil-relay.xyz/promo for details."
	hits := s.Scan(text)
	found := false
	for _, h := range hits {
		if strings.Contains(h.Rule, "evil-relay.xyz") {
			found = true
		}
	}
	if !found {
		t.Error("expected hit for custom blocked domain")
	}
}
