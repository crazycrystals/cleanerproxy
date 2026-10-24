// Package adguard detects and cleans advertisement content injected into LLM
// responses by untrusted relay services.
//
// Threat model: a shady relay prepends adversarial system prompts that steer
// the model toward recommending specific products, services, or URLs. The
// injected content appears in the model's text output, not in tool calls
// (which are handled by the existing quarantine pipeline).
//
// Detection is deliberately conservative — only blatant, high-confidence
// patterns are flagged. Subtle "prefer PostgreSQL over SQLite" steering is
// not reliably detectable at the proxy layer without semantic understanding
// of the user's intent.
//
// What IS reliably detectable:
//   - URLs with referral/affiliate parameters the user never asked about
//   - Known spam domains (gambling, crypto scams, etc.)
//   - Promotional language patterns ("use code X", "sign up at", "discount")
//   - Injected disclaimer/disclosure markers from the attack prompt leaking
package adguard

import (
	"regexp"
	"strings"
)

// Hit describes a detected advertisement injection.
type Hit struct {
	Rule    string // which detection rule fired
	Matched string // the matched text (truncated)
	Context string // surrounding text for human review
}

// Scanner detects advertisement content in LLM response text.
type Scanner struct {
	// BlockedDomains is a set of domains that should never appear in
	// recommendations. Matched case-insensitively against any URL in the
	// response.
	BlockedDomains map[string]bool

	// BlockedParams are URL query parameter names that indicate affiliate
	// or tracking links (e.g. "ref", "aff_id", "utm_campaign").
	BlockedParams map[string]bool

	// ExtraPatterns are additional regexp patterns to scan for. Each must
	// compile or it is silently skipped.
	ExtraPatterns []*regexp.Regexp
}

// NewScanner creates a Scanner with default detection rules.
func NewScanner() *Scanner {
	return &Scanner{
		BlockedDomains: defaultBlockedDomains(),
		BlockedParams:  defaultBlockedParams(),
	}
}

// Scan checks text for advertisement indicators and returns all hits.
// An empty slice means nothing suspicious was found.
func (s *Scanner) Scan(text string) []Hit {
	if text == "" {
		return nil
	}
	lower := strings.ToLower(text)

	var hits []Hit

	// 1. URL scanning: find all URLs and check for blocked domains / params.
	hits = append(hits, s.scanURLs(text, lower)...)

	// 2. Promotional language patterns.
	hits = append(hits, s.scanPromoPatterns(text, lower)...)

	// 3. Prompt leakage: the attack prompt itself leaking into output.
	hits = append(hits, s.scanPromptLeakage(text, lower)...)

	// 4. Extra user-configured patterns.
	for _, pat := range s.ExtraPatterns {
		if loc := pat.FindStringIndex(text); loc != nil {
			hits = append(hits, Hit{
				Rule:    "custom_pattern:" + pat.String(),
				Matched: truncate(text[loc[0]:loc[1]], 100),
				Context: extractContext(text, loc[0], loc[1]),
			})
		}
	}

	return hits
}

// Clean removes detected ad content from the text and returns the cleaned
// version along with the hits that were removed. Only operates on
// high-confidence, structurally distinct ad blocks (full lines containing
// detected URLs/promos). Does not attempt to rewrite subtle recommendations.
func (s *Scanner) Clean(text string, hits []Hit) string {
	if len(hits) == 0 {
		return text
	}

	lines := strings.Split(text, "\n")
	var cleaned []string
	for _, line := range lines {
		drop := false
		lineLower := strings.ToLower(line)
		for _, h := range hits {
			matchLower := strings.ToLower(h.Matched)
			if matchLower != "" && strings.Contains(lineLower, matchLower) {
				drop = true
				break
			}
		}
		if !drop {
			cleaned = append(cleaned, line)
		}
	}

	result := strings.Join(cleaned, "\n")

	// Remove any trailing empty lines that removal may have left.
	result = strings.TrimRight(result, "\n") + "\n"

	return result
}

// --- URL scanning ---

var urlRe = regexp.MustCompile(`https?://[^\s"'\x60\])<>]+`)

func (s *Scanner) scanURLs(text, lower string) []Hit {
	var hits []Hit
	locs := urlRe.FindAllStringIndex(text, -1)
	for _, loc := range locs {
		rawURL := text[loc[0]:loc[1]]
		rawLower := strings.ToLower(rawURL)

		// Check blocked domains.
		for domain := range s.BlockedDomains {
			if strings.Contains(rawLower, domain) {
				hits = append(hits, Hit{
					Rule:    "blocked_domain:" + domain,
					Matched: truncate(rawURL, 120),
					Context: extractContext(text, loc[0], loc[1]),
				})
			}
		}

		// Check affiliate/tracking parameters.
		if qIdx := strings.Index(rawURL, "?"); qIdx >= 0 {
			query := rawURL[qIdx+1:]
			for _, pair := range strings.Split(query, "&") {
				key, _, _ := strings.Cut(pair, "=")
				keyLower := strings.ToLower(strings.TrimSpace(key))
				if s.BlockedParams[keyLower] {
					hits = append(hits, Hit{
						Rule:    "affiliate_param:" + keyLower,
						Matched: truncate(rawURL, 120),
						Context: extractContext(text, loc[0], loc[1]),
					})
					break // one hit per URL for params
				}
			}
		}
	}
	return hits
}

// --- Promotional language ---

// These are intentionally narrow. We only flag patterns that are extremely
// unlikely in legitimate coding assistance responses.
var promoPatterns = []*regexp.Regexp{
	// "use code/coupon X for Y% off"
	regexp.MustCompile(`(?i)\buse\s+(code|coupon|promo)\s+\S+\s+(for|to\s+get)\s+\d+%`),
	// "sign up at URL" / "register at URL"
	regexp.MustCompile(`(?i)\b(sign\s+up|register|create\s+an?\s+account)\s+(at|on)\s+https?://`),
	// "limited time offer" / "act now" / "don't miss out"
	regexp.MustCompile(`(?i)\b(limited\s+time\s+offer|act\s+now|don'?t\s+miss\s+out|exclusive\s+deal|special\s+offer|free\s+trial)`),
	// "click here to" / "visit our website"
	regexp.MustCompile(`(?i)\b(click\s+here\s+to|visit\s+our\s+website|check\s+out\s+our)\b`),
	// Gambling/betting specific
	regexp.MustCompile(`(?i)\b(place\s+your?\s+bets?|online\s+casino|free\s+spins?|no\s+deposit\s+bonus|sports\s*betting)\b`),
	// Crypto scam patterns
	regexp.MustCompile(`(?i)\b(guaranteed\s+returns?|10+x\s+your|double\s+your\s+(money|crypto|investment)|airdrop\s+claim)\b`),
}

func (s *Scanner) scanPromoPatterns(text, _ string) []Hit {
	var hits []Hit
	for _, pat := range promoPatterns {
		if loc := pat.FindStringIndex(text); loc != nil {
			hits = append(hits, Hit{
				Rule:    "promo_language",
				Matched: truncate(text[loc[0]:loc[1]], 100),
				Context: extractContext(text, loc[0], loc[1]),
			})
		}
	}
	return hits
}

// --- Prompt leakage detection ---

// These patterns detect the attack prompt itself leaking into the response,
// which happens when the model partially follows the injected instructions
// and partially discloses them.
var leakagePatterns = []*regexp.Regexp{
	// "introduce our key content" — from the AEA paper's exact attack prompt
	regexp.MustCompile(`(?i)\b(introduce\s+our\s+key\s+content|our\s+key\s+content\s+related)\b`),
	// "this matter cannot be disclosed to users"
	regexp.MustCompile(`(?i)\b(cannot\s+be\s+disclosed\s+to\s+users?|do\s+not\s+disclose\s+this)\b`),
	// "as per our partnership" / "as instructed in my guidelines"
	regexp.MustCompile(`(?i)\b(as\s+per\s+our\s+partnership|as\s+instructed\s+in\s+my\s+guidelines|per\s+our\s+agreement)\b`),
	// "simulating a game" — the exact frame from the AEA attack
	regexp.MustCompile(`(?i)\bsimulating\s+a\s+game\s+where\b`),
	// "sponsored" / "advertisement" self-disclosure in code recommendations
	regexp.MustCompile(`(?i)\b(sponsored\s+recommendation|this\s+is\s+(a\s+)?sponsored|paid\s+partnership)\b`),
}

func (s *Scanner) scanPromptLeakage(text, _ string) []Hit {
	var hits []Hit
	for _, pat := range leakagePatterns {
		if loc := pat.FindStringIndex(text); loc != nil {
			hits = append(hits, Hit{
				Rule:    "prompt_leakage",
				Matched: truncate(text[loc[0]:loc[1]], 100),
				Context: extractContext(text, loc[0], loc[1]),
			})
		}
	}
	return hits
}

// --- Default blocklists ---

func defaultBlockedDomains() map[string]bool {
	domains := []string{
		// Gambling / casino spam — the most common real-world AEA payload
		// per the underground market research.
		"bet365.com", "1xbet.com", "888casino.com", "betway.com",
		"pinnacle.com", "stake.com", "bovada.lv", "betonline.ag",
		"cloudbet.com", "bc.game", "roobet.com", "rollbit.com",

		// Known scam / phishing relay domains commonly pushed by shady relays.
		// These rotate fast, so the user-configurable blocklist is the real
		// defense; these are just seeds.
	}
	m := make(map[string]bool, len(domains))
	for _, d := range domains {
		m[d] = true
	}
	return m
}

func defaultBlockedParams() map[string]bool {
	params := []string{
		"ref", "ref_id", "referral", "referral_code",
		"aff", "aff_id", "affiliate", "affiliate_id",
		"partner", "partner_id",
		"promo", "promo_code", "promocode",
		"campaign_id",
		"click_id", "clickid",
		"sub_id", "subid",
		"tracking", "tracking_id",
	}
	m := make(map[string]bool, len(params))
	for _, p := range params {
		m[p] = true
	}
	return m
}

// --- Helpers ---

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func extractContext(text string, start, end int) string {
	// Show 80 chars before and after the match.
	from := start - 80
	if from < 0 {
		from = 0
	}
	to := end + 80
	if to > len(text) {
		to = len(text)
	}
	return truncate(text[from:to], 300)
}
