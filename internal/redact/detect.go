package redact

// Sensitive-value detection via regex patterns and user-seeded names.

import (
	"regexp"
	"sort"
	"strings"
)

// Match is a detected sensitive value in text.
type Match struct {
	Start    int
	End      int
	Value    string
	Category Category
}

// Detector finds PII and secrets in text.
type Detector struct {
	// patterns is category->compiled regex, applied in priority order.
	patterns []catPattern

	// seededNames are user-provided names to match literally.
	// Stored lowercased for case-insensitive matching.
	seededNames map[string]string // lower->original casing
}

type catPattern struct {
	cat Category
	re  *regexp.Regexp
}

// NewDetector creates a detector with compiled regex patterns.
func NewDetector() *Detector {
	d := &Detector{
		seededNames: make(map[string]string),
	}
	d.compilePatterns()
	return d
}

// SeedNames adds names to match literally. These are matched as whole words,
// case-insensitively. Each entry should be "First Last" or "First".
//
// Names that match genericTerms (common non-identifying words) are rejected
// to prevent false positives from NER models that extract directory names,
// project names, or technical terms as person names.
func (d *Detector) SeedNames(names []string) {
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}

		// Reject the full name if it matches a generic term.
		if isGenericTerm(strings.ToLower(n)) {
			continue
		}

		d.seededNames[strings.ToLower(n)] = n

		// Also seed individual parts of multi-word names so we can catch
		// first-name-only or last-name-only references.
		parts := strings.Fields(n)
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) >= 3 && !isGenericTerm(strings.ToLower(p)) {
				d.seededNames[strings.ToLower(p)] = p
			}
		}
	}
}

func (d *Detector) compilePatterns() {
	// Order matters: more specific patterns first to avoid partial matches.
	d.patterns = []catPattern{
		// AWS access keys: AKIA followed by 16 alphanumeric chars.
		{CatAWSKey, regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},

		// API keys: common prefixes. Match generously.
		{CatAPIKey, regexp.MustCompile(`\b(?:sk|pk|api|key|token|secret|access)[-_][A-Za-z0-9_-]{16,}\b`)},

		// Bearer tokens in auth headers (the token value itself).
		{CatBearer, regexp.MustCompile(`(?i)(?:Bearer|Authorization:?\s*Bearer)\s+([A-Za-z0-9_.+/=-]{20,})`)},

		// UUIDs.
		{CatUUID, regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)},

		// Email addresses.
		{CatEmail, regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)},

		// SSN: ###-##-#### (US Social Security Numbers).
		{CatSSN, regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},

		// Credit card numbers: 4 groups of 4 digits (with optional separators).
		{CatCreditCard, regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)},

		// Phone numbers: various formats.
		{CatPhone, regexp.MustCompile(`(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b`)},

		// Password-like assignments: password=..., passwd:..., etc.
		{CatPassword, regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd)\s*[:=]\s*["']?([^\s"']{4,})["']?`)},
	}
}

// Detect finds all sensitive values in text, returning non-overlapping matches
// ordered by position.
func (d *Detector) Detect(text string) []Match {
	var all []Match

	// 1. Regex-based detection.
	for _, cp := range d.patterns {
		matches := cp.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			val := text[m[0]:m[1]]

			// For Bearer tokens, extract just the token part.
			if cp.cat == CatBearer {
				if subs := cp.re.FindStringSubmatch(text[m[0]:m[1]]); len(subs) > 1 {
					// Adjust to only cover the token, not "Bearer ".
					tokenStart := strings.Index(val, subs[1])
					if tokenStart >= 0 {
						all = append(all, Match{
							Start:    m[0] + tokenStart,
							End:      m[0] + tokenStart + len(subs[1]),
							Value:    subs[1],
							Category: cp.cat,
						})
						continue
					}
				}
			}

			// For Password, extract just the value.
			if cp.cat == CatPassword {
				if subs := cp.re.FindStringSubmatch(text[m[0]:m[1]]); len(subs) > 1 {
					tokenStart := strings.Index(val, subs[1])
					if tokenStart >= 0 {
						all = append(all, Match{
							Start:    m[0] + tokenStart,
							End:      m[0] + tokenStart + len(subs[1]),
							Value:    subs[1],
							Category: cp.cat,
						})
						continue
					}
				}
			}

			all = append(all, Match{
				Start:    m[0],
				End:      m[1],
				Value:    val,
				Category: cp.cat,
			})
		}
	}

	// 2. Seeded-name matching (whole words, case-insensitive).
	if len(d.seededNames) > 0 {
		lower := strings.ToLower(text)
		for lowerName, origName := range d.seededNames {
			idx := 0
			for {
				pos := strings.Index(lower[idx:], lowerName)
				if pos < 0 {
					break
				}
				absPos := idx + pos
				end := absPos + len(lowerName)

				// Whole-word check.
				if (absPos == 0 || !isWordChar(text[absPos-1])) &&
					(end == len(text) || !isWordChar(text[end])) {
					// Use the actual casing from the text, not the seed.
					_ = origName
					all = append(all, Match{
						Start:    absPos,
						End:      end,
						Value:    text[absPos:end],
						Category: CatName,
					})
				}
				idx = absPos + 1
			}
		}
	}

	// De-duplicate: sort by start, remove overlaps (prefer earlier, longer).
	return dedup(all)
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

// dedup removes overlapping matches, preferring earlier start and longer span.
func dedup(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		return (matches[i].End - matches[i].Start) > (matches[j].End - matches[j].Start)
	})
	out := []Match{matches[0]}
	for i := 1; i < len(matches); i++ {
		last := out[len(out)-1]
		if matches[i].Start >= last.End {
			out = append(out, matches[i])
		}
		// overlapping: skip (keep the earlier/longer one)
	}
	return out
}
