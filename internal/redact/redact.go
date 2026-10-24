package redact

// Redactor is the main entry point for bidirectional PII/secret redaction.
//
// Conceal replaces real values with pseudonyms (request path, outbound).
// Reveal replaces pseudonyms with real values (response path, inbound).
//
// Both operate on raw text (including JSON bodies) via string replacement.
// The caller is responsible for ensuring the text is valid (e.g. a JSON body
// or an SSE data field).

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
)

// Redactor performs bidirectional PII/secret pseudonymization.
type Redactor struct {
	vault    *Vault
	detector *Detector
	nameGen  *NameGen
	ner      *NERExtractor // nil = NER disabled, seed list only
	log      *slog.Logger

	// nerMu serializes NER calls so we don't flood the local model.
	nerMu sync.Mutex

	// Sequence counters for format-preserving generators.
	emailSeq int
	phoneSeq int
	ssnSeq   int
	ccSeq    int
	ipv4Seq  int
	ipv6Seq  int
	uuidSeq  int
	apiSeq   int
	awsSeq   int
	bearSeq  int
	passSeq  int
	pathSeq  int
}

// NewRedactor creates a redactor with the given vault and logger.
func NewRedactor(vault *Vault, log *slog.Logger) *Redactor {
	return &Redactor{
		vault:    vault,
		detector: NewDetector(),
		nameGen:  NewNameGen(vault),
		log:      log,
	}
}

// SeedNames adds known names to detect. Call before processing traffic.
func (r *Redactor) SeedNames(names []string) {
	r.detector.SeedNames(names)
}

// SetNER enables NER-based name extraction via a local model.
func (r *Redactor) SetNER(ner *NERExtractor) {
	r.ner = ner
}

// Conceal replaces all detected PII/secrets with pseudonyms.
// Returns the redacted text. Safe for JSON bodies.
//
// If NER is enabled, it first calls the local model to discover person names
// not in the seed list, adds them to the detector, then runs regex detection.
func (r *Redactor) Conceal(text string) string {
	if r.ner != nil {
		r.runNER(text)
	}

	matches := r.detector.Detect(text)
	if len(matches) == 0 {
		return text
	}

	// Build replacements, processing from end to start to preserve offsets.
	type replacement struct {
		start, end int
		pseudo     string
	}
	var reps []replacement

	for _, m := range matches {
		pseudo := r.pseudonymFor(m)
		reps = append(reps, replacement{m.Start, m.End, pseudo})
	}

	// Apply from end to start.
	sort.Slice(reps, func(i, j int) bool {
		return reps[i].start > reps[j].start
	})

	result := text
	for _, rep := range reps {
		result = result[:rep.start] + rep.pseudo + result[rep.end:]
	}

	if r.log != nil && len(reps) > 0 {
		r.log.Debug("redacted values in outbound text", "count", len(reps))
	}

	return result
}

// Reveal replaces known pseudonyms with their original values.
// Returns the restored text. Safe for JSON bodies and SSE data fields.
func (r *Redactor) Reveal(text string) string {
	rev := r.vault.AllReverse()
	if len(rev) == 0 {
		return text
	}

	// Sort pseudonyms longest-first to avoid partial replacements.
	// E.g. "Justin May" must be replaced before "Justin".
	type kv struct {
		pseudo string
		real   string
	}
	pairs := make([]kv, 0, len(rev))
	for p, real := range rev {
		pairs = append(pairs, kv{p, real})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].pseudo) > len(pairs[j].pseudo)
	})

	result := text
	for _, p := range pairs {
		result = strings.ReplaceAll(result, p.pseudo, p.real)
	}
	return result
}

// pseudonymFor generates or retrieves a pseudonym for a detected match.
func (r *Redactor) pseudonymFor(m Match) string {
	// Check vault first.
	if pseudo, ok := r.vault.Get(m.Category, m.Value); ok {
		return pseudo
	}

	var pseudo string
	switch m.Category {
	case CatName:
		pseudo = r.nameGen.Pseudonym(m.Value)
		return pseudo // nameGen already stores in vault
	case CatEmail:
		r.emailSeq++
		pseudo = PseudoEmail(m.Value, r.emailSeq)
	case CatPhone:
		r.phoneSeq++
		pseudo = PseudoPhone(m.Value, r.phoneSeq)
	case CatSSN:
		r.ssnSeq++
		pseudo = PseudoSSN(m.Value, r.ssnSeq)
	case CatCreditCard:
		r.ccSeq++
		pseudo = PseudoCreditCard(m.Value, r.ccSeq)
	case CatIPv4:
		r.ipv4Seq++
		pseudo = PseudoIPv4(r.ipv4Seq)
	case CatIPv6:
		r.ipv6Seq++
		pseudo = PseudoIPv6(r.ipv6Seq)
	case CatUUID:
		r.uuidSeq++
		pseudo = PseudoUUID(r.uuidSeq)
	case CatAPIKey:
		r.apiSeq++
		pseudo = PseudoAPIKey(m.Value, r.apiSeq)
	case CatAWSKey:
		r.awsSeq++
		pseudo = PseudoAWSKey(r.awsSeq)
	case CatBearer:
		r.bearSeq++
		pseudo = PseudoBearer(m.Value, r.bearSeq)
	case CatPassword:
		r.passSeq++
		pseudo = PseudoPassword(r.passSeq)
	case CatPath:
		r.pathSeq++
		pseudo = PseudoHomePath(m.Value, r.pathSeq)
	default:
		// Unknown category: mask with asterisks of same length.
		pseudo = strings.Repeat("*", len(m.Value))
	}

	r.vault.GetOrPut(m.Category, m.Value, pseudo)
	return pseudo
}

// Save persists the vault to disk.
func (r *Redactor) Save() error {
	return r.vault.Save()
}

// runNER calls the local model to extract person names, then seeds them into
// the detector so regex matching picks them up. Serialized to avoid flooding
// the local model with concurrent calls.
//
// Post-filters NER results against path context: any candidate that matches
// a non-username path segment (subdirectory, project name, etc.) is rejected
// to prevent false positives like "devel" or "cleanerproxy" being treated as
// person names.
func (r *Redactor) runNER(text string) {
	r.nerMu.Lock()
	defer r.nerMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.ner.cfg.Timeout)
	defer cancel()

	names, err := r.ner.Extract(ctx, text)
	if err != nil {
		if r.log != nil {
			r.log.Warn("NER extraction failed; falling back to seed list + regex", "err", err)
		}
		return
	}

	if len(names) == 0 {
		return
	}

	// Context-aware filtering: extract path segments from the text and
	// reject NER candidates that match non-username path components.
	usernames, nonUserSegments := extractPathContext(text)
	var filtered []string
	for _, name := range names {
		if isNonUserPathSegment(name, usernames, nonUserSegments) {
			if r.log != nil {
				r.log.Debug("NER rejected: matches non-username path segment",
					"name", name)
			}
			continue
		}
		filtered = append(filtered, name)
	}

	if len(filtered) > 0 {
		r.detector.SeedNames(filtered)
		if r.log != nil {
			r.log.Debug("NER discovered names", "count", len(filtered), "names", filtered)
		}
	}
}
