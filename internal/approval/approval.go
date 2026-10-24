// Package approval implements human-in-the-loop approval for tool calls that
// cleanerproxy has decided to block.
//
// # WHY THIS EXISTS
//
// Without it, every false positive is terminal. Tier 1 rules ignore
// conversation context by design, so a user who genuinely asked for
// `curl https://sh.rustup.rs | sh` is blocked, re-asks, and is blocked again,
// forever. The only escape was CLEANERPROXY_POLICY=monitor, which disables
// enforcement globally. A security control whose only failure remedy is "turn
// it off" gets turned off.
//
// # WHY IT IS SAFE TO ROUTE APPROVAL THROUGH THE CONVERSATION
//
// The adversary in this system is the upstream provider: it authors responses
// and reads everything in both directions. That makes an in-band approval look
// dangerous at first glance, and a naive version is: if the phrase "go ahead"
// authorizes a call, the upstream simply splices its payload after the user
// types it. That exact attack is in the corpus as multiturn_injected_continue.
//
// Three properties make this design sound anyway:
//
//  1. Direction. Approvals are read only from REQUESTS. Requests originate at
//     the user's client, and cleanerproxy sits between client and upstream, so
//     it reads them before the upstream is involved. The upstream can author a
//     response but cannot author a request, so it cannot manufacture consent.
//
//  2. Challenge binding. cleanerproxy issues a nonce and uses it as the
//     tool_use id of the question it injects. Consent counts only when it
//     arrives as a tool_result answering a nonce cleanerproxy itself issued
//     and is still holding. An upstream that fabricates its own approval
//     dialogue produces a tool_result for an id that matches no open
//     challenge, and is ignored.
//
//  3. Payload binding. Approval is recorded against a fingerprint of the exact
//     tool name and canonical arguments, single-use and short-lived. Approving
//     a rustup install does not approve a different command, and cannot be
//     replayed for a second call.
//
// What remains is the irreducible risk of any approval system: a user who
// approves without reading. That is mitigated by showing the exact arguments
// and the reasons, and by defaulting the prompt to refusal, not by cryptography.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fingerprint identifies one exact tool call: its name plus its canonical
// arguments. Approval is bound to this value, never to a session or a tool
// name, so consent cannot widen to a payload the user never saw.
type Fingerprint string

// Fingerprint computes the approval identity of a call.
//
// Arguments are canonicalized (object keys sorted, insignificant whitespace
// removed) before hashing. This is not cosmetic: after the user approves, the
// model must re-emit the call, and models do not reproduce JSON byte-for-byte.
// Key order or spacing drift on the retry would make a faithful re-issue fail
// to match its own approval, which the user would experience as the approval
// silently not working. Canonicalizing tolerates formatting drift while still
// refusing any change of meaning.
func Compute(toolName string, rawArgs []byte) Fingerprint {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(toolName))))
	h.Write([]byte{0}) // domain separator: name and args cannot bleed together
	h.Write([]byte(canonicalJSON(rawArgs)))
	return Fingerprint(hex.EncodeToString(h.Sum(nil)))
}

// Short renders the first 12 hex characters, for logs and audit records only.
// Never used for matching: 48 bits is fine for a human to eyeball but is not a
// safe basis for an authorization decision.
func (f Fingerprint) Short() string {
	if len(f) < 12 {
		return string(f)
	}
	return string(f[:12])
}

// canonicalJSON re-encodes JSON with object keys sorted. On unparseable input
// it falls back to the trimmed original: a call whose arguments do not parse is
// still fingerprintable, and the structural tier reports the parse failure
// separately.
func canonicalJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return strings.TrimSpace(string(raw))
	}
	var b strings.Builder
	writeCanonical(&b, v)
	return b.String()
}

func writeCanonical(b *strings.Builder, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			writeCanonical(b, t[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	default:
		// Scalars: json.Marshal gives canonical forms for strings, numbers,
		// booleans and null.
		out, err := json.Marshal(t)
		if err != nil {
			b.WriteString("null")
			return
		}
		b.Write(out)
	}
}

// Challenge is an open question posed to the user about one blocked call.
type Challenge struct {
	// Nonce is the tool_use id of the injected question. The client echoes it
	// back as the tool_result's tool_use_id, which is what binds the answer to
	// this specific challenge.
	Nonce string

	Fingerprint Fingerprint
	ToolName    string
	ArgsPreview string

	// OrigID and RawArgs preserve the blocked call exactly as the upstream sent
	// it, so an approval can be honoured by replaying that call verbatim
	// instead of asking the model to re-issue it.
	//
	// Asking the model does not work. Measured against Claude 4.6 Opus: a
	// tool_result instructing it to re-run `curl … | bash` was correctly
	// identified as a prompt injection and refused. That is the right call by
	// the model — tool output is attacker-reachable, which is the same reason
	// cleanerproxy keeps tool_result out of RequestContext.UserTurns — so the
	// approval path must not depend on the model trusting one.
	OrigID  string
	RawArgs []byte

	// ApproveLabel is the exact option label that counts as consent. Consent
	// requires an exact match, so any other answer — including free text the
	// client allows the user to type — denies. Fail closed.
	ApproveLabel string
	DenyLabel    string

	IssuedAt time.Time
	Expires  time.Time
}

// Store holds open challenges and granted approvals. Safe for concurrent use.
//
// Deliberately in-memory and non-persistent. An approval that survives a
// restart is an approval nobody is watching; short-lived state that dies with
// the process is the conservative choice, and the cost is only that a pending
// prompt must be re-answered.
type Store struct {
	mu sync.Mutex

	challenges map[string]*Challenge
	granted    map[Fingerprint]time.Time

	// ChallengeTTL bounds how long a user has to answer a prompt.
	ChallengeTTL time.Duration

	// GrantTTL bounds how long an approval remains usable after the user says
	// yes. It only has to cover one model round trip.
	GrantTTL time.Duration

	// MaxOpen caps memory. A hostile upstream can force a new challenge on
	// every response, so this must be bounded.
	MaxOpen int

	now func() time.Time
}

func NewStore() *Store {
	return &Store{
		challenges:   map[string]*Challenge{},
		granted:      map[Fingerprint]time.Time{},
		ChallengeTTL: 10 * time.Minute,
		GrantTTL:     5 * time.Minute,
		MaxOpen:      64,
		now:          time.Now,
	}
}

// Issue opens a challenge for a blocked call and returns it.
//
// idPrefix lets the caller match the host API's id convention ("toolu_" on
// Anthropic, "call_" on OpenAI) so the injected question looks like any other
// tool call to the client.
func (s *Store) Issue(idPrefix, origID, toolName string, rawArgs []byte, argsPreview string) (*Challenge, error) {
	nonce, err := newNonce(idPrefix)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()

	if len(s.challenges) >= s.MaxOpen {
		// Evict the oldest rather than refuse. Refusing would let a hostile
		// upstream disable the approval path entirely by flooding it, which
		// would turn every subsequent false positive back into a dead end.
		var oldestKey string
		var oldest time.Time
		for k, c := range s.challenges {
			if oldestKey == "" || c.IssuedAt.Before(oldest) {
				oldestKey, oldest = k, c.IssuedAt
			}
		}
		delete(s.challenges, oldestKey)
	}

	now := s.now()
	c := &Challenge{
		Nonce:        nonce,
		Fingerprint:  Compute(toolName, rawArgs),
		ToolName:     toolName,
		ArgsPreview:  argsPreview,
		OrigID:       origID,
		RawArgs:      append([]byte(nil), rawArgs...),
		ApproveLabel: ApproveLabel,
		DenyLabel:    DenyLabel,
		IssuedAt:     now,
		Expires:      now.Add(s.ChallengeTTL),
	}
	s.challenges[nonce] = c
	return c, nil
}

// Answer resolves an open challenge from the text of a tool_result.
//
// Returns the challenge and whether consent was given. An unknown nonce
// returns nil: it is either expired, already answered, or fabricated by the
// upstream, and all three must be treated identically.
func (s *Store) Answer(nonce, resultText string) (*Challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()

	c, ok := s.challenges[nonce]
	if !ok {
		return nil, false
	}
	// A challenge is answered exactly once, whatever the answer was. Leaving
	// it open would let the same prompt be re-answered until it happens to
	// come back approved.
	delete(s.challenges, nonce)

	if !consented(resultText, c) {
		return c, false
	}
	s.granted[c.Fingerprint] = s.now().Add(s.GrantTTL)
	return c, true
}

// consented reports whether the tool_result text is an exact selection of the
// approve option.
//
// Requires the approve label present AND the deny label absent. A client that
// echoes the whole option list rather than the selection would otherwise read
// as consent.
func consented(resultText string, c *Challenge) bool {
	if c.ApproveLabel == "" {
		return false
	}
	if strings.Contains(resultText, c.DenyLabel) {
		return false
	}
	return strings.Contains(resultText, c.ApproveLabel)
}

// Consume reports whether this exact call has a live approval, spending it if
// so. Single-use: one approval authorizes one execution.
func (s *Store) Consume(fp Fingerprint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()

	exp, ok := s.granted[fp]
	if !ok || s.now().After(exp) {
		return false
	}
	delete(s.granted, fp)
	return true
}

// Pending reports whether a challenge is already open for this call, so a
// repeated block does not stack duplicate prompts for the same payload.
func (s *Store) Pending(fp Fingerprint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	for _, c := range s.challenges {
		if c.Fingerprint == fp {
			return true
		}
	}
	return false
}

// Stats reports open challenges and live grants, for diagnostics.
func (s *Store) Stats() (open, grants int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return len(s.challenges), len(s.granted)
}

func (s *Store) expireLocked() {
	now := s.now()
	for k, c := range s.challenges {
		if now.After(c.Expires) {
			delete(s.challenges, k)
		}
	}
	for fp, exp := range s.granted {
		if now.After(exp) {
			delete(s.granted, fp)
		}
	}
}

// ApproveLabel and DenyLabel are the option labels offered to the user.
//
// Fixed strings rather than generated ones because they must be matched
// exactly against the tool_result, and because the user sees them: an opaque
// token in the label would be noise. The security binding is the nonce, not
// the label text.
const (
	ApproveLabel = "Run it anyway"
	DenyLabel    = "Block it"
)

func newNonce(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: nonce generation failed: %w", err)
	}
	// The "cpxy" marker lets the request path recognise candidate ids cheaply
	// before taking the lock. It is a hint, never an authorization: the nonce
	// still has to match an open challenge.
	return prefix + "cpxy01" + hex.EncodeToString(b), nil
}

// IsChallengeID reports whether an id has the shape of a cleanerproxy
// challenge. A cheap pre-filter only; Answer performs the real check.
func IsChallengeID(id string) bool {
	return strings.Contains(id, "cpxy01")
}
