// Package redact provides bidirectional PII and secret pseudonymization.
//
// The threat model is an untrusted upstream LLM provider that sees every token
// of every request. Redaction replaces real PII and secrets with plausible
// pseudonyms before the request leaves the machine, and reverses the
// substitution on the response path before the client sees it.
//
// The substitution must be invisible to both sides:
//   - Upstream sees only pseudonyms and cannot correlate across sessions
//     (unless they model style, which is out of scope).
//   - The local user/agent sees only originals and never learns pseudonyms
//     exist.
//
// Design constraints:
//   - Stable within a session: the same real value always maps to the same
//     pseudonym so the model can reason about entities across turns.
//   - Format-preserving: an API key stays an API key, an email stays an
//     email, a name stays a name. The model must not be confused by the
//     shape of a substituted value.
//   - Family-preserving for names: "John Doe" and "Jane Doe" both get the
//     same pseudonym last name, so family relationships survive.
package redact

import (
	"encoding/json"
	"os"
	"sync"
)

// Category is the type of sensitive value being mapped.
type Category string

const (
	CatName       Category = "name"
	CatEmail      Category = "email"
	CatPhone      Category = "phone"
	CatSSN        Category = "ssn"
	CatCreditCard Category = "creditcard"
	CatIPv4       Category = "ipv4"
	CatIPv6       Category = "ipv6"
	CatUUID       Category = "uuid"
	CatAPIKey     Category = "apikey"
	CatAWSKey     Category = "awskey"
	CatBearer     Category = "bearer"
	CatPassword   Category = "password"
	CatPath       Category = "path" // e.g. /Users/john/...
)

// mapping is a single real↔pseudo pair.
type mapping struct {
	Real     string   `json:"real"`
	Pseudo   string   `json:"pseudo"`
	Category Category `json:"category"`
}

// Vault holds the bidirectional mapping between real values and pseudonyms.
// It is safe for concurrent use.
type Vault struct {
	mu sync.RWMutex

	// real→pseudo, keyed by category+real.
	forward map[string]string
	// pseudo→real, keyed by pseudo.
	reverse map[string]string

	// All mappings, for serialization.
	mappings []mapping

	// familyNames maps a real last name to its pseudonym last name.
	familyNames map[string]string

	// path is the file to persist to; empty means memory-only.
	path string
}

// NewVault creates a new empty vault. If path is non-empty, the vault will
// persist its mappings to that file.
func NewVault(path string) *Vault {
	v := &Vault{
		forward:     make(map[string]string),
		reverse:     make(map[string]string),
		familyNames: make(map[string]string),
		path:        path,
	}
	if path != "" {
		v.load()
	}
	return v
}

// vaultKey returns the lookup key for a category+real pair.
func vaultKey(cat Category, real string) string {
	return string(cat) + "\x00" + real
}

// Get returns the pseudonym for a real value, if it exists.
func (v *Vault) Get(cat Category, real string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	pseudo, ok := v.forward[vaultKey(cat, real)]
	return pseudo, ok
}

// Put stores a real→pseudo mapping. Returns false if the real value already
// has a different pseudonym (caller should use Get first).
func (v *Vault) Put(cat Category, real, pseudo string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := vaultKey(cat, real)
	if existing, ok := v.forward[key]; ok {
		return existing == pseudo
	}

	v.forward[key] = pseudo
	v.reverse[pseudo] = real
	v.mappings = append(v.mappings, mapping{
		Real:     real,
		Pseudo:   pseudo,
		Category: cat,
	})
	return true
}

// GetOrPut atomically returns existing or stores new.
func (v *Vault) GetOrPut(cat Category, real, pseudo string) string {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := vaultKey(cat, real)
	if existing, ok := v.forward[key]; ok {
		return existing
	}

	v.forward[key] = pseudo
	v.reverse[pseudo] = real
	v.mappings = append(v.mappings, mapping{
		Real:     real,
		Pseudo:   pseudo,
		Category: cat,
	})
	return pseudo
}

// Reverse returns the real value for a pseudonym, if it exists.
func (v *Vault) Reverse(pseudo string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	real, ok := v.reverse[pseudo]
	return real, ok
}

// FamilyName returns (or creates) the pseudonym last name for a real last name.
func (v *Vault) FamilyName(realLast, pseudoLast string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.familyNames[realLast]; ok {
		return existing
	}
	v.familyNames[realLast] = pseudoLast
	return pseudoLast
}

// GetFamilyName returns the pseudonym last name if it exists.
func (v *Vault) GetFamilyName(realLast string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	p, ok := v.familyNames[realLast]
	return p, ok
}

// AllReverse returns all pseudo→real mappings, for use in Reveal.
// The caller must not mutate the returned map.
func (v *Vault) AllReverse() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	cp := make(map[string]string, len(v.reverse))
	for k, val := range v.reverse {
		cp[k] = val
	}
	return cp
}

// Save persists the vault to disk.
func (v *Vault) Save() error {
	if v.path == "" {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.saveLocked()
}

func (v *Vault) saveLocked() error {
	state := struct {
		Mappings    []mapping         `json:"mappings"`
		FamilyNames map[string]string `json:"family_names"`
	}{
		Mappings:    v.mappings,
		FamilyNames: v.familyNames,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.path, data, 0600)
}

func (v *Vault) load() {
	data, err := os.ReadFile(v.path)
	if err != nil {
		return
	}
	var state struct {
		Mappings    []mapping         `json:"mappings"`
		FamilyNames map[string]string `json:"family_names"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	for _, m := range state.Mappings {
		key := vaultKey(m.Category, m.Real)
		v.forward[key] = m.Pseudo
		v.reverse[m.Pseudo] = m.Real
	}
	v.mappings = state.Mappings
	if state.FamilyNames != nil {
		v.familyNames = state.FamilyNames
	}
}
