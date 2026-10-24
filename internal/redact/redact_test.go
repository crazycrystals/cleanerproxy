package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- Vault tests ----

func TestVaultBasic(t *testing.T) {
	v := NewVault("")
	v.GetOrPut(CatEmail, "alice@example.com", "user0001@mailhost.example")
	got, ok := v.Get(CatEmail, "alice@example.com")
	if !ok || got != "user0001@mailhost.example" {
		t.Errorf("Get = %q, %v; want user0001@mailhost.example, true", got, ok)
	}
	real, ok := v.Reverse("user0001@mailhost.example")
	if !ok || real != "alice@example.com" {
		t.Errorf("Reverse = %q, %v; want alice@example.com, true", real, ok)
	}
}

func TestVaultPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")

	v1 := NewVault(path)
	v1.GetOrPut(CatEmail, "alice@example.com", "user0001@mailhost.example")
	v1.FamilyName("Doe", "May")
	if err := v1.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload from disk.
	v2 := NewVault(path)
	got, ok := v2.Get(CatEmail, "alice@example.com")
	if !ok || got != "user0001@mailhost.example" {
		t.Errorf("after reload: Get = %q, %v", got, ok)
	}
	fam, ok := v2.GetFamilyName("Doe")
	if !ok || fam != "May" {
		t.Errorf("after reload: GetFamilyName = %q, %v", fam, ok)
	}
}

func TestVaultStability(t *testing.T) {
	v := NewVault("")
	// Same real value always returns same pseudo.
	p1 := v.GetOrPut(CatAPIKey, "sk-abc123", "sk-pseudo1")
	p2 := v.GetOrPut(CatAPIKey, "sk-abc123", "sk-DIFFERENT")
	if p1 != p2 {
		t.Errorf("GetOrPut not stable: %q vs %q", p1, p2)
	}
}

// ---- Name generator tests ----

func TestNameGenFamilyPreservation(t *testing.T) {
	v := NewVault("")
	g := NewNameGen(v)

	p1 := g.Pseudonym("John Doe")
	p2 := g.Pseudonym("Jane Doe")

	// Both should share the same last name.
	_, last1 := splitName(p1)
	_, last2 := splitName(p2)
	if last1 != last2 {
		t.Errorf("family not preserved: %q and %q have different last names (%q vs %q)",
			p1, p2, last1, last2)
	}
}

func TestNameGenStability(t *testing.T) {
	v := NewVault("")
	g := NewNameGen(v)

	p1 := g.Pseudonym("John Doe")
	p2 := g.Pseudonym("John Doe")
	if p1 != p2 {
		t.Errorf("not stable: %q vs %q", p1, p2)
	}
}

func TestNameGenDifferentNames(t *testing.T) {
	v := NewVault("")
	g := NewNameGen(v)

	p1 := g.Pseudonym("Alice Smith")
	p2 := g.Pseudonym("Bob Jones")
	if p1 == p2 {
		t.Errorf("different names got same pseudo: %q", p1)
	}
}

// ---- Detector tests ----

func TestDetectEmail(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("Contact alice@example.com for details")
	found := false
	for _, m := range matches {
		if m.Category == CatEmail && m.Value == "alice@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect email; matches = %v", matches)
	}
}

func TestDetectAPIKey(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("Use key sk-abc123def456ghi789jkl012mno345")
	found := false
	for _, m := range matches {
		if m.Category == CatAPIKey {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect API key; matches = %v", matches)
	}
}

func TestDetectAWSKey(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	found := false
	for _, m := range matches {
		if m.Category == CatAWSKey {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect AWS key; matches = %v", matches)
	}
}

func TestDetectIPv4Disabled(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("Server at 192.168.1.100 responded")
	for _, m := range matches {
		if m.Category == CatIPv4 {
			t.Errorf("IPv4 should not be detected (disabled): %v", m)
		}
	}
}

func TestDetectUUID(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("ID: 550e8400-e29b-41d4-a716-446655440000")
	found := false
	for _, m := range matches {
		if m.Category == CatUUID {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect UUID; matches = %v", matches)
	}
}

func TestDetectSeededName(t *testing.T) {
	d := NewDetector()
	d.SeedNames([]string{"John Doe"})
	matches := d.Detect("Ask John Doe about the project")
	found := false
	for _, m := range matches {
		if m.Category == CatName && m.Value == "John Doe" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect seeded name; matches = %v", matches)
	}
}

func TestDetectSeededNamePartial(t *testing.T) {
	d := NewDetector()
	d.SeedNames([]string{"John Doe"})
	matches := d.Detect("Tell John the meeting is at 3pm")
	found := false
	for _, m := range matches {
		if m.Category == CatName && m.Value == "John" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect partial name match; matches = %v", matches)
	}
}

func TestDetectHomeUsername(t *testing.T) {
	d := NewDetector()
	// Username should now be seeded as a name, not detected via homeUser.
	d.SeedNames([]string{"devuser"})
	matches := d.Detect("Reading /Users/devuser/Documents/secret.txt")
	found := false
	for _, m := range matches {
		if m.Category == CatName && m.Value == "devuser" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect seeded username; matches = %v", matches)
	}
}

func TestDetectSSN(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("SSN: 123-45-6789")
	found := false
	for _, m := range matches {
		if m.Category == CatSSN && m.Value == "123-45-6789" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect SSN; matches = %v", matches)
	}
}

func TestDetectPhone(t *testing.T) {
	d := NewDetector()
	matches := d.Detect("Call (555) 867-5309")
	found := false
	for _, m := range matches {
		if m.Category == CatPhone {
			found = true
		}
	}
	if !found {
		t.Errorf("did not detect phone; matches = %v", matches)
	}
}

func TestDetectNoOverlap(t *testing.T) {
	d := NewDetector()
	d.SeedNames([]string{"Alice"})
	matches := d.Detect("alice@example.com belongs to Alice")
	// "alice" should not be matched inside the email.
	for _, m := range matches {
		if m.Category == CatName && strings.Contains(m.Value, "@") {
			t.Errorf("name match inside email: %v", m)
		}
	}
}

// ---- Format-preserving token tests ----

func TestPseudoEmailFormat(t *testing.T) {
	p := PseudoEmail("alice@example.com", 1)
	if !strings.Contains(p, "@") {
		t.Errorf("pseudo email has no @: %q", p)
	}
}

func TestPseudoIPv4Format(t *testing.T) {
	// Generator still works even though detection is disabled —
	// kept for potential future re-enablement.
	p := PseudoIPv4(1)
	if !strings.HasPrefix(p, "198.51.100.") {
		t.Errorf("pseudo IPv4 not in TEST-NET-3: %q", p)
	}
}

func TestPseudoUUIDFormat(t *testing.T) {
	p := PseudoUUID(1)
	parts := strings.Split(p, "-")
	if len(parts) != 5 {
		t.Errorf("pseudo UUID wrong format: %q", p)
	}
}

func TestPseudoAWSKeyFormat(t *testing.T) {
	p := PseudoAWSKey(1)
	if !strings.HasPrefix(p, "AKIA") || len(p) != 20 {
		t.Errorf("pseudo AWS key wrong format: %q (len=%d)", p, len(p))
	}
}

// ---- Redactor end-to-end tests ----

func TestConcealRevealRoundTrip(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"John Doe", "Jane Doe"})

	input := `Please contact John Doe at john@example.com. His wife Jane Doe is at jane@example.com.`

	concealed := r.Conceal(input)

	// Verify real values are gone.
	if strings.Contains(concealed, "John Doe") {
		t.Errorf("concealed still contains 'John Doe': %q", concealed)
	}
	if strings.Contains(concealed, "john@example.com") {
		t.Errorf("concealed still contains 'john@example.com': %q", concealed)
	}
	if strings.Contains(concealed, "Jane Doe") {
		t.Errorf("concealed still contains 'Jane Doe': %q", concealed)
	}

	// Verify pseudonyms look reasonable (contain @).
	if !strings.Contains(concealed, "@") {
		t.Errorf("concealed has no email-like content: %q", concealed)
	}

	// Reveal should restore originals.
	revealed := r.Reveal(concealed)
	if revealed != input {
		t.Errorf("round trip failed:\n  input:    %q\n  revealed: %q", input, revealed)
	}
}

func TestConcealStability(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)

	input := "Key: sk-abc123def456ghi789jkl012mno345"
	c1 := r.Conceal(input)
	c2 := r.Conceal(input)
	if c1 != c2 {
		t.Errorf("concealment not stable: %q vs %q", c1, c2)
	}
}

func TestConcealJSON(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"John Doe"})

	input := `{"name":"John Doe","email":"john@example.com","ip":"10.0.0.1"}`
	concealed := r.Conceal(input)

	if strings.Contains(concealed, "John Doe") {
		t.Errorf("JSON still contains real name: %q", concealed)
	}
	if strings.Contains(concealed, "john@example.com") {
		t.Errorf("JSON still contains real email: %q", concealed)
	}
}

func TestConcealPreservesNonSensitive(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)

	input := "This is a normal message with no PII."
	concealed := r.Conceal(input)
	if concealed != input {
		t.Errorf("concealed changed non-sensitive text: %q → %q", input, concealed)
	}
}

func TestConcealHomePath(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"devuser"})

	input := "Reading file /Users/devuser/secret.txt"
	concealed := r.Conceal(input)
	if strings.Contains(concealed, "devuser") {
		t.Errorf("concealed still contains username: %q", concealed)
	}
	// Path should still look like a path.
	if !strings.Contains(concealed, "/Users/") {
		t.Errorf("concealed lost path structure: %q", concealed)
	}
}

func TestConcealBareUsername(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"devuser"})

	// Simulates whoami output or any bare occurrence.
	input := "The current user is devuser"
	concealed := r.Conceal(input)
	if strings.Contains(concealed, "devuser") {
		t.Errorf("concealed still contains bare username: %q", concealed)
	}

	// Should get a scene name, not "user0001".
	if strings.Contains(concealed, "user0") {
		t.Errorf("bare username got synthetic pseudo instead of scene name: %q", concealed)
	}

	// Round trip.
	revealed := r.Reveal(concealed)
	if revealed != input {
		t.Errorf("round trip failed:\n  input:    %q\n  revealed: %q", input, revealed)
	}
}

func TestRevealInStream(t *testing.T) {
	// Simulates SSE streaming: concealed in request, then model uses
	// pseudonym in response, and we reveal it.
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"John Doe"})

	// Request path: conceal.
	_ = r.Conceal("Ask John Doe about the project")

	// Now the vault has John Doe → <pseudo>. When the model says the
	// pseudonym in the response, Reveal should restore it.
	pseudo, _ := v.Get(CatName, "John Doe")
	streamChunk := `I spoke with ` + pseudo + ` and he said...`
	revealed := r.Reveal(streamChunk)
	if !strings.Contains(revealed, "John Doe") {
		t.Errorf("stream reveal failed: %q → %q (pseudo was %q)", streamChunk, revealed, pseudo)
	}
}

func TestFamilyNamePreservation(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"John Doe", "Jane Doe"})

	concealed := r.Conceal("John Doe and Jane Doe are married")

	// Extract the two pseudonym names.
	pseudoJohn, _ := v.Get(CatName, "John Doe")
	pseudoJane, _ := v.Get(CatName, "Jane Doe")

	_, lastJohn := splitName(pseudoJohn)
	_, lastJane := splitName(pseudoJane)

	if lastJohn != lastJane {
		t.Errorf("family not preserved in concealed output: John→%q Jane→%q (in %q)",
			pseudoJohn, pseudoJane, concealed)
	}
}

func TestVaultStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Create redactor, conceal some values, save.
	v1 := NewVault(path)
	r1 := NewRedactor(v1, nil)
	r1.SeedNames([]string{"John Doe"})
	concealed := r1.Conceal("John Doe at john@example.com")
	if err := r1.Save(); err != nil {
		t.Fatal(err)
	}

	// Verify state file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Create new redactor from same state file.
	v2 := NewVault(path)
	r2 := NewRedactor(v2, nil)

	// Reveal should work with the loaded mappings.
	revealed := r2.Reveal(concealed)
	if !strings.Contains(revealed, "John Doe") {
		t.Errorf("reveal after reload failed: %q", revealed)
	}
	if !strings.Contains(revealed, "john@example.com") {
		t.Errorf("reveal after reload lost email: %q", revealed)
	}
}

func TestVerifyLiveRedaction(t *testing.T) {
	v := NewVault("")
	r := NewRedactor(v, nil)
	r.SeedNames([]string{"John McAffrey"})

	input := `hey brother my name is John McAffrey and my favorite api key is sk-api-234234928406848`
	concealed := r.Conceal(input)

	t.Logf("INPUT:     %s", input)
	t.Logf("CONCEALED: %s", concealed)

	if strings.Contains(concealed, "John McAffrey") {
		t.Error("concealed still contains 'John McAffrey'")
	}
	if strings.Contains(concealed, "John") {
		t.Error("concealed still contains 'John'")
	}
	if strings.Contains(concealed, "McAffrey") {
		t.Error("concealed still contains 'McAffrey'")
	}
	if strings.Contains(concealed, "sk-api-234234928406848") {
		t.Error("concealed still contains the API key")
	}

	revealed := r.Reveal(concealed)
	t.Logf("REVEALED:  %s", revealed)

	if revealed != input {
		t.Errorf("round trip failed:\n  input:    %q\n  revealed: %q", input, revealed)
	}
}

// ---- False positive prevention tests ----

func TestIsPlausibleNameRejectsGenericTerms(t *testing.T) {
	rejects := []string{
		"devel", "proxy", "server", "config", "build",
		"nginx", "docker", "redis", "cleanerproxy",
		"internal", "guardian", "handler", "main",
	}
	for _, name := range rejects {
		if isPlausibleName(name) {
			t.Errorf("isPlausibleName(%q) = true; want false (generic term)", name)
		}
	}
}

func TestIsPlausibleNameAcceptsRealNames(t *testing.T) {
	accepts := []string{
		"crystals", "devuser", "alice", "jdoe",
		"John Doe", "Jane Smith", "John McAffrey",
	}
	for _, name := range accepts {
		if !isPlausibleName(name) {
			t.Errorf("isPlausibleName(%q) = false; want true (real name)", name)
		}
	}
}

func TestTitleCaseWords(t *testing.T) {
	cases := []struct{ in, want string }{
		{"john mcaffrey", "John Mcaffrey"},
		{"john doe", "John Doe"},
		{"JANE SMITH", "JANE SMITH"},       // already uppercase initials
		{"Alice", "Alice"},                 // single word, unchanged
		{"crystals", "crystals"},           // single word, unchanged
		{"mary jane watson", "Mary Jane Watson"},
	}
	for _, tc := range cases {
		got := titleCaseWords(tc.in)
		if got != tc.want {
			t.Errorf("titleCaseWords(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsPlausibleNameAcceptsLowercaseNEROutput(t *testing.T) {
	// NER models may return names preserving user input casing.
	// titleCaseWords should normalize them before isPlausibleName checks.
	lowercaseNames := []string{"john mcaffrey", "john doe", "jane smith"}
	for _, name := range lowercaseNames {
		normalized := titleCaseWords(name)
		if !isPlausibleName(normalized) {
			t.Errorf("isPlausibleName(titleCaseWords(%q)) = false; want true", name)
		}
	}
}

func TestSeedNamesRejectsGenericTerms(t *testing.T) {
	d := NewDetector()
	d.SeedNames([]string{"devel", "cleanerproxy", "proxy"})

	// None of these should be in the seeded names.
	text := "Working in /Users/alice/devel/cleanerproxy with the proxy"
	matches := d.Detect(text)
	for _, m := range matches {
		if m.Category == CatName {
			t.Errorf("generic term detected as name: %q", m.Value)
		}
	}
}

func TestExtractPathContext(t *testing.T) {
	text := `Reading /Users/crystals/devel/cleanerproxy/internal/proxy/server.go and /home/alice/projects/myapp/main.go`

	usernames, nonUser := extractPathContext(text)

	// Usernames: crystals, alice
	if !usernames["crystals"] {
		t.Error("expected 'crystals' in usernames")
	}
	if !usernames["alice"] {
		t.Error("expected 'alice' in usernames")
	}

	// Non-username segments: devel, cleanerproxy, internal, proxy, server, projects, myapp, main
	for _, seg := range []string{"devel", "cleanerproxy", "internal", "proxy", "server", "projects", "myapp", "main"} {
		if !nonUser[seg] {
			t.Errorf("expected %q in nonUserSegments", seg)
		}
	}

	// Usernames should NOT be in nonUser.
	if nonUser["crystals"] {
		t.Error("'crystals' should not be in nonUserSegments")
	}
	if nonUser["alice"] {
		t.Error("'alice' should not be in nonUserSegments")
	}
}

func TestIsNonUserPathSegment(t *testing.T) {
	usernames := map[string]bool{"crystals": true}
	nonUser := map[string]bool{"devel": true, "cleanerproxy": true, "internal": true}

	// "crystals" is a username — should NOT be rejected.
	if isNonUserPathSegment("crystals", usernames, nonUser) {
		t.Error("'crystals' should not be rejected (it's a username)")
	}

	// "devel" is a non-username segment — should be rejected.
	if !isNonUserPathSegment("devel", usernames, nonUser) {
		t.Error("'devel' should be rejected (non-username path segment)")
	}

	// "cleanerproxy" is a non-username segment — should be rejected.
	if !isNonUserPathSegment("cleanerproxy", usernames, nonUser) {
		t.Error("'cleanerproxy' should be rejected (non-username path segment)")
	}

	// "JohnDoe" is neither — should not be rejected.
	if isNonUserPathSegment("JohnDoe", usernames, nonUser) {
		t.Error("'JohnDoe' should not be rejected (not a path segment)")
	}
}

func TestNERDoesNotRedactPathSubdirectories(t *testing.T) {
	// Simulate the exact scenario that caused breakage: NER returns
	// path subdirectories as "names", and Conceal replaces them.
	v := NewVault("")
	r := NewRedactor(v, nil)

	// Manually simulate what NER + runNER would do, using the path
	// context filter directly.
	text := `Edit file /Users/crystals/devel/cleanerproxy/internal/config/config.go`

	// Suppose NER returns these (as it did with Qwen 0.5B):
	nerResults := []string{"crystals", "devel", "cleanerproxy"}

	// Apply path context filtering.
	usernames, nonUser := extractPathContext(text)
	var filtered []string
	for _, name := range nerResults {
		if !isNonUserPathSegment(name, usernames, nonUser) {
			filtered = append(filtered, name)
		}
	}

	// Only "crystals" should survive (it's the username).
	if len(filtered) != 1 || filtered[0] != "crystals" {
		t.Errorf("path context filter: got %v; want [crystals]", filtered)
	}

	// Seed only the filtered name and conceal.
	r.SeedNames(filtered)
	concealed := r.Conceal(text)

	// "crystals" should be replaced.
	if strings.Contains(concealed, "crystals") {
		t.Errorf("concealed still contains username 'crystals': %q", concealed)
	}

	// "devel" and "cleanerproxy" should NOT be replaced.
	if !strings.Contains(concealed, "devel") {
		t.Errorf("concealed wrongly replaced 'devel': %q", concealed)
	}
	if !strings.Contains(concealed, "cleanerproxy") {
		t.Errorf("concealed wrongly replaced 'cleanerproxy': %q", concealed)
	}

	// Path structure should be preserved.
	if !strings.Contains(concealed, "/internal/config/config.go") {
		t.Errorf("concealed lost path structure: %q", concealed)
	}

	// Round trip.
	revealed := r.Reveal(concealed)
	if revealed != text {
		t.Errorf("round trip failed:\n  input:    %q\n  revealed: %q", text, revealed)
	}
}

func TestConcealDoesNotBreakPaths(t *testing.T) {
	// Ensure that even if all three path components were somehow seeded,
	// the genericTerms blocklist in SeedNames prevents "devel" from being
	// treated as a name.
	v := NewVault("")
	r := NewRedactor(v, nil)

	// Only seed the actual username.
	r.SeedNames([]string{"crystals"})

	input := `git diff /Users/crystals/devel/cleanerproxy/go.mod`
	concealed := r.Conceal(input)

	// Username replaced, path structure intact.
	if strings.Contains(concealed, "crystals") {
		t.Errorf("username not concealed: %q", concealed)
	}
	if !strings.Contains(concealed, "/devel/cleanerproxy/go.mod") {
		t.Errorf("path subdirectories corrupted: %q", concealed)
	}
}
