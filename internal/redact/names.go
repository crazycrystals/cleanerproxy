package redact

// Name pseudonym generation with family-name preservation.
//
// Pseudonym identities are real, well-known people from the cracking/warez
// scene and The Com. Each entry is one real person's full name — we never
// mix first/last across different people.

// sceneIdentity is one real person used as a pseudonym source.
type sceneIdentity struct {
	First string
	Last  string
}

// scenePool — real names of well-known cracking scene, warez scene, and
// Com/comm figures. Each is one actual person. Order is randomized.
var scenePool = []sceneIdentity{
	{"Arion", "Kurtaj"},         // Lapsus$
	{"Jordan", "Persad"},        // SIM swap
	{"Peter", "Grimberg"},       // Razor 1911
	{"Noah", "Urban"},           // Scattered Spider
	{"Hew", "Kennedy"},          // SKIDROW
	{"Sebastien", "Raoult"},     // ShinyHunters
	{"Derek", "Borchardt"},      // DrinkOrDie
	{"Cameron", "Wagenius"},     // Scattered Spider
	{"Joel", "Evans"},           // Scattered Spider
	{"Richard", "Berry"},        // SPARKS
	{"Jacob", "Butler"},         // DDoS comm
	{"Gottfrid", "Svartholm"},   // Pirate Bay
	{"Justin", "May"},           // Xbox Underground
	{"Nathan", "Hunt"},          // DrinkOrDie
	{"Mike", "Kelly"},           // Centropy
	{"Veer", "Chetal"},          // crypto theft
	{"Connor", "Moucka"},        // Snowflake hacks
	{"Jon", "Johansen"},         // DeCSS
	{"Tyler", "Buchanan"},       // Scattered Spider
	{"Malone", "Lam"},           // crypto theft
	{"Sean", "O'Toole"},         // SPARKS
	{"Peter", "Sunde"},          // Pirate Bay
	{"Igor", "Serebryany"},      // RiSCISO
	{"Daniel", "Riffe"},         // Razor 1911
	{"John", "Sankus"},          // DrinkOrDie
	{"Ahmed", "Elbadawy"},       // Scattered Spider
	{"Robert", "Powell"},        // SIM swap
	{"Darian", "Mohaseb"},       // DDoS comm
	{"Fredrik", "Neij"},         // Pirate Bay
	{"Kent", "Kartadinata"},     // Razor 1911
	{"Adil", "Cassim"},          // DrinkOrDie
	{"John", "Binns"},           // T-Mobile
	{"Barry", "Erickson"},       // DrinkOrDie
	{"Jeandiel", "Serrano"},     // crypto theft
}

// NameGen generates pseudonym names, preserving family groupings.
type NameGen struct {
	vault *Vault
	idx   int
}

// NewNameGen creates a name generator backed by a vault.
func NewNameGen(vault *Vault) *NameGen {
	return &NameGen{vault: vault}
}

// Pseudonym returns a pseudonym for a real full name. If the real name
// contains a last name that has been seen before, the same pseudonym last
// name is reused.
//
// The input is assumed to be "First Last" or "First" (single name).
func (g *NameGen) Pseudonym(realFull string) string {
	// Check if we already have a mapping.
	if pseudo, ok := g.vault.Get(CatName, realFull); ok {
		return pseudo
	}

	first, last := splitName(realFull)

	var pseudoLast string
	if last != "" {
		if pl, ok := g.vault.GetFamilyName(last); ok {
			pseudoLast = pl
		} else {
			pseudoLast = g.nextIdentity().Last
			g.vault.FamilyName(last, pseudoLast)
		}
	}

	// Pick a first name from a different identity than the one that
	// provided the last name, to avoid accidentally reconstructing a
	// real scene person's full name verbatim.
	pseudoFirst := g.nextIdentity().First

	var pseudoFull string
	if pseudoLast != "" {
		pseudoFull = pseudoFirst + " " + pseudoLast
	} else {
		pseudoFull = pseudoFirst
	}

	pseudoFull = g.vault.GetOrPut(CatName, realFull, pseudoFull)

	// Also register the individual first name mapping for partial matches
	// in conversation (model might say just "John" after seeing "John Doe").
	if first != "" {
		g.vault.GetOrPut(CatName, first, pseudoFirst)
	}

	return pseudoFull
}

func (g *NameGen) nextIdentity() sceneIdentity {
	id := scenePool[g.idx%len(scenePool)]
	g.idx++
	return id
}

// splitName splits "First Last" into ("First", "Last").
// Single-word names return ("Name", "").
func splitName(full string) (string, string) {
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == ' ' {
			return full[:i], full[i+1:]
		}
	}
	return full, ""
}
