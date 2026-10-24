package redact

// Format-preserving pseudonym generators for structured sensitive values.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// PseudoEmail generates a pseudonym email preserving the @domain.tld shape.
// "alice@company.com" → "dmarx@phrack.org"
//
// Domains are drawn from real-looking scene/comm/hacker culture domains so
// that the substitution does not look synthetic to the upstream.
func PseudoEmail(real string, seq int) string {
	parts := strings.SplitN(real, "@", 2)

	user := pseudoEmailUsers[seq%len(pseudoEmailUsers)]

	domain := pseudoEmailDomains1[seq%len(pseudoEmailDomains1)]
	if len(parts) == 2 {
		dots := strings.Count(parts[1], ".")
		switch dots {
		case 0:
			domain = "phrack"
		case 1:
			domain = pseudoEmailDomains1[seq%len(pseudoEmailDomains1)]
		default:
			domain = pseudoEmailDomains2[seq%len(pseudoEmailDomains2)]
		}
	}
	return user + "@" + domain
}

// pseudoEmailUsers — plausible-looking usernames, warez/cracking scene flavour.
var pseudoEmailUsers = []string{
	"hexedit", "scanline", "darkstar", "keygen", "dumpster",
	"phrozen", "deviance", "patchx", "deadcode", "ripzone",
	"blackout", "skidrow", "tracerx", "unpack", "razordox",
	"nfoview", "fairlight", "reloaded", "crackz", "paradox",
}

// pseudoEmailDomains1 — single-dot domains that look like real scene/warez orgs.
var pseudoEmailDomains1 = []string{
	"crackwatch.com", "scenep2p.net", "nforce.nl", "pouet.net",
	"warez-bb.org", "keygenmusic.net", "torrentleech.org", "csdb.dk",
	"predb.net", "usenetfire.com", "scenerules.org", "nzbplanet.net",
	"srrdb.com", "nfoview.com", "demozoo.org", "sceneaccess.org",
	"defacto2.net",
}

// pseudoEmailDomains2 — multi-dot domains for subdomain-preserving cases.
var pseudoEmailDomains2 = []string{
	"relay.nforce.nl", "archive.csdb.dk", "boards.warez-bb.org",
	"api.srrdb.com", "ftp.scenerules.org", "irc.scenep2p.net",
	"mail.predb.net", "mirror.demozoo.org",
}

// PseudoPhone generates a pseudonym phone number preserving the format.
// "+1-555-867-5309" → "+1-555-100-0042"
func PseudoPhone(real string, seq int) string {
	// Preserve the format: count digits, replace with deterministic ones,
	// keep separators in place.
	digitIdx := 0
	replacement := fmt.Sprintf("%010d", 5551000000+seq)
	var b strings.Builder
	for _, r := range real {
		if r >= '0' && r <= '9' {
			if digitIdx < len(replacement) {
				b.WriteByte(replacement[digitIdx])
			} else {
				b.WriteRune(r)
			}
			digitIdx++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PseudoSSN generates a pseudonym SSN preserving the ###-##-#### format.
func PseudoSSN(real string, seq int) string {
	num := fmt.Sprintf("%09d", 100000000+seq)
	// Keep separator format from original.
	var b strings.Builder
	digitIdx := 0
	for _, r := range real {
		if r >= '0' && r <= '9' {
			if digitIdx < len(num) {
				b.WriteByte(num[digitIdx])
			}
			digitIdx++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PseudoCreditCard generates a pseudonym credit card preserving separators.
func PseudoCreditCard(real string, seq int) string {
	num := fmt.Sprintf("%016d", 4000000000000000+int64(seq))
	var b strings.Builder
	digitIdx := 0
	for _, r := range real {
		if r >= '0' && r <= '9' {
			if digitIdx < len(num) {
				b.WriteByte(num[digitIdx])
			}
			digitIdx++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PseudoIPv4 generates a pseudonym IPv4 address.
// Stays in 198.51.100.0/24 (TEST-NET-3, RFC 5737) so it is obviously not real.
func PseudoIPv4(seq int) string {
	return fmt.Sprintf("198.51.100.%d", seq%256)
}

// PseudoIPv6 generates a pseudonym IPv6 address.
// Uses 2001:db8::/32 (documentation prefix, RFC 3849).
func PseudoIPv6(seq int) string {
	return fmt.Sprintf("2001:db8::%04x", seq%0xFFFF)
}

// PseudoUUID generates a pseudonym UUID preserving the 8-4-4-4-12 format.
func PseudoUUID(seq int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("cleanerproxy-uuid-%d", seq)))
	return fmt.Sprintf("%08x-%04x-4%03x-%04x-%012x",
		binary.BigEndian.Uint32(h[0:4]),
		binary.BigEndian.Uint16(h[4:6]),
		binary.BigEndian.Uint16(h[6:8])&0x0FFF,
		(binary.BigEndian.Uint16(h[8:10])&0x3FFF)|0x8000,
		binary.BigEndian.Uint64(h[10:18])&0xFFFFFFFFFFFF)
}

// PseudoAPIKey generates a pseudonym API key preserving the prefix and length.
// "sk-abc123..." → "sk-pseudoXXXX..."
func PseudoAPIKey(real string, seq int) string {
	// Find the prefix (everything up to and including the first '-' or '_').
	prefix := ""
	for i, r := range real {
		if r == '-' || r == '_' {
			prefix = real[:i+1]
			break
		}
	}
	if prefix == "" {
		prefix = "key-"
	}

	// Generate the rest to match the original length.
	suffixLen := len(real) - len(prefix)
	if suffixLen < 8 {
		suffixLen = 8
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("cleanerproxy-apikey-%d-%s", seq, prefix)))
	hex := fmt.Sprintf("%x%x", h, h) // 128 hex chars, enough for any key
	if len(hex) > suffixLen {
		hex = hex[:suffixLen]
	}

	return prefix + hex
}

// PseudoAWSKey generates a pseudonym AWS access key (AKIA prefix, 20 chars).
func PseudoAWSKey(seq int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("cleanerproxy-aws-%d", seq)))
	hex := fmt.Sprintf("%X", h[:8])
	return "AKIA" + hex[:16]
}

// PseudoBearer generates a pseudonym Bearer/token value.
func PseudoBearer(real string, seq int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("cleanerproxy-bearer-%d", seq)))
	targetLen := len(real)
	if targetLen < 16 {
		targetLen = 16
	}
	hex := fmt.Sprintf("%x%x", h, h)
	if len(hex) > targetLen {
		hex = hex[:targetLen]
	}
	return hex
}

// PseudoPassword generates a pseudonym password value.
func PseudoPassword(seq int) string {
	return fmt.Sprintf("Pseudo!Pass%04d#x", seq)
}

// PseudoHomePath replaces a /Users/username or /home/username with a pseudonym.
func PseudoHomePath(realUser string, seq int) string {
	return fmt.Sprintf("user%04d", seq)
}
