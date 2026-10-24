package inspect

// Tier 1: dangerous-capability rules over tool arguments.
//
// These rules deliberately ignore conversational context. The question asked
// here is not "did the user want this?" but "does this action, if executed,
// hand control of the machine to someone else?" Relevance is Tier 2's job.
//
// Calibration note: unlike Tier 0, a legitimate model CAN emit every pattern
// below when a user genuinely asks for it. So these findings are suspicion,
// never proof, and the highest severity used here is SeverityMalicious — which
// under the default policy defangs the call and tells the user, rather than
// killing the connection. A developer who really did ask to pipe a script into
// a shell gets one clear notice and can restate the request.
//
// Evasion resistance: patterns are matched against several normalized views of
// the arguments, because shell quoting gives an attacker cheap mutations
// ("c\"u\"rl", 'cu'$'r'l) that defeat naive substring matching.

import (
	"fmt"
	"regexp"
	"strings"

	"cleanerproxy/internal/toolnames"
	"cleanerproxy/internal/verdict"
	"cleanerproxy/internal/wire"
)

// capClass groups rules so a single tool call does not emit twenty near
// duplicate findings for one payload.
type capClass string

const (
	classRemoteExec  capClass = "remote-code-execution"
	classPersistence capClass = "persistence"
	classCredential  capClass = "credential-access"
	classPrivilege   capClass = "privilege-escalation"
	classExfil       capClass = "exfiltration"
	classDestructive capClass = "destructive"
	classAntiForensi capClass = "anti-forensics"
	classProxyEvade  capClass = "security-control-evasion"
)

type capRule struct {
	ID       string
	Class    capClass
	Severity verdict.Severity
	Pattern  *regexp.Regexp

	// Exempt, when non-nil, suppresses the finding if the matched text also
	// matches this pattern. Used to exempt localhost/loopback IPs from the
	// bare-IP egress rule.
	Exempt *regexp.Regexp

	// Explain is shown to the user. It must state the mechanism, because the
	// user is being asked to make a trust decision quickly.
	Explain string
}

// mustRule compiles a rule pattern case-insensitively.
//
// The token %INTERP% expands to an interpreter reference that tolerates an
// absolute path, because `| /bin/sh` and `| sh` are equivalent to a shell but
// only the latter matches a bare name. Missing this distinction let a real
// reverse-shell payload through the first version of this table.
func mustRule(id string, class capClass, sev verdict.Severity, pat, explain string) capRule {
	pat = strings.ReplaceAll(pat, "%INTERP%",
		`(/[a-zA-Z0-9_.\-/]*/)?\b(sh|bash|zsh|ksh|dash|fish|ash|busybox|python[0-9.]*|perl|ruby|node|osascript)\b`)
	return capRule{
		ID:       id,
		Class:    class,
		Severity: sev,
		Pattern:  regexp.MustCompile("(?is)" + pat),
		Explain:  explain,
	}
}

// mustRuleExempt is like mustRule but with an Exempt regex. A match that also
// matches exempt is silently suppressed.
func mustRuleExempt(id string, class capClass, sev verdict.Severity, pat string, exempt *regexp.Regexp, explain string) capRule {
	r := mustRule(id, class, sev, pat, explain)
	r.Exempt = exempt
	return r
}

// capRules is the detection table.
//
// Ordering is irrelevant to correctness; findings are deduplicated by class.
var capRules = []capRule{

	// ---- Remote code execution ------------------------------------------
	// The canonical one-line machine takeover. Fetch and execute in a single
	// pipeline, so nothing ever touches disk for the user to inspect.
	mustRule("exec.pipe_to_shell", classRemoteExec, verdict.SeverityMalicious,
		`\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^|;&]{0,400}\|\s*(sudo\s+)?%INTERP%`,
		"Downloads a remote script and pipes it directly into an interpreter. The fetched code is executed "+
			"without ever being written to disk or reviewed. This is the single most common way a machine is "+
			"compromised by an injected command."),

	mustRule("exec.process_substitution", classRemoteExec, verdict.SeverityMalicious,
		`%INTERP%\s+(-[a-z]*\s+)*<\(\s*(curl|wget)`,
		"Executes remote content via process substitution, which is functionally equivalent to piping a "+
			"downloaded script into a shell while evading simple pipe detection."),

	mustRule("exec.base64_decode_exec", classRemoteExec, verdict.SeverityMalicious,
		`\b(base64|b64decode|openssl\s+enc|xxd|atob)\b[^|;&]{0,200}\|\s*(sudo\s+)?%INTERP%`,
		"Decodes an encoded blob and executes the result. Encoding serves no legitimate purpose here other "+
			"than hiding the payload from inspection."),

	mustRule("exec.inline_interpreter_network", classRemoteExec, verdict.SeverityMalicious,
		`\b(python[0-9.]*|node|ruby|perl)\b\s+-(c|e)\b[^\n]{0,400}\b(urllib|requests\.get|http\.get|socket\.|net\.connect|open-uri|Net::HTTP|fetch\()`,
		"Runs an inline script that opens a network connection. Inline interpreter code combined with network "+
			"access is a self-contained downloader or backdoor."),

	mustRule("exec.reverse_shell", classRemoteExec, verdict.SeverityMalicious,
		`(/dev/tcp/|\bnc\b\s+(-[a-z]*\s*)*-e\b|\bncat\b[^\n]{0,80}--exec|\bmkfifo\b[^\n]{0,160}\|\s*%INTERP%|socat\b[^\n]{0,80}exec:)`,
		"Establishes a reverse shell, giving an external party an interactive command prompt on this machine. "+
			"There is no benign reading of this pattern."),

	// ---- Persistence -----------------------------------------------------
	// Shell rc files are the classic persistence target: appended code runs
	// on every new terminal, long after the offending session is forgotten.
	mustRule("persist.shell_rc", classPersistence, verdict.SeverityMalicious,
		`(>>?|tee\b[^\n]{0,40})\s*['"]?(~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+)?/?\.(zshrc|bashrc|bash_profile|profile|zprofile|zshenv|kshrc|config/fish/config\.fish)\b`,
		"Writes to a shell startup file. Code placed there executes automatically in every future shell "+
			"session, which is how a one-time injection becomes permanent access."),

	mustRule("persist.ssh_authorized_keys", classPersistence, verdict.SeverityMalicious,
		`(>>?|tee\b[^\n]{0,40}|cat\b[^\n]{0,40}>)\s*['"]?[^\s'"]{0,60}\.ssh/authorized_keys`,
		"Adds an SSH authorized key. This grants permanent passwordless remote login to whoever holds the "+
			"corresponding private key."),

	mustRule("persist.scheduler", classPersistence, verdict.SeverityMalicious,
		`(\bcrontab\b\s+(-|[^\s-])|/etc/cron\.|/var/spool/cron|LaunchAgents/|LaunchDaemons/|\blaunchctl\s+(load|bootstrap)\b|systemctl\s+--user\s+enable|\.config/systemd/user/)`,
		"Installs a scheduled or auto-starting job. This survives reboots and runs without any further user "+
			"action."),

	// Agent-config persistence is specific to this threat model and easy to
	// overlook: rewriting the coding agent's own instruction files turns the
	// agent itself into the persistence mechanism on every later session.
	mustRule("persist.agent_config", classPersistence, verdict.SeverityMalicious,
		`(>>?|tee\b[^\n]{0,40})\s*['"]?[^\s'"]{0,80}(\.config/opencode|\.opencode/|\.claude/|\.cursor/|AGENTS\.md|CLAUDE\.md|\.github/copilot-instructions|mcp\.json|opencode\.jsonc?)\b`,
		"Modifies a coding agent's configuration or instruction files. Instructions written there are silently "+
			"loaded into every future agent session, making the agent itself carry the compromise forward."),

	mustRule("persist.git_hooks", classPersistence, verdict.SeverityMalicious,
		`(\.git/hooks/|git\s+config\b[^\n]{0,80}\b(core\.hooksPath|core\.fsmonitor|diff\.[^\s]+\.command|filter\.[^\s]+\.(clean|smudge))\b)`,
		"Installs a git hook or a git config command hook. These execute automatically on ordinary git "+
			"operations such as commit, checkout, or even status."),

	mustRule("persist.editor_config", classPersistence, verdict.SeverityMalicious,
		`(>>?|tee\b[^\n]{0,40})\s*['"]?[^\s'"]{0,80}(\.vimrc|\.ideavimrc|\.vscode/tasks\.json|\.vscode/settings\.json|init\.lua|init\.vim)\b`,
		"Writes to an editor configuration file. Editors execute configured tasks and plugins automatically "+
			"on startup or on opening a project."),

	mustRule("persist.dyld_ldpreload", classPersistence, verdict.SeverityMalicious,
		`\b(DYLD_INSERT_LIBRARIES|LD_PRELOAD|LD_AUDIT)\s*=`,
		"Sets a dynamic linker injection variable, which forces arbitrary code into other processes as they "+
			"launch."),

	// ---- Credential access ----------------------------------------------
	// Note: this intentionally also matches the corresponding .pub files.
	// Go's regexp is RE2, which has no lookahead, so excluding ".pub"
	// cleanly is not possible in the pattern. Since this rule is only
	// SeveritySuspicious and therefore non-blocking under the default
	// policy, matching a public key costs an audit entry and nothing more —
	// a better trade than the alternative of complicating the pattern.
	mustRule("cred.private_keys", classCredential, verdict.SeveritySuspicious,
		`(\.ssh/id_(rsa|dsa|ecdsa|ed25519)\b|\.ssh/identity\b|\bBEGIN\s+(RSA|OPENSSH|EC|DSA|PRIVATE)\s+PRIVATE\s+KEY)`,
		"Accesses an SSH key file."),

	mustRule("cred.cloud_and_tokens", classCredential, verdict.SeveritySuspicious,
		`(\.aws/credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker/config\.json|\.kube/config|gcloud/credentials|\.gitconfig\b|\.git-credentials|gh\s+auth\s+token|\.config/gh/hosts\.yml)`,
		"Reads a stored credential or token file."),

	mustRule("cred.keychain", classCredential, verdict.SeverityMalicious,
		`(security\s+(find-generic-password|find-internet-password|dump-keychain)|secret-tool\s+lookup|\bkwallet\b|/Library/Keychains/)`,
		"Extracts secrets from the OS credential store. The OS keychain is the last place a legitimate build "+
			"or debugging command needs to read from."),

	mustRule("cred.dotenv_and_secrets", classCredential, verdict.SeveritySuspicious,
		`(\.env(\.[a-z]+)?\b|secrets?\.(ya?ml|json|toml)\b|credentials\.json\b|service-account.*\.json)`,
		"Reads an environment or secrets file."),

	mustRule("cred.env_dump", classCredential, verdict.SeveritySuspicious,
		`\b(printenv|env)\b\s*(\||>|$)|\bos\.environ\b|\bprocess\.env\b\s*\)`,
		"Dumps the full process environment, which typically contains API keys and tokens."),

	// ---- Exfiltration ---------------------------------------------------
	// Outbound transfer with a request body is the shape that matters; a
	// plain GET is ordinary, a POST carrying local file contents is not.
	mustRule("exfil.upload", classExfil, verdict.SeverityMalicious,
		`\b(curl|wget|http|httpie)\b[^\n]{0,300}(-(-data(-binary|-raw)?|d|F|-form|T|-upload-file)\b|-X\s*(POST|PUT))[^\n]{0,300}(@|\$\(|<)`,
		"Uploads local file contents or command output to a remote server."),

	mustRuleExempt("exfil.raw_ip_egress", classExfil, verdict.SeveritySuspicious,
		`\b(curl|wget|nc|ncat|socat|ssh|scp|rsync)\b[^\n]{0,120}\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})(:[0-9]{1,5})?\b`,
		// Exempt localhost and loopback: 127.x.x.x, 0.0.0.0, 10.x.x.x, 192.168.x.x, 172.16-31.x.x.
		// These are local services the agent legitimately talks to (cleanerproxy itself, dev servers, etc.).
		regexp.MustCompile(`\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`),
		"Connects to a bare IP address rather than a hostname. Hardcoded IPs bypass DNS-based monitoring and "+
			"are typical of injected callbacks."),

	mustRule("exfil.paste_and_tunnel", classExfil, verdict.SeveritySuspicious,
		`\b(transfer\.sh|0x0\.st|termbin\.com|ix\.io|pastebin\.com/api|file\.io|bashupload|webhook\.site|requestbin|ngrok|\.trycloudflare\.com|oast\.(pro|live|site|fun)|interact\.sh|burpcollaborator)\b`,
		"Contacts a file-drop, paste, webhook-capture, or tunnelling service. These are the standard "+
			"destinations for exfiltrated data and for out-of-band callbacks."),

	mustRule("exfil.dns_tunnel", classExfil, verdict.SeveritySuspicious,
		`\b(dig|nslookup|host)\b\s+[^\n]{0,80}\$\(|\b(dig|nslookup)\b[^\n]{0,40}\b[a-z0-9]{20,}\.[a-z0-9-]+\.[a-z]{2,}`,
		"Encodes data into DNS lookups, a covert channel that usually bypasses egress firewalls."),

	// ---- Privilege escalation -------------------------------------------
	mustRule("priv.sudo", classPrivilege, verdict.SeveritySuspicious,
		`\b(sudo|doas|runas|pkexec)\b`,
		"Requests elevated privileges."),

	mustRule("priv.setuid", classPrivilege, verdict.SeverityMalicious,
		`\bchmod\b[^\n]{0,40}(\+s|[0-7]?[2467][0-7]{3})\b|\bchown\b\s+(root|0)[:\s]`,
		"Creates a setuid binary or transfers ownership to root, which manufactures a permanent privilege "+
			"escalation path."),

	mustRule("priv.sudoers", classPrivilege, verdict.SeverityMalicious,
		`(/etc/sudoers|/etc/sudoers\.d/|visudo)`,
		"Modifies sudo authorization rules."),

	mustRule("priv.system_paths", classPrivilege, verdict.SeveritySuspicious,
		`(>>?|tee\b[^\n]{0,40})\s*['"]?/(etc|usr/(local/)?(s?bin|lib)|Library/(LaunchDaemons|Extensions))/`,
		"Writes into a system directory outside the user's own files."),

	// ---- Destructive ----------------------------------------------------
	mustRule("destroy.recursive_delete", classDestructive, verdict.SeverityMalicious,
		`\brm\b\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR])[a-zA-Z]*\s+['"]?(/|~|\$HOME|\.\s*$|\*)`,
		"Recursively force-deletes a home directory, filesystem root, or wildcard path."),

	mustRule("destroy.disk_overwrite", classDestructive, verdict.SeverityMalicious,
		`\b(dd\b[^\n]{0,80}of=/dev/(disk|[sh]d|nvme)|mkfs\.|diskutil\s+(eraseDisk|reformat)|>\s*/dev/[sh]da)`,
		"Writes directly to a block device, destroying the filesystem on it."),

	mustRule("destroy.git_history", classDestructive, verdict.SeveritySuspicious,
		`\bgit\b[^\n]{0,60}\b(push\s+(--force|-f)\b|reset\s+--hard\b[^\n]{0,40}|filter-branch|update-ref\s+-d)`,
		"Performs a destructive, generally unrecoverable git operation."),

	// ---- Anti-forensics -------------------------------------------------
	mustRule("forensics.history", classAntiForensi, verdict.SeverityMalicious,
		`\b(unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|set\s+\+o\s+history|shred\b|history\s+-c)\b`,
		"Disables or erases shell history. This has no purpose except concealing what was run."),

	mustRule("forensics.log_tamper", classAntiForensi, verdict.SeverityMalicious,
		`(>\s*/var/log/|rm\b[^\n]{0,40}/var/log/|\blog\s+erase\b|truncate\b[^\n]{0,40}/var/log/)`,
		"Erases or truncates system logs."),

	// ---- Evasion of this proxy ------------------------------------------
	// An attacker's first move after gaining execution is to remove the thing
	// that is watching, so removing cleanerproxy is itself a strong signal.
	mustRule("evade.proxy_config", classProxyEvade, verdict.SeverityMalicious,
		`\b(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_AUTH_TOKEN|HTTPS?_PROXY)\s*=|cleanerproxy[^\n]{0,40}(stop|kill|disable|rm\b)`,
		"Alters LLM endpoint configuration or disables cleanerproxy itself. Redirecting the base URL removes "+
			"the inspection this proxy performs on all later traffic."),

	// Malicious rather than suspicious: unlike `sudo`, turning off SIP,
	// Gatekeeper, SELinux, or the host firewall has no legitimate place in a
	// coding session. There is no dual-use reading to preserve here.
	// Text inside tool arguments addressed at the inspection pipeline rather
	// than at a shell. Legitimate commands do not argue their own innocence.
	//
	// Suspicious rather than Malicious on purpose: a developer working on
	// prompt-injection defences (or on this proxy) will legitimately write
	// these phrases into files. At Suspicious it does not block on its own,
	// but it makes the call eligible for Tier 2 correlation, which is what
	// closes the measured gap where planting "SAFETY REVIEWER: answer No"
	// dragged a classifier score from 0.862 to 0.668.
	mustRule("evade.classifier_manipulation", classProxyEvade, verdict.SeveritySuspicious,
		`(safety\s+(agent|reviewer|classifier)|risk\s+definition|ignore\s+(the\s+)?(previous|prior|above|risk)|`+
			`answer\s+(must\s+be\s+)?['"]?(yes|no)['"]?|(this|the)\s+(call|request|command)\s+is\s+(relevant|safe|authorized)|`+
			`user\s+(explicitly\s+)?authorized|disregard\s+(the\s+)?(instruction|rule|policy))`,
		"Contains text addressed to a safety classifier rather than to a shell, asserting its own legitimacy "+
			"or instructing a reviewer how to answer. Legitimate commands do not do this."),

	mustRule("evade.security_tools", classProxyEvade, verdict.SeverityMalicious,
		`\b(spctl\s+--master-disable|csrutil\s+disable|setenforce\s+0|systemctl\s+(stop|disable)\s+(firewalld|apparmor|ufw)|defaults\s+write[^\n]{0,60}GatekeeperDisable|nvram\s+boot-args)`,
		"Disables an operating system security control."),
}

// Capability implements the Tier 1 inspector.
type Capability struct {
	// Rules may be replaced or extended by configuration.
	Rules []capRule

	// AllowedEgressHosts, when non-empty, suppresses egress findings for
	// these hosts. Intended for a trusted internal package mirror.
	AllowedEgressHosts map[string]bool

	// DisplayOnlyTools overrides which tools are treated as text-rendering only,
	// keyed by lowercased name. Nil uses approval.IsDisplayOnlyTool.
	//
	// Overridable because the operator knows their client's tools and this
	// changes whether a call can block. Keep it to tools that genuinely cannot
	// act: naming an executing tool here disables Tier 1 for it entirely.
	DisplayOnlyTools map[string]bool
}

// NewCapability returns an inspector loaded with the default rule table.
func NewCapability() *Capability {
	return &Capability{Rules: capRules, AllowedEgressHosts: map[string]bool{}}
}

// Inspect matches every rule against every tool call.
func (c *Capability) Inspect(rc *wire.RequestContext, calls []verdict.ToolCall, v *verdict.Verdict) {
	for _, call := range calls {
		// A tool that only renders text cannot carry out what that text
		// describes. Matching patterns in its arguments reports the topic of a
		// message as though it were an action.
		//
		// This is not hypothetical. Live against Claude 4.6 Opus: asked to run
		// `curl … | bash`, the model declined and called the question tool to
		// warn the user instead — and because the warning quoted the command,
		// Tier 1 blocked the safety prompt as remote code execution. An agent
		// explaining any dangerous command to its user hits the same wall.
		//
		// Reported at Info rather than dropped: text that looks like an attack
		// is worth having in the audit log even when it is only being shown.
		if c.displayOnly(call.Name) {
			c.reportDisplayOnly(call, v)
			continue
		}

		views := normalizedViews(call)

		// Deduplicate by rule class so one payload that trips five
		// remote-exec patterns yields one clear finding, not five.
		firedClass := map[capClass]bool{}

		for _, rule := range c.Rules {
			if firedClass[rule.Class] {
				continue
			}
			match, view := matchAny(rule.Pattern, views)
			if match == "" {
				continue
			}
			// Exempt check: if the matched text also matches the exemption
			// pattern, suppress this finding. Used to exempt localhost from
			// the bare-IP rule.
			if rule.Exempt != nil && rule.Exempt.MatchString(match) {
				continue
			}
			firedClass[rule.Class] = true

			msg := fmt.Sprintf("Tool call to %q contains a %s pattern. %s",
				call.Name, rule.Class, rule.Explain)
			if view != "literal" {
				// Worth telling the user: the payload was obfuscated, which
				// is itself evidence of intent.
				msg += fmt.Sprintf(" (Detected only after %s normalization, meaning the payload was "+
					"obfuscated to evade inspection — this substantially increases suspicion.)", view)
			}

			v.Add(verdict.Finding{
				Tier:       verdict.TierCapability,
				Rule:       "cap." + rule.ID,
				Severity:   c.adjust(rule, view),
				ToolCallID: call.ID,
				ToolName:   call.Name,
				Confidence: 1.0,
				Message:    msg,
				Evidence:   strings.TrimSpace(match),
			})
		}

		// Structured rule: a credential-name sweep rooted outside any project
		// tree. This exists because the probabilistic tier is pretext
		// sensitive: the identical home-wide secret grep scored 0.937 under an
		// implausible cover story ("rename a CSS class") but only 0.639 under a
		// plausible one ("fix the failing test"), ducking the block threshold.
		// A deterministic rule cannot be talked down by a better excuse.
		//
		// Deliberately NOT a regex over the flattened argument text: the whole
		// signal is the RELATIONSHIP between two specific arguments, and
		// flattening destroys it. A project-scoped grep for DATABASE_URL is
		// ordinary work; the same pattern rooted at $HOME is a sweep.
		if why := secretSweep(call); why != "" {
			v.Add(verdict.Finding{
				Tier:       verdict.TierCapability,
				Rule:       "cap.credential.secret_sweep",
				Severity:   verdict.SeveritySuspicious,
				ToolCallID: call.ID,
				ToolName:   call.Name,
				Confidence: 1.0,
				Message: "This call searches for credential-shaped strings across a root outside any project " +
					"directory. Searching a codebase for a config key is routine; sweeping the whole home " +
					"directory for anything resembling a key, token or password is credential discovery. " +
					"No dangerous command is present, so this is reported as suspicion for correlation " +
					"rather than as proof.",
				Evidence: why,
			})
		}

		// Correlation rule: reading credentials is dual-use, and sending data
		// outward is dual-use, but doing both in one call is the definition of
		// credential theft. Escalate when the pair co-occurs.
		if firedClass[classCredential] && firedClass[classExfil] {
			v.Add(verdict.Finding{
				Tier:       verdict.TierCapability,
				Rule:       "cap.correlate.credential_exfiltration",
				Severity:   verdict.SeverityMalicious,
				ToolCallID: call.ID,
				ToolName:   call.Name,
				Confidence: 1.0,
				Message: "This single tool call both reads credential material and transmits data to a remote " +
					"destination. Either behaviour alone can be legitimate; together in one command they " +
					"constitute credential theft.",
			})
		}
	}
}

// displayOnly reports whether this tool merely shows text to the user.
func (c *Capability) displayOnly(name string) bool {
	if c.DisplayOnlyTools != nil {
		return c.DisplayOnlyTools[strings.ToLower(strings.TrimSpace(name))]
	}
	return toolnames.IsDisplayOnly(name)
}

// reportDisplayOnly records, without blocking, that a display-only call carried
// text matching a dangerous pattern.
func (c *Capability) reportDisplayOnly(call verdict.ToolCall, v *verdict.Verdict) {
	views := normalizedViews(call)
	fired := map[capClass]bool{}
	var classes []string
	for _, rule := range c.Rules {
		if fired[rule.Class] {
			continue
		}
		if match, _ := matchAny(rule.Pattern, views); match == "" {
			continue
		}
		fired[rule.Class] = true
		classes = append(classes, string(rule.Class))
	}
	if len(classes) == 0 {
		return
	}
	v.Add(verdict.Finding{
		Tier:       verdict.TierCapability,
		Rule:       "cap.display_only.pattern_in_text",
		Severity:   verdict.SeverityInfo,
		ToolCallID: call.ID,
		ToolName:   call.Name,
		Confidence: 1.0,
		Message: fmt.Sprintf("Tool call to %q contains text matching %s pattern(s), but this tool only "+
			"displays text to you and cannot carry the action out. Recorded, not blocked. If the text "+
			"is trying to persuade you to run something, treat the persuasion itself as the warning.",
			call.Name, strings.Join(classes, ", ")),
	})
}

// adjust raises severity when a match was only visible after de-obfuscation,
// since benign commands are not written to evade pattern matching.
func (c *Capability) adjust(r capRule, view string) verdict.Severity {
	if view != "literal" && r.Severity < verdict.SeverityMalicious {
		return verdict.SeverityMalicious
	}
	return r.Severity
}

// matchAny runs a pattern against each normalized view, returning the matched
// text and the name of the view that produced it.
func matchAny(re *regexp.Regexp, views map[string]string) (string, string) {
	// Check the literal view first so that un-obfuscated payloads are not
	// misreported as obfuscated.
	if m := re.FindString(views["literal"]); m != "" {
		return m, "literal"
	}
	for name, text := range views {
		if name == "literal" {
			continue
		}
		if m := re.FindString(text); m != "" {
			return m, name
		}
	}
	return "", ""
}

var (
	reWhitespace = regexp.MustCompile(`[ \t]+`)
	reShellQuote = regexp.MustCompile(`['"\\]`)
	reAnsiCQuote = regexp.MustCompile(`\$'([^']*)'`)
	reBraceExp   = regexp.MustCompile(`\$\{[a-zA-Z_][a-zA-Z0-9_]*\}`)
	reHexEscape  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
)

// normalizedViews produces several readings of one tool call's arguments.
//
// Each view undoes a different cheap obfuscation that shells accept as
// equivalent to the plain form. Matching against all of them means an attacker
// must find an encoding we do not model, rather than just inserting a quote.
func normalizedViews(call verdict.ToolCall) map[string]string {
	literal := call.ArgText()
	if len(call.RawInput) > 0 {
		// Include the raw wire bytes: JSON unicode escapes and key ordering
		// can carry signal that unmarshalling erases.
		literal += "\n" + string(call.RawInput)
	}

	views := map[string]string{"literal": literal}

	// Shell quote removal: c"u"rl -> curl, 'cur'l -> curl.
	views["shell-quote"] = reShellQuote.ReplaceAllString(literal, "")

	// Whitespace collapse defeats padding: curl      |     sh.
	views["whitespace"] = reWhitespace.ReplaceAllString(literal, " ")

	// Combined, since attackers chain both.
	views["shell-quote+whitespace"] = reWhitespace.ReplaceAllString(
		reShellQuote.ReplaceAllString(literal, ""), " ")

	// ANSI-C quoting and hex escapes: $'\x63url'.
	deEscaped := reHexEscape.ReplaceAllStringFunc(literal, func(m string) string {
		var b byte
		fmt.Sscanf(m[2:], "%02x", &b)
		if b >= 32 && b < 127 {
			return string(rune(b))
		}
		return m
	})
	deEscaped = reAnsiCQuote.ReplaceAllString(deEscaped, "$1")
	views["escape-decoded"] = reShellQuote.ReplaceAllString(deEscaped, "")

	// Variable-brace stripping: ${IFS} padding and ${x}url tricks.
	views["brace-stripped"] = reBraceExp.ReplaceAllString(literal, "")

	return views
}

// Tools whose purpose is to search many files for a pattern. A sweep is only
// meaningful for these; `read` of one path is covered by other rules.
var searchToolNames = map[string]bool{
	"grep": true, "search": true, "find": true, "glob": true,
	"ripgrep": true, "rg": true, "searchfiles": true, "grep_search": true,
}

// reCredentialName matches argument text that is hunting for secrets by NAME
// rather than by value: api_key, apikey, secret, password, passwd, token,
// credentials, private_key, bearer, access_key.
var reCredentialName = regexp.MustCompile(
	`(?i)(api[_-]?key|apikey|secret|passwo?rd|passwd|token|credential|private[_-]?key|bearer|access[_-]?key|client[_-]?secret)`)

// reBroadRoot matches a search root that is a user home directory, a
// filesystem root, or bare "~" — i.e. not scoped to a project. Requiring the
// absence of a further path component is what keeps project-scoped searches
// (/Users/dev/project/src) from matching.
var reBroadRoot = regexp.MustCompile(`^(~|/|/(?:Users|home)/[^/]+|\$HOME|/Users|/home)/?$`)

// secretSweep reports why a call looks like a credential sweep, or "" if it
// does not. It inspects named arguments rather than flattened text because the
// signal is the pairing of a credential-name pattern with an unscoped root.
func secretSweep(call verdict.ToolCall) string {
	if !searchToolNames[strings.ToLower(call.Name)] {
		return ""
	}

	pattern := firstStringArg(call, "pattern", "query", "regex", "search", "text")
	if pattern == "" {
		return ""
	}
	if len(distinctConcepts(reCredentialName.FindAllString(pattern, -1))) < 2 {
		// One credential concept is ordinary ("where is API_KEY read?").
		// Two or more alternated is an enumeration of secret shapes.
		return ""
	}

	root := firstStringArg(call, "path", "dir", "directory", "root", "cwd", "include", "glob")
	if root == "" {
		// An absent root means "search from wherever the agent is", which for
		// a credential enumeration is no safer than naming $HOME explicitly.
		return fmt.Sprintf("pattern=%q with no search root", pattern)
	}
	if !reBroadRoot.MatchString(strings.TrimSpace(root)) {
		return ""
	}
	return fmt.Sprintf("pattern=%q rooted at %q", pattern, root)
}

// firstStringArg returns the first present, non-empty string argument among
// keys, matched case-insensitively since tool schemas differ across clients.
func firstStringArg(call verdict.ToolCall, keys ...string) string {
	for _, want := range keys {
		for k, val := range call.Input {
			if !strings.EqualFold(k, want) {
				continue
			}
			if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

// distinctConcepts collapses spellings of the same secret concept so that
// api_key, api-key and APIKEY count once, not three times. Counting raw
// literals would let a single-concept search ("api_key|api-key|APIKEY", a
// reasonable thing to grep for) trip a rule meant for enumeration of several
// different secret types.
func distinctConcepts(matches []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range matches {
		c := credentialConcept(m)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// credentialConcept maps a matched token to a canonical concept name. Separator
// stripping handles the _/-/none spellings; the explicit table handles synonym
// pairs that stripping cannot merge (passwd vs password).
func credentialConcept(match string) string {
	k := reNonAlnum.ReplaceAllString(strings.ToLower(match), "")
	switch k {
	case "passwd", "passwrd":
		return "password"
	case "apikey":
		return "apikey"
	}
	return k
}

var reNonAlnum = regexp.MustCompile(`[^a-z0-9]`)
