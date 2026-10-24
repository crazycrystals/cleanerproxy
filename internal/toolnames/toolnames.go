// Package toolnames holds the shared taxonomy of client tool names.
//
// A leaf package with no internal imports, because two packages that must not
// depend on each other both need it: internal/approval builds the prompt and so
// needs to know which tools can ask a question, and internal/inspect needs the
// same list to know which tools merely display text and therefore cannot carry
// out what their arguments describe.
//
// Keeping one list avoids the failure mode where the two drift apart and a tool
// is treated as a prompt by one tier and as an executor by the other.
package toolnames

import "strings"

// AskTools are client tool names that put a question to the user and return
// their selection, in preference order (most expressive first).
//
// Supported clients:
//   - opencode:    "question"            (shapeQuestions)
//   - Claude Code: "AskUserQuestion"     (shapeFlat)
//   - Codex CLI:   "request_user_input"  (shapeFlat)
//   - Roo Code:    "ask_followup_question" (shapeFlat)
//
// Not standardized across clients, which is why this is a list rather than a
// single name and why it is overridable by configuration.
var AskTools = []string{
	"question", "AskUserQuestion", "ask", "ask_user", "askuser",
	"ask_followup_question", "user_question", "prompt_user",
	"elicit", "request_user_input",
}

// IsDisplayOnly reports whether a tool's only effect is to render text and
// return a choice.
//
// Such a tool cannot perform what its arguments describe, so matching
// dangerous-capability patterns against them reports the subject of a message as
// if it were an action. Observed live: asked to run `curl … | bash`, a model
// declined and called the question tool to warn the user instead; because the
// warning quoted the command, the capability tier blocked the safety prompt as
// remote code execution.
//
// Membership is deliberately narrow. A tool that writes files or runs commands
// never belongs here, however harmless its arguments look, because for those the
// text is the effect.
func IsDisplayOnly(name string) bool {
	n := strings.TrimSpace(name)
	for _, known := range AskTools {
		if strings.EqualFold(n, known) {
			return true
		}
	}
	return false
}
