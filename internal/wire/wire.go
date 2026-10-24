// Package wire holds the normalized, API-agnostic view of a request/response
// pair that inspectors operate on, plus the format-specific codecs.
//
// Normalizing at the edge is what lets a detection rule be written once and
// apply to both the Anthropic Messages API and the OpenAI Chat Completions
// API. The alternative — parallel rule sets per format — guarantees the two
// drift and an attacker simply picks the weaker endpoint.
package wire

import (
	"encoding/json"
	"strings"
)

// Format identifies which API dialect a request arrived in.
type Format int

const (
	FormatAnthropic Format = iota
	FormatOpenAI
)

func (f Format) String() string {
	if f == FormatOpenAI {
		return "openai"
	}
	return "anthropic"
}

// DeclaredTool is a tool the *client* advertised in its request. This is the
// authoritative allowlist: the client can only execute what it declared, so
// any tool call naming something outside this set is unexecutable by
// definition and its presence means the response was edited in transit.
type DeclaredTool struct {
	Name        string
	Description string

	// Schema is the raw declared input schema ("input_schema" on Anthropic,
	// "function.parameters" on OpenAI).
	Schema json.RawMessage
}

// RequestContext is everything the inspectors need to know about what the
// client actually asked for.
type RequestContext struct {
	Format Format
	Model  string
	Stream bool

	// Tools is the client's declared tool set, in declaration order.
	Tools []DeclaredTool

	// toolIndex is the lookup built from Tools.
	toolIndex map[string]DeclaredTool

	// System is the concatenated system prompt.
	System string

	// UserTurns holds the text of user messages in order, oldest first.
	// Used by the semantic relevance classifier to judge whether a proposed
	// tool call follows from what the user actually requested.
	UserTurns []string

	// PriorAssistantToolNames records tools already invoked earlier in this
	// conversation. A call to a tool with established precedent in-thread is
	// weaker evidence of injection than a first-time call to a dangerous one.
	PriorAssistantToolNames []string

	// RawBody is the original request body, retained for the corroboration
	// tier which must replay the identical request to a trusted path.
	RawBody []byte
}

// Index builds the tool lookup. Must be called after Tools is populated.
func (rc *RequestContext) Index() {
	rc.toolIndex = make(map[string]DeclaredTool, len(rc.Tools))
	for _, t := range rc.Tools {
		rc.toolIndex[t.Name] = t
	}
}

// Tool returns the declared tool by exact name.
func (rc *RequestContext) Tool(name string) (DeclaredTool, bool) {
	if rc.toolIndex == nil {
		rc.Index()
	}
	t, ok := rc.toolIndex[name]
	return t, ok
}

// DeclaredNames returns declared tool names, for diagnostics.
func (rc *RequestContext) DeclaredNames() []string {
	out := make([]string, 0, len(rc.Tools))
	for _, t := range rc.Tools {
		out = append(out, t.Name)
	}
	return out
}

// LastUserTurn returns the most recent user message text.
func (rc *RequestContext) LastUserTurn() string {
	if len(rc.UserTurns) == 0 {
		return ""
	}
	return rc.UserTurns[len(rc.UserTurns)-1]
}

// ConversationDigest renders a bounded summary of user intent for the
// classifier prompt. Bounded because the classifier is a cost centre and
// because a hostile upstream may have inflated the conversation; we cap what
// we are willing to pay to inspect.
func (rc *RequestContext) ConversationDigest(maxChars int) string {
	var b strings.Builder
	if rc.System != "" {
		sys := rc.System
		if len(sys) > 600 {
			sys = sys[:600] + "..."
		}
		b.WriteString("[system]\n")
		b.WriteString(sys)
		b.WriteString("\n\n")
	}
	// Most recent turns matter most, so walk backwards and prepend.
	var turns []string
	budget := maxChars
	for i := len(rc.UserTurns) - 1; i >= 0 && budget > 0; i-- {
		t := rc.UserTurns[i]
		if len(t) > budget {
			t = t[:budget] + "..."
		}
		budget -= len(t)
		turns = append([]string{t}, turns...)
	}
	for _, t := range turns {
		b.WriteString("[user]\n")
		b.WriteString(t)
		b.WriteString("\n\n")
	}
	return b.String()
}

// ResponseMeta carries response-level fields used for structural coherence
// checks that are independent of any individual tool call.
type ResponseMeta struct {
	// StopReason as reported upstream, normalized: "tool_use", "end_turn",
	// "max_tokens", "stop_sequence".
	StopReason string

	// Model echoed by the response.
	Model string

	// OutputTokens as claimed by the upstream usage block.
	OutputTokens int

	// TextBytes is the actual number of bytes of text content we observed.
	// A large mismatch against OutputTokens suggests content was appended
	// after the provider generated (and counted) the response.
	TextBytes int

	// ToolCallBytes is the observed byte count of tool call arguments.
	ToolCallBytes int

	// BlockIndices is every content block index seen, in arrival order.
	BlockIndices []int

	// SawMessageStart guards against spliced-in extra message envelopes.
	MessageStartCount int
}

// QuestionCall is a tool call cleanerproxy injects in place of a blocked one,
// to ask the user whether they actually wanted it.
//
// The tool must be one the client declared in this same request. cleanerproxy
// does not invent tools: an injected call to an undeclared tool is precisely
// what the Tier 0 allowlist exists to catch, and the client would reject it.
type QuestionCall struct {
	// ID is the approval nonce. The client echoes it back as the tool_result's
	// tool_use_id, which is what binds the answer to this challenge.
	ID   string
	Name string
	Args json.RawMessage
}

// Replacement is what takes the place of a blocked tool call.
//
// Question is preferred when available because it gets a real decision from the
// user; Notice is the fallback for clients that declare no way to ask.
type Replacement struct {
	Notice   string
	Question *QuestionCall
}

// ToolResult is one tool output carried in a request, used to find answers to
// cleanerproxy's approval prompts.
type ToolResult struct {
	// ID is "tool_use_id" on Anthropic, "tool_call_id" on OpenAI.
	ID string
	// Text is the flattened result content.
	Text string
}
