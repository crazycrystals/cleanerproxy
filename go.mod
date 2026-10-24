module cleanerproxy

go 1.27

// Dependency policy: stdlib only.
//
// This is a security boundary. Every third-party module added here is a
// package that gets to run code inside the process that inspects hostile
// input. The JSON Schema subset validator, SSE codec, and crypto usage are
// all deliberately hand-rolled against stdlib rather than pulled in.
//
// Do not add a dependency to this file without a written justification in
// docs/ and a review of the full transitive tree.
