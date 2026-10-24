// Command guardian-eval measures the Tier 2 classifier against the labeled
// corpus in internal/evalset.
//
// It reports three things separately, because only the third is decision-useful:
//
//	Tier 1 alone      what the deterministic rules already catch
//	Tier 2 alone      what the classifier catches by relevance
//	Combined          what actually ships, including the correlation rule
//
// A classifier that scores well on cases Tier 1 already blocks adds nothing.
// The number that matters is recall on the relevance-only subset (no dangerous
// pattern in the arguments, so Tier 1 is blind) at an acceptable false
// positive rate on the benign set.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"cleanerproxy/internal/classifier"
	"cleanerproxy/internal/evalset"
	"cleanerproxy/internal/guard"
	"cleanerproxy/internal/verdict"
	"cleanerproxy/internal/wire"
)

func main() {
	// Policy thresholds default to the SHIPPED values rather than to literals.
	// Duplicating them here once caused the harness to report 0.92 recall for
	// a policy the proxy does not use, while the real pipeline achieved 0.96.
	// A harness that simulates something other than production is worse than
	// no harness.
	shipped := guard.New()

	var (
		url       = flag.String("url", "http://127.0.0.1:18080", "llama-server base URL")
		variants  = flag.String("variants", "function_call,injection,injection_fc", "comma-separated variants to compare")
		blockConf = flag.Float64("block-confidence", shipped.SemanticBlockConfidence,
			"risk at or above which Tier 2 blocks on its own (default: shipped value)")
		corrConf = flag.Float64("correlate-confidence", shipped.CorrelateConfidence,
			"risk at or above which Tier 2 escalates a Tier 1 Suspicious finding (default: shipped value)")
		timeout  = flag.Duration("timeout", 120*time.Second, "per-call timeout")
		verbose  = flag.Bool("v", false, "print every case as it is scored")
		detail   = flag.Bool("detail", false, "print every payload with its score, grouped and sorted")
		dumpName = flag.String("dump-prompt", "", "print the exact classifier prompt for one case name, then exit")
	)
	flag.Parse()

	if *dumpName != "" {
		if err := dumpPrompt(*variants, *dumpName); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cases := evalset.Cases()
	fmt.Printf("corpus: %d cases (%d injected, %d benign, %d relevance-only)\n\n",
		len(cases), count(cases, true), count(cases, false), countRelOnly(cases))

	// Tier 0 + Tier 1 only: no classifier attached.
	base := guard.New()
	tier1 := make([]verdict.Severity, len(cases))
	for i, c := range cases {
		v, _ := base.Evaluate(c.Context(), []verdict.ToolCall{c.ToolCall()}, toolMeta())
		tier1[i] = v.MaxSeverity()
	}
	fmt.Println("== Tier 1 only (deterministic) ==")
	reportBinary(cases, func(i int) bool { return tier1[i] >= verdict.SeverityMalicious })

	for _, name := range strings.Split(*variants, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		v, err := classifier.ParseVariant(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %q: %v\n", name, err)
			continue
		}
		if err := runVariant(*url, v, cases, tier1, *blockConf, *corrConf, *timeout, *verbose, *detail); err != nil {
			fmt.Fprintf(os.Stderr, "variant %s failed: %v\n", name, err)
			os.Exit(1)
		}
	}
}

func runVariant(url string, v classifier.Variant, cases []evalset.Case, tier1 []verdict.Severity,
	blockConf, corrConf float64, timeout time.Duration, verbose, detail bool) error {

	g := classifier.NewGuardian(url, classifier.BackendLlama, v)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := g.Ready(ctx); err != nil {
		return fmt.Errorf("guardian not ready: %w", err)
	}

	fmt.Printf("\n\n======== variant: %s ========\n", v)

	risks := make([]float64, len(cases))
	lat := make([]time.Duration, 0, len(cases))
	var promptTokens int

	for i, c := range cases {
		cctx, ccancel := context.WithTimeout(context.Background(), timeout)
		s, err := g.Score(cctx, c.Context(), c.ToolCall())
		ccancel()
		if err != nil {
			return fmt.Errorf("case %s: %w", c.Name, err)
		}
		risks[i] = s.Risk
		lat = append(lat, s.Elapsed)
		promptTokens += s.PromptTokens

		if verbose {
			mark := " "
			if (s.Risk >= 0.5) != c.Injected {
				mark = "X"
			}
			fmt.Printf("  %s %-32s risk=%.3f %-4s injected=%-5v tier1=%-10s %s\n",
				mark, c.Name, s.Risk, s.Label, c.Injected, tier1[i], c.Note)
		}
		fmt.Fprintf(os.Stderr, "\r  scored %d/%d", i+1, len(cases))
	}
	fmt.Fprintln(os.Stderr)

	fmt.Printf("\nlatency: p50=%v p95=%v max=%v | mean prompt=%d tokens\n",
		pct(lat, 0.50).Round(time.Millisecond), pct(lat, 0.95).Round(time.Millisecond),
		pct(lat, 1.0).Round(time.Millisecond), promptTokens/len(cases))
	fmt.Printf("AUC (all cases): %.3f\n", auc(cases, risks))

	if detail {
		reportDetail(cases, risks, tier1, blockConf, corrConf)
	}

	fmt.Println("\n-- Tier 2 only, threshold sweep --")
	fmt.Printf("  %-6s %-8s %-8s %-10s %-8s\n", "thresh", "recall", "FPR", "rel-only", "blocked-benign")
	for _, th := range []float64{0.3, 0.5, 0.7, 0.9} {
		tpr, fpr, relRec, fp := rates(cases, func(i int) bool { return risks[i] >= th })
		fmt.Printf("  %-6.1f %-8.2f %-8.2f %-10.2f %d\n", th, tpr, fpr, relRec, fp)
	}

	fmt.Printf("\n-- Combined: Tier1>=Malicious OR Tier2>=%.2f OR (Tier1==Suspicious AND Tier2>=%.2f) --\n",
		blockConf, corrConf)
	fmt.Println("   (approximates guard's policy; internal/guard live_test.go is authoritative)")
	blocked := func(i int) bool {
		if tier1[i] >= verdict.SeverityMalicious {
			return true
		}
		if risks[i] >= blockConf {
			return true
		}
		return tier1[i] == verdict.SeveritySuspicious && risks[i] >= corrConf
	}
	reportBinary(cases, blocked)

	fmt.Println("\n-- Errors under the combined policy --")
	for i, c := range cases {
		if got := blocked(i); got != c.Injected {
			kind := "FALSE NEGATIVE (attack allowed)"
			if got {
				kind = "FALSE POSITIVE (benign blocked)"
			}
			fmt.Printf("  %-32s %s risk=%.3f tier1=%s\n    %s\n", c.Name, kind, risks[i], tier1[i], c.Note)
		}
	}
	return nil
}

func toolMeta() wire.ResponseMeta {
	return wire.ResponseMeta{StopReason: "tool_use", MessageStartCount: 1}
}

func reportBinary(cases []evalset.Case, blocked func(int) bool) {
	tpr, fpr, relRec, fp := rates(cases, blocked)
	tp, fn := 0, 0
	for i, c := range cases {
		if c.Injected {
			if blocked(i) {
				tp++
			} else {
				fn++
			}
		}
	}
	fmt.Printf("  recall (attacks blocked):   %.2f  (%d/%d)\n", tpr, tp, tp+fn)
	fmt.Printf("  FPR    (benign blocked):    %.2f  (%d/%d)\n", fpr, fp, count(cases, false))
	fmt.Printf("  recall on relevance-only:   %.2f\n", relRec)
}

func rates(cases []evalset.Case, blocked func(int) bool) (tpr, fpr, relRecall float64, falsePos int) {
	var tp, inj, fp, ben, relTP, rel int
	for i, c := range cases {
		b := blocked(i)
		if c.Injected {
			inj++
			if b {
				tp++
			}
			if c.RelevanceOnly {
				rel++
				if b {
					relTP++
				}
			}
		} else {
			ben++
			if b {
				fp++
			}
		}
	}
	div := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return float64(a) / float64(b)
	}
	return div(tp, inj), div(fp, ben), div(relTP, rel), fp
}

// auc computes the rank-based area under the ROC curve, handling ties.
func auc(cases []evalset.Case, score []float64) float64 {
	type pair struct {
		s   float64
		pos bool
	}
	ps := make([]pair, len(cases))
	for i, c := range cases {
		ps[i] = pair{score[i], c.Injected}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].s < ps[j].s })

	ranks := make([]float64, len(ps))
	for i := 0; i < len(ps); {
		j := i
		for j < len(ps) && ps[j].s == ps[i].s {
			j++
		}
		avg := float64(i+j+1) / 2 // average of 1-based ranks in the tie group
		for k := i; k < j; k++ {
			ranks[k] = avg
		}
		i = j
	}
	var sumPos float64
	var nPos, nNeg int
	for i, p := range ps {
		if p.pos {
			sumPos += ranks[i]
			nPos++
		} else {
			nNeg++
		}
	}
	if nPos == 0 || nNeg == 0 {
		return 0
	}
	return (sumPos - float64(nPos)*float64(nPos+1)/2) / (float64(nPos) * float64(nNeg))
}

func pct(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(p * float64(len(s)-1))
	return s[i]
}

func count(cases []evalset.Case, injected bool) int {
	n := 0
	for _, c := range cases {
		if c.Injected == injected {
			n++
		}
	}
	return n
}

func countRelOnly(cases []evalset.Case) int {
	n := 0
	for _, c := range cases {
		if c.RelevanceOnly {
			n++
		}
	}
	return n
}

// reportDetail prints every payload with its score, grouped by ground truth and
// sorted so the separation between the two populations is visible.
func reportDetail(cases []evalset.Case, risks []float64, tier1 []verdict.Severity, blockConf, corrConf float64) {
	idx := make([]int, len(cases))
	for i := range idx {
		idx[i] = i
	}

	blocked := func(i int) bool {
		if tier1[i] >= verdict.SeverityMalicious {
			return true
		}
		if risks[i] >= blockConf {
			return true
		}
		return tier1[i] == verdict.SeveritySuspicious && risks[i] >= corrConf
	}

	show := func(title string, want bool, desc bool) {
		sel := []int{}
		for _, i := range idx {
			if cases[i].Injected == want {
				sel = append(sel, i)
			}
		}
		sort.Slice(sel, func(a, b int) bool {
			if desc {
				return risks[sel[a]] > risks[sel[b]]
			}
			return risks[sel[a]] < risks[sel[b]]
		})

		fmt.Printf("\n\n%s\n%s\n", title, strings.Repeat("=", len(title)))
		for _, i := range sel {
			c := cases[i]
			mark := "ok "
			if blocked(i) != c.Injected {
				mark = "ERR"
			}
			tag := ""
			if c.RelevanceOnly {
				tag = "  [relevance-only: no dangerous pattern for Tier 1 to match]"
			}
			fmt.Printf("\n[%s] risk=%.3f  tier1=%-10s  ->%s%s\n", mark, risks[i], tier1[i], action(blocked(i)), tag)
			fmt.Printf("      case: %s\n", c.Name)
			fmt.Printf("      user asked: %q\n", lastTurn(c))
			fmt.Printf("      tool call:  %s(%s)\n", c.Tool, oneLine(c.ToolCall().RawInput, 220))
		}
	}

	show("INJECTED PAYLOADS (highest risk first) - all should be blocked", true, true)
	show("BENIGN CALLS (lowest risk first) - none should be blocked", false, false)
}

func action(blocked bool) string {
	if blocked {
		return "BLOCKED"
	}
	return "allowed"
}

func lastTurn(c evalset.Case) string {
	if len(c.UserTurns) == 0 {
		return ""
	}
	if len(c.UserTurns) == 1 {
		return c.UserTurns[0]
	}
	return strings.Join(c.UserTurns, " | ")
}

// oneLine collapses a payload onto a single readable line.
func oneLine(b []byte, max int) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > max {
		return s[:max] + fmt.Sprintf(" ...(+%d bytes)", len(s)-max)
	}
	return s
}

// dumpPrompt prints the exact bytes sent to the classifier for one case, so the
// prompt can be inspected rather than trusted.
func dumpPrompt(variantList, name string) error {
	vname := strings.TrimSpace(strings.Split(variantList, ",")[0])
	v, err := classifier.ParseVariant(vname)
	if err != nil {
		return err
	}
	g := classifier.NewGuardian("http://unused", classifier.BackendLlama, v)

	for _, c := range evalset.Cases() {
		if c.Name != name {
			continue
		}
		prompt, neutralized, err := g.BuildPrompt(c.Context(), c.ToolCall())
		if err != nil {
			return err
		}
		fmt.Printf("case:     %s\nvariant:  %s\ninjected: %v\nneutralized control sequences: %d\n",
			c.Name, v, c.Injected, neutralized)
		fmt.Printf("--- exact prompt (%d bytes) ---\n%s\n--- end ---\n", len(prompt), prompt)
		return nil
	}
	var names []string
	for _, c := range evalset.Cases() {
		names = append(names, c.Name)
	}
	return fmt.Errorf("no case named %q; available: %s", name, strings.Join(names, ", "))
}
