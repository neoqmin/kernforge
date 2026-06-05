package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	modelReviewConsentAsk    = "ask"
	modelReviewConsentAlways = "always"
	modelReviewConsentNever  = "never"

	modelReviewSkipByUser               = "skipped_by_user"
	modelReviewSkipNoInteractiveConsent = "skipped_no_interactive_consent"
	modelReviewSkipConfigNever          = "skipped_by_config_never"
)

type ModelReviewConsentRequest struct {
	Trigger              string
	OriginalMainProposal string
}

type ModelReviewConsentDecision struct {
	Allowed       bool
	Policy        string
	ConsentSource string
	SkipReason    string
}

func normalizeModelReviewConsent(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", modelReviewConsentAsk:
		return modelReviewConsentAsk
	case "on", "yes", "true", modelReviewConsentAlways:
		return modelReviewConsentAlways
	case "off", "no", "false", modelReviewConsentNever:
		return modelReviewConsentNever
	default:
		return modelReviewConsentAsk
	}
}

func configModelReviewConsent(cfg Config) string {
	return normalizeModelReviewConsent(configReviewHarness(cfg).ModelReviewConsent)
}

func (a *Agent) confirmImplicitModelReview(trigger string, originalMainProposal string) ModelReviewConsentDecision {
	req := ModelReviewConsentRequest{
		Trigger:              strings.TrimSpace(trigger),
		OriginalMainProposal: strings.TrimSpace(originalMainProposal),
	}
	if a != nil && a.PromptConfirmModelReview != nil {
		return normalizeModelReviewConsentDecision(a.PromptConfirmModelReview(req), a.Config)
	}
	policy := configModelReviewConsent(Config{})
	if a != nil {
		policy = configModelReviewConsent(a.Config)
	}
	switch policy {
	case modelReviewConsentAlways:
		return ModelReviewConsentDecision{Allowed: true, Policy: policy, ConsentSource: "config_always"}
	case modelReviewConsentNever:
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "config_never", SkipReason: modelReviewSkipConfigNever}
	default:
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "no_runtime_prompt", SkipReason: modelReviewSkipNoInteractiveConsent}
	}
}

func (rt *runtimeState) confirmImplicitModelReview(req ModelReviewConsentRequest) ModelReviewConsentDecision {
	policy := modelReviewConsentAsk
	if rt != nil {
		policy = configModelReviewConsent(rt.cfg)
	}
	if rt != nil && !rt.modelReviewConsentPromptEnabled && rt.agent != nil && rt.agent.PromptConfirmModelReview != nil {
		return normalizeModelReviewConsentDecision(rt.agent.PromptConfirmModelReview(req), rt.cfg)
	}
	switch policy {
	case modelReviewConsentAlways:
		return ModelReviewConsentDecision{Allowed: true, Policy: policy, ConsentSource: "config_always"}
	case modelReviewConsentNever:
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "config_never", SkipReason: modelReviewSkipConfigNever}
	}
	if rt == nil {
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "runtime_missing", SkipReason: modelReviewSkipNoInteractiveConsent}
	}
	if !rt.modelReviewConsentPromptEnabled {
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "runtime_prompt_not_enabled", SkipReason: modelReviewSkipNoInteractiveConsent}
	}
	if rt.alwaysApproveModelReview {
		return ModelReviewConsentDecision{Allowed: true, Policy: policy, ConsentSource: "session_auto_review"}
	}
	if !rt.interactive {
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "non_interactive", SkipReason: modelReviewSkipNoInteractiveConsent}
	}
	trigger := strings.TrimSpace(req.Trigger)
	if trigger == "" {
		trigger = "implicit"
	}
	fmt.Fprintln(rt.writer, rt.ui.statusKV("model_review_trigger", trigger))
	beforeAlways := rt.alwaysApproveModelReview
	allowed, err := rt.confirm(modelReviewQuestion(rt.cfg))
	if err != nil {
		return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "prompt_error", SkipReason: "model_review_consent_prompt_failed: " + err.Error()}
	}
	if allowed {
		source := "user"
		if !beforeAlways && rt.alwaysApproveModelReview {
			source = "session_auto_review"
		}
		return ModelReviewConsentDecision{Allowed: true, Policy: policy, ConsentSource: source}
	}
	return ModelReviewConsentDecision{Allowed: false, Policy: policy, ConsentSource: "user", SkipReason: modelReviewSkipByUser}
}

func normalizeModelReviewConsentDecision(decision ModelReviewConsentDecision, cfg Config) ModelReviewConsentDecision {
	decision.Policy = normalizeModelReviewConsent(firstNonBlankString(decision.Policy, configModelReviewConsent(cfg)))
	decision.ConsentSource = strings.TrimSpace(decision.ConsentSource)
	decision.SkipReason = strings.TrimSpace(decision.SkipReason)
	if decision.Allowed {
		decision.SkipReason = ""
		if decision.ConsentSource == "" {
			decision.ConsentSource = "allowed"
		}
	} else if decision.SkipReason == "" {
		decision.SkipReason = modelReviewSkipByUser
	}
	return decision
}

func applyModelReviewConsentToRun(run *ReviewRun, decision ModelReviewConsentDecision) {
	if run == nil {
		return
	}
	decision = normalizeModelReviewConsentDecision(decision, Config{})
	run.ModelReviewConsent = decision.Policy
	run.ConsentSource = decision.ConsentSource
	run.SkipReason = decision.SkipReason
	if decision.Allowed {
		return
	}
	run.Result.Degraded = true
	run.Result.DegradedReason = "model review " + decision.SkipReason
	if run.Result.ModelQuality == "" {
		run.Result.ModelQuality = reviewModelQualityUsable
	}
	if run.ModelPlan.UserGuidance == nil {
		run.ModelPlan.UserGuidance = []string{}
	}
	run.ModelPlan.UserGuidance = append(run.ModelPlan.UserGuidance, "Implicit model review skipped: "+decision.SkipReason)
}

func reviewConsentTriggerForRun(run ReviewRun) string {
	trigger := strings.TrimSpace(run.Trigger)
	if trigger != "" {
		return strings.ReplaceAll(trigger, "_", "-")
	}
	switch strings.TrimSpace(run.Target) {
	case reviewTargetFinal:
		return "final-answer"
	case reviewTargetGoal:
		return "goal iteration"
	case reviewTargetAnalysis:
		return "analysis reviewer"
	case reviewTargetPlan:
		return "plan/feature reviewer"
	case reviewTargetChange:
		return "post-change"
	default:
		return "implicit"
	}
}

func reviewOriginalMainProposalForOptions(opts ReviewHarnessOptions) string {
	parts := []string{}
	if strings.TrimSpace(opts.OriginalMainProposal) != "" {
		parts = append(parts, strings.TrimSpace(opts.OriginalMainProposal))
	}
	if strings.TrimSpace(opts.ProvidedDiff) != "" {
		parts = append(parts, "Proposed diff:\n"+strings.TrimSpace(opts.ProvidedDiff))
	}
	if strings.TrimSpace(opts.ImplementationReply) != "" {
		parts = append(parts, "Implementation reply:\n"+strings.TrimSpace(opts.ImplementationReply))
	}
	if len(opts.EditProposals) > 0 {
		parts = append(parts, "Edit proposals:\n"+renderOriginalMainEditProposals(opts.EditProposals))
	}
	if strings.TrimSpace(opts.ProvidedCode) != "" {
		parts = append(parts, "Provided code:\n"+strings.TrimSpace(opts.ProvidedCode))
	}
	return compactPromptSection(strings.Join(parts, "\n\n"), 12000)
}

func renderOriginalMainEditProposals(items []EditProposal) string {
	items = normalizeEditProposals(items)
	if len(items) == 0 {
		return ""
	}
	lines := []string{}
	for _, item := range items {
		line := strings.TrimSpace(item.File)
		if line == "" && len(item.Files) > 0 {
			line = strings.Join(item.Files, ", ")
		}
		if line == "" {
			line = strings.TrimSpace(item.Operation)
		}
		if line == "" {
			line = "edit proposal"
		}
		if strings.TrimSpace(item.Rationale) != "" {
			line += ": " + strings.TrimSpace(item.Rationale)
		} else if strings.TrimSpace(item.Risk) != "" {
			line += ": " + strings.TrimSpace(item.Risk)
		}
		lines = append(lines, "- "+line)
	}
	return strings.Join(lines, "\n")
}

func writeReviewOriginalMainProposalArtifact(root string, run *ReviewRun) (string, error) {
	if run == nil || strings.TrimSpace(run.OriginalMainProposal) == "" {
		return "", nil
	}
	dir := reviewRunDir(root, run.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "original_main_proposal.md")
	body := "# Original Main Proposal\n\n" + strings.TrimSpace(run.OriginalMainProposal) + "\n"
	if err := atomicWriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return filepath.ToSlash(path), nil
}

func formatOriginalMainProposalReviewRef(cfg Config, run ReviewRun) string {
	ref := strings.TrimSpace(run.OriginalMainProposalRef)
	proposal := strings.TrimSpace(run.OriginalMainProposal)
	if ref == "" && proposal == "" {
		return ""
	}
	korean := reviewRunPrefersKorean(cfg, run)
	var b strings.Builder
	if korean {
		b.WriteString("원본 메인 모델 제안")
	} else {
		b.WriteString("Original main-model proposal")
	}
	if ref != "" {
		fmt.Fprintf(&b, ": %s", filepath.ToSlash(ref))
	}
	if first := firstNonEmptyLine(proposal); first != "" {
		if ref != "" {
			b.WriteString("\n")
		} else {
			b.WriteString(": ")
		}
		if korean {
			b.WriteString("요약: ")
		} else {
			b.WriteString("Summary: ")
		}
		b.WriteString(compactPromptSection(first, 300))
	}
	return strings.TrimSpace(b.String())
}

func modelReviewQuestion(_ Config) string {
	return modelReviewQuestionEnglish
}

const (
	modelReviewQuestionEnglish = "Run model review now?"
)

func isModelReviewQuestion(question string) bool {
	normalized := strings.TrimSpace(question)
	return strings.EqualFold(normalized, modelReviewQuestionEnglish)
}
