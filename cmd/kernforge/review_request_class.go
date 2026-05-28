package main

import (
	"strings"
)

const (
	reviewRequestClassGeneral          = "general"
	reviewRequestClassReviewOnly       = "review_only"
	reviewRequestClassDocumentArtifact = "document_artifact"
	reviewRequestClassReviewThenModify = "review_then_modify"
	reviewRequestClassModifyThenReview = "modify_then_review"
	reviewRequestClassVerificationOnly = "verification_only"
	reviewRequestClassValidationOnly   = "validation_only"

	reviewRouteModeSingleModel       = "single_model"
	reviewRouteModeCrossModel        = "cross_model"
	reviewRouteModeDeterministicOnly = "deterministic_only"
)

type ReviewRequestLifecycle struct {
	RequestClass           string   `json:"request_class,omitempty"`
	Phase                  string   `json:"phase,omitempty"`
	RouteMode              string   `json:"route_mode,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
	ReviewGateStatus       string   `json:"review_gate_status,omitempty"`
	RepairGateStatus       string   `json:"repair_gate_status,omitempty"`
	DocumentGateStatus     string   `json:"document_gate_status,omitempty"`
	VerificationGateStatus string   `json:"verification_gate_status,omitempty"`
	SecondPassStatus       string   `json:"second_pass_status,omitempty"`
	CrossReviewTriage      string   `json:"cross_review_triage,omitempty"`
	RemainingObligations   []string `json:"remaining_obligations,omitempty"`
	NextRecommendedCommand string   `json:"next_recommended_command,omitempty"`
}

func (l *ReviewRequestLifecycle) Normalize() {
	if l == nil {
		return
	}
	l.RequestClass = normalizeReviewRequestClass(l.RequestClass)
	l.Phase = strings.TrimSpace(l.Phase)
	l.RouteMode = strings.TrimSpace(l.RouteMode)
	l.Reason = strings.TrimSpace(l.Reason)
	l.ReviewGateStatus = strings.TrimSpace(l.ReviewGateStatus)
	l.RepairGateStatus = strings.TrimSpace(l.RepairGateStatus)
	l.DocumentGateStatus = strings.TrimSpace(l.DocumentGateStatus)
	l.VerificationGateStatus = strings.TrimSpace(l.VerificationGateStatus)
	l.SecondPassStatus = strings.TrimSpace(l.SecondPassStatus)
	l.CrossReviewTriage = strings.TrimSpace(l.CrossReviewTriage)
	l.RemainingObligations = normalizeTaskStateList(l.RemainingObligations, 8)
	l.NextRecommendedCommand = strings.TrimSpace(l.NextRecommendedCommand)
}

func normalizeReviewRequestClass(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "-", "_")))
	switch value {
	case reviewRequestClassReviewOnly, "review", "code_review", "read_only_review":
		return reviewRequestClassReviewOnly
	case reviewRequestClassDocumentArtifact, "document", "document_generation", "generated_document", "report_artifact":
		return reviewRequestClassDocumentArtifact
	case reviewRequestClassReviewThenModify, "review_then_fix", "review_before_fix", "pre_fix":
		return reviewRequestClassReviewThenModify
	case reviewRequestClassModifyThenReview, "edit_then_review", "post_change", "pre_write":
		return reviewRequestClassModifyThenReview
	case reviewRequestClassVerificationOnly, "verify_only", "verification":
		return reviewRequestClassVerificationOnly
	case reviewRequestClassValidationOnly, "validate_only", "validation":
		return reviewRequestClassValidationOnly
	case "", reviewRequestClassGeneral:
		return reviewRequestClassGeneral
	default:
		return value
	}
}

func classifyReviewRequestClass(rt *runtimeState, root string, opts ReviewHarnessOptions, target string, mode string, discovery ReviewScopeDiscovery) (string, string) {
	request := strings.TrimSpace(baseUserQueryText(opts.Request))
	lower := strings.ToLower(request)
	trigger := strings.ToLower(strings.TrimSpace(opts.Trigger))
	if requestClassLooksLikeDocumentArtifact(rt, request, opts) {
		return reviewRequestClassDocumentArtifact, "request asks for a generated document/report artifact; artifact-quality gates are primary"
	}
	if requestLooksLikeValidationOnly(lower) {
		return reviewRequestClassValidationOnly, "request asks to validate existing work without asking for code edits"
	}
	if requestLooksLikeVerificationOnly(lower) {
		return reviewRequestClassVerificationOnly, "request asks to run or report verification without asking for code edits"
	}
	switch trigger {
	case reviewBeforeFixTrigger:
		return reviewRequestClassReviewThenModify, "pre-fix trigger requires review findings before repair guidance"
	case "pre_write", "post_change":
		return reviewRequestClassModifyThenReview, "code-changing lifecycle requires review after the proposed or applied modification"
	case naturalReviewTrigger:
		return reviewRequestClassReviewOnly, "natural-language review route is read-only unless the user explicitly asks for a fix"
	}
	if requestLooksLikeReviewThenModify(lower) {
		return reviewRequestClassReviewThenModify, "request explicitly asks to review first and then fix the findings"
	}
	if requestLooksLikeModifyThenReview(lower) {
		return reviewRequestClassModifyThenReview, "request asks for implementation or modification with review afterwards"
	}
	if looksLikeReviewInspectionOnlyRequest(lower) ||
		(hasTurnReviewIntent(lower) && !looksLikeExplicitEditIntent(lower)) {
		return reviewRequestClassReviewOnly, "request asks for review/inspection only and has no explicit edit command"
	}
	if requestLooksLikeReviewOfExistingChange(lower) {
		return reviewRequestClassReviewOnly, "request asks to review an existing change or provided diff without asking for a new edit"
	}
	if looksLikeExplicitEditIntent(lower) || strings.EqualFold(mode, reviewModeLiveFix) {
		return reviewRequestClassModifyThenReview, "request is an edit/fix lifecycle; post-change review and validation disclosure are required"
	}
	if strings.EqualFold(target, reviewTargetAnalysis) && containsAny(lower, "write", "generate", "create", "작성", "생성", "만들") {
		return reviewRequestClassDocumentArtifact, "analysis/report target is being authored as an artifact"
	}
	if len(discovery.CandidateFiles) > 0 && hasTurnReviewIntent(lower) {
		return reviewRequestClassReviewOnly, "request mentions reviewable files and no modification lifecycle was selected"
	}
	return reviewRequestClassGeneral, "no specialized request lifecycle was selected"
}

func requestClassLooksLikeDocumentArtifact(rt *runtimeState, request string, opts ReviewHarnessOptions) bool {
	if preWriteRequestLooksLikeGeneratedDocumentArtifact(request) {
		return true
	}
	if looksLikeDocumentAuthoringIntent(request) {
		return true
	}
	if rt != nil && rt.session != nil {
		if generatedDocumentArtifactRequestContextForTurn(rt.session, request) != "" {
			return true
		}
		if rt.session.AcceptanceContract != nil {
			for _, path := range rt.session.AcceptanceContract.RequiredArtifacts {
				if pathLooksLikeDocumentArtifact(path) {
					return true
				}
			}
		}
	}
	for _, path := range opts.Paths {
		if pathLooksLikeDocumentArtifact(path) && looksLikeDocumentAuthoringIntent(request) {
			return true
		}
	}
	return false
}

func requestLooksLikeValidationOnly(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" {
		return false
	}
	if !containsAny(lower, "validate", "validation", "검산") {
		return false
	}
	if requestLooksLikeImplementationOrSourceEditWork(lower) {
		return false
	}
	return !hasTurnReviewIntent(lower) || containsAny(lower, "validation only", "validate only", "검증만")
}

func requestLooksLikeVerificationOnly(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" || !requestLooksLikeLocalVerificationWork(lower) {
		return false
	}
	return !requestLooksLikeImplementationOrSourceEditWork(lower)
}

func requestLooksLikeReviewThenModify(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" {
		return false
	}
	if looksLikeReviewBeforeFixIntent(lower) {
		return true
	}
	return containsAny(lower,
		"review and fix", "review then fix", "review, then fix", "review before fixing",
		"inspect and fix", "audit and fix", "fix after review", "repair after review",
		"검토하고 수정", "검토 후 수정", "검토해서 수정", "리뷰하고 수정", "리뷰 후 수정", "리뷰해서 수정",
		"검토한 뒤 수정", "리뷰한 뒤 수정",
	)
}

func requestLooksLikeModifyThenReview(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" {
		return false
	}
	if requestLooksLikeReviewThenModify(lower) {
		return false
	}
	if !looksLikeExplicitEditIntent(lower) {
		return false
	}
	return containsAny(lower,
		"then review", "review after", "post-change review", "self-review", "self review",
		"수정 후 검토", "수정하고 검토", "패치 후 리뷰", "변경 후 리뷰", "변경 후 검토",
	) || !hasTurnReviewIntent(lower)
}

func requestLooksLikeReviewOfExistingChange(lower string) bool {
	lower = strings.ToLower(strings.TrimSpace(lower))
	if lower == "" || !hasTurnReviewIntent(lower) {
		return false
	}
	if requestLooksLikeReviewThenModify(lower) {
		return false
	}
	return containsAny(lower,
		"review the modified code",
		"review modified code",
		"review this diff",
		"review the diff",
		"review the change",
		"review changed code",
		"code i changed",
		"방금 수정한 코드",
		"수정한 코드",
		"변경한 코드",
		"변경된 코드",
		"수정된 코드",
		"diff 리뷰",
		"diff 검토",
		"코드 리뷰",
	)
}

func classifyAcceptanceContractRequestClass(userText string, intent TurnIntent, readOnlyAnalysis bool, explicitEditRequest bool) (string, string) {
	base := strings.TrimSpace(baseUserQueryText(userText))
	lower := strings.ToLower(base)
	for _, path := range extractContractArtifactPaths(base) {
		if pathLooksLikeDocumentArtifact(path) {
			return reviewRequestClassDocumentArtifact, "acceptance contract classified the request as document/report artifact authoring"
		}
	}
	if looksLikeDocumentAuthoringIntent(base) {
		return reviewRequestClassDocumentArtifact, "acceptance contract classified the request as document/report artifact authoring"
	}
	if requestLooksLikeValidationOnly(lower) {
		return reviewRequestClassValidationOnly, "acceptance contract classified the request as validation-only"
	}
	if requestLooksLikeVerificationOnly(lower) {
		return reviewRequestClassVerificationOnly, "acceptance contract classified the request as verification-only"
	}
	if requestLooksLikeReviewThenModify(lower) {
		return reviewRequestClassReviewThenModify, "acceptance contract classified the request as review-before-modify"
	}
	if requestLooksLikeReviewOfExistingChange(lower) {
		return reviewRequestClassReviewOnly, "acceptance contract classified the request as review of an existing change"
	}
	if explicitEditRequest || intent == TurnIntentEditCode {
		return reviewRequestClassModifyThenReview, "acceptance contract classified the request as modify-then-review"
	}
	if readOnlyAnalysis && (intent == TurnIntentReviewCode || hasTurnReviewIntent(lower)) {
		return reviewRequestClassReviewOnly, "acceptance contract classified the request as read-only review"
	}
	return reviewRequestClassGeneral, "acceptance contract did not select a specialized lifecycle"
}

func buildReviewRequestLifecycle(run *ReviewRun, session *Session) *ReviewRequestLifecycle {
	if run == nil {
		return nil
	}
	class := firstNonBlankString(run.RequestClass, run.RequestAnalysis.RequestClass)
	reason := firstNonBlankString(run.RequestAnalysis.RequestClassReason, "request class selected by review request analysis")
	lifecycle := &ReviewRequestLifecycle{
		RequestClass:           class,
		Phase:                  reviewLifecyclePhaseForRun(*run),
		RouteMode:              reviewRouteModeForRun(*run),
		Reason:                 reason,
		ReviewGateStatus:       firstNonBlankString(run.Gate.Verdict, run.Result.Verdict, "unknown"),
		RepairGateStatus:       reviewRepairGateStatus(*run),
		DocumentGateStatus:     reviewDocumentGateStatusForRun(*run, session),
		VerificationGateStatus: reviewVerificationGateStatusForRun(*run),
		SecondPassStatus:       reviewSecondPassStatusLine(buildReviewSecondPassObservability(*run)),
		CrossReviewTriage:      reviewCrossReviewTriageStatusLine(buildReviewCrossReviewTriageSummary(run.CrossReviewTriage)),
		RemainingObligations:   reviewLifecycleRemainingObligations(*run),
		NextRecommendedCommand: reviewLifecycleNextCommand(run.Gate.NextCommands),
	}
	lifecycle.Normalize()
	return lifecycle
}

func reviewLifecyclePhaseForRun(run ReviewRun) string {
	if len(run.StateTransitions) > 0 {
		last := run.StateTransitions[len(run.StateTransitions)-1]
		if strings.TrimSpace(last.To) != "" {
			return strings.TrimSpace(last.To)
		}
	}
	if strings.TrimSpace(run.Gate.Action) != "" {
		return reviewActionBoundaryState(run)
	}
	if len(run.Findings) > 0 || strings.TrimSpace(run.Gate.Verdict) != "" {
		return reviewStateGateDecision
	}
	if len(run.Evidence.Sources) > 0 {
		return reviewStateMainReview
	}
	return reviewStateCollectEvidence
}

func reviewRouteModeForRun(run ReviewRun) string {
	if run.SingleModelPolicy.Enabled {
		return reviewRouteModeSingleModel
	}
	if reviewRunHasReviewerRun(run, "cross_reviewer") || strings.TrimSpace(run.CapabilityManifest.CrossReviewModel) == "available" {
		return reviewRouteModeCrossModel
	}
	if len(run.ReviewerRuns) == 0 {
		return reviewRouteModeDeterministicOnly
	}
	return reviewRouteModeSingleModel
}

func reviewRepairGateStatus(run ReviewRun) string {
	if run.RepairPlan.Required || reviewRunNeedsRepair(run) {
		return "required"
	}
	if len(run.RepairFindings) > 0 {
		return "tracked"
	}
	return "not_required"
}

func reviewDocumentGateStatusForRun(run ReviewRun, session *Session) string {
	if normalizeReviewRequestClass(firstNonBlankString(run.RequestClass, run.RequestAnalysis.RequestClass)) != reviewRequestClassDocumentArtifact {
		return "not_applicable"
	}
	if session != nil {
		if sessionHasDocumentArtifactQualityAcceptedHarness(session) ||
			sessionHasDocumentArtifactContentAcceptedHarness(session) ||
			sessionHasApprovedDocumentArtifactOnlyHarness(session) {
			return "accepted"
		}
		if session.LastCodingHarnessReport != nil &&
			codingHarnessFindingsHaveBlockers(session.LastCodingHarnessReport.ArtifactQuality.Findings) {
			return "blocked"
		}
	}
	return "pending"
}

func reviewVerificationGateStatusForRun(run ReviewRun) string {
	if run.Evidence.VerificationFailed {
		return "failed"
	}
	if strings.TrimSpace(run.Evidence.VerificationSummary) != "" {
		return "recorded"
	}
	if run.Evidence.VerificationRequired ||
		(strings.TrimSpace(run.Evidence.VerificationSummary) == "" && reviewRunHasChangeEvidence(run) && run.Target != reviewTargetPlan) {
		return "gap_recorded"
	}
	return "not_required"
}

func reviewLifecycleRemainingObligations(run ReviewRun) []string {
	if run.ObligationLedger.TotalCount == 0 && len(run.ObligationLedger.Items) == 0 {
		return nil
	}
	return normalizeTaskStateList(run.ObligationLedger.Summary, 8)
}

func reviewLifecycleNextCommand(commands []ReviewNextCommand) string {
	if len(commands) == 0 {
		return ""
	}
	return strings.TrimSpace(commands[0].Command)
}

func buildRuntimeGateLifecycle(session *Session, action string, changedPaths []string, review *ReviewRun) *ReviewRequestLifecycle {
	if review != nil {
		return buildReviewRequestLifecycle(review, session)
	}
	class, reason := classifyRuntimeGateRequestClass(session, action, changedPaths)
	lifecycle := &ReviewRequestLifecycle{
		RequestClass:       class,
		Phase:              "runtime_gate",
		Reason:             reason,
		DocumentGateStatus: reviewRuntimeGateDocumentStatus(session, class),
	}
	lifecycle.Normalize()
	return lifecycle
}

func classifyRuntimeGateRequestClass(session *Session, action string, changedPaths []string) (string, string) {
	if session == nil {
		return reviewRequestClassGeneral, "no session request context was available"
	}
	request := ""
	if session.AcceptanceContract != nil {
		if class := normalizeReviewRequestClass(session.AcceptanceContract.RequestClass); class != reviewRequestClassGeneral {
			return class, firstNonBlankString(session.AcceptanceContract.RequestClassReason, "request class came from the acceptance contract")
		}
		request = session.AcceptanceContract.SourcePrompt
	}
	if request == "" && session.TaskState != nil {
		request = session.TaskState.Goal
	}
	if request == "" {
		request = latestExternalOrUserMessageText(session.Messages)
	}
	if generatedDocumentArtifactGateAcceptedForRequest(session, request, changedPaths) ||
		changedPathsAreGeneratedDocumentArtifacts(session, request, changedPaths) {
		return reviewRequestClassDocumentArtifact, "runtime gate detected generated document artifact paths and accepted artifact-quality context"
	}
	readOnly := prefersReadOnlyAnalysisIntent(request) || looksLikeReviewInspectionOnlyRequest(request)
	class, reason := classifyAcceptanceContractRequestClass(request, classifyTurnIntent(request), readOnly, looksLikeExplicitEditIntent(request))
	if class == reviewRequestClassGeneral && strings.EqualFold(normalizeRuntimeGateAction(action), runtimeGateActionFinalAnswer) {
		return reviewRequestClassGeneral, "final-answer gate has no specialized lifecycle context"
	}
	return class, reason
}

func reviewRuntimeGateDocumentStatus(session *Session, class string) string {
	if normalizeReviewRequestClass(class) != reviewRequestClassDocumentArtifact {
		return "not_applicable"
	}
	if session == nil {
		return "unknown"
	}
	if sessionHasDocumentArtifactQualityAcceptedHarness(session) ||
		sessionHasDocumentArtifactContentAcceptedHarness(session) ||
		sessionHasApprovedDocumentArtifactOnlyHarness(session) {
		return "accepted"
	}
	if session.LastCodingHarnessReport != nil &&
		codingHarnessFindingsHaveBlockers(session.LastCodingHarnessReport.ArtifactQuality.Findings) {
		return "blocked"
	}
	return "pending"
}
