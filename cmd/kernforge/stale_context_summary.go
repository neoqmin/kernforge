package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	staleContextStatusFresh   = "fresh"
	staleContextStatusWarned  = "warned"
	staleContextStatusBlocked = "blocked"

	staleContextSeverityWarning = "warning"
	staleContextSeverityBlocker = "blocker"

	staleContextKindChangedFilesAfterReview      = "changed_files_after_review"
	staleContextKindChangedArtifactsAfterQuality = "changed_artifacts_after_quality_gate"
	staleContextKindStaleReviewEvidence          = "stale_review_evidence"
	staleContextKindStaleVerification            = "stale_verification"
	staleContextKindStaleFinalAnswerDraft        = "stale_final_answer_draft"
	staleContextKindReviewEvidenceBeforeResume   = "review_evidence_before_resume"
	staleContextKindCorrectionPendingNewRequest  = "correction_pending_new_request"
)

type StaleContextSummary struct {
	HasStaleContext bool               `json:"has_stale_context"`
	Status          string             `json:"status,omitempty"`
	Counts          map[string]int     `json:"counts,omitempty"`
	Items           []StaleContextItem `json:"items,omitempty"`
	NextSafeAction  string             `json:"next_safe_action,omitempty"`
	NextCommand     string             `json:"next_command,omitempty"`
	BlockerCount    int                `json:"blocker_count,omitempty"`
	WarningCount    int                `json:"warning_count,omitempty"`
}

type StaleContextItem struct {
	Kind                  string `json:"kind,omitempty"`
	Severity              string `json:"severity,omitempty"`
	Status                string `json:"status,omitempty"`
	Reason                string `json:"reason,omitempty"`
	EvidenceRef           string `json:"evidence_ref,omitempty"`
	NextSafeAction        string `json:"next_safe_action,omitempty"`
	NextCommand           string `json:"next_command,omitempty"`
	FinalizationBlocked   bool   `json:"finalization_blocked,omitempty"`
	AllowedWithDisclosure bool   `json:"allowed_with_disclosure,omitempty"`
}

func buildStaleContextSummary(session *Session, run *ReviewRun, ledger *RuntimeGateLedger, report *CodingHarnessReport) *StaleContextSummary {
	summary := &StaleContextSummary{Status: staleContextStatusFresh}
	if run != nil {
		if run.Freshness.Stale {
			kind := staleContextKindStaleReviewEvidence
			if strings.Contains(strings.ToLower(run.Freshness.StaleReason), "unreviewed changed files") {
				kind = staleContextKindChangedFilesAfterReview
			}
			summary.add(StaleContextItem{
				Kind:           kind,
				Severity:       staleContextSeverityBlocker,
				Status:         staleContextStatusBlocked,
				Reason:         firstNonBlankString(run.Freshness.StaleReason, "latest review evidence is stale"),
				EvidenceRef:    "review_freshness",
				NextSafeAction: "rerun review after the current workspace changes",
				NextCommand:    "/review",
			})
		}
	}
	if ledger != nil {
		if ledger.ReviewTransaction.Stale {
			reason := strings.Join(ledger.ReviewTransaction.StaleReasons, " | ")
			kind := staleContextKindStaleReviewEvidence
			if strings.Contains(strings.ToLower(reason), "unreviewed changed files") {
				kind = staleContextKindChangedFilesAfterReview
			}
			summary.add(StaleContextItem{
				Kind:           kind,
				Severity:       staleContextSeverityBlocker,
				Status:         staleContextStatusBlocked,
				Reason:         firstNonBlankString(reason, "review transaction is stale"),
				EvidenceRef:    "review_transaction",
				NextSafeAction: "rerun review so the gate covers the current changed files",
				NextCommand:    "/review",
			})
		}
		for _, reason := range ledger.StaleReasons {
			kind := staleContextKindStaleReviewEvidence
			if strings.Contains(strings.ToLower(reason), "unreviewed changed files") {
				kind = staleContextKindChangedFilesAfterReview
			}
			summary.add(StaleContextItem{
				Kind:           kind,
				Severity:       staleContextSeverityBlocker,
				Status:         staleContextStatusBlocked,
				Reason:         reason,
				EvidenceRef:    runtimeGateEvidenceRef(ledger),
				NextSafeAction: "rerun review against the current workspace state",
				NextCommand:    "/review",
			})
		}
		for _, blocker := range ledger.Blockers {
			lower := strings.ToLower(blocker)
			if strings.Contains(lower, "latest review is stale") {
				summary.add(StaleContextItem{
					Kind:           staleContextKindStaleReviewEvidence,
					Severity:       staleContextSeverityBlocker,
					Status:         staleContextStatusBlocked,
					Reason:         blocker,
					EvidenceRef:    runtimeGateEvidenceRef(ledger),
					NextSafeAction: "replace the stale review with a fresh review run",
					NextCommand:    "/review",
				})
			}
		}
		for _, warning := range ledger.Warnings {
			lower := strings.ToLower(warning)
			if strings.Contains(lower, "latest verification predates") ||
				strings.Contains(lower, "latest verification is stale") ||
				strings.Contains(lower, "does not cover the current patch") {
				summary.add(StaleContextItem{
					Kind:           staleContextKindStaleVerification,
					Severity:       staleContextSeverityWarning,
					Status:         staleContextStatusWarned,
					Reason:         warning,
					EvidenceRef:    firstNonBlankString(ledger.VerificationReportID, runtimeGateEvidenceRef(ledger)),
					NextSafeAction: "rerun focused verification for the current patch or disclose the verification gap",
					NextCommand:    "/verify --full",
				})
			}
		}
	}
	if !summary.hasKind(staleContextKindStaleVerification) {
		if reason, evidenceRef, ok := staleVerificationReason(session, ledger); ok {
			summary.add(StaleContextItem{
				Kind:           staleContextKindStaleVerification,
				Severity:       staleContextSeverityWarning,
				Status:         staleContextStatusWarned,
				Reason:         reason,
				EvidenceRef:    evidenceRef,
				NextSafeAction: "rerun focused verification for the current patch or disclose the verification gap",
				NextCommand:    "/verify --full",
			})
		}
	}
	if report != nil {
		if reason, ok := staleArtifactQualityReason(session, ledger, report); ok {
			severity := staleContextSeverityWarning
			status := staleContextStatusWarned
			if staleArtifactQualityShouldBlock(session, ledger) {
				severity = staleContextSeverityBlocker
				status = staleContextStatusBlocked
			}
			summary.add(StaleContextItem{
				Kind:           staleContextKindChangedArtifactsAfterQuality,
				Severity:       severity,
				Status:         status,
				Reason:         reason,
				EvidenceRef:    "artifact_quality",
				NextSafeAction: "rerun the artifact-quality gate against the current document artifact",
				NextCommand:    "/status detail",
			})
		}
	}
	if staleFinalAnswerDraftExists(session, ledger, report) {
		summary.add(StaleContextItem{
			Kind:           staleContextKindStaleFinalAnswerDraft,
			Severity:       staleContextSeverityWarning,
			Status:         staleContextStatusWarned,
			Reason:         "a final-answer candidate exists while gate state changed or remains unresolved",
			EvidenceRef:    "session.final_answer_candidate",
			NextSafeAction: "discard the stale draft and rebuild the final answer from the current ledger",
			NextCommand:    "/status detail",
		})
	}
	if reviewEvidenceBeforeResume(session, run) {
		summary.add(StaleContextItem{
			Kind:                  staleContextKindReviewEvidenceBeforeResume,
			Severity:              staleContextSeverityWarning,
			Status:                staleContextStatusWarned,
			Reason:                "review evidence was created before context compaction or session resume; use ledger evidence refs before finalizing",
			EvidenceRef:           firstNonBlankString(reviewEvidenceRefForResume(run), "session.compaction"),
			NextSafeAction:        "confirm the runtime ledger still references the latest review evidence after resume",
			NextCommand:           "/status detail",
			AllowedWithDisclosure: true,
		})
	}
	if pendingCorrectionInterruptedByUser(session) {
		summary.add(StaleContextItem{
			Kind:                staleContextKindCorrectionPendingNewRequest,
			Severity:            staleContextSeverityBlocker,
			Status:              staleContextStatusBlocked,
			Reason:              "a new user request arrived while a final-answer correction contract was pending",
			EvidenceRef:         "session.last_final_answer_correction",
			NextSafeAction:      "resolve, reject, or explicitly disclose the pending correction contract before finalizing the interrupted work",
			NextCommand:         "/status detail",
			FinalizationBlocked: true,
		})
	}
	summary.Normalize()
	return summary
}

func (s *StaleContextSummary) Normalize() {
	if s == nil {
		return
	}
	s.Status = strings.TrimSpace(strings.ToLower(s.Status))
	s.Counts = map[string]int{}
	seen := map[string]bool{}
	out := make([]StaleContextItem, 0, len(s.Items))
	s.BlockerCount = 0
	s.WarningCount = 0
	for _, item := range s.Items {
		item.Normalize()
		if item.Kind == "" {
			continue
		}
		key := strings.Join([]string{item.Kind, item.Severity, item.Reason, item.EvidenceRef}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
		s.Counts[item.Kind]++
		if item.Severity == staleContextSeverityBlocker || item.Status == staleContextStatusBlocked {
			s.BlockerCount++
		} else {
			s.WarningCount++
		}
		if s.NextSafeAction == "" {
			s.NextSafeAction = item.NextSafeAction
		}
		if s.NextCommand == "" {
			s.NextCommand = item.NextCommand
		}
	}
	s.Items = out
	if len(s.Items) == 0 {
		s.HasStaleContext = false
		s.Status = staleContextStatusFresh
		s.Counts = nil
		s.NextSafeAction = ""
		s.NextCommand = ""
		return
	}
	s.HasStaleContext = true
	if s.BlockerCount > 0 {
		s.Status = staleContextStatusBlocked
	} else if s.WarningCount > 0 {
		s.Status = staleContextStatusWarned
	} else if s.Status == "" {
		s.Status = staleContextStatusFresh
	}
	if len(s.Counts) == 0 {
		s.Counts = nil
	}
}

func (i *StaleContextItem) Normalize() {
	if i == nil {
		return
	}
	i.Kind = strings.TrimSpace(strings.ToLower(i.Kind))
	i.Severity = strings.TrimSpace(strings.ToLower(i.Severity))
	i.Status = strings.TrimSpace(strings.ToLower(i.Status))
	i.Reason = strings.TrimSpace(i.Reason)
	i.EvidenceRef = filepath.ToSlash(strings.TrimSpace(i.EvidenceRef))
	i.NextSafeAction = strings.TrimSpace(i.NextSafeAction)
	i.NextCommand = strings.TrimSpace(i.NextCommand)
	if i.Severity == "" {
		i.Severity = staleContextSeverityWarning
	}
	if i.Status == "" {
		if i.Severity == staleContextSeverityBlocker {
			i.Status = staleContextStatusBlocked
		} else {
			i.Status = staleContextStatusWarned
		}
	}
	if i.Severity == staleContextSeverityBlocker || i.Status == staleContextStatusBlocked {
		i.FinalizationBlocked = true
		i.AllowedWithDisclosure = false
	} else if !i.FinalizationBlocked {
		i.AllowedWithDisclosure = true
	}
}

func (s *StaleContextSummary) add(item StaleContextItem) {
	if s == nil {
		return
	}
	item.Normalize()
	if item.Kind == "" {
		return
	}
	s.Items = append(s.Items, item)
}

func (s *StaleContextSummary) hasKind(kind string) bool {
	if s == nil {
		return false
	}
	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind == "" {
		return false
	}
	for _, item := range s.Items {
		if strings.EqualFold(strings.TrimSpace(item.Kind), kind) {
			return true
		}
	}
	return false
}

func staleArtifactQualityReason(session *Session, ledger *RuntimeGateLedger, report *CodingHarnessReport) (string, bool) {
	if report == nil {
		return "", false
	}
	copyReport := *report
	copyReport.Normalize()
	if len(copyReport.ArtifactQuality.Artifacts) == 0 || copyReport.ArtifactQuality.GeneratedAt.IsZero() {
		return "", false
	}
	artifactSet := map[string]bool{}
	for _, artifact := range copyReport.ArtifactQuality.Artifacts {
		if path := normalizeSessionRelativePath(artifact.Path); path != "" {
			artifactSet[strings.ToLower(filepath.ToSlash(path))] = true
		}
	}
	if len(artifactSet) == 0 {
		return "", false
	}
	changed, changedAt := artifactPathChangedAfter(session, ledger, artifactSet, copyReport.ArtifactQuality.GeneratedAt)
	if changed == "" {
		return "", false
	}
	return fmt.Sprintf("%s changed after artifact-quality gate at %s", filepath.ToSlash(changed), changedAt.Format(time.RFC3339)), true
}

func staleArtifactQualityShouldBlock(session *Session, ledger *RuntimeGateLedger) bool {
	if ledger != nil {
		action := normalizeRuntimeGateAction(ledger.Action)
		if action == runtimeGateActionFinalAnswer || action == runtimeGateActionCompletionAudit || action == runtimeGateActionGitWrite || action == runtimeGateActionMCPWrite {
			if normalizeReviewRequestClass(ledger.RequestClass) == reviewRequestClassDocumentArtifact ||
				runtimeGateHasGeneratedDocumentArtifactContext(session, ledger.ChangedPaths) {
				return true
			}
		}
	}
	if session != nil && session.AcceptanceContract != nil {
		return normalizeReviewRequestClass(session.AcceptanceContract.RequestClass) == reviewRequestClassDocumentArtifact
	}
	return false
}

func artifactPathChangedAfter(session *Session, ledger *RuntimeGateLedger, artifactSet map[string]bool, since time.Time) (string, time.Time) {
	if session == nil || since.IsZero() {
		return "", time.Time{}
	}
	for _, tx := range staleContextPatchTransactions(session, ledger) {
		tx.Normalize()
		for _, entry := range tx.Entries {
			changedAt := firstNonZeroTime(entry.CompletedAt, tx.CompletedAt, tx.UpdatedAt, entry.StartedAt, tx.StartedAt)
			if changedAt.IsZero() || !changedAt.After(since) {
				continue
			}
			for _, path := range entry.Paths {
				normalized := strings.ToLower(filepath.ToSlash(normalizeSessionRelativePath(path.Path)))
				if artifactSet[normalized] {
					return path.Path, changedAt
				}
			}
		}
	}
	return "", time.Time{}
}

func staleVerificationReason(session *Session, ledger *RuntimeGateLedger) (string, string, bool) {
	if session == nil || session.LastVerification == nil {
		return "", "", false
	}
	report := *session.LastVerification
	reportTime := verificationReportTimestamp(report, time.Time{})
	if reportTime.IsZero() {
		return "", "", false
	}
	changed, changedAt := patchPathChangedAfter(session, ledger, reportTime)
	if changed == "" {
		return "", "", false
	}
	evidenceRef := ""
	if ledger != nil {
		evidenceRef = ledger.VerificationReportID
	}
	if evidenceRef == "" {
		evidenceRef = runtimeGateVerificationReportID(report)
	}
	return fmt.Sprintf("%s changed after verification at %s", filepath.ToSlash(changed), changedAt.Format(time.RFC3339)), evidenceRef, true
}

func patchPathChangedAfter(session *Session, ledger *RuntimeGateLedger, since time.Time) (string, time.Time) {
	if session == nil || since.IsZero() {
		return "", time.Time{}
	}
	for _, tx := range staleContextPatchTransactions(session, ledger) {
		tx.Normalize()
		for _, entry := range tx.Entries {
			changedAt := firstNonZeroTime(entry.CompletedAt, tx.CompletedAt, tx.UpdatedAt, entry.StartedAt, tx.StartedAt)
			if changedAt.IsZero() || !changedAt.After(since) {
				continue
			}
			for _, path := range entry.Paths {
				normalized := normalizeSessionRelativePath(path.Path)
				if normalized != "" {
					return normalized, changedAt
				}
			}
		}
	}
	return "", time.Time{}
}

func staleContextPatchTransactions(session *Session, ledger *RuntimeGateLedger) []PatchTransaction {
	if session == nil {
		return nil
	}
	var out []PatchTransaction
	targetID := ""
	if ledger != nil {
		targetID = strings.TrimSpace(ledger.PatchTransactionID)
	}
	if session.ActivePatchTransaction != nil {
		tx := *session.ActivePatchTransaction
		if targetID == "" || strings.TrimSpace(tx.ID) == targetID {
			out = append(out, tx)
		}
	}
	for _, tx := range session.PatchTransactions {
		if targetID != "" && strings.TrimSpace(tx.ID) != targetID {
			continue
		}
		out = append(out, tx)
	}
	return out
}

func staleFinalAnswerDraftExists(session *Session, ledger *RuntimeGateLedger, report *CodingHarnessReport) bool {
	if session == nil {
		return false
	}
	hasCandidate := false
	for _, msg := range session.Messages {
		if strings.EqualFold(strings.TrimSpace(msg.Role), "assistant") &&
			strings.TrimSpace(msg.Phase) == messagePhaseFinalAnswerCandidate {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return false
	}
	if ledger != nil && (len(ledger.Blockers) > 0 || len(ledger.Warnings) > 0 || len(ledger.StaleReasons) > 0) {
		return true
	}
	if report != nil {
		copyReport := *report
		copyReport.Normalize()
		return !copyReport.Approved
	}
	return true
}

func staleContextSummaryStatusLine(summary *StaleContextSummary) string {
	if summary == nil {
		return "none"
	}
	copySummary := *summary
	copySummary.Normalize()
	if !copySummary.HasStaleContext {
		return "fresh"
	}
	parts := []string{
		"status=" + copySummary.Status,
		fmt.Sprintf("blockers=%d", copySummary.BlockerCount),
		fmt.Sprintf("warnings=%d", copySummary.WarningCount),
	}
	for _, kind := range []string{
		staleContextKindChangedFilesAfterReview,
		staleContextKindChangedArtifactsAfterQuality,
		staleContextKindStaleReviewEvidence,
		staleContextKindStaleVerification,
		staleContextKindStaleFinalAnswerDraft,
		staleContextKindReviewEvidenceBeforeResume,
		staleContextKindCorrectionPendingNewRequest,
	} {
		if count := copySummary.Counts[kind]; count > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", kind, count))
		}
	}
	if copySummary.NextCommand != "" {
		parts = append(parts, "next="+copySummary.NextCommand)
	}
	return strings.Join(parts, " ")
}

func reviewEvidenceBeforeResume(session *Session, run *ReviewRun) bool {
	if session == nil || run == nil || strings.TrimSpace(run.ID) == "" {
		return false
	}
	if len(session.Messages) == 0 && strings.TrimSpace(session.Summary) == "" {
		return false
	}
	if strings.Contains(strings.ToLower(session.Summary), "compact") && strings.Contains(strings.ToLower(session.Summary), "review") {
		return true
	}
	for _, msg := range session.Messages {
		if len(msg.CodexCompactionItems) > 0 {
			return true
		}
	}
	for _, event := range session.ConversationEvents {
		text := strings.ToLower(strings.Join([]string{event.Kind, event.Summary, event.Raw}, " "))
		if strings.Contains(text, "compact") || strings.Contains(text, "resume") {
			return true
		}
	}
	return false
}

func reviewEvidenceRefForResume(run *ReviewRun) string {
	if run == nil {
		return ""
	}
	if len(run.ArtifactRefs) > 0 {
		return run.ArtifactRefs[0]
	}
	if strings.TrimSpace(run.ID) != "" {
		return "review:" + strings.TrimSpace(run.ID)
	}
	return ""
}

func pendingCorrectionInterruptedByUser(session *Session) bool {
	if session == nil || session.LastFinalAnswerCorrection == nil {
		return false
	}
	correction := *session.LastFinalAnswerCorrection
	correction.Normalize()
	if !correction.Required || correction.Corrected || correction.Rejected {
		return false
	}
	if correction.hasRecordedMessages || correction.HasRecordedMessages {
		return finalAnswerCorrectionHasExternalUserAfter(session, correction.recordedMessageCount)
	}
	return false
}
