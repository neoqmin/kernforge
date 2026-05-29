package main

import (
	"strconv"
	"strings"
	"time"
)

type FinalAnswerCorrectionVisibility struct {
	Required             bool      `json:"required"`
	Corrected            bool      `json:"corrected,omitempty"`
	Rejected             bool      `json:"rejected,omitempty"`
	Status               string    `json:"status,omitempty"`
	Source               string    `json:"source,omitempty"`
	Reasons              []string  `json:"reasons,omitempty"`
	FindingTitles        []string  `json:"finding_titles,omitempty"`
	AttemptCount         int       `json:"attempt_count,omitempty"`
	MaxAttempts          int       `json:"max_attempts,omitempty"`
	RecordedAt           time.Time `json:"recorded_at,omitempty"`
	CorrectedAt          time.Time `json:"corrected_at,omitempty"`
	RejectedAt           time.Time `json:"rejected_at,omitempty"`
	LastAttemptAt        time.Time `json:"last_attempt_at,omitempty"`
	recordedMessageCount int
	hasRecordedMessages  bool
}

const (
	finalAnswerCorrectionStatusRequired     = "required"
	finalAnswerCorrectionStatusAccepted     = "accepted"
	finalAnswerCorrectionStatusRejected     = "rejected"
	finalAnswerCorrectionDefaultMaxAttempts = 2
)

func (v *FinalAnswerCorrectionVisibility) Normalize() {
	if v == nil {
		return
	}
	v.Source = strings.TrimSpace(v.Source)
	if v.Source == "" {
		v.Source = "pre_final_coding_harness"
	}
	v.Reasons = normalizeTaskStateList(v.Reasons, 8)
	v.FindingTitles = normalizeTaskStateList(v.FindingTitles, 12)
	if !v.Required && len(v.Reasons) > 0 {
		v.Required = true
	}
	v.Status = strings.TrimSpace(strings.ToLower(v.Status))
	if v.MaxAttempts < 0 {
		v.MaxAttempts = 0
	}
	if v.AttemptCount < 0 {
		v.AttemptCount = 0
	}
	if v.Corrected {
		v.Status = finalAnswerCorrectionStatusAccepted
		v.Rejected = false
	}
	if v.Rejected {
		v.Status = finalAnswerCorrectionStatusRejected
		v.Corrected = false
	}
	if v.Status == "" && v.Required {
		v.Status = finalAnswerCorrectionStatusRequired
	}
	switch v.Status {
	case finalAnswerCorrectionStatusAccepted:
		v.Corrected = true
		v.Rejected = false
	case finalAnswerCorrectionStatusRejected:
		v.Rejected = true
		v.Corrected = false
	case finalAnswerCorrectionStatusRequired:
	default:
		v.Status = strings.TrimSpace(v.Status)
	}
}

func finalAnswerCorrectionVisibilityFromReport(report *CodingHarnessReport, corrected bool) *FinalAnswerCorrectionVisibility {
	if report == nil || !codingHarnessReportRequiresFinalAnswerOnlyRevision(report) {
		return nil
	}
	copyReport := *report
	copyReport.Normalize()
	visibility := &FinalAnswerCorrectionVisibility{
		Required:    true,
		Corrected:   corrected,
		Source:      "pre_final_coding_harness",
		RecordedAt:  time.Now(),
		MaxAttempts: finalAnswerCorrectionDefaultMaxAttempts,
	}
	for _, finding := range copyReport.allFindings() {
		if !strings.EqualFold(strings.TrimSpace(finding.Severity), "blocker") ||
			!codingHarnessFindingRequiresFinalAnswerOnlyRevision(finding) {
			continue
		}
		if reason := finalAnswerCorrectionReasonForFinding(finding); reason != "" {
			visibility.Reasons = append(visibility.Reasons, reason)
		}
		if title := strings.TrimSpace(finding.Title); title != "" {
			visibility.FindingTitles = append(visibility.FindingTitles, title)
		}
	}
	visibility.Normalize()
	if len(visibility.Reasons) == 0 {
		return nil
	}
	if corrected {
		visibility.Status = finalAnswerCorrectionStatusAccepted
	} else {
		visibility.Status = finalAnswerCorrectionStatusRequired
	}
	return visibility
}

func finalAnswerCorrectionReasonForFinding(finding CodingHarnessFinding) string {
	switch strings.TrimSpace(finding.Title) {
	case "Changed-file summary is missing",
		"Final answer contradicts the patch transaction":
		return "changed_file_disclosure"
	case "Review result is missing":
		return "review_self_review_disclosure"
	case "Validation result is missing",
		"Required verification has no outcome",
		"Unresolved verification failure",
		"Verification was not run disclosure missing",
		"Generated document artifact verification disclosure is missing",
		"Verification claim has no recorded evidence",
		"Edit loop verification failure is unstated":
		return "validation_disclosure"
	case "Remaining-risk statement is missing",
		"Final answer contradicts remaining edit-loop risk",
		"Edit loop remaining risk is omitted",
		"No-finding review omits residual risk",
		"Cross-review residual risk is undisclosed",
		"Document artifact limitation statement is missing":
		return "remaining_risk_disclosure"
	case "Review-only answer is not findings-first",
		"Review-only no-edit statement is missing":
		return "review_only_findings_first_no_edit"
	case "Document artifact path is missing",
		"Document artifact quality status is missing":
		return "document_artifact_disclosure"
	case "Document artifact verification disclosure is missing":
		return "validation_disclosure"
	default:
		return ""
	}
}

func finalAnswerCorrectionStatusLine(visibility *FinalAnswerCorrectionVisibility) string {
	if visibility == nil {
		return "none"
	}
	copyVisibility := *visibility
	copyVisibility.Normalize()
	parts := []string{}
	if copyVisibility.Required {
		parts = append(parts, "required=true")
	}
	if copyVisibility.Status != "" {
		parts = append(parts, "status="+copyVisibility.Status)
	}
	if copyVisibility.Corrected {
		parts = append(parts, "corrected=true")
	}
	if copyVisibility.Rejected {
		parts = append(parts, "rejected=true")
	}
	if copyVisibility.AttemptCount > 0 {
		attempts := "attempts=" + strconv.Itoa(copyVisibility.AttemptCount)
		if copyVisibility.MaxAttempts > 0 {
			attempts += "/" + strconv.Itoa(copyVisibility.MaxAttempts)
		}
		parts = append(parts, attempts)
	}
	if len(copyVisibility.Reasons) > 0 {
		parts = append(parts, "reasons="+strings.Join(copyVisibility.Reasons, ","))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func finalAnswerCorrectionDetailedLine(visibility *FinalAnswerCorrectionVisibility) string {
	if visibility == nil {
		return ""
	}
	copyVisibility := *visibility
	copyVisibility.Normalize()
	if len(copyVisibility.FindingTitles) == 0 {
		return ""
	}
	return "titles=" + strings.Join(limitStrings(copyVisibility.FindingTitles, 4), " | ")
}

func (a *Agent) recordFinalAnswerCorrectionRequired(report *CodingHarnessReport) {
	if a == nil || a.Session == nil {
		return
	}
	visibility := finalAnswerCorrectionVisibilityFromReport(report, false)
	if visibility == nil {
		return
	}
	now := time.Now()
	if existing := a.Session.LastFinalAnswerCorrection; existing != nil {
		existing.Normalize()
		if existing.Required && !existing.Corrected && !existing.Rejected {
			visibility.AttemptCount = existing.AttemptCount + 1
			visibility.MaxAttempts = existing.MaxAttempts
			visibility.RecordedAt = existing.RecordedAt
			if visibility.RecordedAt.IsZero() {
				visibility.RecordedAt = now
			}
		}
	}
	if visibility.AttemptCount <= 0 {
		visibility.AttemptCount = 1
	}
	if visibility.MaxAttempts <= 0 {
		visibility.MaxAttempts = finalAnswerCorrectionDefaultMaxAttempts
	}
	visibility.LastAttemptAt = now
	visibility.Status = finalAnswerCorrectionStatusRequired
	visibility.recordedMessageCount = len(a.Session.Messages)
	visibility.hasRecordedMessages = true
	a.Session.LastFinalAnswerCorrection = visibility
	if report != nil {
		report.FinalAnswerCorrection = visibility
	}
}

func (a *Agent) markFinalAnswerCorrectionAccepted() {
	if a == nil || a.Session == nil || a.Session.LastFinalAnswerCorrection == nil {
		return
	}
	if a.Session.LastCodingHarnessReport != nil && !a.Session.LastCodingHarnessReport.Approved {
		return
	}
	visibility := *a.Session.LastFinalAnswerCorrection
	if visibility.hasRecordedMessages && finalAnswerCorrectionHasExternalUserAfter(a.Session, visibility.recordedMessageCount) {
		return
	}
	visibility.Corrected = true
	visibility.Rejected = false
	visibility.Status = finalAnswerCorrectionStatusAccepted
	if visibility.CorrectedAt.IsZero() {
		visibility.CorrectedAt = time.Now()
	}
	visibility.Normalize()
	a.Session.LastFinalAnswerCorrection = &visibility
	if a.Session.LastCodingHarnessReport != nil {
		a.Session.LastCodingHarnessReport.FinalAnswerCorrection = &visibility
	}
}

func (a *Agent) markFinalAnswerCorrectionRejected(reason string) {
	if a == nil || a.Session == nil || a.Session.LastFinalAnswerCorrection == nil {
		return
	}
	visibility := *a.Session.LastFinalAnswerCorrection
	visibility.Rejected = true
	visibility.Corrected = false
	visibility.Status = finalAnswerCorrectionStatusRejected
	if strings.TrimSpace(reason) != "" {
		visibility.Reasons = append(visibility.Reasons, strings.TrimSpace(reason))
	}
	if visibility.RejectedAt.IsZero() {
		visibility.RejectedAt = time.Now()
	}
	visibility.Normalize()
	a.Session.LastFinalAnswerCorrection = &visibility
	if a.Session.LastCodingHarnessReport != nil {
		a.Session.LastCodingHarnessReport.FinalAnswerCorrection = &visibility
	}
}

func finalAnswerCorrectionHasExternalUserAfter(session *Session, recordedMessageCount int) bool {
	if session == nil || recordedMessageCount < 0 || recordedMessageCount >= len(session.Messages) {
		return false
	}
	for _, message := range session.Messages[recordedMessageCount:] {
		if message.Role == "user" && !message.Internal {
			return true
		}
	}
	return false
}
