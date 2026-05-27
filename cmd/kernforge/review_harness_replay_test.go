package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type reviewReplayFixture struct {
	Name                     string                        `json:"name"`
	Category                 string                        `json:"category"`
	Trigger                  string                        `json:"trigger"`
	UserRequest              string                        `json:"user_request"`
	ReviewerRuns             []ReviewReviewerRun           `json:"reviewer_runs"`
	Findings                 []ReviewFinding               `json:"findings"`
	RepairFindings           []ReviewFinding               `json:"repair_findings"`
	EditProposals            []EditProposal                `json:"edit_proposals"`
	ExternalLookupIntents    []ReviewExternalLookupIntent  `json:"external_lookup_intents"`
	ExpectedGate             string                        `json:"expected_gate"`
	ExpectedAction           string                        `json:"expected_action"`
	ExpectedLedgerStatus     string                        `json:"expected_ledger_status"`
	ExpectedObligationCounts *reviewReplayObligationCounts `json:"expected_obligation_counts"`
	ExpectedObligations      []reviewReplayObligation      `json:"expected_obligations"`
	ExpectedProgressContains []string                      `json:"expected_progress_contains"`
	ExpectedReplyContains    []string                      `json:"expected_reply_contains"`
	ExpectedMCPContains      []string                      `json:"expected_mcp_contains"`
	ExpectedMarkdownContains []string                      `json:"expected_markdown_contains"`
}

type reviewReplayObligationCounts struct {
	Total        int `json:"total"`
	Open         int `json:"open"`
	Repair       int `json:"repair"`
	Verification int `json:"verification"`
	Evidence     int `json:"evidence"`
	Route        int `json:"route"`
}

type reviewReplayObligation struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

func TestReviewReplayFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "review_replay", "*.json"))
	if err != nil {
		t.Fatalf("glob replay fixtures: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected review replay fixtures")
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			fixture, err := loadReviewReplayFixture(path)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			run, reply := runReviewReplayFixture(fixture)
			if run.Gate.Verdict != fixture.ExpectedGate {
				t.Fatalf("expected gate %q, got %#v", fixture.ExpectedGate, run.Gate)
			}
			if strings.TrimSpace(fixture.ExpectedAction) != "" && run.Gate.Action != fixture.ExpectedAction {
				t.Fatalf("expected action %q, got %#v", fixture.ExpectedAction, run.Gate)
			}
			progress := renderReviewCLIResult(Config{AutoLocale: boolPtr(false)}, run)
			for _, want := range fixture.ExpectedProgressContains {
				if !strings.Contains(progress, want) {
					t.Fatalf("expected progress to contain %q, got %q", want, progress)
				}
			}
			for _, want := range fixture.ExpectedReplyContains {
				if !strings.Contains(reply, want) {
					t.Fatalf("expected reply to contain %q, got %q", want, reply)
				}
			}
			if strings.TrimSpace(fixture.ExpectedLedgerStatus) != "" && run.LedgerConsistency.Status != fixture.ExpectedLedgerStatus {
				t.Fatalf("expected ledger status %q, got %#v", fixture.ExpectedLedgerStatus, run.LedgerConsistency)
			}
			assertReviewReplayObligationLedger(t, fixture, run)
			mcp := renderReviewMCPResponse(run, 20000)
			for _, want := range fixture.ExpectedMCPContains {
				if !strings.Contains(mcp, want) {
					t.Fatalf("expected MCP response to contain %q, got %q", want, mcp)
				}
			}
			markdown := renderReviewRunMarkdown(run)
			for _, want := range fixture.ExpectedMarkdownContains {
				if !strings.Contains(markdown, want) {
					t.Fatalf("expected markdown to contain %q, got %q", want, markdown)
				}
			}
		})
	}
}

func TestReviewReplayFixtureRejectsMissingExpectedGate(t *testing.T) {
	fixture := reviewReplayFixture{Name: "missing_gate"}
	if err := validateReviewReplayFixture(fixture); err == nil {
		t.Fatalf("expected missing expected_gate to fail validation")
	}
}

func TestReviewReplayFixtureCanModelSoftTimeoutWithoutSleeping(t *testing.T) {
	fixture := reviewReplayFixture{
		Name:        "soft_timeout",
		Trigger:     "pre_write",
		UserRequest: "review timeout",
		ReviewerRuns: []ReviewReviewerRun{
			{Kind: "main", Role: "primary_reviewer", Status: "completed", ModelQuality: reviewModelQualityUsable},
			{Kind: "cross", Role: "cross_reviewer", Status: "failed", ModelQuality: reviewModelQualityFailed, Error: "review model soft timeout after 5m0s"},
		},
		ExpectedGate:         reviewVerdictInsufficientEvidence,
		ExpectedAction:       reviewGateActionUserDecisionRequired,
		ExpectedLedgerStatus: reviewLedgerConsistencyBlocked,
	}
	start := time.Now()
	run, _ := runReviewReplayFixture(fixture)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("replay should not sleep for soft timeout, elapsed=%s", elapsed)
	}
	if run.Gate.Verdict != reviewVerdictInsufficientEvidence {
		t.Fatalf("expected insufficient evidence gate, got %#v", run.Gate)
	}
	if !reviewActionEnvelopeHasFailure(run.ActionEnvelopes, reviewActionMergeGate, "reviewer_unavailable") {
		t.Fatalf("expected replay action envelope to preserve reviewer_unavailable failure, got %#v", run.ActionEnvelopes)
	}
}

func loadReviewReplayFixture(path string) (reviewReplayFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return reviewReplayFixture{}, err
	}
	var fixture reviewReplayFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return reviewReplayFixture{}, err
	}
	return fixture, validateReviewReplayFixture(fixture)
}

func validateReviewReplayFixture(fixture reviewReplayFixture) error {
	if strings.TrimSpace(fixture.Name) == "" {
		return errReviewReplayFixture("missing name")
	}
	if strings.TrimSpace(fixture.ExpectedGate) == "" {
		return errReviewReplayFixture("missing expected_gate")
	}
	return nil
}

type errReviewReplayFixture string

func (e errReviewReplayFixture) Error() string {
	return string(e)
}

func runReviewReplayFixture(fixture reviewReplayFixture) (ReviewRun, string) {
	run := ReviewRun{
		ID:                 "replay-" + fixture.Name,
		CreatedAt:          time.Now(),
		Trigger:            valueOrDefault(fixture.Trigger, "pre_write"),
		Target:             reviewTargetChange,
		Mode:               reviewModeLiveFix,
		Objective:          fixture.UserRequest,
		ReviewerRuns:       append([]ReviewReviewerRun(nil), fixture.ReviewerRuns...),
		ReviewerGatePolicy: "",
		ModelPlan: ReviewModelPlan{
			RequiredRoles: []string{"primary_reviewer", "cross_reviewer"},
			AssignedModels: map[string]string{
				"primary_reviewer": "scripted / main-model",
				"cross_reviewer":   "scripted / reviewer-model",
			},
			Strategy: "dual",
		},
		Evidence: ReviewEvidencePack{
			Sources: []string{"replay.diff"},
			Text:    "Frozen diff and local source evidence from replay fixture.",
		},
		EditProposals:         append([]EditProposal(nil), fixture.EditProposals...),
		ExternalLookupIntents: append([]ReviewExternalLookupIntent(nil), fixture.ExternalLookupIntents...),
	}
	run.Findings = append(run.Findings, fixture.Findings...)
	run.RepairFindings = normalizeReviewFindingCopies(fixture.RepairFindings)
	assignReviewFindingIDs(run.Findings)
	run.Findings = append(run.Findings, requiredReviewerFailureFindings(run)...)
	run.Findings, run.MergeResult = mergeReviewFindings(run.Findings)
	run.ObligationLedger = buildReviewObligationLedger(run)
	run.Gate = evaluateReviewGate(run)
	run.RepairPlan = buildReviewRepairPlan(run)
	run.Result.Summary = reviewResultSummary(run)
	run.finalizeStatus(false)
	finalizeReviewRunProtocol("", nil, &run)
	return run, formatReviewerGateUnavailableReply(Config{AutoLocale: boolPtr(false)}, run)
}

func assertReviewReplayObligationLedger(t *testing.T, fixture reviewReplayFixture, run ReviewRun) {
	t.Helper()
	if fixture.ExpectedObligationCounts != nil {
		got := run.ObligationLedger
		want := *fixture.ExpectedObligationCounts
		if got.TotalCount != want.Total ||
			got.OpenCount != want.Open ||
			got.OpenRepairCount != want.Repair ||
			got.OpenVerificationCount != want.Verification ||
			got.OpenEvidenceCount != want.Evidence ||
			got.OpenRouteCount != want.Route {
			t.Fatalf("unexpected obligation counts: got=%#v want=%#v ledger=%#v", got, want, got.Items)
		}
	}
	for _, expected := range fixture.ExpectedObligations {
		if !reviewReplayHasExpectedObligation(run.ObligationLedger, expected) {
			t.Fatalf("expected obligation %#v in %#v", expected, run.ObligationLedger.Items)
		}
	}
}

func reviewReplayHasExpectedObligation(ledger ReviewObligationLedger, expected reviewReplayObligation) bool {
	for _, obligation := range ledger.Items {
		if strings.EqualFold(strings.TrimSpace(obligation.ID), strings.TrimSpace(expected.ID)) &&
			strings.EqualFold(strings.TrimSpace(obligation.Type), strings.TrimSpace(expected.Type)) &&
			strings.EqualFold(strings.TrimSpace(obligation.Status), strings.TrimSpace(expected.Status)) {
			return true
		}
	}
	return false
}

func reviewActionEnvelopeHasFailure(envelopes []ReviewActionEnvelope, actionType string, failureClass string) bool {
	for _, envelope := range envelopes {
		if strings.EqualFold(strings.TrimSpace(envelope.ActionType), strings.TrimSpace(actionType)) &&
			strings.EqualFold(strings.TrimSpace(envelope.FailureClass), strings.TrimSpace(failureClass)) {
			return true
		}
	}
	return false
}
