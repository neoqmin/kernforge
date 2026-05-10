package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeGateLedgerBlocksStaleReviewForFinalAnswer(t *testing.T) {
	root := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "other.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write other.go: %v", err)
	}
	session := NewSession(root, "provider", "model", "", "default")
	session.LastReviewRun = &ReviewRun{
		ID:                "review-stale",
		SchemaVersion:     reviewSchemaVersion,
		Target:            reviewTargetChange,
		Mode:              reviewModeGeneralChange,
		Branch:            delegationGitBranch(root),
		ReviewFingerprint: "fp-1",
		ChangeSet: ReviewChangeSet{
			ChangedPaths: []string{"main.go"},
		},
		Freshness: ReviewFreshness{
			ReviewFingerprint: "fp-1",
		},
		Gate: GateDecision{
			Verdict: reviewVerdictApproved,
		},
	}

	ledger := buildRuntimeGateLedger(root, session, runtimeGateActionFinalAnswer)

	if ledger.Status != runtimeGateStatusBlocked || ledger.Ready {
		t.Fatalf("expected stale review to block final answer, got %#v", ledger)
	}
	if !strings.Contains(strings.Join(ledger.StaleReasons, " "), "other.go") {
		t.Fatalf("expected stale reason to mention unreviewed file, got %#v", ledger.StaleReasons)
	}
	if len(ledger.NextCommands) == 0 || ledger.NextCommands[0].Command != "/review" {
		t.Fatalf("expected /review recovery command, got %#v", ledger.NextCommands)
	}
}

func TestRuntimeGateLedgerLinksReviewPatchVerificationAndWaiver(t *testing.T) {
	root := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("updated\n"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	now := time.Now()
	session := NewSession(root, "provider", "model", "", "default")
	session.PatchTransactions = []PatchTransaction{{
		ID:        "patch-tx-1",
		Status:    patchTransactionStatusCommitted,
		StartedAt: now,
		UpdatedAt: now,
		Entries: []PatchTransactionEntry{{
			ID:     "patch-tx-1-001",
			Status: "success",
			Paths: []PatchPathChange{{
				Path:      "README.md",
				Operation: "modify",
			}},
		}},
	}}
	session.LastVerification = &VerificationReport{
		GeneratedAt:  now,
		Trigger:      "manual",
		Workspace:    root,
		ChangedPaths: []string{"README.md"},
		Steps: []VerificationStep{{
			Label:   "go test",
			Command: "go test ./...",
			Status:  VerificationPassed,
		}},
	}
	session.LastReviewRun = &ReviewRun{
		ID:                "review-waived",
		SchemaVersion:     reviewSchemaVersion,
		Target:            reviewTargetChange,
		Mode:              reviewModeGeneralChange,
		Branch:            delegationGitBranch(root),
		ReviewFingerprint: "fp-1",
		ChangeSet: ReviewChangeSet{
			ChangedPaths: []string{"README.md"},
		},
		Freshness: ReviewFreshness{
			ReviewFingerprint: "fp-1",
		},
		Gate: GateDecision{
			Verdict:          reviewVerdictApproved,
			BlockingFindings: []string{"RF-001"},
		},
		Waivers: []ReviewWaiver{{
			ID:        "waiver-1",
			FindingID: "RF-001",
			Reason:    "accepted for test",
			Allowed:   true,
			Status:    "active",
			ExpiresAt: now.Add(time.Hour),
		}},
	}

	ledger := buildRuntimeGateLedger(root, session, runtimeGateActionFinalAnswer)

	if ledger.Status != runtimeGateStatusReady || !ledger.Ready {
		t.Fatalf("expected waived blocker and passing verification to be ready, got %#v", ledger)
	}
	if ledger.ReviewRunID != "review-waived" || ledger.PatchTransactionID != "patch-tx-1" {
		t.Fatalf("expected linked review and patch IDs, got %#v", ledger)
	}
	if ledger.VerificationReportID == "" || ledger.FinalAnswerReviewID != "" {
		t.Fatalf("unexpected verification/final-review IDs: %#v", ledger)
	}
	if len(ledger.Waivers) != 1 || !strings.Contains(ledger.Waivers[0], "RF-001") {
		t.Fatalf("expected active waiver summary, got %#v", ledger.Waivers)
	}
}

func TestCompletionAuditIncludesRuntimeGateLedger(t *testing.T) {
	root := initTestGitRepo(t)
	session := NewSession(root, "provider", "model", "", "default")
	session.LastReviewRun = &ReviewRun{
		ID:            "review-blocked",
		SchemaVersion: reviewSchemaVersion,
		Target:        reviewTargetChange,
		Mode:          reviewModeGeneralChange,
		Branch:        delegationGitBranch(root),
		Gate: GateDecision{
			Verdict:          reviewVerdictNeedsRevision,
			BlockingFindings: []string{"RF-001"},
		},
		Findings: []ReviewFinding{{
			ID:         "RF-001",
			Severity:   reviewSeverityBlocker,
			Title:      "blocking review finding",
			BlocksGate: true,
		}},
	}
	rt := &runtimeState{
		session: session,
		workspace: Workspace{
			BaseRoot: root,
			Root:     root,
		},
	}

	artifact := rt.buildCompletionAuditArtifact(root, "finish guarded work")

	if artifact.RuntimeGateLedger == nil {
		t.Fatalf("expected runtime gate ledger in completion audit")
	}
	if artifact.RuntimeGateLedger.Status != runtimeGateStatusBlocked {
		t.Fatalf("expected blocked runtime gate ledger, got %#v", artifact.RuntimeGateLedger)
	}
	item, ok := completionAuditChecklistItem(artifact, "Runtime gate ledger is blocker-free")
	if !ok || item.Status != completionAuditStatusBlocked {
		t.Fatalf("expected blocked runtime gate checklist item, got %#v ok=%t", item, ok)
	}
}

func TestRuntimeGateFeedbackBlocksGitWriteOnReviewBlocker(t *testing.T) {
	root := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("updated\n"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	session := NewSession(root, "provider", "model", "", "default")
	session.LastReviewRun = &ReviewRun{
		ID:            "review-blocker",
		SchemaVersion: reviewSchemaVersion,
		Target:        reviewTargetChange,
		Mode:          reviewModeGeneralChange,
		Branch:        delegationGitBranch(root),
		ChangeSet: ReviewChangeSet{
			ChangedPaths: []string{"README.md"},
		},
		Gate: GateDecision{
			Verdict:          reviewVerdictNeedsRevision,
			BlockingFindings: []string{"RF-001"},
		},
	}
	agent := &Agent{
		Workspace: Workspace{BaseRoot: root, Root: root},
		Session:   session,
	}

	blocked, feedback := agent.runtimeGateFeedbackForAction(runtimeGateActionGitWrite)

	if !blocked {
		t.Fatalf("expected git write to be blocked")
	}
	if !strings.Contains(feedback, "RF-001") || session.RuntimeGateLedger == nil {
		t.Fatalf("expected feedback and session ledger to include review blocker, got %q %#v", feedback, session.RuntimeGateLedger)
	}
}

func TestRuntimeGateStatusOutputShowsRecoveryCommand(t *testing.T) {
	root := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	session := NewSession(root, "provider", "model", "", "default")
	var output bytes.Buffer
	rt := &runtimeState{
		writer:  &output,
		ui:      NewUI(),
		session: session,
		workspace: Workspace{
			BaseRoot: root,
			Root:     root,
		},
	}

	rt.printRuntimeGateStatus(runtimeGateActionFinalAnswer)

	text := output.String()
	for _, want := range []string{"Runtime Gate", "runtime_gate", runtimeGateStatusNeedsReview, "review_freshness", "missing", "next_command", "/review"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected status output to contain %q, got %q", want, text)
		}
	}
	if session.RuntimeGateLedger == nil || session.RuntimeGateLedger.Status != runtimeGateStatusNeedsReview {
		t.Fatalf("expected session runtime gate ledger to be refreshed, got %#v", session.RuntimeGateLedger)
	}
}

func TestHooksStatusIncludesRuntimeGateSummary(t *testing.T) {
	root := initTestGitRepo(t)
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	session := NewSession(root, "provider", "model", "", "default")
	var output bytes.Buffer
	rt := &runtimeState{
		writer:  &output,
		ui:      NewUI(),
		session: session,
		workspace: Workspace{
			BaseRoot: root,
			Root:     root,
		},
	}

	rt.handleHooksCommand()

	text := output.String()
	for _, want := range []string{"Hooks", "runtime_gate", runtimeGateStatusNeedsReview, "review_freshness", "missing", "No hook rules loaded."} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected hooks output to contain %q, got %q", want, text)
		}
	}
}

func TestRuntimeGateSummaryTreatsEmptyLedgerAsUnknown(t *testing.T) {
	if got := runtimeGateStatusSummary(RuntimeGateLedger{}); got != "unknown" {
		t.Fatalf("expected empty ledger summary to be unknown, got %q", got)
	}
	if got := runtimeGateReviewFreshnessLabel(RuntimeGateLedger{}); got != "unknown" {
		t.Fatalf("expected empty ledger review freshness to be unknown, got %q", got)
	}
}
