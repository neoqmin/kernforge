package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCodexAppParityScenarioFixturesCoverSingleAndCrossModelLifecycles(t *testing.T) {
	scenarios := []struct {
		name      string
		class     string
		kind      string
		trigger   string
		target    string
		request   string
		mixed     bool
		secondary []string
	}{
		{
			name:    "document artifact",
			class:   reviewRequestClassDocumentArtifact,
			kind:    reviewLifecycleKindDocumentArtifact,
			target:  reviewTargetAnalysis,
			request: "write docs/report.md as a document artifact",
		},
		{
			name:    "review only",
			class:   reviewRequestClassReviewOnly,
			kind:    reviewLifecycleKindReviewOnly,
			target:  reviewTargetChange,
			request: "review main.go without editing",
		},
		{
			name:    "implementation",
			class:   reviewRequestClassModifyThenReview,
			kind:    reviewLifecycleKindImplementation,
			target:  reviewTargetChange,
			request: "implement startup validation in main.go",
		},
		{
			name:    "modify then review",
			class:   reviewRequestClassModifyThenReview,
			kind:    reviewLifecycleKindModifyThenReview,
			trigger: "post_change",
			target:  reviewTargetChange,
			request: "fix main.go and review the applied change",
		},
		{
			name:    "fix from review",
			class:   reviewRequestClassReviewThenModify,
			kind:    reviewLifecycleKindFixFromReview,
			trigger: reviewBeforeFixTrigger,
			target:  reviewTargetChange,
			request: "review main.go and fix confirmed findings",
		},
		{
			name:    "analysis",
			class:   reviewRequestClassGeneral,
			kind:    reviewLifecycleKindAnalysis,
			target:  reviewTargetAnalysis,
			request: "analyze the project architecture and explain the request flow",
		},
		{
			name:      "mixed flow",
			class:     reviewRequestClassModifyThenReview,
			kind:      reviewLifecycleKindMixedFlow,
			target:    reviewTargetChange,
			request:   "fix main.go, review the result, and write docs/review_report.md",
			mixed:     true,
			secondary: []string{reviewRequestClassDocumentArtifact, reviewRequestClassReviewOnly},
		},
	}

	for _, scenario := range scenarios {
		for _, routeMode := range []string{reviewRouteModeSingleModel, reviewRouteModeCrossModel} {
			t.Run(strings.ReplaceAll(scenario.name+"_"+routeMode, " ", "_"), func(t *testing.T) {
				run := codexAppParityScenarioRun(t, scenario.class, scenario.kind, scenario.trigger, scenario.target, scenario.request, routeMode, scenario.mixed, scenario.secondary)
				if run.Lifecycle == nil {
					t.Fatalf("expected lifecycle")
				}
				if run.Lifecycle.LifecycleKind != scenario.kind {
					t.Fatalf("lifecycle kind = %q, want %q; lifecycle=%#v", run.Lifecycle.LifecycleKind, scenario.kind, run.Lifecycle)
				}
				if normalizeReviewRequestClass(scenario.class) != reviewRequestClassGeneral && run.Lifecycle.RequestClass != scenario.class {
					t.Fatalf("request class = %q, want %q; lifecycle=%#v", run.Lifecycle.RequestClass, scenario.class, run.Lifecycle)
				}
				if run.Lifecycle.RouteMode != routeMode {
					t.Fatalf("route mode = %q, want %q; lifecycle=%#v", run.Lifecycle.RouteMode, routeMode, run.Lifecycle)
				}
				if scenario.mixed && !run.Lifecycle.MixedFlow {
					t.Fatalf("expected mixed flow lifecycle, got %#v", run.Lifecycle)
				}

				mcp := renderReviewMCPResponse(run, 60000)
				markdown := renderReviewRunMarkdown(run)
				for _, want := range []string{
					`"lifecycle_timeline"`,
					`"compact_status"`,
					`"blocker_summary"`,
					`"route_quality"`,
					`"final_answer_contract_status"`,
					`"stale_context_summary"`,
					`"next_recommended_command"`,
				} {
					if !strings.Contains(mcp, want) {
						t.Fatalf("expected MCP response to contain %q, got:\n%s", want, mcp)
					}
				}
				for _, want := range []string{"Request Lifecycle", "Compact Operator Status", "Lifecycle Timeline", "Stale Context Summary"} {
					if !strings.Contains(markdown, want) {
						t.Fatalf("expected markdown to contain %q, got:\n%s", want, markdown)
					}
				}
			})
		}
	}
}

func TestOptionalRealProviderSmokePathSkipsWithoutConfig(t *testing.T) {
	if os.Getenv("KERNFORGE_REAL_PROVIDER_SMOKE") != "1" {
		t.Skip("skipped real-provider smoke: set KERNFORGE_REAL_PROVIDER_SMOKE=1 with KERNFORGE_REAL_PROVIDER and KERNFORGE_REAL_MODEL to run it")
	}
	provider := strings.TrimSpace(os.Getenv("KERNFORGE_REAL_PROVIDER"))
	model := strings.TrimSpace(os.Getenv("KERNFORGE_REAL_MODEL"))
	if provider == "" || model == "" {
		t.Skip("skipped real-provider smoke: provider/model config is unavailable")
	}
	root := t.TempDir()
	cfg := DefaultConfig(root)
	cfg.Provider = provider
	cfg.Model = model
	cfg.BaseURL = strings.TrimSpace(os.Getenv("KERNFORGE_REAL_BASE_URL"))
	cfg.APIKey = strings.TrimSpace(os.Getenv("KERNFORGE_REAL_API_KEY"))
	if _, err := NewProviderClient(cfg); err != nil {
		t.Skipf("skipped real-provider smoke: provider config unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	report, err := runOptionalRealProviderSmokeDrill(ctx, root, cfg)
	if err != nil {
		t.Fatalf("real-provider smoke failed: %v", err)
	}
	if report.Status != liveProviderDrillStatusPassed || len(report.Turns) == 0 || report.FinalGateStatus != runtimeGateStatusReady {
		t.Fatalf("unexpected real-provider smoke drill report: %#v", report)
	}
	rendered := renderLiveProviderDrillMarkdown(&report)
	if !strings.Contains(rendered, "real-provider smoke completed") || !strings.Contains(rendered, "latency_ms") {
		t.Fatalf("expected real-provider smoke drill artifact, got:\n%s", rendered)
	}
}

func codexAppParityScenarioRun(t *testing.T, class string, kind string, trigger string, target string, request string, routeMode string, mixed bool, secondary []string) ReviewRun {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	run := ReviewRun{
		ID:            "scenario-" + strings.ReplaceAll(kind+"-"+routeMode, "_", "-"),
		SchemaVersion: reviewSchemaVersion,
		Trigger:       firstNonBlankString(trigger, naturalReviewTrigger),
		Target:        target,
		Mode:          reviewModeGeneralChange,
		RequestClass:  class,
		RequestAnalysis: ReviewRequestAnalysis{
			OriginalRequest:         request,
			RequestClass:            class,
			LifecycleKind:           kind,
			MixedFlow:               mixed,
			SecondaryRequestClasses: secondary,
			RequestClassReason:      "deterministic Codex App parity scenario fixture",
			RequestClassConfidence:  0.95,
		},
		CreatedAt: time.Now(),
		Workspace: root,
		Branch:    delegationGitBranch(root),
		ChangeSet: ReviewChangeSet{
			ChangedPaths: []string{"main.go"},
		},
		Evidence: ReviewEvidencePack{
			Sources:             []string{"scenario_fixture", "frozen_diff", "self_review"},
			Text:                "scenario fixture includes frozen evidence, touched-path regression review, and verification disclosure hooks",
			ChangedPaths:        []string{"main.go"},
			VerificationSummary: "scenario verification was not run; deterministic fixture records the skip",
		},
		Gate: GateDecision{
			Verdict: reviewVerdictApproved,
			Action:  reviewGateActionFinalSummary,
			Reason:  "scenario fixture accepted",
			NextCommands: []ReviewNextCommand{{
				ID:      "status-detail",
				Command: "/status detail",
				Reason:  "inspect the lifecycle timeline",
				Safety:  "read_only",
			}},
		},
		Result: ReviewResult{
			Verdict:      reviewVerdictApproved,
			Summary:      "scenario fixture accepted",
			ModelQuality: reviewModelQualityUsable,
		},
	}
	if normalizeReviewRequestClass(class) == reviewRequestClassDocumentArtifact {
		run.ChangeSet.ChangedPaths = []string{"docs/report.md"}
		run.Evidence.ChangedPaths = []string{"docs/report.md"}
	}
	if routeMode == reviewRouteModeSingleModel {
		run.SingleModelPolicy = SingleModelReviewPolicy{
			Enabled:             true,
			IndependenceLevel:   "single_model",
			NoCrossReviewReason: "single_model_mode",
		}
		run.SingleModelSecondPass = &SingleModelSecondPassReview{
			Enabled:       true,
			Status:        "completed",
			Model:         "scripted/main-model",
			ReviewedPaths: append([]string(nil), run.ChangeSet.ChangedPaths...),
		}
		run.ReviewerRuns = []ReviewReviewerRun{{
			Role:         "primary_reviewer",
			Kind:         "main",
			Status:       "completed",
			Model:        "scripted/main-model",
			ModelQuality: reviewModelQualityUsable,
		}}
	} else {
		run.ReviewerRuns = []ReviewReviewerRun{{
			Role:         "primary_reviewer",
			Kind:         "main",
			Status:       "completed",
			Model:        "scripted/main-model",
			ModelQuality: reviewModelQualityUsable,
		}, {
			Role:         "cross_reviewer",
			Kind:         "cross",
			Status:       "completed",
			Model:        "scripted/cross-model",
			ModelQuality: reviewModelQualityUsable,
		}}
	}
	run.Lifecycle = buildReviewRequestLifecycle(&run, nil)
	run.RuntimeGateLedger = RuntimeGateLedger{
		ID:           "runtime-gate-" + run.ID,
		Action:       runtimeGateActionFinalAnswer,
		Status:       runtimeGateStatusReady,
		Ready:        true,
		RequestClass: run.RequestClass,
		Lifecycle:    run.Lifecycle,
		ChangedPaths: append([]string(nil), run.ChangeSet.ChangedPaths...),
		ReviewRunID:  run.ID,
		NextCommands: append([]ReviewNextCommand(nil), run.Gate.NextCommands...),
	}
	run.RuntimeGateLedger.StaleContextSummary = buildStaleContextSummary(nil, &run, &run.RuntimeGateLedger, nil)
	run.DecisionObservability = buildReviewDecisionObservability(&run, &run.RuntimeGateLedger, nil)
	return run
}
