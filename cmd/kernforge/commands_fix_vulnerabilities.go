package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type fixVulnerabilitiesOptions struct {
	ProjectName   string
	Severity      string
	Max           int
	DryRun        bool
	NoTest        bool
	Advise        bool
	MaxIterations int
}

var fixVulnerabilitiesSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
}

// parseFixVulnerabilitiesArgs parses the /fix-vulnerabilities command line.
// Defaults: Severity=HIGH, Max=0 (no cap), MaxIterations=-1 (caller picks a
// default per run mode). The first non-flag token is the optional project name.
func parseFixVulnerabilitiesArgs(args string) (fixVulnerabilitiesOptions, error) {
	opts := fixVulnerabilitiesOptions{
		Severity:      "HIGH",
		Max:           0,
		Advise:        true,
		MaxIterations: -1,
	}
	for _, field := range splitAnalysisCommandLine(strings.TrimSpace(args)) {
		switch {
		case field == "--dry-run":
			opts.DryRun = true
		case field == "--no-test":
			opts.NoTest = true
		case field == "--no-advise":
			opts.Advise = false
		case strings.HasPrefix(field, "--severity="):
			value := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(field, "--severity=")))
			if !fixVulnerabilitiesSeverities[value] {
				return opts, fmt.Errorf("invalid --severity %q (want CRITICAL, HIGH, MEDIUM, or LOW)", value)
			}
			opts.Severity = value
		case strings.HasPrefix(field, "--max="):
			value, err := parseNonNegativeInt(strings.TrimPrefix(field, "--max="))
			if err != nil {
				return opts, fmt.Errorf("invalid --max: %v", err)
			}
			opts.Max = value
		case strings.HasPrefix(field, "--max-iterations="):
			value, err := parseNonNegativeInt(strings.TrimPrefix(field, "--max-iterations="))
			if err != nil {
				return opts, fmt.Errorf("invalid --max-iterations: %v", err)
			}
			opts.MaxIterations = value
		case strings.HasPrefix(field, "--"):
			return opts, fmt.Errorf("unknown flag %q", field)
		default:
			if opts.ProjectName == "" {
				opts.ProjectName = field
				continue
			}
			return opts, fmt.Errorf("unexpected argument %q (project name already set to %q)", field, opts.ProjectName)
		}
	}
	return opts, nil
}

func parseNonNegativeInt(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("missing value")
	}
	value := 0
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a non-negative integer: %q", trimmed)
		}
		value = value*10 + int(r-'0')
	}
	return value, nil
}

// resolveDtrackProjectName returns the explicit name if given, otherwise the
// workspace directory base name (the agent reconciles against dtrack_list_projects).
func (rt *runtimeState) resolveDtrackProjectName(explicit string) string {
	if name := strings.TrimSpace(explicit); name != "" {
		return name
	}
	root := strings.TrimSpace(rt.workspace.Root)
	if root == "" {
		root = strings.TrimSpace(rt.workspace.BaseRoot)
	}
	if root == "" {
		return ""
	}
	return filepath.Base(root)
}

// buildFixVulnerabilitiesObjective renders the autonomous goal objective that
// drives scan -> manifest edit -> test -> re-scan, with hard rules the
// non-bypassable guard also enforces.
func buildFixVulnerabilitiesObjective(opts fixVulnerabilitiesOptions, projectName string) string {
	maxClause := "no limit"
	if opts.Max > 0 {
		maxClause = fmt.Sprintf("%d", opts.Max)
	}

	var b strings.Builder
	fmt.Fprintln(&b, "Remediate vulnerable dependencies in this workspace using the Dependency-Track MCP server, with LLM-assisted manifest edits verified by tests.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Target Dependency-Track project: %q (if this name does not exist, call mcp__dependency-track__dtrack_list_projects, pick the closest match for this workspace; if none is clear, stop and report the candidate names).\n", projectName)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Scope: only attempt findings with severity >= %s; attempt at most %s findings this run.\n", opts.Severity, maxClause)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Hard rules (never violate): NEVER run any git command that changes state (no reset, clean, checkout, restore, revert, rm, stash, commit, merge, rebase, pull, push, branch deletion). Git is read-only at most (status/diff/log). NEVER edit application source files; edit ONLY the dependency manifests/lockfiles listed below. If a fix seems to require touching source or git, stop and report it as not auto-fixable instead. (These rules are also enforced by a non-bypassable guard; violating attempts will be denied.)")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Step 0 - Preconditions: confirm mcp__dependency-track__* tools are callable; if not, stop and report the server is unavailable.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Step 1 - Enumerate: call mcp__dependency-track__dtrack_get_findings (and mcp__dependency-track__dtrack_get_component_remediation per component) to build {component, currentVersion, fixedVersion, CVE, severity, direct-or-transitive}. Skip findings with no fixed version.")
	fmt.Fprintln(&b)

	if opts.DryRun {
		fmt.Fprintln(&b, "Step 2 - Plan only (dry run): produce a per-finding remediation plan (component, current->fixed, manifest file, direct/transitive, override needed). Do NOT call apply_edit_proposal, do NOT install or regenerate lockfiles, and do NOT re-submit to Dependency-Track.")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Completion: complete when the remediation plan has been reported for every targeted finding.")
		return b.String()
	}

	if opts.Advise {
		fmt.Fprintln(&b, "Step 1.5 - Advisory (before editing anything): for every finding you intend to fix, first reason about and report the planned change. For each one state: the manifest file you will edit, the exact version change (current -> fixed), whether the dependency is direct or transitive, whether an override/resolution block is required, and the risk of the bump (e.g. patch vs breaking major-version jump). Present this advisory plan as a short list, then proceed to apply the changes one finding at a time. Do not edit any file before its advisory line has been produced.")
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "Step 2 - Per finding, in isolation (one finding per change):")
	fmt.Fprintln(&b, "- Edit ONLY dependency manifests/lockfiles to the fixed version via the apply_edit_proposal tool. Allowed files: package.json, package-lock.json, pnpm-lock.yaml, yarn.lock, go.mod, go.sum, pom.xml, build.gradle, *.csproj, packages.lock.json. Never modify application source to satisfy a dependency bump.")
	fmt.Fprintln(&b, "- If the vulnerable component is TRANSITIVE, do not edit it directly; add the correct override (npm \"overrides\" / yarn \"resolutions\" / pnpm \"overrides\") or, for Go, bump the indirect requirement, then regenerate the lockfile (npm install / go mod tidy / equivalent).")
	if opts.NoTest {
		fmt.Fprintln(&b, "- Run a build/compile only; do not run the full test suite. Note that results are less strongly verified.")
	} else {
		fmt.Fprintln(&b, "- Run the project's tests. If there is no test suite, run a build/compile instead and mark the fix applied-but-unverified.")
	}
	fmt.Fprintln(&b, "- If tests/build FAIL, roll back this single change (restore the checkpoint) before the next finding, and record it as \"not auto-fixable: <reason>\" (e.g. breaking major-version bump).")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Step 3 - Re-scan to confirm: re-submit via mcp__dependency-track__dtrack_submit_project (or dtrack_upload_bom), allow async processing, call mcp__dependency-track__dtrack_get_findings again, confirm each fixed CVE/component is gone and mcp__dependency-track__dtrack_get_project_metrics counts dropped. Report the before/after findings count.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Completion: complete only when every targeted finding is either cleared on re-scan or explicitly recorded as not-auto-fixable. Do not declare success on an unchanged findings count.")
	return b.String()
}

func fixVulnerabilitiesUsage() string {
	return strings.Join([]string{
		"/fix-vulnerabilities [project-name] [--severity=HIGH] [--max=N] [--dry-run] [--no-test] [--no-advise] [--max-iterations=N]",
		"Use LLM assistance to bump vulnerable dependencies to fixed versions, run tests,",
		"and re-scan via the Dependency-Track MCP server to confirm findings clear.",
		"By default the model reports its planned change per finding before editing (advisor); use --no-advise to skip.",
		"Destructive git is blocked and writes are restricted to dependency manifests for the whole run.",
	}, "\n")
}

func (rt *runtimeState) handleFixVulnerabilitiesCommand(args string) error {
	opts, err := parseFixVulnerabilitiesArgs(args)
	if err != nil {
		fmt.Fprintln(rt.writer, rt.ui.section("Fix Vulnerabilities"))
		fmt.Fprintln(rt.writer, rt.ui.hintLine(err.Error()))
		fmt.Fprintln(rt.writer, rt.ui.hintLine(fixVulnerabilitiesUsage()))
		return nil
	}

	if rt.agent == nil || rt.agent.Client == nil {
		return fmt.Errorf("no model provider is configured")
	}
	if err := rt.requirePersistedGoalState(); err != nil {
		return err
	}
	if rt.fixVulnGuard == nil {
		return fmt.Errorf("fix-vulnerabilities safety guard is unavailable; refusing to run unguarded")
	}

	projectName := rt.resolveDtrackProjectName(opts.ProjectName)

	maxIterations := opts.MaxIterations
	if maxIterations < 0 {
		// Interactive sessions default to until-complete; one-shot/non-interactive
		// runs get a bounded default so they cannot loop unattended forever.
		if rt.interactive {
			maxIterations = defaultGoalMaxIterations
		} else {
			maxIterations = 12
		}
	}

	testMode := "tests"
	if opts.NoTest {
		testMode = "build-only"
	}
	maxLabel := "no limit"
	if opts.Max > 0 {
		maxLabel = fmt.Sprintf("%d", opts.Max)
	}

	fmt.Fprintln(rt.writer, rt.ui.section("Fix Vulnerabilities"))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("workspace", rt.session.WorkingDir))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("dtrack_project", projectName))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("severity_floor", opts.Severity))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("max_findings", maxLabel))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("mode", map[bool]string{true: "dry-run", false: "apply"}[opts.DryRun]))
	if !opts.DryRun {
		fmt.Fprintln(rt.writer, rt.ui.statusKV("advisor", map[bool]string{true: "on (plan reported before each edit)", false: "off"}[opts.Advise]))
	}
	fmt.Fprintln(rt.writer, rt.ui.statusKV("verification", testMode))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("safety", "git mutations blocked; writes limited to dependency manifests"))

	// Activate the non-bypassable safety guard for the entire run, even though the
	// autonomous loop enables ModeBypass. Deactivate on return.
	rt.fixVulnGuard.SetActive(true)
	defer rt.fixVulnGuard.SetActive(false)

	// Mandatory checkpoint before any agent action. Checkpoints live outside the
	// working tree, so recovery is guaranteed independent of git.
	if !opts.DryRun && rt.checkpoints != nil {
		if meta, err := rt.checkpoints.Create(workspaceCheckpointRoot(rt.workspace), "fix-vulnerabilities"); err != nil {
			return fmt.Errorf("failed to create safety checkpoint before fixing vulnerabilities: %w", err)
		} else {
			fmt.Fprintln(rt.writer, rt.ui.statusKV("checkpoint", meta.ID))
		}
	}

	objective := buildFixVulnerabilitiesObjective(opts, projectName)

	now := time.Now()
	goal := GoalState{
		ID:            fmt.Sprintf("goal-%s-%03d", now.Format("20060102-150405"), now.Nanosecond()/1_000_000),
		Objective:     strings.TrimSpace(objective),
		Status:        goalStatusPending,
		MaxIterations: maxIterations,
		AutoRollback:  true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	goal.Normalize()
	rt.primeGoalRuntimeState(&goal, "created")
	goal.updateUsageTelemetry(rt.session)
	rt.session.UpsertGoal(goal)
	rt.session.AppendConversationEvent(ConversationEvent{
		Kind:     conversationEventKindGoal,
		Severity: conversationSeverityInfo,
		Summary:  "fix-vulnerabilities goal created: " + compactPromptSection(goal.Objective, 120),
		Entities: map[string]string{
			"goal":   goal.ID,
			"status": goal.Status,
		},
	})
	if err := rt.writeGoalArtifacts(goal); err != nil {
		return err
	}
	if rt.store != nil {
		if err := rt.store.Save(rt.session); err != nil {
			return err
		}
	}
	fmt.Fprintln(rt.writer, rt.ui.successLine("Created fix-vulnerabilities goal: "+goal.ID))

	return rt.runGoalBySelector(goal.ID, maxIterations)
}
