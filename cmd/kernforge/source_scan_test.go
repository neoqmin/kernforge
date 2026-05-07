package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSourceScanBuiltInMatchersDetectKernelUnrealAndTelemetrySignals(t *testing.T) {
	root := t.TempDir()
	driverPath := filepath.Join(root, "driver", "dispatch.cpp")
	if err := os.MkdirAll(filepath.Dir(driverPath), 0o755); err != nil {
		t.Fatalf("mkdir driver: %v", err)
	}
	driverSource := `
#define METHOD_NEITHER 3
NTSTATUS DispatchIoctl(void *Type3InputBuffer, size_t InputBufferLength)
{
    ULONG IoControlCode = 0;
    switch (IoControlCode)
    {
    case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS):
        ProbeForRead(Type3InputBuffer, InputBufferLength, 1);
        if (InputBufferLength < sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(g_Buffer, Type3InputBuffer, g_State.Size);
        void *Pool = ExAllocatePool(NonPagedPoolNx, InputBufferLength * sizeof(ULONG));
        RtlCopyMemory(Pool, Type3InputBuffer, InputBufferLength);
        Irp->IoStatus.Information = OutputBufferLength;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, Pool, OutputBufferLength);
        WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &InputBuffer, &BufferSize);
        WdfMemoryCopyFromBuffer(Memory, 0, InputBuffer, BufferSize);
        ObReferenceObject(TargetProcess);
        ExFreePool(Pool);
        ObDereferenceObject(TargetProcess);
        PAGED_CODE();
        if (KeGetCurrentIrql() == DISPATCH_LEVEL)
        {
            KeAcquireSpinLock(&g_Lock, &g_Irql);
        }
        ObRegisterCallbacks(&g_Registration, &g_Handle);
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
        PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
        g_ProcessStateList.PushBack(ProcessId);
        FltRegisterFilter(DriverObject, &FilterRegistration, &g_Filter);
        PFLT_CALLBACK_DATA Data = NULL;
        FltSetStreamContext(instance, stream, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL);
        FltReleaseContext(context);
        EventWriteGuardDecision(provider, buffer);
        recv(socket, buffer, sizeof(buffer), 0);
        ParseTelemetry(buffer, InputBufferLength);
        break;
    }
    return STATUS_SUCCESS;
}
`
	if err := os.WriteFile(driverPath, []byte(driverSource), 0o644); err != nil {
		t.Fatalf("write driver: %v", err)
	}
	unrealPath := filepath.Join(root, "Source", "Guard", "GuardActor.h")
	if err := os.MkdirAll(filepath.Dir(unrealPath), 0o755); err != nil {
		t.Fatalf("mkdir unreal: %v", err)
	}
	unrealSource := `
UCLASS()
class AGuardActor : public AActor
{
    GENERATED_BODY()
    UFUNCTION(Server, Reliable)
    void ServerSubmitTelemetry(const TArray<uint8>& Payload);
};
`
	if err := os.WriteFile(unrealPath, []byte(unrealSource), 0o644); err != nil {
		t.Fatalf("write unreal: %v", err)
	}
	index := SemanticIndexV2{
		RunID:       "run-source-scan",
		Goal:        "ioctl ufunction telemetry source scan",
		Root:        root,
		GeneratedAt: time.Now(),
		Files: []FileRecord{
			{Path: "driver/dispatch.cpp", Extension: ".cpp", Language: "cpp"},
			{Path: "Source/Guard/GuardActor.h", Extension: ".h", Language: "cpp"},
		},
		Symbols: []SymbolRecord{
			{ID: "func:DispatchIoctl", Name: "DispatchIoctl", Kind: "function", Language: "cpp", File: "driver/dispatch.cpp", Signature: "NTSTATUS DispatchIoctl(void *Type3InputBuffer, size_t InputBufferLength)", StartLine: 3, EndLine: 35, Tags: []string{"ioctl"}},
			{ID: "func:ServerSubmitTelemetry", Name: "ServerSubmitTelemetry", Kind: "method", Language: "cpp", File: "Source/Guard/GuardActor.h", Signature: "void ServerSubmitTelemetry(const TArray<uint8>& Payload)", StartLine: 2, EndLine: 8, Tags: []string{"rpc"}},
		},
	}
	candidates := buildSourceScanCandidates(root, "source-scan-test", index, SourceScanOptions{})
	slugs := map[string]bool{}
	for _, candidate := range candidates {
		slugs[candidate.MatcherSlug] = true
	}
	for _, want := range []string{
		"windows-kernel-method-neither-user-buffer",
		"ioctl-dispatch-selector",
		"probe-copy-size-drift",
		"size-contract-drift",
		"irql-paged-memory",
		"object-callback-handle-access",
		"process-notify-lifetime-race",
		"minifilter-context-cleanup",
		"double-fetch-user-buffer",
		"ioctl-output-infoleak",
		"wdf-request-buffer-size-drift",
		"integer-overflow-allocation",
		"pool-lifetime-refcount",
		"unreal-rpc-trust-boundary",
		"telemetry-parser-untrusted-buffer",
	} {
		if !slugs[want] {
			t.Fatalf("missing matcher %s in candidates: %#v", want, slugs)
		}
	}
}

func TestSourceScanCandidatesCarryEvidenceAndStayInsideFunctionWindow(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "driver", "window.cpp")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatalf("mkdir driver: %v", err)
	}
	source := strings.Join([]string{
		"void SafeHelper(void)",
		"{",
		"    LogOnly();",
		"}",
		"NTSTATUS Vulnerable(void *UserBuffer, size_t InputBufferLength)",
		"{",
		"    ProbeForRead(UserBuffer, InputBufferLength, 1);",
		"    if (InputBufferLength < sizeof(ULONG))",
		"    {",
		"        return STATUS_INVALID_PARAMETER;",
		"    }",
		"    RtlCopyMemory(g_Buffer, UserBuffer, InputBufferLength);",
		"    return STATUS_SUCCESS;",
		"}",
	}, "\n")
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	index := SemanticIndexV2{
		RunID: "run-window",
		Root:  root,
		Files: []FileRecord{{Path: "driver/window.cpp", Extension: ".cpp", Language: "cpp"}},
		Symbols: []SymbolRecord{
			{ID: "func:SafeHelper", Name: "SafeHelper", Kind: "function", Language: "cpp", File: "driver/window.cpp", Signature: "void SafeHelper(void)", StartLine: 1, EndLine: 4},
			{ID: "func:Vulnerable", Name: "Vulnerable", Kind: "function", Language: "cpp", File: "driver/window.cpp", Signature: "NTSTATUS Vulnerable(void *UserBuffer, size_t InputBufferLength)", StartLine: 5, EndLine: 14},
		},
	}
	candidates := buildSourceScanCandidates(root, "source-window", index, SourceScanOptions{OnlySlugs: []string{"probe-copy-size-drift"}})
	if len(candidates) == 0 {
		t.Fatalf("expected candidate")
	}
	for _, candidate := range candidates {
		if candidate.SymbolName != "Vulnerable" {
			t.Fatalf("candidate escaped function window: %+v", candidate)
		}
		if candidate.FileContentHash == "" || candidate.SymbolSignatureHash == "" {
			t.Fatalf("expected candidate fingerprints: %+v", candidate)
		}
		if len(candidate.EvidenceSpans) == 0 || len(candidate.DataflowFacts) == 0 || len(candidate.ControlflowFacts) == 0 {
			t.Fatalf("expected evidence facts: %+v", candidate)
		}
	}
}

func TestSourceCandidateLinksToFunctionFuzzAndNeedsNativeRevalidation(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:          "sc-test",
		Workspace:   "C:/repo",
		MatcherSlug: "probe-copy-size-drift",
		NoiseTier:   "precise",
		File:        "driver/dispatch.cpp",
		Score:       90,
	}
	run := FunctionFuzzRun{
		ID:                "fuzz-test",
		Workspace:         "C:/repo",
		SourceCandidateID: "sc-test",
		TargetSymbolName:  "DispatchIoctl",
		TargetFile:        "driver/dispatch.cpp",
		ReportPath:        "C:/repo/.kernforge/fuzz/fuzz-test/report.md",
		VirtualScenarios: []FunctionFuzzVirtualScenario{{
			Title:        "short buffer reaches copy sink",
			ExpectedFlow: "short Type3InputBuffer drives RtlCopyMemory",
		}},
	}
	linked := linkSourceCandidateToFunctionFuzz(candidate, run)
	if linked.Status != "needs-native" {
		t.Fatalf("expected needs-native, got %q", linked.Status)
	}
	if !containsString(linked.LinkedFuzzRunIDs, "fuzz-test") {
		t.Fatalf("expected linked fuzz run, got %#v", linked.LinkedFuzzRunIDs)
	}
	if len(linked.RevalidationHistory) == 0 || linked.RevalidationHistory[len(linked.RevalidationHistory)-1].Verdict != "needs-native" {
		t.Fatalf("expected needs-native revalidation, got %#v", linked.RevalidationHistory)
	}
}

func TestSourceCandidateFunctionFuzzLinkIsIdempotentAcrossUpserts(t *testing.T) {
	root := t.TempDir()
	store := &SourceScanStore{Path: filepath.Join(root, "source_scan.json")}
	candidate := SourceCandidateRecord{
		ID:          "sc-idempotent",
		Workspace:   root,
		MatcherSlug: "probe-copy-size-drift",
		NoiseTier:   "precise",
		File:        "driver/dispatch.cpp",
		Score:       90,
	}
	if _, err := store.UpsertCandidate(candidate); err != nil {
		t.Fatalf("upsert initial candidate: %v", err)
	}
	run := FunctionFuzzRun{
		ID:                "fuzz-idempotent",
		Workspace:         root,
		AnalysisRunID:     "analysis-idempotent",
		SourceCandidateID: "sc-idempotent",
		TargetSymbolName:  "DispatchIoctl",
		TargetFile:        "driver/dispatch.cpp",
		ReportPath:        filepath.Join(root, ".kernforge", "fuzz", "fuzz-idempotent", "report.md"),
		PlanPath:          filepath.Join(root, ".kernforge", "fuzz", "fuzz-idempotent", "plan.json"),
		HarnessPath:       filepath.Join(root, ".kernforge", "fuzz", "fuzz-idempotent", "harness.cpp"),
		VirtualScenarios: []FunctionFuzzVirtualScenario{{
			Title: "short buffer reaches copy sink",
		}},
	}
	loaded, ok, err := store.GetCandidate("sc-idempotent")
	if err != nil || !ok {
		t.Fatalf("get candidate before link: ok=%v err=%v", ok, err)
	}
	linked := linkSourceCandidateToFunctionFuzz(loaded, run)
	if _, err := store.UpsertCandidate(linked); err != nil {
		t.Fatalf("upsert first link: %v", err)
	}
	loaded, ok, err = store.GetCandidate("sc-idempotent")
	if err != nil || !ok {
		t.Fatalf("get candidate after first link: ok=%v err=%v", ok, err)
	}
	linked = linkSourceCandidateToFunctionFuzz(loaded, run)
	if _, err := store.UpsertCandidate(linked); err != nil {
		t.Fatalf("upsert second link: %v", err)
	}
	loaded, ok, err = store.GetCandidate("sc-idempotent")
	if err != nil || !ok {
		t.Fatalf("get candidate after second link: ok=%v err=%v", ok, err)
	}
	if got := len(loaded.AnalysisHistory); got != 1 {
		t.Fatalf("expected one analysis history entry, got %d: %#v", got, loaded.AnalysisHistory)
	}
	if got := len(loaded.RevalidationHistory); got != 1 {
		t.Fatalf("expected one revalidation history entry, got %d: %#v", got, loaded.RevalidationHistory)
	}
	if got := len(loaded.LinkedFuzzRunIDs); got != 1 || loaded.LinkedFuzzRunIDs[0] != "fuzz-idempotent" {
		t.Fatalf("expected one linked fuzz run, got %#v", loaded.LinkedFuzzRunIDs)
	}
}

func TestSourceScanStoreLatestAndPrefixAreWorkspaceScoped(t *testing.T) {
	root := t.TempDir()
	store := &SourceScanStore{Path: filepath.Join(root, "source_scan.json")}
	workspaceA := filepath.Join(root, "repo-a")
	workspaceB := filepath.Join(root, "repo-b")
	now := time.Now()
	candidateA := SourceCandidateRecord{
		ID:          "sc-workspace-a",
		Workspace:   workspaceA,
		MatcherSlug: "probe-copy-size-drift",
		File:        "driver/a.cpp",
		SymbolName:  "TargetA",
		Score:       70,
		CreatedAt:   now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
	}
	candidateB := SourceCandidateRecord{
		ID:          "sc-workspace-b",
		Workspace:   workspaceB,
		MatcherSlug: "double-fetch-user-buffer",
		File:        "driver/b.cpp",
		SymbolName:  "TargetB",
		Score:       95,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if _, err := store.UpsertCandidate(candidateA); err != nil {
		t.Fatalf("upsert candidate A: %v", err)
	}
	if _, err := store.UpsertCandidate(candidateB); err != nil {
		t.Fatalf("upsert candidate B: %v", err)
	}
	latestA, ok, err := store.GetCandidateForWorkspace("latest", workspaceA)
	if err != nil || !ok {
		t.Fatalf("get latest workspace A: ok=%v err=%v", ok, err)
	}
	if latestA.ID != candidateA.ID {
		t.Fatalf("expected workspace A latest, got %+v", latestA)
	}
	if other, ok, err := store.GetCandidateForWorkspace("sc-workspace-b", workspaceA); err != nil || ok {
		t.Fatalf("expected workspace-scoped prefix miss, got ok=%v err=%v candidate=%+v", ok, err, other)
	}
}

func TestResolveFunctionFuzzFromCandidateLatestUsesCurrentWorkspace(t *testing.T) {
	root := t.TempDir()
	store := &SourceScanStore{Path: filepath.Join(root, "source_scan.json")}
	workspaceA := filepath.Join(root, "repo-a")
	workspaceB := filepath.Join(root, "repo-b")
	now := time.Now()
	if _, err := store.UpsertCandidate(SourceCandidateRecord{
		ID:          "sc-latest-a",
		Workspace:   workspaceA,
		MatcherSlug: "probe-copy-size-drift",
		File:        "driver/a.cpp",
		SymbolName:  "TargetA",
		Score:       70,
		CreatedAt:   now.Add(-time.Hour),
		UpdatedAt:   now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("upsert candidate A: %v", err)
	}
	if _, err := store.UpsertCandidate(SourceCandidateRecord{
		ID:          "sc-latest-b",
		Workspace:   workspaceB,
		MatcherSlug: "double-fetch-user-buffer",
		File:        "driver/b.cpp",
		SymbolName:  "TargetB",
		Score:       95,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("upsert candidate B: %v", err)
	}
	rt := &runtimeState{
		sourceScan: store,
		workspace:  Workspace{Root: workspaceA},
	}
	query, candidate, fromCandidate, err := rt.resolveFunctionFuzzSourceCandidateQuery("--from-candidate latest")
	if err != nil {
		t.Fatalf("resolve latest candidate: %v", err)
	}
	if !fromCandidate || candidate.ID != "sc-latest-a" {
		t.Fatalf("expected workspace A candidate, got from=%v candidate=%+v query=%q", fromCandidate, candidate, query)
	}
	if !strings.Contains(query, "TargetA") || strings.Contains(query, "TargetB") {
		t.Fatalf("expected TargetA query, got %q", query)
	}
}

func TestSourceCandidateEvidenceAugmentsFunctionFuzzRun(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:                 "sc-evidence",
		MatcherSlug:        "probe-copy-size-drift",
		MatcherDescription: "probe and copy operations in the same scope",
		NoiseTier:          "precise",
		File:               "driver/dispatch.cpp",
		LineNumbers:        []int{42},
		Snippet:            "42: RtlCopyMemory(g_Buffer, UserBuffer, Size);",
		MatchedPattern:     "probe/copy size drift",
		SymbolName:         "DispatchIoctl",
		SourceAnchor:       "driver/dispatch.cpp:42",
		DataflowFacts: []SourceCandidateFact{{
			Kind:   "probe_to_copy",
			Line:   42,
			Detail: "matched window contains both user-buffer probe and memory-copy sink",
		}},
		ControlflowFacts: []SourceCandidateFact{{
			Kind:   "size_guard",
			Line:   40,
			Detail: "matched window contains size guard control flow",
		}},
		EvidenceSpans: []SourceCandidateEvidenceSpan{{
			Kind:      "matcher_focus",
			File:      "driver/dispatch.cpp",
			StartLine: 42,
			EndLine:   42,
			Text:      "RtlCopyMemory(g_Buffer, UserBuffer, Size);",
		}},
	}
	run := FunctionFuzzRun{
		ID:               "fuzz-evidence",
		TargetSymbolName: "DispatchIoctl",
		TargetFile:       "driver/dispatch.cpp",
	}
	run = applySourceCandidateEvidenceToFunctionFuzzRun(run, candidate)
	if len(run.CodeObservations) < 2 {
		t.Fatalf("expected candidate observations, got %+v", run.CodeObservations)
	}
	if len(run.VirtualScenarios) == 0 || !strings.Contains(run.VirtualScenarios[0].PathHint, "source-scan") {
		t.Fatalf("expected candidate scenario, got %+v", run.VirtualScenarios)
	}
	if !containsString(run.SuggestedCommands, "/fuzz-campaign run") {
		t.Fatalf("expected campaign handoff command, got %+v", run.SuggestedCommands)
	}
}

func TestSourceCandidateFunctionFuzzLinkPreservesTerminalStatus(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:          "sc-confirmed",
		Workspace:   "C:/repo",
		Status:      "native-confirmed",
		MatcherSlug: "probe-copy-size-drift",
		File:        "driver/dispatch.cpp",
		Score:       95,
	}
	run := FunctionFuzzRun{
		ID:                "fuzz-confirmed",
		Workspace:         "C:/repo",
		SourceCandidateID: "sc-confirmed",
		TargetSymbolName:  "DispatchIoctl",
		TargetFile:        "driver/dispatch.cpp",
		VirtualScenarios: []FunctionFuzzVirtualScenario{{
			Title: "short buffer reaches copy sink",
		}},
	}
	linked := linkSourceCandidateToFunctionFuzz(candidate, run)
	if linked.Status != "native-confirmed" {
		t.Fatalf("expected terminal status to be preserved, got %q", linked.Status)
	}
}

func TestSourceCandidateRevalidationMarksChangedFingerprintStale(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "driver", "stale.cpp")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatalf("mkdir driver: %v", err)
	}
	original := "NTSTATUS Target(void *UserBuffer, size_t Size) { ProbeForRead(UserBuffer, Size, 1); RtlCopyMemory(g, UserBuffer, Size); return STATUS_SUCCESS; }"
	if err := os.WriteFile(sourcePath, []byte(original), 0o644); err != nil {
		t.Fatalf("write original: %v", err)
	}
	candidate := SourceCandidateRecord{
		ID:                  "sc-stale",
		Workspace:           root,
		MatcherSlug:         "probe-copy-size-drift",
		NoiseTier:           "precise",
		File:                "driver/stale.cpp",
		SymbolName:          "Target",
		FileContentHash:     sourceScanTextHash(original),
		SymbolSignatureHash: sourceScanSignatureHash("NTSTATUS Target(void *UserBuffer, size_t Size)"),
		Score:               90,
	}
	changed := "NTSTATUS Target(void *UserBuffer, size_t Size, ULONG Flags) { return STATUS_SUCCESS; }"
	if err := os.WriteFile(sourcePath, []byte(changed), 0o644); err != nil {
		t.Fatalf("write changed: %v", err)
	}
	rt := &runtimeState{workspace: Workspace{Root: root}}
	updated, verdict := rt.revalidateSourceCandidate(candidate, "", "")
	if verdict.Verdict != sourceCandidateStatusStale {
		t.Fatalf("expected stale verdict, got %+v", verdict)
	}
	if !updated.Stale || updated.CurrentFileHash == "" || updated.CurrentFileHash == updated.FileContentHash {
		t.Fatalf("expected stale fingerprint update: %+v", updated)
	}
}

func TestSourceCandidateNativeOutcomeCalibratesConfidence(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:          "sc-native",
		Status:      "needs-native",
		MatcherSlug: "probe-copy-size-drift",
		File:        "driver/dispatch.cpp",
		Score:       82,
	}
	campaign := FuzzCampaign{ID: "campaign-native"}
	result := FuzzCampaignNativeResult{
		RunID:              "fuzz-native",
		Outcome:            "failed",
		CrashCount:         1,
		ReportPath:         "reports/fuzz-native.md",
		SuspectedInvariant: "copy size exceeded probed user-buffer length",
	}
	updated := linkSourceCandidateToNativeOutcome(candidate, campaign, result)
	if updated.Status != "native-confirmed" {
		t.Fatalf("expected native-confirmed, got %+v", updated)
	}
	if updated.Score <= candidate.Score {
		t.Fatalf("expected confidence score increase, got %d -> %d", candidate.Score, updated.Score)
	}
	if updated.ConfidenceBreakdown["native_feedback"] <= 0 {
		t.Fatalf("expected native feedback confidence: %+v", updated.ConfidenceBreakdown)
	}
	passed := linkSourceCandidateToNativeOutcome(SourceCandidateRecord{ID: "sc-pass", Status: "needs-native", Score: 70}, campaign, FuzzCampaignNativeResult{RunID: "fuzz-pass", Outcome: "passed"})
	if passed.Status != "source-false-positive" {
		t.Fatalf("expected source-false-positive, got %+v", passed)
	}
}

func TestSourceCandidateSignatureHashIgnoresBraceAndBody(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "driver", "stable.cpp")
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatalf("mkdir driver: %v", err)
	}
	source := "NTSTATUS Target(void *UserBuffer, size_t Size) { ProbeForRead(UserBuffer, Size, 1); RtlCopyMemory(g, UserBuffer, Size); return STATUS_SUCCESS; }"
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	candidate := SourceCandidateRecord{
		ID:                  "sc-stable",
		Workspace:           root,
		MatcherSlug:         "probe-copy-size-drift",
		NoiseTier:           "precise",
		File:                "driver/stable.cpp",
		SymbolName:          "Target",
		FileContentHash:     sourceScanTextHash(source),
		SymbolSignatureHash: sourceScanSignatureHash("NTSTATUS Target(void *UserBuffer, size_t Size)"),
		Score:               90,
	}
	rt := &runtimeState{workspace: Workspace{Root: root}}
	updated, verdict := rt.revalidateSourceCandidate(candidate, "", "")
	if verdict.Verdict == sourceCandidateStatusStale {
		t.Fatalf("unchanged one-line function should not be stale: updated=%+v verdict=%+v", updated, verdict)
	}
	if updated.Stale {
		t.Fatalf("candidate should remain fresh: %+v", updated)
	}
}

func TestSourceCandidateNativeResultRequiresCandidateRunOrSymbolNotJustFile(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:          "sc-target",
		MatcherSlug: "probe-copy-size-drift",
		File:        "driver/shared.cpp",
		SymbolName:  "TargetA",
	}
	otherResult := FuzzCampaignNativeResult{
		RunID:      "fuzz-other",
		Target:     "TargetB",
		TargetFile: "driver/shared.cpp",
		Outcome:    "failed",
	}
	if sourceCandidateNativeResultMatches(candidate, otherResult) {
		t.Fatalf("same-file native result for another symbol must not match candidate")
	}
	linkedResult := otherResult
	linkedResult.SourceCandidateID = candidate.ID
	if !sourceCandidateNativeResultMatches(candidate, linkedResult) {
		t.Fatalf("explicit source_candidate_id should match candidate")
	}
	symbolResult := otherResult
	symbolResult.Target = "TargetA"
	if !sourceCandidateNativeResultMatches(candidate, symbolResult) {
		t.Fatalf("same-file exact target symbol should match candidate")
	}
}

func TestSourceScanOptionsRestrictFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	vulnerable := strings.Join([]string{
		"#include <cstring>",
		"bool ValidateRequest(const unsigned char* data, size_t size)",
		"{",
		"    if (size < 4)",
		"    {",
		"        return false;",
		"    }",
		"    memcpy(g_Buffer, data, size);",
		"    return true;",
		"}",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "src", "guard.cpp"), []byte(vulnerable), 0o644); err != nil {
		t.Fatalf("write guard: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "other.cpp"), []byte(vulnerable), 0o644); err != nil {
		t.Fatalf("write other: %v", err)
	}
	index := SemanticIndexV2{
		RunID: "run-source-scan-files",
		Goal:  "file restricted scan",
		Root:  root,
		Files: []FileRecord{
			{Path: "src/guard.cpp", Extension: ".cpp", Language: "cpp"},
			{Path: "src/other.cpp", Extension: ".cpp", Language: "cpp"},
		},
		Symbols: []SymbolRecord{
			{ID: "func:ValidateRequest@src/guard.cpp", Name: "ValidateRequest", Kind: "function", Language: "cpp", File: "src/guard.cpp", Signature: "bool ValidateRequest(const unsigned char* data, size_t size)", StartLine: 2, EndLine: 9},
			{ID: "func:OtherRequest@src/other.cpp", Name: "OtherRequest", Kind: "function", Language: "cpp", File: "src/other.cpp", Signature: "bool OtherRequest(const unsigned char* data, size_t size)", StartLine: 2, EndLine: 9},
		},
	}
	candidates := buildSourceScanCandidates(root, "source-scan-files", index, SourceScanOptions{Files: []string{"src/guard.cpp"}})
	if len(candidates) == 0 {
		t.Fatalf("expected restricted scan to find candidates")
	}
	for _, candidate := range candidates {
		if filepath.ToSlash(candidate.File) != "src/guard.cpp" {
			t.Fatalf("expected only guard.cpp candidates, got %+v", candidate)
		}
	}
}

func TestSourceScanRenderGuidesToFuzzFuncFromCandidate(t *testing.T) {
	candidate := SourceCandidateRecord{
		ID:          "sc-guided",
		MatcherSlug: "probe-copy-size-drift",
		NoiseTier:   "precise",
		File:        "driver/dispatch.cpp",
		SymbolName:  "DispatchIoctl",
		Score:       91,
	}
	runText := renderSourceScanRun(SourceScanRun{ID: "source-scan-guided"}, []SourceCandidateRecord{candidate})
	if !strings.Contains(runText, "Next: send the strongest source candidate into focused function fuzzing.") {
		t.Fatalf("expected natural next-step guidance, got:\n%s", runText)
	}
	if !strings.Contains(runText, "/fuzz-func --from-candidate sc-guided") {
		t.Fatalf("expected fuzz-func handoff command, got:\n%s", runText)
	}
	showText := renderSourceCandidate(candidate)
	if !strings.Contains(showText, "/fuzz-func --from-candidate sc-guided") {
		t.Fatalf("expected candidate view handoff command, got:\n%s", showText)
	}
}
