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
        ExAllocatePool(NonPagedPoolNx, InputBufferLength);
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
		"unreal-rpc-trust-boundary",
		"telemetry-parser-untrusted-buffer",
	} {
		if !slugs[want] {
			t.Fatalf("missing matcher %s in candidates: %#v", want, slugs)
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
