package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFunctionFuzzWriteDictionaryEmitsConstantsAndIdentifiers(t *testing.T) {
	dir := t.TempDir()
	dictPath := filepath.Join(dir, "dict.txt")
	run := FunctionFuzzRun{
		ID:               "run-1",
		TargetSymbolName: "Validate",
		CodeObservations: []FunctionFuzzCodeObservation{
			{
				Kind:            "size_guard",
				Evidence:        "if (len > 0x1000) return STATUS_BUFFER_TOO_SMALL;",
				ComparisonFacts: []string{"len > 0x1000"},
				FocusInputs:     []string{"len"},
			},
			{
				Kind:     "dispatch_guard",
				Evidence: "if (ioctl == IOCTL_DEVICE_INIT) { ... }",
			},
		},
		SinkSignals: []FunctionFuzzSinkSignal{
			{Kind: "copy", Name: "RtlCopyMemory", Reason: "writes user buffer"},
		},
		VirtualScenarios: []FunctionFuzzVirtualScenario{
			{
				Title:          "size drift on copy",
				ConcreteInputs: []string{"len=0xFFFFFFFF, header=\"AAAA\""},
				Invariants: []FunctionFuzzInvariant{
					{Kind: "size_eq", Left: "claimed", Right: "actual", Detail: "claimed == actual"},
				},
			},
		},
		ParameterStrategies: []FunctionFuzzParamStrategy{
			{Index: 0, Name: "buf", Class: "buffer"},
			{Index: 1, Name: "len", Class: "length"},
		},
	}
	written, err := functionFuzzWriteDictionary(run, dictPath)
	if err != nil {
		t.Fatalf("write dictionary: %v", err)
	}
	if written == 0 {
		t.Fatalf("expected dictionary entries to be written")
	}
	data, err := os.ReadFile(dictPath)
	if err != nil {
		t.Fatalf("read dictionary: %v", err)
	}
	text := string(data)
	checks := []string{
		`"0x1000"`,           // raw integer literal as text
		`"\x00\x10\x00\x00"`, // little-endian encoding of 0x1000
		`"RtlCopyMemory"`,    // sink identifier
		`"AAAA"`,             // string literal pulled from scenario concrete inputs
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Fatalf("dictionary missing expected entry %q\nfull dictionary:\n%s", want, text)
		}
	}
}

func TestFunctionFuzzWriteDictionaryIsEmptyWhenNoSignals(t *testing.T) {
	dir := t.TempDir()
	dictPath := filepath.Join(dir, "dict.txt")
	count, err := functionFuzzWriteDictionary(FunctionFuzzRun{ID: "empty"}, dictPath)
	if err != nil {
		t.Fatalf("write dictionary: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected zero entries for empty run, got %d", count)
	}
	if _, err := os.Stat(dictPath); !os.IsNotExist(err) {
		t.Fatalf("expected dictionary file to be absent when empty, stat err=%v", err)
	}
}

func TestFunctionFuzzWriteSeedCorpusWithProvenanceProducesBoundarySeeds(t *testing.T) {
	dir := t.TempDir()
	corpusDir := filepath.Join(dir, "corpus")
	manifestPath := filepath.Join(dir, "corpus_manifest.json")
	run := FunctionFuzzRun{
		ID:               "run-corpus",
		TargetSymbolName: "Handle",
		ParameterStrategies: []FunctionFuzzParamStrategy{
			{Index: 0, Name: "buf", Class: "buffer"},
			{Index: 1, Name: "len", Class: "length"},
		},
		VirtualScenarios: []FunctionFuzzVirtualScenario{
			{Title: "short header", ConcreteInputs: []string{"len=0xFFFFFFFF"}},
		},
	}
	if err := functionFuzzWriteSeedCorpusWithProvenance(run, corpusDir, manifestPath, ""); err != nil {
		t.Fatalf("seed corpus: %v", err)
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest functionFuzzCorpusManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.RunID != "run-corpus" {
		t.Fatalf("manifest run id = %q, want run-corpus", manifest.RunID)
	}
	requiredRules := []string{
		"empty_input",
		"diagnostic_pattern",
		"length_prefix_header",
		"buffer_empty",
		"buffer_oversized_4k",
		"scalar_max_u32",
		"scenario_concrete_inputs",
	}
	have := map[string]bool{}
	for _, seed := range manifest.Seeds {
		have[seed.Rule] = true
		if seed.Sha256 == "" {
			t.Fatalf("seed %q has empty sha256", seed.Name)
		}
		path := filepath.Join(corpusDir, seed.Name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("seed file %s missing: %v", path, err)
		}
		if int(info.Size()) != seed.Size {
			t.Fatalf("seed %q manifest size=%d on-disk size=%d", seed.Name, seed.Size, info.Size())
		}
	}
	for _, rule := range requiredRules {
		if !have[rule] {
			t.Fatalf("expected boundary seed with rule %q not present in manifest %+v", rule, manifest.Seeds)
		}
	}
}

func TestFunctionFuzzRunArgsSelectsProfileBehavior(t *testing.T) {
	run := FunctionFuzzRun{
		ParameterStrategies: []FunctionFuzzParamStrategy{
			{Index: 0, Name: "buf", Class: "buffer"},
		},
	}
	exec := FunctionFuzzExecution{
		CorpusDir:      filepath.Join("art", "corpus"),
		CrashDir:       filepath.Join("art", "crashes"),
		DictionaryPath: filepath.Join("art", "dict.txt"),
		Profile:        "smoke",
	}

	smokeArgs := functionFuzzRunArgs(run, exec)
	if !sliceContainsString(smokeArgs, "-max_total_time=20") {
		t.Fatalf("smoke profile missing short total time: %v", smokeArgs)
	}
	if !sliceContainsPrefix(smokeArgs, "-dict=") {
		t.Fatalf("smoke profile must include dict: %v", smokeArgs)
	}

	exec.Profile = "extended"
	extArgs := functionFuzzRunArgs(run, exec)
	if !sliceContainsString(extArgs, "-max_total_time=600") {
		t.Fatalf("extended profile missing long total time: %v", extArgs)
	}
	if !sliceContainsString(extArgs, "-fork=2") {
		t.Fatalf("extended profile missing fork workers: %v", extArgs)
	}

	exec.Profile = "repro"
	exec.CrashInputPath = filepath.Join("art", "crashes", "crash-1.bin")
	reproArgs := functionFuzzRunArgs(run, exec)
	if !sliceContainsString(reproArgs, "-runs=1") {
		t.Fatalf("repro profile must run a single iteration: %v", reproArgs)
	}
	if !sliceContainsString(reproArgs, exec.CrashInputPath) {
		t.Fatalf("repro profile must include crash input path: %v", reproArgs)
	}

	exec.Profile = "minimize"
	minArgs := functionFuzzRunArgs(run, exec)
	if !sliceContainsString(minArgs, "-minimize_crash=1") {
		t.Fatalf("minimize profile must include -minimize_crash=1: %v", minArgs)
	}
}

func TestParseFunctionFuzzContinueArgsAcceptsProfile(t *testing.T) {
	id, profile, err := parseFunctionFuzzContinueArgs("run-123 --profile extended")
	if err != nil {
		t.Fatalf("parse continue args: %v", err)
	}
	if id != "run-123" {
		t.Fatalf("id = %q, want run-123", id)
	}
	if profile != "extended" {
		t.Fatalf("profile = %q, want extended", profile)
	}
}

func TestParseFunctionFuzzContinueArgsRejectsUnknownProfile(t *testing.T) {
	if _, _, err := parseFunctionFuzzContinueArgs("run-123 --profile bogus"); err == nil {
		t.Fatalf("expected error for unknown profile")
	}
}

func TestParseFunctionFuzzReplayArgsAcceptsPositionalCrashPath(t *testing.T) {
	id, crashInput, err := parseFunctionFuzzReplayArgs("run-1 crashes/crash-abc.bin")
	if err != nil {
		t.Fatalf("parse replay args: %v", err)
	}
	if id != "run-1" {
		t.Fatalf("id = %q", id)
	}
	if crashInput != "crashes/crash-abc.bin" {
		t.Fatalf("crashInput = %q", crashInput)
	}
}

func sliceContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func sliceContainsPrefix(items []string, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}
