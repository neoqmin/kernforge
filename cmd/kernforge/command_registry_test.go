package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCommandSpecsCoverPublicSlashCommands(t *testing.T) {
	specs := commandSpecs()
	if len(specs) != len(slashCommands) {
		t.Fatalf("commandSpecs count = %d, slashCommands count = %d", len(specs), len(slashCommands))
	}

	seen := map[string]CommandSpec{}
	for _, spec := range specs {
		if strings.TrimSpace(spec.Canonical) == "" {
			t.Fatalf("command spec has empty canonical name: %#v", spec)
		}
		if spec.Visibility != CommandVisibilityPublic {
			t.Fatalf("%s visibility = %q, want public", spec.Canonical, spec.Visibility)
		}
		if strings.TrimSpace(spec.Family) == "" {
			t.Fatalf("%s has empty family", spec.Canonical)
		}
		if strings.TrimSpace(spec.HelpTopic) == "" {
			t.Fatalf("%s has empty help topic", spec.Canonical)
		}
		if strings.TrimSpace(spec.Completion) == "" {
			t.Fatalf("%s has empty completion key", spec.Canonical)
		}
		if strings.TrimSpace(spec.Handler) == "" {
			t.Fatalf("%s has empty handler mapping", spec.Canonical)
		}
		seen[spec.Canonical] = spec
	}

	for _, command := range slashCommands {
		spec, ok := seen[command]
		if !ok {
			t.Fatalf("missing command spec for public command %q", command)
		}
		if spec.Canonical != command {
			t.Fatalf("spec canonical mismatch for %q: %#v", command, spec)
		}
	}
}

func TestCommandSpecsHaveHelpCoverage(t *testing.T) {
	overview := HelpText()
	for _, spec := range commandSpecs() {
		if _, ok := HelpDetail(spec.HelpTopic); ok {
			continue
		}
		if strings.Contains(overview, "/"+spec.Canonical) {
			continue
		}
		t.Fatalf("%s has no detail help topic %q and is missing from overview help", spec.Canonical, spec.HelpTopic)
	}
}

func TestHiddenSlashCommandAliasesAreNotPublicCompletionCommands(t *testing.T) {
	public := map[string]bool{}
	for _, command := range slashCommands {
		public[command] = true
	}

	for alias, spec := range hiddenSlashCommandAliases {
		if public[alias] {
			t.Fatalf("hidden alias %q is still exposed as a public slash command", alias)
		}
		if !public[spec.Canonical] {
			t.Fatalf("hidden alias %q points to non-public canonical command %q", alias, spec.Canonical)
		}
		if !strings.HasPrefix(spec.Replacement, "/") {
			t.Fatalf("hidden alias %q has non-command replacement %q", alias, spec.Replacement)
		}
	}
}

func TestHiddenSlashCommandAliasDispatchWarns(t *testing.T) {
	var output bytes.Buffer
	rt := &runtimeState{
		writer: &output,
		ui:     UI{color: false},
	}

	_, err := rt.handleCommand(Command{Name: "mem"})
	if err == nil || !strings.Contains(err.Error(), "persistent memory is not configured") {
		t.Fatalf("expected /mem to route to /memory recent handler, got %v", err)
	}
	if !strings.Contains(output.String(), "/mem is deprecated; use /memory recent instead.") {
		t.Fatalf("expected hidden alias warning, got %q", output.String())
	}
}

func TestMCPToolsDocumentedInMcpSkills(t *testing.T) {
	server := newKernforgeMCPServer(&runtimeState{})
	docPath := filepath.Join("..", "..", "MCP-SKILLS.md")
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	documented := documentedMCPToolNames(string(content))
	for name := range server.tools {
		if !documented[name] {
			t.Fatalf("MCP-SKILLS.md is missing registered tool %q", name)
		}
	}

	koreanGuidePath := filepath.Join("..", "..", "MCP_SERVER_MODE_kor.md")
	koreanGuide, err := os.ReadFile(koreanGuidePath)
	if err != nil {
		t.Fatalf("read %s: %v", koreanGuidePath, err)
	}
	koreanGuideText := string(koreanGuide)
	for name := range server.tools {
		if !strings.Contains(koreanGuideText, name) {
			t.Fatalf("MCP_SERVER_MODE_kor.md is missing registered tool %q", name)
		}
	}
}

func documentedMCPToolNames(content string) map[string]bool {
	documented := map[string]bool{}
	toolListLine := regexp.MustCompile(`(?m)^- Tools:\s*(.+)$`).FindStringSubmatch(content)
	if len(toolListLine) != 2 {
		return documented
	}
	for _, match := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(toolListLine[1], -1) {
		if len(match) == 2 {
			documented[strings.TrimSpace(match[1])] = true
		}
	}
	return documented
}
