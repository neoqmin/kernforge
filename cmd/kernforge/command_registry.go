package main

import (
	"sort"
	"strings"
)

type CommandVisibility string

const (
	CommandVisibilityPublic CommandVisibility = "public"
	CommandVisibilityHidden CommandVisibility = "hidden"
)

type CommandSpec struct {
	Canonical       string
	Family          string
	Visibility      CommandVisibility
	Aliases         []string
	HelpTopic       string
	Completion      string
	Handler         string
	MCPMapping      []string
	DeprecatedSince string
	Replacement     string
}

type commandAliasSpec struct {
	Canonical   string
	ArgsPrefix  string
	Replacement string
}

var hiddenSlashCommandAliases = map[string]commandAliasSpec{
	"review-pr":                  {Canonical: "review", ArgsPrefix: "pr", Replacement: "/review pr"},
	"review-selection":           {Canonical: "review", ArgsPrefix: "selection", Replacement: "/review selection"},
	"review-selections":          {Canonical: "review", ArgsPrefix: "selection --all", Replacement: "/review selection --all"},
	"do-plan-review":             {Canonical: "review", ArgsPrefix: "plan", Replacement: "/review plan"},
	"set-plan-review":            {Canonical: "review", ArgsPrefix: "plan", Replacement: "/review plan"},
	"profile-review":             {Canonical: "model", ArgsPrefix: "cross-review", Replacement: "/model cross-review"},
	"suggest-dashboard-html":     {Canonical: "suggest", ArgsPrefix: "dashboard --html", Replacement: "/suggest dashboard --html"},
	"session-dashboard-html":     {Canonical: "session", ArgsPrefix: "dashboard --html", Replacement: "/session dashboard --html"},
	"verify-dashboard":           {Canonical: "verify", ArgsPrefix: "dashboard", Replacement: "/verify dashboard"},
	"verify-dashboard-html":      {Canonical: "verify", ArgsPrefix: "dashboard --html", Replacement: "/verify dashboard --html"},
	"investigate-dashboard":      {Canonical: "investigate", ArgsPrefix: "dashboard", Replacement: "/investigate dashboard"},
	"investigate-dashboard-html": {Canonical: "investigate", ArgsPrefix: "dashboard --html", Replacement: "/investigate dashboard --html"},
	"simulate-dashboard":         {Canonical: "simulate", ArgsPrefix: "dashboard", Replacement: "/simulate dashboard"},
	"simulate-dashboard-html":    {Canonical: "simulate", ArgsPrefix: "dashboard --html", Replacement: "/simulate dashboard --html"},
	"evidence-search":            {Canonical: "evidence", ArgsPrefix: "search", Replacement: "/evidence search"},
	"evidence-show":              {Canonical: "evidence", ArgsPrefix: "show", Replacement: "/evidence show"},
	"evidence-dashboard":         {Canonical: "evidence", ArgsPrefix: "dashboard", Replacement: "/evidence dashboard"},
	"evidence-dashboard-html":    {Canonical: "evidence", ArgsPrefix: "dashboard --html", Replacement: "/evidence dashboard --html"},
	"mem":                        {Canonical: "memory", ArgsPrefix: "recent", Replacement: "/memory recent"},
	"mem-search":                 {Canonical: "memory", ArgsPrefix: "search", Replacement: "/memory search"},
	"mem-show":                   {Canonical: "memory", ArgsPrefix: "show", Replacement: "/memory show"},
	"mem-promote":                {Canonical: "memory", ArgsPrefix: "promote", Replacement: "/memory promote"},
	"mem-demote":                 {Canonical: "memory", ArgsPrefix: "demote", Replacement: "/memory demote"},
	"mem-confirm":                {Canonical: "memory", ArgsPrefix: "confirm", Replacement: "/memory confirm"},
	"mem-tentative":              {Canonical: "memory", ArgsPrefix: "tentative", Replacement: "/memory tentative"},
	"mem-dashboard":              {Canonical: "memory", ArgsPrefix: "dashboard", Replacement: "/memory dashboard"},
	"mem-dashboard-html":         {Canonical: "memory", ArgsPrefix: "dashboard --html", Replacement: "/memory dashboard --html"},
	"mem-prune":                  {Canonical: "memory", ArgsPrefix: "prune", Replacement: "/memory prune"},
	"mem-stats":                  {Canonical: "memory", ArgsPrefix: "stats", Replacement: "/memory stats"},
	"override-add":               {Canonical: "override", ArgsPrefix: "add", Replacement: "/override add"},
	"override-clear":             {Canonical: "override", ArgsPrefix: "clear", Replacement: "/override clear"},
	"checkpoint-auto":            {Canonical: "checkpoint", ArgsPrefix: "auto", Replacement: "/checkpoint auto"},
	"checkpoint-diff":            {Canonical: "checkpoint", ArgsPrefix: "diff", Replacement: "/checkpoint diff"},
	"detect-verification-tools":  {Canonical: "verify", ArgsPrefix: "tools detect", Replacement: "/verify tools detect"},
	"set-msbuild-path":           {Canonical: "verify", ArgsPrefix: "tools set msbuild", Replacement: "/verify tools set msbuild"},
	"clear-msbuild-path":         {Canonical: "verify", ArgsPrefix: "tools clear msbuild", Replacement: "/verify tools clear msbuild"},
	"set-cmake-path":             {Canonical: "verify", ArgsPrefix: "tools set cmake", Replacement: "/verify tools set cmake"},
	"clear-cmake-path":           {Canonical: "verify", ArgsPrefix: "tools clear cmake", Replacement: "/verify tools clear cmake"},
	"set-ctest-path":             {Canonical: "verify", ArgsPrefix: "tools set ctest", Replacement: "/verify tools set ctest"},
	"clear-ctest-path":           {Canonical: "verify", ArgsPrefix: "tools clear ctest", Replacement: "/verify tools clear ctest"},
	"set-ninja-path":             {Canonical: "verify", ArgsPrefix: "tools set ninja", Replacement: "/verify tools set ninja"},
	"clear-ninja-path":           {Canonical: "verify", ArgsPrefix: "tools clear ninja", Replacement: "/verify tools clear ninja"},
}

func commandSpecs() []CommandSpec {
	specs := make([]CommandSpec, 0, len(slashCommands))
	for _, command := range slashCommands {
		specs = append(specs, CommandSpec{
			Canonical:  command,
			Family:     commandFamily(command),
			Visibility: CommandVisibilityPublic,
			Aliases:    aliasesForCanonicalCommand(command),
			HelpTopic:  commandHelpTopic(command),
			Completion: command,
			Handler:    "handleCommand:" + command,
			MCPMapping: commandMCPMapping(command),
		})
	}
	return specs
}

func aliasesForCanonicalCommand(command string) []string {
	var aliases []string
	for alias, spec := range hiddenSlashCommandAliases {
		if spec.Canonical == command {
			aliases = append(aliases, alias)
		}
	}
	sort.Strings(aliases)
	return aliases
}

func commandFamily(command string) string {
	if idx := strings.Index(command, "-"); idx > 0 {
		return command[:idx]
	}
	return command
}

func commandHelpTopic(command string) string {
	switch command {
	case "review":
		return "review"
	case "verify", "checkpoint", "fuzz-func", "fuzz-campaign", "source-scan", "create-driver-poc":
		return "verification"
	case "memory", "evidence":
		return "memory"
	case "open", "selection", "selections", "use-selection", "drop-selection", "note-selection", "tag-selection", "clear-selection", "clear-selections", "diff-selection", "edit-selection":
		return "selection"
	case "mcp", "resources", "resource", "prompts", "prompt", "skills":
		return "mcp"
	case "init", "worktree", "locale-auto":
		return "workspace"
	default:
		return command
	}
}

func commandMCPMapping(command string) []string {
	switch command {
	case "review":
		return []string{"kernforge_review"}
	case "verify":
		return []string{"kernforge_verify"}
	case "analyze-project":
		return []string{"kernforge_analyze_project"}
	case "find-root-cause":
		return []string{"kernforge_find_root_cause"}
	case "source-scan":
		return []string{"kernforge_source_scan"}
	case "fuzz-func":
		return []string{"kernforge_fuzz", "kernforge_fuzz_func", "kernforge_fuzz_func_preview", "kernforge_fuzz_func_build"}
	case "fuzz-campaign":
		return []string{"kernforge_fuzz_campaign_status", "kernforge_fuzz_campaign_run"}
	case "memory":
		return []string{"kernforge_memory_search"}
	case "evidence":
		return []string{"kernforge_evidence_search"}
	case "status":
		return []string{"kernforge_status"}
	default:
		return nil
	}
}

func hiddenSlashCommandAlias(name string) (commandAliasSpec, bool) {
	spec, ok := hiddenSlashCommandAliases[normalizeSlashCommandName(name)]
	return spec, ok
}

func joinCommandArgs(prefix string, args string) string {
	prefix = strings.TrimSpace(prefix)
	args = strings.TrimSpace(args)
	if prefix == "" {
		return args
	}
	if args == "" {
		return prefix
	}
	return prefix + " " + args
}
