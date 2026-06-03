package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func commandSubcommandAndRest(args string) (string, string) {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" {
		return "", ""
	}
	fields := splitCommandFields(trimmed)
	if len(fields) == 0 {
		return "", ""
	}
	subcommand := normalizeSlashCommandName(fields[0])
	rest := strings.TrimSpace(trimmed)
	if strings.HasPrefix(rest, fields[0]) {
		rest = strings.TrimSpace(rest[len(fields[0]):])
	} else {
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) == 2 {
			rest = strings.TrimSpace(parts[1])
		} else {
			rest = ""
		}
	}
	return subcommand, rest
}

func commandArgsHaveHTMLFlag(args string) (string, bool) {
	fields := splitCommandFields(strings.TrimSpace(args))
	var kept []string
	html := false
	for _, field := range fields {
		if strings.EqualFold(field, "--html") || strings.EqualFold(field, "html") {
			html = true
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " "), html
}

func (rt *runtimeState) handleMemoryFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	switch subcommand {
	case "":
		return rt.handleLoadedMemoryCommand()
	case "loaded", "context":
		return rt.handleLoadedMemoryCommand()
	case "recent":
		return rt.handlePersistentMemoryRecent(rest)
	case "search":
		return rt.handlePersistentMemorySearch(rest)
	case "show":
		return rt.handlePersistentMemoryShow(rest)
	case "promote", "demote", "confirm", "tentative":
		return rt.handlePersistentMemoryAdjust(rest, subcommand)
	case "dashboard":
		query, html := commandArgsHaveHTMLFlag(rest)
		return rt.handlePersistentMemoryDashboard(query, html)
	case "dashboard-html":
		return rt.handlePersistentMemoryDashboard(rest, true)
	case "prune":
		return rt.handlePersistentMemoryPrune(rest)
	case "stats":
		return rt.handlePersistentMemoryStats()
	default:
		return fmt.Errorf("usage: /memory [loaded|recent|search|show|promote|demote|confirm|tentative|dashboard [--html]|prune|stats]")
	}
}

func (rt *runtimeState) handleLoadedMemoryCommand() error {
	if len(rt.memory.Files) == 0 {
		fmt.Fprintln(rt.writer, rt.ui.warnLine("No memory files loaded."))
		return nil
	}
	fmt.Fprintln(rt.writer, rt.ui.section("Memory"))
	for _, file := range rt.memory.Files {
		fmt.Fprintln(rt.writer, rt.ui.dim(file.Path))
	}
	return nil
}

func (rt *runtimeState) handleEvidenceFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	switch subcommand {
	case "", "recent":
		return rt.handleEvidenceRecent(rest)
	case "search":
		return rt.handleEvidenceSearch(rest)
	case "show":
		return rt.handleEvidenceShow(rest)
	case "dashboard":
		query, html := commandArgsHaveHTMLFlag(rest)
		return rt.handleEvidenceDashboard(query, html)
	case "dashboard-html":
		return rt.handleEvidenceDashboard(rest, true)
	default:
		return fmt.Errorf("usage: /evidence [recent|search|show|dashboard [--html]]")
	}
}

func (rt *runtimeState) handleVerifyFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	switch subcommand {
	case "":
		return rt.handleVerifyCommand(args)
	case "dashboard":
		filtered, html := commandArgsHaveHTMLFlag(rest)
		if html {
			return rt.handleVerifyDashboardHTMLCommand(filtered)
		}
		return rt.handleVerifyDashboardCommand(filtered)
	case "dashboard-html":
		return rt.handleVerifyDashboardHTMLCommand(rest)
	case "tools":
		return rt.handleVerifyToolsCommand(rest)
	default:
		return rt.handleVerifyCommand(args)
	}
}

func (rt *runtimeState) handleVerifyToolsCommand(args string) error {
	action, rest := commandSubcommandAndRest(args)
	if action == "" {
		return fmt.Errorf("usage: /verify tools <detect|set|clear> [tool] [path]")
	}
	switch action {
	case "detect":
		return rt.handleDetectVerificationToolsCommand()
	case "set":
		toolName, pathValue := commandSubcommandAndRest(rest)
		if toolName == "" {
			return fmt.Errorf("usage: /verify tools set <msbuild|cmake|ctest|ninja> [path]")
		}
		return rt.handleSetVerificationToolPathCommand(toolName, pathValue)
	case "clear":
		toolName, _ := commandSubcommandAndRest(rest)
		if toolName == "" {
			return fmt.Errorf("usage: /verify tools clear <msbuild|cmake|ctest|ninja>")
		}
		return rt.handleClearVerificationToolPathCommand(toolName)
	default:
		return fmt.Errorf("usage: /verify tools <detect|set|clear> [tool] [path]")
	}
}

func (rt *runtimeState) handleOverrideFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	switch subcommand {
	case "", "status", "list":
		return rt.handleHookOverridesCommand()
	case "add":
		return rt.handleHookOverrideAddCommand(rest)
	case "clear":
		return rt.handleHookOverrideClearCommand(rest)
	default:
		return fmt.Errorf("usage: /override [status|add|clear]")
	}
}

func (rt *runtimeState) handleCheckpointFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	switch subcommand {
	case "auto":
		return rt.handleCheckpointAutoCommand(rest)
	case "diff":
		return rt.handleCheckpointDiffCommand(rest)
	default:
		return rt.handleCheckpointCommand(args)
	}
}

func (rt *runtimeState) handleSuggestFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	if subcommand == "dashboard" || subcommand == "dashboard-html" {
		rest, _ = commandArgsHaveHTMLFlag(rest)
		return rt.handleSuggestDashboardHTMLCommand(rest)
	}
	return rt.handleSuggestCommand(args)
}

func (rt *runtimeState) handleSessionFamilyCommand(args string) error {
	subcommand, rest := commandSubcommandAndRest(args)
	if subcommand == "dashboard" || subcommand == "dashboard-html" {
		rest, _ = commandArgsHaveHTMLFlag(rest)
		return rt.handleSessionDashboardHTMLCommand(rest)
	}
	fmt.Fprintln(rt.writer, rt.ui.section("Session"))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("session_id", rt.session.ID))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("name", rt.session.Name))
	fmt.Fprintln(rt.writer, rt.ui.statusKV("stored_at", filepath.Join(rt.store.Root(), rt.session.ID+".json")))
	return nil
}
