# KernForge Command Surface Feature Inventory

Date: 2026-06-04
Scope: CLI slash commands, command help/completion, automation/suggestion dispatch, and MCP tool command surface.

## Feature Boundaries

1. CLI command registry and alias normalization
   - Entry points: `cmd/kernforge/completion.go:10`, `cmd/kernforge/command_registry.go:41`, `cmd/kernforge/main.go:6381`
   - Purpose: define public slash commands, hidden compatibility aliases, and canonical command dispatch.
   - Core files: `completion.go`, `command_registry.go`, `main.go`

2. Family command handlers
   - Entry points: `cmd/kernforge/commands_family.go:47`, `cmd/kernforge/commands_family.go:88`, `cmd/kernforge/commands_family.go:107`
   - Purpose: route canonical family commands such as `/memory`, `/evidence`, `/verify`, `/override`, `/checkpoint`, `/suggest`, and `/session`.
   - Core files: `commands_family.go`, plus domain handlers called by it.

3. Help and completion catalog
   - Entry points: `cmd/kernforge/completion.go:96`, `cmd/kernforge/completion.go:218`, `cmd/kernforge/completion.go:745`, `cmd/kernforge/config.go:3376`
   - Purpose: expose command descriptions, argument completions, and detailed help topics.
   - Core files: `completion.go`, `config.go`, `cli_help.go`

4. Verification, checkpoints, and tool paths
   - Entry points: `cmd/kernforge/commands_verify_checkpoint.go:12`, `cmd/kernforge/commands_verify_checkpoint.go:171`, `cmd/kernforge/main.go:7427`
   - Purpose: run adaptive verification, show verification history, manage rollback checkpoints, and configure verification tool paths.
   - Core files: `commands_verify_checkpoint.go`, `commands_family.go`, `verify.go`, `main.go`

5. Memory and evidence records
   - Entry points: `cmd/kernforge/commands_family.go:47`, `cmd/kernforge/commands_family.go:88`, `cmd/kernforge/evidence_store.go`, `cmd/kernforge/persistent_memory.go`
   - Purpose: browse short-term memory, persistent memory, evidence records, and dashboards.
   - Core files: `commands_family.go`, `commands_memory.go`, `commands_evidence.go`, `evidence_store.go`, `persistent_memory.go`

6. Investigation, simulation, and risk handoffs
   - Entry points: `cmd/kernforge/commands_investigate.go:10`, `cmd/kernforge/commands_simulate.go:9`, `cmd/kernforge/command_handoff.go:50`
   - Purpose: capture investigation sessions, run heuristic simulations, and hand off to evidence, verification, dashboards, or fuzzing.
   - Core files: `commands_investigate.go`, `commands_simulate.go`, `simulation_profiles.go`, `command_handoff.go`

7. Model routing and task ownership
   - Entry points: `cmd/kernforge/main.go:4729`, `cmd/kernforge/main.go:7961`, `cmd/kernforge/main.go:8020`, `cmd/kernforge/specialists.go:1010`
   - Purpose: configure main/provider routes, analysis worker/reviewer routes, cross-review route, reasoning effort, and task-owner model overrides.
   - Core files: `main.go`, `specialists.go`, `config.go`, `completion.go`

8. Session, continuity, recovery, jobs, and delegation
   - Entry points: `cmd/kernforge/main.go:6633`, `cmd/kernforge/main.go:6641`, `cmd/kernforge/main.go:6659`, `cmd/kernforge/main.go:6663`, `cmd/kernforge/main.go:7103`, `cmd/kernforge/main.go:7154`
   - Purpose: manage local session state, continuity packets, recovery briefs, completion audits, background jobs, delegation handoff, tasks, and dashboards.
   - Core files: `main.go`, `commands_family.go`, `continuity.go`, `recovery.go`, `completion_audit.go`, `delegation_handoff.go`, `session_dashboard.go`

9. Analysis, root cause, fuzzing, and POC creation
   - Entry points: `cmd/kernforge/main.go:6759`, `cmd/kernforge/main.go:6763`, `cmd/kernforge/main.go:6767`, `cmd/kernforge/main.go:6775`, `cmd/kernforge/main.go:7329`, `cmd/kernforge/main.go:7333`, `cmd/kernforge/main.go:7337`, `cmd/kernforge/main.go:7341`
   - Purpose: project analysis, generated dashboards/docs, performance analysis, root-cause investigation, source scanning, directed function fuzzing, campaigns, and driver POC generation.
   - Core files: `main.go`, `analysis_project.go`, `commands_find_root_cause.go`, `commands_fuzz_func.go`, `fuzz_campaign.go`, `source_scan.go`, `create_driver_poc.go`

10. MCP tool surface
    - Entry points: `cmd/kernforge/mcp_server.go:590`, `cmd/kernforge/mcp_server.go:618`, `cmd/kernforge/mcp_server.go:627`, `cmd/kernforge/mcp_server.go:640`, `cmd/kernforge/mcp_server.go:686`, `cmd/kernforge/mcp_server.go:716`
    - Purpose: expose KernForge routing, review, fuzz, status, analysis, source candidate, campaign, verification, and root-cause flows to MCP clients.
    - Core files: `mcp_server.go`, `mcp_review.go`, and the runtime handlers called by MCP tools.

11. Suggestion and automation safe dispatcher
    - Entry points: `cmd/kernforge/suggestion_execution.go:120`, `cmd/kernforge/suggestion_execution.go:458`, `cmd/kernforge/suggestion_execution.go:1240`
    - Purpose: store recurring automation slots and execute only safe commands from suggestions or scheduled jobs.
    - Core files: `suggestion_execution.go`, `proactive_suggestions.go`
