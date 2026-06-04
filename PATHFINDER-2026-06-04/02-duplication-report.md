# Command Duplication And Consolidation Report

## P0 - Hidden Alias Dispatch Still Has Dead Direct Cases

Finding: hidden aliases are normalized before the main dispatch switch, but all 42 hidden aliases still have explicit `case` branches or help/completion remnants.

Evidence:
- Alias normalization happens before `switch cmd.Name`: `cmd/kernforge/main.go:6381`.
- Hidden alias map defines compatibility rewrites: `cmd/kernforge/command_registry.go:41`.
- Direct hidden cases remain in `handleCommand`, for example `/suggest-dashboard-html`, `/verify-dashboard`, `/mem-*`, verification tool path commands, and old review aliases: `cmd/kernforge/main.go:6625`, `cmd/kernforge/main.go:6675`, `cmd/kernforge/main.go:6719`, `cmd/kernforge/main.go:6835`, `cmd/kernforge/main.go:7358`.
- Hidden descriptions remain in completion metadata: `cmd/kernforge/completion.go:108`, `cmd/kernforge/completion.go:121`, `cmd/kernforge/completion.go:127`, `cmd/kernforge/completion.go:145`, `cmd/kernforge/completion.go:159`.
- Hidden dynamic completion remnants remain for `checkpoint-auto`, `evidence-show`, and `mem-*`: `cmd/kernforge/completion.go:760`, `cmd/kernforge/completion.go:949`, `cmd/kernforge/completion.go:954`.

Why it matters:
- The direct switch cases are effectively unreachable after alias rewrite, so they look like supported primary commands to future maintainers.
- Descriptions for hidden aliases make the completion catalog and public command registry disagree.

Recommendation:
- Keep `hiddenSlashCommandAliases` as the only compatibility layer.
- Delete hidden alias `case` branches from `handleCommand`.
- Delete hidden alias descriptions and first-level/dynamic completion entries unless a dedicated "deprecated alias" inspector is added.
- Keep regression tests that assert hidden aliases warn and dispatch through the canonical family path.

## P1 - Model Routing Has A Hub But Still Keeps Separate Set Commands

Finding: `/model` is documented and implemented as the model-routing hub, but `/set-analysis-models` and `/set-specialist-model` remain public top-level commands.

Evidence:
- `/model` can select main, analysis worker, analysis reviewer, cross review, and task-owner routing: `cmd/kernforge/main.go:4729`, `cmd/kernforge/main.go:4760`, `cmd/kernforge/main.go:4778`.
- Separate handlers still own analysis and task-owner configuration: `cmd/kernforge/main.go:7961`, `cmd/kernforge/main.go:8020`.
- Public completion still exposes both set commands: `cmd/kernforge/completion.go:84`, `cmd/kernforge/completion.go:206`, `cmd/kernforge/completion.go:784`.
- Docs say `/model` is the main entry point, then still list `/set-analysis-models` and `/set-specialist-model`: `README.md:1178`, `README.md:1218`, `README.md:1219`, `README.md:1247`.

Why it matters:
- Users must learn two configuration styles for the same model-routing concern.
- Scripted routes for analysis/task-owner cannot use one consistent `/model ...` grammar yet.

Recommendation:
- Extend `/model` to support non-interactive forms:
  - `/model analysis-worker [provider] [model]`
  - `/model analysis-reviewer [provider] [model]`
  - `/model clear analysis`
  - `/model task-owner [status|clear <owner|all>|<owner> <provider> [model]]`
- Convert `/set-analysis-models` and `/set-specialist-model` to hidden aliases after parity tests pass.

## P1 - Checkpoint Family Is Only Partially Consolidated

Finding: `/checkpoint` now owns `auto` and `diff`, but listing and rollback are still separate top-level commands.

Evidence:
- Family handler only routes `auto` and `diff`; everything else falls back to create checkpoint: `cmd/kernforge/commands_family.go:166`.
- `handleCommand` still routes `/checkpoints` and `/rollback` separately: `cmd/kernforge/main.go:6887`, `cmd/kernforge/main.go:6891`, `cmd/kernforge/main.go:6895`.
- README exposes one logical checkpoint block with `/checkpoint`, `/checkpoint auto`, `/checkpoint diff`, `/checkpoints`, and `/rollback`: `README.md:1399`, `README.md:1400`, `README.md:1401`, `README.md:1402`, `README.md:1403`.

Recommendation:
- Add canonical forms:
  - `/checkpoint list`
  - `/checkpoint rollback [target]`
- Keep `/checkpoints` and `/rollback` as hidden aliases.

## P1 - Session Lifecycle Commands Are Scattered

Finding: session state, continuation, recovery, jobs, handoff, tasks, and audit commands are top-level even though they all manage the same conversation/workflow lifecycle.

Evidence:
- `handleCommand` routes `/events`, `/continuity`, `/completion-audit`, `/recover`, `/jobs`, `/session`, `/sessions`, `/handoff`, and `/tasks` separately: `cmd/kernforge/main.go:6633`, `cmd/kernforge/main.go:6641`, `cmd/kernforge/main.go:6659`, `cmd/kernforge/main.go:6663`, `cmd/kernforge/main.go:7103`, `cmd/kernforge/main.go:7154`.
- README lists the same group together as conversation/session commands: `README.md:1184`, `README.md:1193`, `README.md:1194`, `README.md:1195`, `README.md:1196`, `README.md:1197`, `README.md:1198`, `README.md:1199`.
- Current session family only handles `/session dashboard --html` plus metadata: `cmd/kernforge/commands_family.go:187`.

Recommendation:
- Expand `/session` into a real lifecycle family:
  - `/session list|search`
  - `/session events`
  - `/session continuity`
  - `/session recover`
  - `/session audit`
  - `/session jobs`
  - `/session handoff`
  - `/session tasks`
- Keep old top-level commands as compatibility aliases until docs/tests are migrated.

## P2 - Dashboard Command Pattern Is Repeated Across Families

Finding: many families implement `dashboard` and `dashboard --html` with similar parsing but different handlers.

Evidence:
- `/memory dashboard [--html]`: `cmd/kernforge/commands_family.go:62`.
- `/evidence dashboard [--html]`: `cmd/kernforge/commands_family.go:96`.
- `/verify dashboard [--html]`: `cmd/kernforge/commands_family.go:112`.
- `/suggest dashboard --html` and `/session dashboard --html`: `cmd/kernforge/commands_family.go:178`, `cmd/kernforge/commands_family.go:187`.
- `/investigate dashboard [--html]`: `cmd/kernforge/commands_investigate.go:32`.
- `/simulate dashboard [--html]`: `cmd/kernforge/commands_simulate.go:26`.

Recommendation:
- Keep family-local dashboard commands for discoverability.
- Add a shared dashboard argument parser/renderer helper.
- Optionally add `/dashboard <verify|evidence|memory|investigate|simulate|suggest|session> [--html]` as a thin hub later.

## P2 - Hooks And Overrides Are One Operational Area With Two Top-Level Shapes

Finding: `/hooks`, `/hook-reload`, and `/override` operate on hook/runtime policy but are exposed as unrelated top-level commands.

Evidence:
- Hook inspection/reload route is in `handleCommand`: `cmd/kernforge/main.go:7024`, `cmd/kernforge/main.go:7027`.
- Override family is separate: `cmd/kernforge/commands_family.go:152`.
- Help groups `hooks`, `hook-reload`, `trust`, `override`, and hidden override aliases together: `cmd/kernforge/config.go:3590`.

Recommendation:
- Add canonical forms:
  - `/hooks status`
  - `/hooks reload`
  - `/hooks override status|add|clear`
- Keep `/override` visible only if the shorter emergency UX is intentionally preferred; otherwise make it a compatibility alias.

## P2 - MCP Router Tools Overlap Heavily

Finding: MCP exposes multiple natural-language routers: `kernforge`, `kernforge_guide`, `kernforge_look`, and `kernforge_fuzz`. Some direct tools duplicate the same path with different safety defaults.

Evidence:
- Tool registration exposes the router set: `cmd/kernforge/mcp_server.go:590`, `cmd/kernforge/mcp_server.go:618`, `cmd/kernforge/mcp_server.go:627`, `cmd/kernforge/mcp_server.go:640`.
- `toolKernforge` routes review/fuzz/vague requests to other tools: `cmd/kernforge/mcp_server.go:1412`.
- `toolFuzz` routes source/preview modes to `toolFuzzFunc` and `toolFuzzFuncPreview`: `cmd/kernforge/mcp_server.go:1520`.

Recommendation:
- Keep typed direct tools because MCP model selection benefits from clear tool names.
- Consolidate natural-language routers to one primary router (`kernforge`) plus one explicit fuzz shortcut if needed.
- Treat `kernforge_look` as an alias behavior inside `kernforge`, not a separate conceptual command in docs.

## P3 - Analysis And Fuzz Families Could Become Typed Command Hubs

Finding: analysis and fuzzing are still mostly top-level verbs.

Evidence:
- Analysis-related commands are top-level in completion: `/analyze-project`, `/analyze-dashboard`, `/docs-refresh`, `/analyze-performance`, `/find-root-cause`, `/root-cause-patterns`: `cmd/kernforge/completion.go:87`, `cmd/kernforge/completion.go:88`, `cmd/kernforge/completion.go:89`, `cmd/kernforge/completion.go:90`, `cmd/kernforge/completion.go:44`, `cmd/kernforge/completion.go:45`.
- Fuzz/source commands are top-level: `/fuzz-func`, `/fuzz-campaign`, `/source-scan`, `/create-driver-poc`: `cmd/kernforge/completion.go:40`, `cmd/kernforge/completion.go:41`, `cmd/kernforge/completion.go:42`, `cmd/kernforge/completion.go:43`.

Recommendation:
- Long-term canonical forms:
  - `/analyze project|dashboard|docs refresh|performance|root-cause|root-cause patterns`
  - `/fuzz func|campaign|source-scan|driver-poc`
- Do this only after P0/P1 cleanup, because docs and tests will be broad.

## Do Not Merge Yet

- `/memory` and `/evidence`: similar query/dashboard shape, but different trust/lifecycle semantics. Share helpers, do not collapse user commands.
- `/investigate` and `/simulate`: both feed evidence, but investigation is stateful evidence capture while simulation is heuristic risk projection. Share dashboard/handoff helpers only.
- `/review` and `/verify`: review is semantic/model/deterministic gate, verification is build/test/planner evidence. Keep separate.
