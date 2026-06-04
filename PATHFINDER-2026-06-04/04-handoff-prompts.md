# Handoff Prompts

## P0 - Remove Dead Hidden Alias Surface

```text
/make-plan Review and implement P0 command surface cleanup in F:\kernullist\kernforge.

Objective:
Make hiddenSlashCommandAliases the only compatibility layer for deprecated slash commands.

Evidence:
- Hidden alias registry: cmd/kernforge/command_registry.go:41
- Alias normalization before dispatch: cmd/kernforge/main.go:6381
- Dead direct alias cases: cmd/kernforge/main.go:6625, 6675, 6719, 6835, 7358
- Hidden alias completion remnants: cmd/kernforge/completion.go:108, 121, 127, 145, 159, 760, 949, 954
- Flowchart: PATHFINDER-2026-06-04/01-flowcharts/command-surface.md

Required plan:
1. Remove hidden alias direct cases from handleCommand after confirming alias normalization preserves behavior.
2. Remove hidden alias descriptions and hidden alias argument completion from completion.go.
3. Keep or add regression tests proving hidden aliases warn and dispatch to the canonical family path.
4. Run targeted command registry/completion/help tests and stale alias scans.

Anti-pattern guards:
- Do not add a second alias registry.
- Do not leave hidden aliases in public completion descriptions.
- Do not break compatibility dispatch for existing hidden aliases.
```
## P1 - Model Routing Hub

```text
/make-plan Consolidate model route commands under /model in F:\kernullist\kernforge.

Objective:
Make /model the scriptable and interactive hub for main, cross-review, analysis worker/reviewer, and task-owner model routes.

Evidence:
- Current /model hub: cmd/kernforge/main.go:4729, 4760, 4778
- Separate set handlers: cmd/kernforge/main.go:7961, 8020
- Public completion/docs duplication: cmd/kernforge/completion.go:84, 206, 784 and README.md:1178, 1218, 1219, 1247
- Flowchart: PATHFINDER-2026-06-04/01-flowcharts/command-surface.md

Required plan:
1. Add non-interactive /model analysis-worker, /model analysis-reviewer, /model clear analysis, and /model task-owner forms.
2. Preserve existing interactive /model behavior.
3. Convert /set-analysis-models and /set-specialist-model into hidden aliases after parity tests.
4. Update help, completion, README, README_kor, QUICKSTART, and feature guide.

Anti-pattern guards:
- Do not remove reasoning effort from /effort; keep it separate.
- Do not create another /models command.
- Do not lose task-owner clear/status functionality.
```

## P1 - Checkpoint Family Completion

```text
/make-plan Complete the /checkpoint family in F:\kernullist\kernforge.

Objective:
Move checkpoint listing and rollback into canonical /checkpoint subcommands.

Evidence:
- Current family only routes auto/diff: cmd/kernforge/commands_family.go:166
- Separate top-level /checkpoints and /rollback: cmd/kernforge/main.go:6887, 6891, 6895
- Docs group them together: README.md:1399, 1400, 1401, 1402, 1403

Required plan:
1. Add /checkpoint list and /checkpoint rollback [target].
2. Keep /checkpoints and /rollback as hidden aliases.
3. Update completion/help/docs.
4. Add regression tests for canonical and hidden alias forms.

Anti-pattern guards:
- Do not change checkpoint storage format.
- Do not change rollback safety semantics.
```

## P1 - Session Lifecycle Hub

```text
/make-plan Consolidate session lifecycle commands under /session in F:\kernullist\kernforge.

Objective:
Make /session the operator hub for session metadata, list/search, events, continuity, recovery, completion audit, jobs, handoff, tasks, and dashboard.

Evidence:
- Separate lifecycle routes: cmd/kernforge/main.go:6633, 6641, 6659, 6663, 7103, 7154
- Current session family is narrow: cmd/kernforge/commands_family.go:187
- README groups these commands as conversation/session commands: README.md:1184-1199

Required plan:
1. Add /session list|search|events|continuity|recover|audit|jobs|handoff|tasks|dashboard.
2. Keep existing top-level commands as compatibility aliases until docs/tests are stable.
3. Update completion/help/docs and command handoff references.
4. Add tests covering old and new forms, including automation/suggestion allowlist impact.

Anti-pattern guards:
- Do not change artifact file formats.
- Do not make /session execute unsafe commands automatically.
```

## P2 - Dashboard And Hooks Helpers

```text
/make-plan Refactor repeated dashboard and hook command surfaces in F:\kernullist\kernforge.

Objective:
Share dashboard parsing/rendering helpers and decide whether hooks/override should become one canonical /hooks family.

Evidence:
- Repeated dashboard parsing: cmd/kernforge/commands_family.go:62, 96, 112, 178, 187; cmd/kernforge/commands_investigate.go:32; cmd/kernforge/commands_simulate.go:26
- Hook/override split: cmd/kernforge/main.go:7024, 7027; cmd/kernforge/commands_family.go:152; cmd/kernforge/config.go:3590

Required plan:
1. Introduce one helper for dashboard/html argument normalization.
2. Keep family-specific handlers and tests.
3. Add /hooks reload and /hooks override status|add|clear, or explicitly document why /override remains visible.
4. Update help/completion/docs.

Anti-pattern guards:
- Do not merge memory and evidence stores.
- Do not make dashboard rendering depend on a global registry unless it removes real duplication.
```
