package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writeAnalysisDashboard(run ProjectAnalysisRun, outputPath string, docsHref string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(buildAnalysisDashboardHTML(run, docsHref)), 0o644)
}

func buildAnalysisDashboardHTML(run ProjectAnalysisRun, docsHref string) string {
	docsHref = strings.TrimSpace(filepath.ToSlash(docsHref))
	if docsHref == "" {
		docsHref = "docs"
	}
	labels := analysisDashboardLabelsForRun(run)

	reused, missed := analysisDashboardCacheCounts(run.Shards)
	securitySurfaces := analysisSecuritySurfaceSymbols(run)
	fuzzTargets := analysisFuzzTargetCatalog(run)
	entrypoints := analysisEntrypointSymbols(run)
	docLinks := analysisDashboardDocLinks(run, docsHref)
	subsystems := analysisDashboardSubsystems(run.KnowledgePack.Subsystems)
	securityRows := analysisDashboardSymbolRows(limitSymbolRecords(securitySurfaces, 12), "security")
	fuzzRows := analysisDashboardFuzzRows(limitAnalysisFuzzTargetCatalog(fuzzTargets, 12))
	verificationRows := analysisDashboardVerificationRows(analysisVerificationMatrixCatalog(run))
	buildRows := analysisDashboardBuildRows(limitBuildContexts(run.Snapshot.BuildContexts, 8), limitCompileCommands(run.Snapshot.CompileCommands, 8))
	staleRows := analysisDashboardStaleRows(run)
	portalIndex := analysisDashboardPortalIndex(run, docsHref)
	portalTotal := len(portalIndex)
	inlinePortalIndex := analysisDashboardInlinePortalItems(portalIndex)
	portalRows := analysisDashboardFallbackRows("", 4, "Loading document portal...")
	portalData := analysisDashboardPortalJSON(inlinePortalIndex)
	docsData := analysisDashboardDocsJSON(run, docsHref)
	sourceAnchorRows := analysisDashboardSourceAnchorRows(run, docsHref)
	evidenceRows := analysisDashboardEvidenceMemoryRows(run, docsHref)
	staleDiffRows := analysisDashboardStaleDiffRows(run, docsHref)
	trustBoundaryRows := analysisDashboardTrustBoundaryRows(run)
	attackFlowRows := analysisDashboardAttackFlowRows(run)
	runtimeLens := analysisDashboardRuntimeLensPanel(run, labels)
	riskFiles := analysisDashboardList(run.KnowledgePack.HighRiskFiles, 12)
	importantFiles := analysisDashboardList(run.KnowledgePack.TopImportantFiles, 12)
	if importantFiles == "" {
		importantFiles = analysisDashboardList(run.Snapshot.EntrypointFiles, 12)
	}

	statusClass := "status-ok"
	if strings.TrimSpace(run.Summary.Status) != "" && !strings.EqualFold(run.Summary.Status, "completed") {
		statusClass = "status-warn"
	}
	completedAt := run.Summary.CompletedAt
	if completedAt.IsZero() {
		completedAt = time.Now()
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="%s">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
:root {
	color-scheme: dark;
	--bg: #070b12;
	--bg-2: #0a1220;
	--panel: rgba(14, 21, 33, .94);
	--panel-2: #101826;
	--panel-3: #0c1421;
	--panel-head: rgba(17, 28, 44, .96);
	--ink: #e8eef8;
	--ink-strong: #f8fbff;
	--muted: #93a3b9;
	--muted-2: #64748b;
	--line: #223047;
	--line-strong: #334762;
	--accent: #35d6b7;
	--accent-2: #74a7ff;
	--accent-soft: rgba(53, 214, 183, .13);
	--warn: #f4b760;
	--warn-soft: rgba(244, 183, 96, .14);
	--danger: #ff6f91;
	--link: #8fc7ff;
	--code: #dbeafe;
	--code-bg: #08111f;
	--table-head: rgba(10, 18, 32, .96);
	--shadow: 0 22px 70px rgba(0, 0, 0, .34);
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
	margin: 0;
	min-height: 100vh;
	overflow-x: hidden;
	background:
		linear-gradient(120deg, rgba(53, 214, 183, .09), transparent 30%%),
		linear-gradient(245deg, rgba(116, 167, 255, .10), transparent 34%%),
		linear-gradient(180deg, var(--bg) 0, var(--bg-2) 45%%, var(--bg) 100%%);
	color: var(--ink);
	font-family: Segoe UI, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
	line-height: 1.45;
}
::selection { background: rgba(53, 214, 183, .28); color: var(--ink-strong); }
a { color: var(--link); text-decoration: none; transition: color .15s ease, border-color .15s ease, background .15s ease, box-shadow .15s ease; }
a:hover { color: var(--accent); text-decoration: none; }
a:focus-visible, button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.shell { position: relative; width: 100%%; max-width: 1480px; margin: 0 auto; padding: 26px; }
.topbar {
	position: sticky;
	top: 0;
	z-index: 10;
	display: grid;
	grid-template-columns: minmax(0, 1fr) auto;
	gap: 20px;
	align-items: center;
	margin-bottom: 18px;
	padding: 20px 22px;
	border: 1px solid var(--line);
	border-radius: 10px;
	background: linear-gradient(180deg, rgba(18, 30, 47, .94), rgba(11, 18, 30, .94));
	box-shadow: var(--shadow);
	backdrop-filter: blur(18px);
}
.topbar > * { min-width: 0; }
.eyebrow { color: var(--accent); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .12em; }
h1 { margin: 5px 0 8px; color: var(--ink-strong); font-size: 34px; line-height: 1.12; letter-spacing: 0; }
h2 { margin: 0 0 12px; color: var(--ink-strong); font-size: 17px; font-weight: 750; letter-spacing: 0; }
h3 { margin: 0 0 8px; color: var(--ink-strong); font-size: 14px; font-weight: 740; letter-spacing: 0; }
.goal { min-width: 0; max-width: 940px; color: var(--muted); overflow-wrap: anywhere; word-break: break-word; }
.status-pill {
	display: inline-flex;
	align-items: center;
	gap: 8px;
	min-height: 34px;
	padding: 6px 12px;
	border: 1px solid var(--line-strong);
	border-radius: 999px;
	font-size: 12px;
	font-weight: 800;
	letter-spacing: .02em;
	background: rgba(8, 17, 31, .78);
	white-space: nowrap;
	box-shadow: inset 0 1px 0 rgba(255, 255, 255, .04);
}
.status-pill::before {
	content: "";
	width: 8px;
	height: 8px;
	border-radius: 999px;
	background: currentColor;
	box-shadow: 0 0 18px currentColor;
}
.status-ok { color: var(--accent); border-color: rgba(53, 214, 183, .38); background: var(--accent-soft); }
.status-warn { color: var(--warn); border-color: rgba(244, 183, 96, .36); background: var(--warn-soft); }
.meta-grid {
	display: grid;
	grid-template-columns: repeat(4, minmax(0, 1fr));
	gap: 12px;
	margin-bottom: 14px;
}
.meta, .metric, .panel, .table-panel {
	background: var(--panel);
	border: 1px solid var(--line);
	border-radius: 10px;
	box-shadow: 0 14px 38px rgba(0, 0, 0, .18);
	backdrop-filter: blur(10px);
}
.meta { padding: 13px 14px; min-width: 0; background: linear-gradient(180deg, rgba(18, 29, 45, .95), rgba(12, 20, 33, .94)); }
.meta span, .metric span { display: block; color: var(--muted-2); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.meta strong, .metric strong { display: block; margin-top: 5px; color: var(--ink-strong); overflow-wrap: anywhere; }
.metric-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
.metric { position: relative; min-height: 84px; padding: 14px 15px; overflow: hidden; background: linear-gradient(180deg, rgba(16, 26, 41, .98), rgba(11, 18, 30, .98)); }
.metric::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: linear-gradient(90deg, var(--accent), transparent 76%%); opacity: .7; }
.metric strong { font-size: 27px; line-height: 1.12; font-weight: 800; }
.lens-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
.lens { min-width: 0; padding: 13px 14px; background: linear-gradient(180deg, rgba(16, 26, 41, .96), rgba(10, 18, 30, .94)); border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 12px 32px rgba(0, 0, 0, .16); }
.lens span { display: block; color: var(--muted-2); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; }
.lens strong { display: block; margin-top: 5px; color: var(--ink-strong); overflow-wrap: anywhere; }
.layout { display: grid; grid-template-columns: minmax(0, 1.78fr) minmax(340px, .72fr); gap: 18px; align-items: start; min-width: 0; }
.layout > *, .stack > *, .document-workspace > * { min-width: 0; }
.stack { display: grid; gap: 18px; }
.panel { padding: 16px; min-width: 0; }
.table-panel { overflow: auto; }
.table-panel > .panel { background: var(--panel-head); }
.document-workspace { display: grid; grid-template-columns: minmax(300px, .72fr) minmax(0, 1.28fr); gap: 18px; align-items: start; }
.document-list-panel { max-height: 760px; overflow: auto; }
.document-workspace .doc-grid { grid-template-columns: 1fr; }
.doc-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.portal-search {
	display: grid;
	grid-template-columns: minmax(0, 1fr) auto;
	gap: 10px;
	margin-bottom: 12px;
}
.portal-search input {
	width: 100%%;
	min-height: 40px;
	border: 1px solid var(--line);
	border-radius: 8px;
	padding: 8px 12px;
	background: var(--code-bg);
	color: var(--ink);
	font: inherit;
	font-size: 13px;
	box-shadow: inset 0 1px 0 rgba(255, 255, 255, .03);
}
.portal-search input::placeholder { color: #5f718a; }
.portal-search input:focus { border-color: rgba(53, 214, 183, .7); }
.portal-search input::-webkit-search-cancel-button { filter: invert(1); opacity: .75; }
.portal-search input::-webkit-search-decoration { filter: invert(1); }
.portal-search input::-ms-clear { display: none; }
.portal-search input::-ms-reveal { display: none; }
.portal-search input::-webkit-input-placeholder { color: #5f718a; }
.portal-search input:-ms-input-placeholder { color: #5f718a; }
.portal-search input::-ms-input-placeholder { color: #5f718a; }
.portal-search input::placeholder { color: #5f718a; }
.portal-search input[type="search"] { appearance: none; }
.portal-search input[type="search"]::-webkit-search-cancel-button { appearance: none; }
.portal-search input[type="search"]::-webkit-search-decoration { appearance: none; }
.portal-search input[type="search"]::-webkit-search-results-button { appearance: none; }
.portal-search input[type="search"]::-webkit-search-results-decoration { appearance: none; }
.portal-search input[type="search"]::-webkit-search-cancel-button {
	width: 12px;
	height: 12px;
	background: linear-gradient(45deg, transparent 44%%, var(--muted) 45%%, var(--muted) 55%%, transparent 56%%), linear-gradient(-45deg, transparent 44%%, var(--muted) 45%%, var(--muted) 55%%, transparent 56%%);
	cursor: pointer;
}
.portal-count {
	min-height: 40px;
	display: inline-flex;
	align-items: center;
	padding: 0 12px;
	border: 1px solid var(--line);
	border-radius: 8px;
	color: var(--muted);
	background: var(--panel-3);
	font-size: 12px;
	font-weight: 700;
	white-space: nowrap;
}
.portal-filters {
	display: flex;
	flex-wrap: wrap;
	gap: 7px;
	margin-bottom: 12px;
}
.portal-filter {
	min-height: 32px;
	border: 1px solid var(--line);
	border-radius: 999px;
	background: rgba(10, 18, 30, .78);
	color: var(--muted);
	padding: 5px 11px;
	font: inherit;
	font-size: 12px;
	font-weight: 700;
	cursor: pointer;
	transition: background .15s ease, color .15s ease, border-color .15s ease, transform .15s ease;
}
.portal-filter:hover {
	color: var(--ink);
	border-color: var(--line-strong);
	transform: translateY(-1px);
}
.portal-filter.active {
	background: var(--accent-soft);
	color: var(--accent);
	border-color: rgba(53, 214, 183, .5);
	box-shadow: inset 0 0 0 1px rgba(53, 214, 183, .08);
}
.doc-link {
	display: block;
	min-height: 108px;
	padding: 12px;
	border: 1px solid var(--line);
	border-radius: 8px;
	background: linear-gradient(180deg, rgba(16, 27, 43, .96), rgba(11, 18, 30, .96));
	color: var(--ink);
	overflow-wrap: anywhere;
	transition: transform .15s ease, border-color .15s ease, background .15s ease, box-shadow .15s ease;
}
.doc-link strong {
	display: block;
	margin-bottom: 6px;
	color: var(--ink-strong);
}
.doc-link:hover {
	transform: translateY(-1px);
	border-color: var(--line-strong);
	background: linear-gradient(180deg, rgba(20, 35, 55, .96), rgba(12, 22, 36, .96));
	box-shadow: 0 12px 28px rgba(0, 0, 0, .22);
}
.doc-link.active-doc {
	border-color: rgba(53, 214, 183, .58);
	background: var(--accent-soft);
	box-shadow: inset 3px 0 0 var(--accent), 0 16px 34px rgba(0, 0, 0, .22);
}
.doc-link.active-doc strong, a.active-doc {
	color: var(--accent);
}
a.active-doc code {
	border-color: rgba(53, 214, 183, .5);
	background: rgba(53, 214, 183, .12);
	color: var(--accent);
}
.markdown-viewer-panel { padding: 0; overflow: hidden; }
.viewer-head {
	display: grid;
	grid-template-columns: minmax(0, 1fr) auto;
	gap: 12px;
	align-items: start;
	padding: 17px 18px;
	border-bottom: 1px solid var(--line);
	background: linear-gradient(180deg, rgba(18, 30, 47, .98), rgba(11, 19, 31, .98));
}
.markdown-viewer {
	max-height: 680px;
	overflow: auto;
	padding: 24px 26px;
	background: linear-gradient(180deg, #0b1422, #08111f);
	color: var(--ink);
}
.markdown-viewer.empty { color: var(--muted); }
.markdown-viewer h1 {
	margin: 0 0 14px;
	color: var(--ink-strong);
	font-size: 29px;
	line-height: 1.18;
}
.markdown-viewer h2 {
	margin: 26px 0 10px;
	padding-bottom: 7px;
	border-bottom: 1px solid var(--line);
	color: var(--ink-strong);
	font-size: 21px;
}
.markdown-viewer h3 { margin: 20px 0 8px; color: var(--ink-strong); font-size: 17px; }
.markdown-viewer h4 { margin: 16px 0 8px; color: var(--ink-strong); font-size: 15px; }
.markdown-viewer p { margin: 10px 0; }
.markdown-viewer ul, .markdown-viewer ol { margin: 8px 0 14px; padding-left: 24px; }
.markdown-viewer li { margin: 5px 0; }
.markdown-viewer blockquote {
	margin: 12px 0;
	padding: 10px 13px;
	border-radius: 0 8px 8px 0;
	border-left: 4px solid var(--accent);
	background: var(--accent-soft);
	color: #c9fff2;
}
.markdown-viewer pre {
	margin: 12px 0;
	padding: 12px;
	overflow: auto;
	border: 1px solid var(--line);
	border-radius: 8px;
	background: #050b14;
	color: #e5edf7;
}
.markdown-viewer pre code {
	padding: 0;
	background: transparent;
	color: inherit;
	font-size: 12px;
}
.markdown-viewer table {
	width: 100%%;
	margin: 12px 0 16px;
	border: 1px solid var(--line);
	border-radius: 8px;
	table-layout: auto;
	overflow: hidden;
}
.markdown-viewer th, .markdown-viewer td { padding: 8px 10px; }
.markdown-viewer tr:nth-child(even) td { background: rgba(255, 255, 255, .025); }
.list { margin: 0; padding-left: 18px; color: var(--ink); }
.list li { margin: 5px 0; overflow-wrap: anywhere; }
.empty { color: var(--muted); }
table { width: 100%%; border-collapse: collapse; table-layout: fixed; }
th, td { padding: 11px 10px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { color: var(--muted-2); background: var(--table-head); font-size: 11px; font-weight: 850; text-transform: uppercase; letter-spacing: .07em; }
td { color: #d8e2f0; font-size: 13px; }
tbody tr { transition: background .15s ease; }
tbody tr:hover td { background: rgba(116, 167, 255, .055); }
code { color: var(--code); background: var(--code-bg); border: 1px solid rgba(116, 167, 255, .14); border-radius: 6px; padding: 2px 6px; font-family: Consolas, ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.command-chip { display: inline-block; margin: 2px 4px 2px 0; color: #c8fff3; border-color: rgba(53, 214, 183, .24); background: rgba(53, 214, 183, .08); }
.tag { display: inline-block; margin: 2px 4px 2px 0; padding: 2px 8px; border: 1px solid rgba(116, 167, 255, .14); border-radius: 999px; background: rgba(116, 167, 255, .08); color: #aebed4; font-size: 11px; font-weight: 700; }
.subsystem { border-top: 1px solid var(--line); padding-top: 12px; margin-top: 12px; }
.subsystem:first-of-type { border-top: 0; padding-top: 0; margin-top: 0; }
.subtle { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
.footer { margin-top: 18px; padding: 12px 2px; color: var(--muted-2); font-size: 12px; }
::-webkit-scrollbar { width: 11px; height: 11px; }
::-webkit-scrollbar-track { background: rgba(8, 17, 31, .8); }
::-webkit-scrollbar-thumb { background: #253650; border: 3px solid rgba(8, 17, 31, .8); border-radius: 999px; }
::-webkit-scrollbar-thumb:hover { background: #38506f; }
@media (max-width: 980px) {
	.shell { padding: 18px; }
	.topbar { position: static; }
	.topbar, .layout { grid-template-columns: 1fr; }
	.document-workspace { grid-template-columns: 1fr; }
	.document-list-panel { max-height: none; }
	.meta-grid, .metric-grid, .lens-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
	.doc-grid { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
	.shell { padding: 14px 24px 14px 14px; }
	.topbar { padding: 17px; }
	.topbar > div:first-child { max-width: 300px; }
	.meta-grid, .metric-grid, .lens-grid { grid-template-columns: 1fr; }
	h1 { font-size: 23px; overflow-wrap: anywhere; }
	.goal { font-size: 15px; line-height: 1.5; word-break: normal; }
	th, td { padding: 8px 6px; font-size: 13px; }
	.portal-search { grid-template-columns: 1fr; }
	.status-pill { justify-self: start; max-width: 100%%; }
	.markdown-viewer { padding: 18px; }
}
</style>
</head>
<body>
<main class="shell">
	<header class="topbar">
		<div>
			<div class="eyebrow">Kernforge analyze-project</div>
			<h1>%s</h1>
			<div class="goal">%s</div>
		</div>
		<div class="status-pill %s">%s</div>
	</header>
	<section class="meta-grid">
		<div class="meta"><span>%s</span><strong>%s</strong></div>
		<div class="meta"><span>%s</span><strong>%s</strong></div>
		<div class="meta"><span>%s</span><strong>%s</strong></div>
		<div class="meta"><span>%s</span><strong>%s</strong></div>
	</section>
	<section class="metric-grid">
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
		<div class="metric"><span>%s</span><strong>%d</strong></div>
	</section>
	%s
	<section class="layout">
		<div class="stack">
			<section class="document-workspace">
				<section class="panel document-list-panel">
					<h2>%s</h2>
					<div class="doc-grid">%s</div>
				</section>
				<section class="panel markdown-viewer-panel" id="markdown-viewer-panel">
					<div class="viewer-head">
						<div>
							<h2 id="markdown-viewer-title">%s</h2>
							<div id="markdown-viewer-path" class="subtle">%s</div>
						</div>
					</div>
					<article id="markdown-viewer" class="markdown-viewer empty">%s</article>
				</section>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;">
					<h2>%s</h2>
					<div class="portal-search">
						<input id="portal-search" type="search" placeholder="%s">
						<span id="portal-count" class="portal-count">%d/%d items</span>
					</div>
					<div class="portal-filters" aria-label="Document portal filters">
						<button class="portal-filter active" type="button" data-query="">All</button>
						<button class="portal-filter" type="button" data-query="developer_docs">Developer Docs</button>
						<button class="portal-filter" type="button" data-query="verification_planner">Verification</button>
						<button class="portal-filter" type="button" data-query="fuzz_target_discovery">Fuzz</button>
						<button class="portal-filter" type="button" data-query="evidence">Evidence</button>
					</div>
				</div>
				<table><thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody id="portal-results">%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>%s</h2></div>
				<table><thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Evidence And Memory Drilldown</h2></div>
				<table><thead><tr><th>Context</th><th>Artifact</th><th>Command</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Stale Section Diff</h2></div>
				<table><thead><tr><th>Section</th><th>Change</th><th>Impact</th><th>Refresh</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Trust Boundary Graph</h2></div>
				<table><thead><tr><th>Source</th><th>Boundary</th><th>Target</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Attack Flow View</h2></div>
				<table><thead><tr><th>Entry</th><th>Flow</th><th>Risk</th><th>Next</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Stale And Invalidation Markers</h2></div>
				<table><thead><tr><th>Marker</th><th>Source</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="panel">
				<h2>Subsystem Map</h2>
				%s
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Security Surface</h2></div>
				<table><thead><tr><th>Symbol</th><th>Kind</th><th>File</th><th>Tags</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Fuzz Target Candidates</h2></div>
				<table><thead><tr><th>Priority</th><th>Target</th><th>Surface</th><th>Harness</th><th>Suggested Command</th></tr></thead><tbody>%s</tbody></table>
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Verification Matrix</h2></div>
				<table><thead><tr><th>Change Area</th><th>Required</th><th>Optional</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table>
			</section>
		</div>
		<aside class="stack">
			<section class="panel">
				<h2>Important Files</h2>
				%s
			</section>
			<section class="panel">
				<h2>High Risk Files</h2>
				%s
			</section>
			<section class="table-panel">
				<div class="panel" style="border:0; border-radius:8px 8px 0 0;"><h2>Build Coverage</h2></div>
				<table><thead><tr><th>Kind</th><th>Name</th><th>Coverage</th></tr></thead><tbody>%s</tbody></table>
			</section>
		</aside>
	</section>
	<div class="footer">Generated from analyze-project artifacts. Source output: %s</div>
</main>
<script>
const portalItems = %s;
const markdownDocs = %s;
const portalTotalItems = %d;
const portalInlineItems = %d;
const portalDisplayLimit = 80;
const portalResults = document.getElementById('portal-results');
const portalCount = document.getElementById('portal-count');
const portalSearch = document.getElementById('portal-search');
const portalFilters = Array.prototype.slice.call(document.querySelectorAll('.portal-filter'));
const markdownViewerPanel = document.getElementById('markdown-viewer-panel');
const markdownViewer = document.getElementById('markdown-viewer');
const markdownViewerTitle = document.getElementById('markdown-viewer-title');
const markdownViewerPath = document.getElementById('markdown-viewer-path');
let portalFilterQuery = '';
function escapeHTML(value) {
	return String(value || '').replace(/[&<>"']/g, function(ch) {
		return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
	});
}
function markdownAnchor(value) {
	return String(value || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
function parseDocHref(href) {
	const raw = String(href || '').replace(/\\/g, '/');
	const hashAt = raw.indexOf('#');
	const path = hashAt >= 0 ? raw.slice(0, hashAt) : raw;
	const cleanPath = path.split('?')[0];
	const parts = cleanPath.split('/').filter(Boolean);
	return {
		name: String(parts.length ? parts[parts.length - 1] : cleanPath).toLowerCase(),
		anchor: hashAt >= 0 ? raw.slice(hashAt + 1) : ''
	};
}
const markdownByName = {};
(markdownDocs || []).forEach(function(doc) {
	const name = String(doc.name || '').toLowerCase();
	if (name) {
		markdownByName[name] = doc;
	}
});
function renderInlineMarkdown(text) {
	let escaped = escapeHTML(text);
	escaped = escaped.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function(match, label, href) {
		const safeHref = sanitizeMarkdownHref(href);
		if (!safeHref) {
			return label;
		}
		const docAttr = /\.md(?:#|$)/i.test(safeHref) ? ' data-doc-href="' + safeHref + '"' : '';
		return '<a href="' + safeHref + '"' + docAttr + '>' + label + '</a>';
	});
	const tick = String.fromCharCode(96);
	escaped = escaped.replace(new RegExp(tick + '([^' + tick + ']+)' + tick, 'g'), '<code>$1</code>');
	escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
	return escaped;
}
function sanitizeMarkdownHref(href) {
	const value = String(href || '').trim();
	const lower = value.toLowerCase();
	if (!value || lower.indexOf('javascript:') === 0 || lower.indexOf('data:') === 0 || lower.indexOf('vbscript:') === 0) {
		return '';
	}
	return value;
}
function isMarkdownTableLine(line) {
	return line.indexOf('|') >= 0 && line.trim().length > 1;
}
function isMarkdownTableDivider(line) {
	return /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?$/.test(line);
}
function splitMarkdownTableRow(line) {
	return line.replace(/^\|/, '').replace(/\|$/, '').split('|').map(function(cell) {
		return cell.trim();
	});
}
function renderMarkdown(markdown) {
	const lines = String(markdown || '').replace(/\r\n/g, '\n').split('\n');
	const out = [];
	let inCode = false;
	let codeLines = [];
	let listType = '';
	function closeList() {
		if (listType) {
			out.push('</' + listType + '>');
			listType = '';
		}
	}
	function openList(kind) {
		if (listType !== kind) {
			closeList();
			out.push('<' + kind + '>');
			listType = kind;
		}
	}
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const trimmed = line.trim();
		if (trimmed.indexOf(String.fromCharCode(96, 96, 96)) === 0) {
			if (inCode) {
				out.push('<pre><code>' + escapeHTML(codeLines.join('\n')) + '</code></pre>');
				codeLines = [];
				inCode = false;
			} else {
				closeList();
				inCode = true;
			}
			continue;
		}
		if (inCode) {
			codeLines.push(line);
			continue;
		}
		if (!trimmed) {
			closeList();
			continue;
		}
		const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
		if (heading) {
			closeList();
			const level = Math.min(6, heading[1].length);
			const title = heading[2].replace(/\s+#+$/, '').trim();
			const anchor = markdownAnchor(title);
			const anchorAttr = anchor ? ' id="' + anchor + '" data-md-anchor="' + anchor + '"' : '';
			out.push('<h' + level + anchorAttr + '>' + renderInlineMarkdown(title) + '</h' + level + '>');
			continue;
		}
		if (i + 1 < lines.length && isMarkdownTableLine(trimmed) && isMarkdownTableDivider(lines[i + 1].trim())) {
			closeList();
			const header = splitMarkdownTableRow(trimmed);
			i += 2;
			const rows = [];
			while (i < lines.length && isMarkdownTableLine(lines[i].trim())) {
				rows.push(splitMarkdownTableRow(lines[i].trim()));
				i++;
			}
			i--;
			out.push('<table><thead><tr>' + header.map(function(cell) { return '<th>' + renderInlineMarkdown(cell) + '</th>'; }).join('') + '</tr></thead><tbody>' + rows.map(function(row) {
				return '<tr>' + row.map(function(cell) { return '<td>' + renderInlineMarkdown(cell) + '</td>'; }).join('') + '</tr>';
			}).join('') + '</tbody></table>');
			continue;
		}
		if (/^[-*]\s+/.test(trimmed)) {
			openList('ul');
			out.push('<li>' + renderInlineMarkdown(trimmed.replace(/^[-*]\s+/, '')) + '</li>');
			continue;
		}
		if (/^\d+\.\s+/.test(trimmed)) {
			openList('ol');
			out.push('<li>' + renderInlineMarkdown(trimmed.replace(/^\d+\.\s+/, '')) + '</li>');
			continue;
		}
		if (trimmed.indexOf('>') === 0) {
			closeList();
			out.push('<blockquote>' + renderInlineMarkdown(trimmed.replace(/^>\s?/, '')) + '</blockquote>');
			continue;
		}
		closeList();
		out.push('<p>' + renderInlineMarkdown(trimmed) + '</p>');
	}
	closeList();
	if (inCode) {
		out.push('<pre><code>' + escapeHTML(codeLines.join('\n')) + '</code></pre>');
	}
	return out.join('');
}
function markActiveDoc(href) {
	const current = parseDocHref(href);
	Array.prototype.slice.call(document.querySelectorAll('a[data-doc-href]')).forEach(function(link) {
		const target = parseDocHref(link.getAttribute('data-doc-href') || link.getAttribute('href') || '');
		link.classList.toggle('active-doc', target.name === current.name && (!current.anchor || !target.anchor || target.anchor === current.anchor));
	});
}
function scrollMarkdownAnchor(anchor) {
	if (!anchor) {
		markdownViewer.scrollTop = 0;
		return;
	}
	const targets = Array.prototype.slice.call(markdownViewer.querySelectorAll('[data-md-anchor]'));
	const target = targets.find(function(node) {
		return node.getAttribute('data-md-anchor') === anchor;
	});
	if (target) {
		target.scrollIntoView({block: 'start'});
	} else {
		markdownViewer.scrollTop = 0;
	}
}
function openMarkdownDoc(href, options) {
	const parsed = parseDocHref(href);
	const doc = markdownByName[parsed.name];
	if (!doc || !markdownViewer) {
		return false;
	}
	markdownViewer.classList.remove('empty');
	markdownViewerTitle.textContent = doc.title || doc.name || 'Markdown';
	markdownViewerPath.textContent = doc.href || doc.name || '';
	markdownViewer.innerHTML = renderMarkdown(doc.markdown || '');
	scrollMarkdownAnchor(parsed.anchor);
	markActiveDoc(href);
	if (!options || options.scroll !== false) {
		markdownViewerPanel.scrollIntoView({behavior: 'smooth', block: 'start'});
	}
	return true;
}
function renderPortal(items) {
	const visible = Math.min(items.length, portalDisplayLimit);
	const suffix = portalInlineItems < portalTotalItems ? ' loaded of ' + portalTotalItems + ' total' : ' total';
	portalCount.textContent = String(visible) + ' shown / ' + String(items.length) + suffix;
	if (items.length === 0) {
		portalResults.innerHTML = '<tr><td colspan="4" class="empty">No matching document portal items.</td></tr>';
		return;
	}
	portalResults.innerHTML = items.slice(0, portalDisplayLimit).map(function(item) {
		const title = item.href ? '<a href="' + escapeHTML(item.href) + '" data-doc-href="' + escapeHTML(item.href) + '">' + escapeHTML(item.title) + '</a>' : escapeHTML(item.title);
		const detail = item.detail ? '<div class="subtle">' + escapeHTML(item.detail) + '</div>' : '';
		const source = item.source ? '<code>' + escapeHTML(item.source) + '</code>' : '<span class="subtle">none</span>';
		const reuse = (item.reuse || []).map(function(value) { return '<span class="tag">' + escapeHTML(value) + '</span>'; }).join('');
		return '<tr><td>' + escapeHTML(item.kind) + '</td><td>' + title + detail + '</td><td>' + source + '</td><td>' + reuse + '</td></tr>';
	}).join('');
}
function filterPortal() {
	const query = portalSearch.value.trim().toLowerCase();
	renderPortal(portalItems.filter(function(item) {
		const search = item.search || '';
		const matchesText = !query || search.indexOf(query) >= 0;
		const matchesFilter = !portalFilterQuery || search.indexOf(portalFilterQuery) >= 0;
		return matchesText && matchesFilter;
	}));
}
portalFilters.forEach(function(button) {
	button.addEventListener('click', function() {
		portalFilterQuery = String(button.getAttribute('data-query') || '').toLowerCase();
		portalFilters.forEach(function(item) { item.classList.remove('active'); });
		button.classList.add('active');
		filterPortal();
	});
});
portalSearch.addEventListener('input', filterPortal);
renderPortal(portalItems);
document.addEventListener('click', function(event) {
	const link = event.target.closest ? event.target.closest('a[data-doc-href]') : null;
	if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
		return;
	}
	const href = link.getAttribute('data-doc-href') || link.getAttribute('href') || '';
	if (openMarkdownDoc(href)) {
		event.preventDefault();
	}
});
if (markdownDocs && markdownDocs.length > 0) {
	openMarkdownDoc(markdownDocs[0].href || markdownDocs[0].name, {scroll: false});
}
</script>
</body>
</html>`,
		htmlEscape(labels.Lang),
		htmlEscape(labels.Title),
		htmlEscape(labels.Title),
		htmlEscape(valueOrDefault(run.Summary.Goal, "Project knowledge base")),
		statusClass,
		htmlEscape(valueOrDefault(run.Summary.Status, "completed")),
		htmlEscape(labels.RunID),
		htmlEscape(run.Summary.RunID),
		htmlEscape(labels.Mode),
		htmlEscape(valueOrDefault(run.Summary.Mode, run.Snapshot.AnalysisMode)),
		htmlEscape(labels.Workspace),
		htmlEscape(valueOrDefault(run.Snapshot.Root, run.KnowledgePack.Root)),
		htmlEscape(labels.Completed),
		htmlEscape(completedAt.Format(time.RFC3339)),
		htmlEscape(labels.Files),
		run.Snapshot.TotalFiles,
		htmlEscape(labels.Lines),
		run.Snapshot.TotalLines,
		htmlEscape(labels.Shards),
		run.Summary.TotalShards,
		htmlEscape(labels.Symbols),
		len(run.SemanticIndexV2.Symbols),
		htmlEscape(labels.Subsystems),
		len(run.KnowledgePack.Subsystems),
		htmlEscape(labels.SecuritySurfaces),
		len(securitySurfaces),
		htmlEscape(labels.FuzzCandidates),
		len(fuzzTargets),
		htmlEscape(labels.Entrypoints),
		len(entrypoints),
		htmlEscape(labels.CacheReused),
		reused,
		htmlEscape(labels.CacheMiss),
		missed,
		runtimeLens,
		htmlEscape(labels.GeneratedDocuments),
		docLinks,
		htmlEscape(labels.MarkdownViewer),
		htmlEscape(labels.ViewerEmpty),
		htmlEscape(labels.ViewerEmpty),
		htmlEscape(labels.DocumentPortal),
		htmlEscape(labels.PortalPlaceholder),
		len(inlinePortalIndex),
		portalTotal,
		htmlEscape(labels.Kind),
		htmlEscape(labels.Item),
		htmlEscape(labels.Source),
		htmlEscape(labels.Reuse),
		portalRows,
		htmlEscape(labels.SourceAnchors),
		htmlEscape(labels.Anchor),
		htmlEscape(labels.Document),
		htmlEscape(labels.Confidence),
		htmlEscape(labels.State),
		analysisDashboardFallbackRows(sourceAnchorRows, 4, "No source anchors recorded."),
		analysisDashboardFallbackRows(evidenceRows, 3, "No evidence or memory drilldown context recorded."),
		analysisDashboardFallbackRows(staleDiffRows, 4, "No stale section diff recorded."),
		analysisDashboardFallbackRows(trustBoundaryRows, 4, "No trust-boundary graph edges inferred."),
		analysisDashboardFallbackRows(attackFlowRows, 4, "No attack-flow candidates inferred."),
		analysisDashboardFallbackRows(staleRows, 2, "No stale or invalidation markers recorded."),
		subsystems,
		analysisDashboardFallbackRows(securityRows, 4, "No indexed security surfaces found."),
		analysisDashboardFallbackRows(fuzzRows, 5, "No fuzz target candidates found."),
		verificationRows,
		analysisDashboardFallbackPanel(importantFiles, "No important files recorded."),
		analysisDashboardFallbackPanel(riskFiles, "No high risk files recorded."),
		analysisDashboardFallbackRows(buildRows, 3, "No build contexts or compile commands found."),
		htmlEscape(run.Summary.OutputPath),
		portalData,
		docsData,
		portalTotal,
		len(inlinePortalIndex),
	)
}

type analysisDashboardPortalItem struct {
	Kind   string   `json:"kind"`
	Title  string   `json:"title"`
	Detail string   `json:"detail,omitempty"`
	Source string   `json:"source,omitempty"`
	Href   string   `json:"href,omitempty"`
	Reuse  []string `json:"reuse,omitempty"`
	Search string   `json:"search"`
}

type analysisDashboardLabels struct {
	Lang               string
	Title              string
	RunID              string
	Mode               string
	Workspace          string
	Completed          string
	Files              string
	Lines              string
	Shards             string
	Symbols            string
	Subsystems         string
	SecuritySurfaces   string
	FuzzCandidates     string
	Entrypoints        string
	CacheReused        string
	CacheMiss          string
	GeneratedDocuments string
	MarkdownViewer     string
	ViewerEmpty        string
	DocumentPortal     string
	PortalPlaceholder  string
	Kind               string
	Item               string
	Source             string
	Reuse              string
	SourceAnchors      string
	Anchor             string
	Document           string
	Confidence         string
	State              string
	StartupCandidate   string
	DriverRuntimeEntry string
	IOCTLDeviceControl string
	BuildSigning       string
	None               string
	NotInferred        string
}

func analysisDashboardLabelsForRun(run ProjectAnalysisRun) analysisDashboardLabels {
	if textContainsHangul(run.Summary.Goal) || textContainsHangul(run.KnowledgePack.Goal) {
		return analysisDashboardLabels{
			Lang:               "ko",
			Title:              "프로젝트 분석 대시보드",
			RunID:              "Run ID",
			Mode:               "모드",
			Workspace:          "워크스페이스",
			Completed:          "완료 시각",
			Files:              "파일",
			Lines:              "라인",
			Shards:             "샤드",
			Symbols:            "심볼",
			Subsystems:         "서브시스템",
			SecuritySurfaces:   "보안 표면",
			FuzzCandidates:     "Fuzz 후보",
			Entrypoints:        "엔트리포인트",
			CacheReused:        "캐시 재사용",
			CacheMiss:          "캐시 미스",
			GeneratedDocuments: "생성 문서",
			MarkdownViewer:     "마크다운 뷰어",
			ViewerEmpty:        "생성 문서를 선택하면 여기에서 열립니다.",
			DocumentPortal:     "문서 포털",
			PortalPlaceholder:  "문서, anchor, fuzz target, 검증, evidence 검색",
			Kind:               "종류",
			Item:               "항목",
			Source:             "소스",
			Reuse:              "재사용",
			SourceAnchors:      "소스 Anchor",
			Anchor:             "Anchor",
			Document:           "문서",
			Confidence:         "신뢰도",
			State:              "상태",
			StartupCandidate:   "Startup 후보",
			DriverRuntimeEntry: "Driver/runtime entry",
			IOCTLDeviceControl: "IOCTL/device control",
			BuildSigning:       "Build/signing artifact",
			None:               "없음",
			NotInferred:        "추론 안 됨",
		}
	}
	return analysisDashboardLabels{
		Lang:               "en",
		Title:              "Project Analysis Dashboard",
		RunID:              "Run ID",
		Mode:               "Mode",
		Workspace:          "Workspace",
		Completed:          "Completed",
		Files:              "Files",
		Lines:              "Lines",
		Shards:             "Shards",
		Symbols:            "Symbols",
		Subsystems:         "Subsystems",
		SecuritySurfaces:   "Security Surfaces",
		FuzzCandidates:     "Fuzz Candidates",
		Entrypoints:        "Entrypoints",
		CacheReused:        "Cache Reused",
		CacheMiss:          "Cache Miss",
		GeneratedDocuments: "Generated Documents",
		MarkdownViewer:     "Markdown Viewer",
		ViewerEmpty:        "Select a generated document to preview it here.",
		DocumentPortal:     "Document Portal",
		PortalPlaceholder:  "Search docs, anchors, fuzz targets, verification, evidence",
		Kind:               "Kind",
		Item:               "Item",
		Source:             "Source",
		Reuse:              "Reuse",
		SourceAnchors:      "Source Anchors",
		Anchor:             "Anchor",
		Document:           "Document",
		Confidence:         "Confidence",
		State:              "State",
		StartupCandidate:   "Startup candidate",
		DriverRuntimeEntry: "Driver/runtime entry",
		IOCTLDeviceControl: "IOCTL/device control",
		BuildSigning:       "Build/signing artifacts",
		None:               "none",
		NotInferred:        "not inferred",
	}
}

func analysisDashboardInlinePortalItems(items []analysisDashboardPortalItem) []analysisDashboardPortalItem {
	const inlineLimit = 1200
	if len(items) <= inlineLimit {
		return items
	}
	return append([]analysisDashboardPortalItem(nil), items[:inlineLimit]...)
}

func analysisDashboardPortalIndex(run ProjectAnalysisRun, docsHref string) []analysisDashboardPortalItem {
	docsHref = strings.TrimRight(strings.TrimSpace(filepath.ToSlash(docsHref)), "/")
	if docsHref == "" {
		docsHref = "docs"
	}
	items := []analysisDashboardPortalItem{}
	for _, doc := range analysisDashboardGeneratedDocs(run) {
		href := docsHref + "/" + doc.Name
		kind := "document"
		if analysisDashboardIsDeveloperDoc(doc.Name) {
			kind = "developer document"
		}
		items = append(items, analysisDashboardNewPortalItem(kind, doc.Title, analysisDocPurpose(doc.Name), doc.Name, href, doc.ReuseTargets))
		for _, section := range doc.Sections {
			sectionHref := href + "#" + analysisDashboardMarkdownAnchor(section.Title)
			source := strings.Join(limitStrings(section.SourceAnchors, 3), ", ")
			detail := firstNonBlankAnalysisString(section.Confidence, "unknown confidence")
			if len(section.StaleMarkers) > 0 {
				detail += " | stale: " + strings.Join(limitStrings(section.StaleMarkers, 3), "; ")
			}
			items = append(items, analysisDashboardNewPortalItem("section", section.Title, detail, source, sectionHref, section.ReuseTargets))
		}
	}
	for _, target := range limitAnalysisFuzzTargetCatalog(analysisFuzzTargetCatalog(run), 24) {
		detail := strings.Join(limitStrings(target.PriorityReasons, 3), " | ")
		if strings.TrimSpace(target.SuggestedCommand) != "" {
			detail = firstNonBlankAnalysisString(detail, "fuzz target") + " | " + target.SuggestedCommand
		}
		items = append(items, analysisDashboardNewPortalItem("fuzz target", target.Name, detail, target.SourceAnchor, docsHref+"/FUZZ_TARGETS.md", []string{"fuzz_target_discovery", "verification_planner"}))
	}
	for _, row := range analysisVerificationMatrixCatalog(run) {
		source := strings.Join(limitStrings(row.SourceAnchors, 3), ", ")
		detail := row.RequiredVerification
		if strings.TrimSpace(row.OptionalVerification) != "" {
			detail += " | optional: " + row.OptionalVerification
		}
		items = append(items, analysisDashboardNewPortalItem("verification", row.ChangeArea, detail, source, docsHref+"/VERIFICATION_MATRIX.md", []string{"verification_planner", "evidence"}))
	}
	for _, anchor := range analysisDashboardSourceAnchorsWithDocsHref(run, docsHref) {
		items = append(items, analysisDashboardNewPortalItem("source anchor", anchor.Anchor, anchor.Document, anchor.Anchor, anchor.Href, []string{"analysis_context", "evidence"}))
	}
	return items
}

func analysisDashboardGeneratedDocs(run ProjectAnalysisRun) []AnalysisGeneratedDoc {
	names := analysisGeneratedDocNames()
	out := make([]AnalysisGeneratedDoc, 0, len(names))
	generatedAt := analysisDocsGeneratedAt(run)
	for _, name := range names {
		out = append(out, AnalysisGeneratedDoc{
			Name:          name,
			Title:         analysisDocTitle(name),
			Kind:          analysisDocKind(name),
			Path:          name,
			GeneratedAt:   generatedAt,
			SourceAnchors: analysisDocSourceAnchors(run, name),
			Confidence:    analysisDocConfidence(run, name),
			StaleMarkers:  analysisDocStaleMarkers(run, name),
			ReuseTargets:  analysisDocReuseTargets(name),
			Sections:      analysisDocSections(run, name),
		})
	}
	return out
}

func analysisDashboardNewPortalItem(kind string, title string, detail string, source string, href string, reuse []string) analysisDashboardPortalItem {
	item := analysisDashboardPortalItem{
		Kind:   strings.TrimSpace(kind),
		Title:  strings.TrimSpace(title),
		Detail: strings.TrimSpace(detail),
		Source: strings.TrimSpace(filepath.ToSlash(source)),
		Href:   strings.TrimSpace(filepath.ToSlash(href)),
		Reuse:  analysisUniqueStrings(reuse),
	}
	searchParts := []string{item.Kind, item.Title, item.Detail, item.Source, item.Href}
	searchParts = append(searchParts, item.Reuse...)
	item.Search = strings.ToLower(strings.Join(searchParts, " "))
	return item
}

func analysisDashboardPortalRows(items []analysisDashboardPortalItem) string {
	rows := []string{}
	for _, item := range limitAnalysisDashboardPortalItems(items, 18) {
		title := htmlEscape(item.Title)
		if strings.TrimSpace(item.Href) != "" {
			title = `<a ` + analysisDashboardDocLinkAttrs(item.Href) + `>` + title + `</a>`
		}
		detail := ""
		if strings.TrimSpace(item.Detail) != "" {
			detail = `<div class="subtle">` + htmlEscape(item.Detail) + `</div>`
		}
		source := `<span class="subtle">none</span>`
		if strings.TrimSpace(item.Source) != "" {
			source = `<code>` + htmlEscape(item.Source) + `</code>`
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%s%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(item.Kind),
			title,
			detail,
			source,
			analysisDashboardTags(item.Reuse),
		))
	}
	return analysisDashboardFallbackRows(strings.Join(rows, ""), 4, "No document portal index items generated.")
}

func analysisDashboardPortalJSON(items []analysisDashboardPortalItem) string {
	data, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(data)
}

type analysisDashboardDocContent struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Href     string `json:"href"`
	Markdown string `json:"markdown"`
}

func analysisDashboardDocsJSON(run ProjectAnalysisRun, docsHref string) string {
	data, err := json.Marshal(analysisDashboardDocsContent(run, docsHref))
	if err != nil {
		return "[]"
	}
	return string(data)
}

func analysisDashboardDocsContent(run ProjectAnalysisRun, docsHref string) []analysisDashboardDocContent {
	docs := buildAnalysisDocs(run)
	docsHref = analysisDashboardNormalizeDocsHref(docsHref)
	out := []analysisDashboardDocContent{}
	for _, name := range analysisGeneratedDocNames() {
		markdown := strings.TrimSpace(docs[name])
		if markdown == "" {
			continue
		}
		href := docsHref + "/" + name
		out = append(out, analysisDashboardDocContent{
			Name:     name,
			Title:    analysisDocTitle(name),
			Href:     filepath.ToSlash(href),
			Markdown: markdown,
		})
	}
	return out
}

func analysisDashboardJSString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\t", `\t`)
	return value
}

func limitAnalysisDashboardPortalItems(items []analysisDashboardPortalItem, limit int) []analysisDashboardPortalItem {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

type analysisDashboardSourceAnchor struct {
	Anchor     string
	Document   string
	Confidence string
	State      string
	Href       string
}

func analysisDashboardSourceAnchors(run ProjectAnalysisRun) []analysisDashboardSourceAnchor {
	return analysisDashboardSourceAnchorsWithDocsHref(run, "docs")
}

func analysisDashboardSourceAnchorsWithDocsHref(run ProjectAnalysisRun, docsHref string) []analysisDashboardSourceAnchor {
	docsHref = analysisDashboardNormalizeDocsHref(docsHref)
	out := []analysisDashboardSourceAnchor{}
	seen := map[string]struct{}{}
	for _, doc := range analysisDashboardGeneratedDocs(run) {
		for _, anchor := range doc.SourceAnchors {
			anchor = strings.TrimSpace(filepath.ToSlash(anchor))
			if anchor == "" {
				continue
			}
			key := strings.ToLower(doc.Name + "|" + anchor)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			state := analysisDashboardStateLabel(doc.StaleMarkers)
			out = append(out, analysisDashboardSourceAnchor{
				Anchor:     anchor,
				Document:   doc.Name,
				Confidence: firstNonBlankAnalysisString(doc.Confidence, "unknown"),
				State:      state,
				Href:       docsHref + "/" + doc.Name,
			})
		}
		for _, section := range doc.Sections {
			for _, anchor := range section.SourceAnchors {
				anchor = strings.TrimSpace(filepath.ToSlash(anchor))
				if anchor == "" {
					continue
				}
				key := strings.ToLower(doc.Name + "|" + section.ID + "|" + anchor)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				state := analysisDashboardStateLabel(section.StaleMarkers)
				out = append(out, analysisDashboardSourceAnchor{
					Anchor:     anchor,
					Document:   doc.Name + " / " + section.Title,
					Confidence: firstNonBlankAnalysisString(section.Confidence, firstNonBlankAnalysisString(doc.Confidence, "unknown")),
					State:      state,
					Href:       docsHref + "/" + doc.Name + "#" + analysisDashboardMarkdownAnchor(section.Title),
				})
			}
		}
	}
	return out
}

func analysisDashboardSourceAnchorRows(run ProjectAnalysisRun, docsHref string) string {
	rows := []string{}
	for _, anchor := range limitAnalysisDashboardSourceAnchors(analysisDashboardSourceAnchorsWithDocsHref(run, docsHref), 24) {
		rows = append(rows, fmt.Sprintf(`<tr><td><code>%s</code></td><td><a %s>%s</a></td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(anchor.Anchor),
			analysisDashboardDocLinkAttrs(anchor.Href),
			htmlEscape(anchor.Document),
			htmlEscape(anchor.Confidence),
			htmlEscape(anchor.State),
		))
	}
	return strings.Join(rows, "")
}

func analysisDashboardNormalizeDocsHref(docsHref string) string {
	docsHref = strings.TrimRight(strings.TrimSpace(filepath.ToSlash(docsHref)), "/")
	if docsHref == "" {
		return "docs"
	}
	return docsHref
}

func analysisDashboardDocLinkAttrs(href string) string {
	href = strings.TrimSpace(filepath.ToSlash(href))
	return fmt.Sprintf(`href="%s" data-doc-href="%s"`, htmlEscape(href), htmlEscape(href))
}

func analysisDashboardIsMarkdownDocHref(href string) bool {
	href = strings.ToLower(strings.TrimSpace(filepath.ToSlash(href)))
	if hashAt := strings.Index(href, "#"); hashAt >= 0 {
		href = href[:hashAt]
	}
	if queryAt := strings.Index(href, "?"); queryAt >= 0 {
		href = href[:queryAt]
	}
	return strings.HasSuffix(href, ".md")
}

func analysisDashboardArtifactHTML(artifact string) string {
	artifact = filepath.ToSlash(artifact)
	if analysisDashboardIsMarkdownDocHref(artifact) {
		return fmt.Sprintf(`<a %s><code>%s</code></a>`, analysisDashboardDocLinkAttrs(artifact), htmlEscape(artifact))
	}
	return `<code>` + htmlEscape(artifact) + `</code>`
}

func analysisDashboardStateLabel(markers []string) string {
	markers = analysisUniqueStrings(markers)
	if len(markers) == 0 {
		return "fresh"
	}
	nonBaseline := []string{}
	for _, marker := range markers {
		if strings.EqualFold(strings.TrimSpace(marker), "no_previous_run") {
			continue
		}
		nonBaseline = append(nonBaseline, marker)
	}
	if len(nonBaseline) == 0 {
		return "baseline:none"
	}
	return "stale"
}

func limitAnalysisDashboardSourceAnchors(items []analysisDashboardSourceAnchor, limit int) []analysisDashboardSourceAnchor {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func analysisDashboardEvidenceMemoryRows(run ProjectAnalysisRun, docsHref string) string {
	docsHref = strings.TrimRight(strings.TrimSpace(filepath.ToSlash(docsHref)), "/")
	if docsHref == "" {
		docsHref = "docs"
	}
	manifestPath := strings.TrimRight(filepath.Dir(docsHref), "/") + "/docs_manifest.json"
	if strings.HasPrefix(manifestPath, ".") || manifestPath == "/docs_manifest.json" {
		manifestPath = "docs_manifest.json"
	}
	rows := []string{
		analysisDashboardDrilldownRow("analysis docs evidence", manifestPath, "/evidence-search kind:analysis_docs"),
		analysisDashboardDrilldownRow("project memory", docsHref+"/INDEX.md", "/mem-search analyze-project"),
		analysisDashboardDrilldownRow("verification matrix", docsHref+"/VERIFICATION_MATRIX.md", "/verify"),
		analysisDashboardDrilldownRow("fuzz targets", docsHref+"/FUZZ_TARGETS.md", "/fuzz-campaign run"),
	}
	if len(analysisRunStaleMarkers(run)) > 0 {
		rows = append(rows, analysisDashboardDrilldownRow("stale docs refresh", "dashboard stale markers", "/docs-refresh"))
	}
	return strings.Join(rows, "")
}

func analysisDashboardStaleDiffRows(run ProjectAnalysisRun, docsHref string) string {
	docsHref = strings.TrimRight(strings.TrimSpace(filepath.ToSlash(docsHref)), "/")
	if docsHref == "" {
		docsHref = "docs"
	}
	rows := []string{}
	seen := map[string]struct{}{}
	for _, subsystem := range run.KnowledgePack.Subsystems {
		section := canonicalKnowledgeTitle(subsystem)
		doc := analysisDashboardDocForSubsystem(subsystem)
		if len(subsystem.InvalidationDiff) > 0 {
			for _, diff := range limitStrings(subsystem.InvalidationDiff, 4) {
				key := strings.ToLower(section + "|" + diff)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				targetDoc, targetSection := analysisDashboardStaleDiffTarget(doc, section, diff, InvalidationChange{})
				rows = append(rows, analysisDashboardStaleDiffRow(docsHref, section, targetDoc, targetSection, diff, analysisDashboardStaleDiffImpact(subsystem, diff), "/docs-refresh"))
			}
		}
		for _, change := range limitInvalidationChanges(subsystem.InvalidationChanges, 4) {
			diff := renderInvalidationChange(change)
			key := strings.ToLower(section + "|" + diff)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targetDoc, targetSection := analysisDashboardStaleDiffTarget(doc, section, diff, change)
			rows = append(rows, analysisDashboardStaleDiffRow(docsHref, section, targetDoc, targetSection, diff, analysisDashboardInvalidationChangeImpact(change), "/docs-refresh"))
		}
		if len(rows) >= 16 {
			break
		}
	}
	for _, shard := range run.Shards {
		if len(rows) >= 16 {
			break
		}
		section := firstNonBlankAnalysisString(shard.Name, shard.ID)
		doc := analysisDashboardDocForShard(shard)
		for _, diff := range limitStrings(shard.InvalidationDiff, 3) {
			key := strings.ToLower(section + "|" + diff)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targetDoc, targetSection := analysisDashboardStaleDiffTarget(doc, section, diff, InvalidationChange{})
			rows = append(rows, analysisDashboardStaleDiffRow(docsHref, section, targetDoc, targetSection, diff, firstNonBlankAnalysisString(shard.InvalidationReason, "recomputed shard"), "/docs-refresh"))
		}
	}
	return strings.Join(rows, "")
}

func analysisDashboardTrustBoundaryRows(run ProjectAnalysisRun) string {
	edges := analysisDashboardTrustBoundaryEdges(run)
	rows := []string{}
	for _, edge := range limitProjectEdges(edges, 18) {
		boundary := firstNonBlankAnalysisString(edge.Type, edge.Attributes["kind"])
		if attrs := analysisDashboardEdgeAttributeSummary(edge.Attributes); attrs != "" {
			boundary = firstNonBlankAnalysisString(boundary, "boundary") + " / " + attrs
		}
		evidence := strings.Join(limitStrings(edge.Evidence, 3), ", ")
		if strings.TrimSpace(evidence) == "" {
			evidence = firstNonBlankAnalysisString(edge.Attributes["source"], edge.Confidence)
		}
		rows = append(rows, fmt.Sprintf(`<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`,
			htmlEscape(edge.Source),
			htmlEscape(firstNonBlankAnalysisString(boundary, "boundary")),
			htmlEscape(edge.Target),
			htmlEscape(firstNonBlankAnalysisString(evidence, "inferred")),
		))
	}
	return strings.Join(rows, "")
}

func analysisDashboardEdgeAttributeSummary(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	parts := []string{}
	for _, key := range []string{"kind", "flow", "source", "mode", "owner"} {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, " / ")
}

func analysisDashboardTrustBoundaryEdges(run ProjectAnalysisRun) []ProjectEdge {
	candidates := append([]ProjectEdge{}, run.Snapshot.ProjectEdges...)
	candidates = append(candidates, run.KnowledgePack.ProjectEdges...)
	out := []ProjectEdge{}
	for _, edge := range analysisUniqueProjectEdges(candidates) {
		text := strings.ToLower(strings.Join([]string{
			edge.Source,
			edge.Target,
			edge.Type,
			edge.Confidence,
			strings.Join(edge.Evidence, " "),
			edge.Attributes["kind"],
			edge.Attributes["flow"],
		}, " "))
		if containsAny(text, "trust", "security", "integrity", "anti", "tamper", "rpc", "ioctl", "driver", "kernel", "user", "handle", "memory", "telemetry", "configured_by", "runtime_edge") {
			out = append(out, edge)
		}
	}
	return out
}

func analysisDashboardAttackFlowRows(run ProjectAnalysisRun) string {
	flows := analysisDashboardAttackFlows(run)
	rows := []string{}
	for _, flow := range limitAnalysisDashboardAttackFlows(flows, 18) {
		rows = append(rows, fmt.Sprintf(`<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><code class="command-chip">%s</code></td></tr>`,
			htmlEscape(flow.Entry),
			htmlEscape(flow.Flow),
			htmlEscape(flow.Risk),
			htmlEscape(flow.Next),
		))
	}
	return strings.Join(rows, "")
}

type analysisDashboardAttackFlow struct {
	Entry string
	Flow  string
	Risk  string
	Next  string
}

func analysisDashboardAttackFlows(run ProjectAnalysisRun) []analysisDashboardAttackFlow {
	flows := []analysisDashboardAttackFlow{}
	seen := map[string]struct{}{}
	add := func(entry string, flow string, risk string, next string) {
		entry = strings.TrimSpace(entry)
		flow = strings.TrimSpace(flow)
		if entry == "" && flow == "" {
			return
		}
		key := strings.ToLower(entry + "|" + flow + "|" + risk)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		flows = append(flows, analysisDashboardAttackFlow{
			Entry: firstNonBlankAnalysisString(entry, "unknown"),
			Flow:  firstNonBlankAnalysisString(flow, "inferred attack path"),
			Risk:  firstNonBlankAnalysisString(risk, "review required"),
			Next:  firstNonBlankAnalysisString(next, "/verify"),
		})
	}
	for _, target := range limitAnalysisFuzzTargetCatalog(analysisFuzzTargetCatalog(run), 16) {
		entry := firstNonBlankAnalysisString(target.Name, target.SymbolID)
		flow := strings.Join(limitStrings(analysisUniqueStrings(append([]string{target.InputSurfaceKind, target.SourceAnchor}, target.PriorityReasons...)), 4), " -> ")
		risk := firstNonBlankAnalysisString(target.CompileContextWarning, target.HarnessReadiness)
		next := firstNonBlankAnalysisString(target.SuggestedCommand, "/fuzz-campaign run")
		add(entry, flow, risk, next)
	}
	for _, edge := range limitRuntimeEdges(runtimeEdgesForStartup(run.Snapshot.RuntimeEdges, run.Snapshot.PrimaryStartup), 8) {
		flow := fmt.Sprintf("%s -> %s (%s)", edge.Source, edge.Target, firstNonBlankAnalysisString(edge.Kind, "runtime"))
		add(edge.Source, flow, firstNonBlankAnalysisString(edge.Confidence, "medium confidence"), "/analyze-dashboard")
	}
	for _, edge := range limitProjectEdges(analysisDashboardTrustBoundaryEdges(run), 8) {
		flow := fmt.Sprintf("%s -> %s [%s]", edge.Source, edge.Target, firstNonBlankAnalysisString(edge.Type, "boundary"))
		next := "/verify"
		if containsAny(strings.ToLower(flow), "fuzz", "parser", "ioctl", "rpc") {
			next = "/fuzz-campaign run"
		}
		add(edge.Source, flow, firstNonBlankAnalysisString(edge.Confidence, "medium confidence"), next)
	}
	return flows
}

func limitAnalysisDashboardAttackFlows(items []analysisDashboardAttackFlow, limit int) []analysisDashboardAttackFlow {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func analysisDashboardStaleDiffRow(docsHref string, section string, doc string, anchorTitle string, diff string, impact string, command string) string {
	href := analysisDashboardNormalizeDocsHref(docsHref) + "/" + firstNonBlankAnalysisString(doc, "INDEX.md")
	detail := firstNonBlankAnalysisString(doc, "INDEX.md")
	if strings.TrimSpace(anchorTitle) != "" {
		href += "#" + analysisDashboardMarkdownAnchor(anchorTitle)
		detail += " / " + strings.TrimSpace(anchorTitle)
	}
	return fmt.Sprintf(`<tr><td><a %s>%s</a><div class="subtle">%s</div></td><td>%s</td><td>%s</td><td><code class="command-chip">%s</code></td></tr>`,
		analysisDashboardDocLinkAttrs(href),
		htmlEscape(firstNonBlankAnalysisString(section, "analysis section")),
		htmlEscape(detail),
		htmlEscape(diff),
		htmlEscape(impact),
		htmlEscape(command),
	)
}

func analysisDashboardStaleDiffTarget(fallbackDoc string, section string, diff string, change InvalidationChange) (string, string) {
	text := strings.ToLower(strings.Join([]string{
		fallbackDoc,
		section,
		diff,
		change.Kind,
		change.Scope,
		change.Owner,
		change.Subject,
		change.Before,
		change.After,
		change.Source,
	}, " "))
	switch {
	case containsAny(text, "trust_boundary", "trust boundary", "security_signal", "security_action", "ioctl", "kernel", "driver", "tamper", "integrity", "handle"):
		return "SECURITY_SURFACE.md", "Trust Boundary Graph"
	case containsAny(text, "rpc", "packet", "parser", "telemetry", "attack", "input"):
		return "SECURITY_SURFACE.md", "Attack And Data Flow View"
	case containsAny(text, "replicated", "config_binding", "configured_by", "asset", "runtime", "dependency", "data_flow", "data-flow", "flow"):
		return "ARCHITECTURE.md", "Data Flow Graph"
	case containsAny(text, "edge_added", "edge_removed", "edge changed", "edge_changed"):
		return "ARCHITECTURE.md", "Project Edges"
	default:
		return firstNonBlankAnalysisString(fallbackDoc, "INDEX.md"), ""
	}
}

func analysisDashboardDocForSubsystem(subsystem KnowledgeSubsystem) string {
	text := strings.ToLower(strings.Join([]string{
		subsystem.Title,
		subsystem.Group,
		strings.Join(subsystem.Responsibilities, " "),
		strings.Join(subsystem.EntryPoints, " "),
		strings.Join(subsystem.Risks, " "),
		strings.Join(subsystem.KeyFiles, " "),
		strings.Join(subsystem.EvidenceFiles, " "),
	}, " "))
	switch {
	case containsAny(text, "fuzz", "parser", "ioctl", "rpc", "telemetry", "deserialize"):
		return "FUZZ_TARGETS.md"
	case containsAny(text, "verify", "build", "sign", "symbol", "driver verifier"):
		return "VERIFICATION_MATRIX.md"
	case containsAny(text, "security", "driver", "ioctl", "handle", "memory", "anti", "tamper"):
		return "SECURITY_SURFACE.md"
	case containsAny(text, "api", "entry", "endpoint", "dispatch"):
		return "API_AND_ENTRYPOINTS.md"
	default:
		return "ARCHITECTURE.md"
	}
}

func analysisDashboardDocForShard(shard AnalysisShard) string {
	text := strings.ToLower(strings.Join([]string{shard.Name, shard.ID, strings.Join(shard.PrimaryFiles, " "), strings.Join(shard.ReferenceFiles, " ")}, " "))
	switch {
	case containsAny(text, "fuzz", "parser", "ioctl", "rpc"):
		return "FUZZ_TARGETS.md"
	case containsAny(text, "verify", "build", "test"):
		return "VERIFICATION_MATRIX.md"
	case containsAny(text, "security", "driver", "integrity", "hook"):
		return "SECURITY_SURFACE.md"
	default:
		return "ARCHITECTURE.md"
	}
}

func analysisDashboardStaleDiffImpact(subsystem KnowledgeSubsystem, diff string) string {
	parts := []string{}
	if len(subsystem.InvalidationReasons) > 0 {
		parts = append(parts, strings.Join(limitStrings(describeAnalysisInvalidationReasonsWithContext(subsystem.InvalidationReasons, subsystem.ShardNames, 3), 3), " | "))
	}
	if len(subsystem.EntryPoints) > 0 {
		parts = append(parts, "entrypoints="+strings.Join(limitStrings(subsystem.EntryPoints, 2), ", "))
	}
	if len(subsystem.Risks) > 0 {
		parts = append(parts, "risk="+limitStrings(subsystem.Risks, 1)[0])
	}
	if len(parts) == 0 {
		parts = append(parts, firstNonBlankAnalysisString(diff, "stale generated section"))
	}
	return strings.Join(parts, " | ")
}

func analysisDashboardInvalidationChangeImpact(change InvalidationChange) string {
	parts := []string{}
	if strings.TrimSpace(change.Scope) != "" {
		parts = append(parts, "scope="+change.Scope)
	}
	if strings.TrimSpace(change.Owner) != "" {
		parts = append(parts, "owner="+change.Owner)
	}
	if strings.TrimSpace(change.Subject) != "" {
		parts = append(parts, "subject="+change.Subject)
	}
	if strings.TrimSpace(change.Source) != "" {
		parts = append(parts, "source="+filepath.ToSlash(change.Source))
	}
	if len(parts) == 0 {
		parts = append(parts, firstNonBlankAnalysisString(change.Kind, "structured invalidation change"))
	}
	return strings.Join(parts, " | ")
}

func analysisDashboardDrilldownRow(context string, artifact string, command string) string {
	return fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><code class="command-chip">%s</code></td></tr>`,
		htmlEscape(context),
		analysisDashboardArtifactHTML(artifact),
		htmlEscape(command),
	)
}

func analysisDashboardMarkdownAnchor(title string) string {
	title = strings.ToLower(strings.TrimSpace(title))
	var b strings.Builder
	lastDash := false
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func analysisDashboardCacheCounts(shards []AnalysisShard) (int, int) {
	reused := 0
	missed := 0
	for _, shard := range shards {
		if shard.CacheStatus == "reused" {
			reused++
		} else {
			missed++
		}
	}
	return reused, missed
}

func analysisDashboardDocLinks(run ProjectAnalysisRun, docsHref string) string {
	docsHref = analysisDashboardNormalizeDocsHref(docsHref)
	names := analysisGeneratedDocNames()
	items := []string{}
	for _, name := range names {
		href := strings.TrimRight(docsHref, "/") + "/" + name
		badges := []string{
			`<span class="tag">confidence:` + htmlEscape(firstNonBlankAnalysisString(analysisDocConfidence(run, name), "unknown")) + `</span>`,
		}
		if markers := analysisDocStaleMarkers(run, name); len(markers) > 0 {
			state := analysisDashboardStateLabel(markers)
			label := state
			if state == "stale" {
				label = "stale:" + fmt.Sprintf("%d", len(markers))
			}
			badges = append(badges, `<span class="tag">`+htmlEscape(label)+`</span>`)
		}
		if sections := analysisDocSections(run, name); len(sections) > 0 {
			badges = append(badges, `<span class="tag">sections:`+htmlEscape(fmt.Sprintf("%d", len(sections)))+`</span>`)
		}
		if analysisDashboardIsDeveloperDoc(name) {
			badges = append([]string{`<span class="tag">developer_docs</span>`}, badges...)
		}
		items = append(items, fmt.Sprintf(`<a class="doc-link" %s><strong>%s</strong><div class="subtle">%s</div><div>%s</div></a>`, analysisDashboardDocLinkAttrs(href), htmlEscape(analysisDocTitle(name)), htmlEscape(analysisDocPurpose(name)), strings.Join(badges, "")))
	}
	return strings.Join(items, "")
}

func analysisDashboardIsDeveloperDoc(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DEVELOPER_OVERVIEW.MD", "FOLDER_MAP.MD", "MODULES.MD", "STRUCTURE_DIAGRAMS.MD", "CODE_STRUCTURE_REFERENCE.MD":
		return true
	default:
		return false
	}
}

func analysisDashboardSubsystems(subsystems []KnowledgeSubsystem) string {
	if len(subsystems) == 0 {
		return `<div class="empty">No subsystem records found.</div>`
	}
	items := []string{}
	for _, subsystem := range subsystems {
		title := canonicalKnowledgeTitle(subsystem)
		tags := []string{}
		for _, item := range limitStrings(analysisUniqueStrings(append(subsystem.CacheStatuses, subsystem.InvalidationReasons...)), 5) {
			tags = append(tags, `<span class="tag">`+htmlEscape(item)+`</span>`)
		}
		items = append(items, fmt.Sprintf(`<article class="subsystem"><h3>%s</h3><div class="subtle">%s</div><div>%s</div><div class="subtle">Entry: %s</div><div class="subtle">Files: %s</div></article>`,
			htmlEscape(title),
			htmlEscape(valueOrDefault(subsystem.Group, "Ungrouped")),
			strings.Join(tags, ""),
			htmlEscape(strings.Join(limitStrings(subsystem.EntryPoints, 5), ", ")),
			htmlEscape(strings.Join(limitStrings(subsystem.KeyFiles, 6), ", ")),
		))
	}
	return strings.Join(items, "")
}

func analysisDashboardSymbolRows(symbols []SymbolRecord, mode string) string {
	rows := []string{}
	for _, symbol := range symbols {
		rows = append(rows, fmt.Sprintf(`<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(valueOrDefault(symbol.Name, symbol.CanonicalName)),
			htmlEscape(symbol.Kind),
			htmlEscape(symbol.File),
			analysisDashboardTags(symbol.Tags),
		))
	}
	_ = mode
	return strings.Join(rows, "")
}

func analysisDashboardFuzzRows(targets []AnalysisFuzzTargetCatalogEntry) string {
	rows := []string{}
	for _, target := range targets {
		display := `<code>` + htmlEscape(target.Name) + `</code>`
		if strings.TrimSpace(target.SourceAnchor) != "" {
			display += `<div class="subtle">` + htmlEscape(target.SourceAnchor) + `</div>`
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`,
			target.PriorityScore,
			display,
			htmlEscape(firstNonBlankAnalysisString(target.InputSurfaceKind, "unknown")),
			htmlEscape(firstNonBlankAnalysisString(target.HarnessReadiness, "unknown")),
			htmlEscape(target.SuggestedCommand),
		))
	}
	return strings.Join(rows, "")
}

func analysisDashboardVerificationRows(rows []AnalysisVerificationMatrixEntry) string {
	out := []string{}
	for _, row := range rows {
		out = append(out, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, htmlEscape(row.ChangeArea), htmlEscape(row.RequiredVerification), htmlEscape(row.OptionalVerification), htmlEscape(row.EvidenceHook)))
	}
	return analysisDashboardFallbackRows(strings.Join(out, ""), 4, "No verification rows generated.")
}

func analysisDashboardStaleRows(run ProjectAnalysisRun) string {
	rows := []string{}
	for _, marker := range analysisRunStaleMarkers(run) {
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>analysis execution</td></tr>`, htmlEscape(marker)))
	}
	return strings.Join(rows, "")
}

func analysisDashboardBuildRows(contexts []BuildContextRecord, commands []CompilationCommandRecord) string {
	rows := []string{}
	for _, ctx := range contexts {
		coverage := fmt.Sprintf("%d file(s)", len(ctx.Files))
		if ctx.Compiler != "" {
			coverage += ", " + ctx.Compiler
		}
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, htmlEscape(valueOrDefault(ctx.Kind, "context")), htmlEscape(valueOrDefault(ctx.Name, ctx.ID)), htmlEscape(coverage)))
	}
	for _, cmd := range commands {
		name := valueOrDefault(cmd.File, cmd.Output)
		coverage := valueOrDefault(cmd.Compiler, cmd.Source)
		rows = append(rows, fmt.Sprintf(`<tr><td>compile command</td><td>%s</td><td>%s</td></tr>`, htmlEscape(name), htmlEscape(coverage)))
	}
	return strings.Join(rows, "")
}

func analysisDashboardRuntimeLensPanel(run ProjectAnalysisRun, labels analysisDashboardLabels) string {
	cards := []string{}
	add := func(label string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			value = labels.None
		}
		cards = append(cards, fmt.Sprintf(`<div class="lens"><span>%s</span><strong>%s</strong></div>`, htmlEscape(label), htmlEscape(value)))
	}
	add(labels.StartupCandidate, firstNonBlankAnalysisString(run.Snapshot.PrimaryStartup, labels.NotInferred))
	driverEntries := driverEntrypointFiles(run)
	driverEntryItems := append([]string{}, driverEntries...)
	for _, symbol := range run.SemanticIndexV2.Symbols {
		if strings.Contains(strings.ToLower(firstNonBlankAnalysisString(symbol.CanonicalName, symbol.Name)), "driverentry") {
			driverEntryItems = append(driverEntryItems, firstNonBlankDeveloperString(symbol.CanonicalName, symbol.Name, symbol.File))
		}
	}
	add(labels.DriverRuntimeEntry, strings.Join(limitStrings(analysisUniqueStrings(driverEntryItems), 3), ", "))
	ioctlSymbols := developerIOCTLSymbols(run)
	ioctlNames := []string{}
	for _, symbol := range limitSymbolRecords(ioctlSymbols, 3) {
		ioctlNames = append(ioctlNames, firstNonBlankDeveloperString(symbol.CanonicalName, symbol.Name, symbol.ID))
	}
	add(labels.IOCTLDeviceControl, strings.Join(ioctlNames, ", "))
	artifacts := analysisDashboardBuildArtifactSummary(run)
	add(labels.BuildSigning, artifacts)
	return `<section class="lens-grid">` + strings.Join(cards, "") + `</section>`
}

func analysisDashboardBuildArtifactSummary(run ProjectAnalysisRun) string {
	items := []string{}
	for _, file := range run.Snapshot.ManifestFiles {
		if containsAny(strings.ToLower(file), ".vcxproj", ".sln", ".inf", ".ddf", ".bat", ".cmd") {
			items = append(items, filepath.ToSlash(file))
		}
	}
	for _, file := range run.KnowledgePack.TopImportantFiles {
		if containsAny(strings.ToLower(file), ".vcxproj", ".sln", ".inf", ".ddf", ".bat", "sign", "cab", "vmp") {
			items = append(items, filepath.ToSlash(file))
		}
	}
	return strings.Join(limitStrings(analysisUniqueStrings(items), 3), ", ")
}

func analysisDashboardList(items []string, limit int) string {
	items = limitStrings(analysisUniqueStrings(items), limit)
	if len(items) == 0 {
		return ""
	}
	rows := []string{}
	for _, item := range items {
		rows = append(rows, `<li><code>`+htmlEscape(item)+`</code></li>`)
	}
	return `<ul class="list">` + strings.Join(rows, "") + `</ul>`
}

func analysisDashboardTags(tags []string) string {
	if len(tags) == 0 {
		return `<span class="subtle">none</span>`
	}
	out := []string{}
	for _, tag := range limitStrings(tags, 6) {
		out = append(out, `<span class="tag">`+htmlEscape(tag)+`</span>`)
	}
	return strings.Join(out, "")
}

func analysisDashboardFallbackPanel(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return `<div class="empty">` + htmlEscape(fallback) + `</div>`
	}
	return value
}

func analysisDashboardFallbackRows(value string, colspan int, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fmt.Sprintf(`<tr><td colspan="%d" class="empty">%s</td></tr>`, colspan, htmlEscape(fallback))
	}
	return value
}
