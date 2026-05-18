# Kernforge 소스 코드 퍼징 강화 플랜

작성 기준일: 2026-05-18
마지막 갱신: 2026-05-18 (P0-1 ~ P0-3 구현 완료)

이 문서는 Kernforge의 소스 코드 기반 퍼징(`/fuzz-func`, `/fuzz-campaign`) 기능을 현재 코드 상태에서 어떻게 강화할지 정리한 플랜이다. 상위 GAP 분석 문서(`FUZZING_SECURITY_TOOLS_GAP_ANALYSIS_kor.md`)와 `ROADMAP_kor.md`의 "Fuzzing Workbench" 항목을 받아, 실제 소스 위치 기반의 실행 계획으로 좁힌다.

## 진행 상태 요약

| 항목 | 상태 | 비고 |
| --- | --- | --- |
| P0-1 source-derived dictionary | ✅ 완료 | `functionFuzzWriteDictionary`, `<artifact_dir>/dict.txt`, libFuzzer `-dict=` 자동 부착 |
| P0-2 deterministic boundary corpus | ✅ 완료 | parameter class별 boundary seed + `<artifact_dir>/corpus_manifest.json` |
| P0-3 multi-stage run profile | ✅ 완료 | `smoke/extended/repro/minimize` + `/fuzz-func continue --profile`, `/fuzz-func repro`, `/fuzz-func minimize` 서브커맨드 |
| P0-4 sanitizer 로그 파서 | ⏳ 대기 | 다음 단계 |
| P1 이후 | ⏳ 대기 | `/fuzz-crash`, `/fuzz-corpus`, AFL++ wrapper, coverage plateau detector |

연관 문서:
- [FUZZING_SECURITY_TOOLS_GAP_ANALYSIS_kor.md](FUZZING_SECURITY_TOOLS_GAP_ANALYSIS_kor.md): 외부 도구 대비 격차 분석
- [ROADMAP_kor.md](ROADMAP_kor.md): P0 Fuzzing Workbench 마일스톤
- [PROJECT_ANALYSIS_NEXT_SPEC_kor.md](PROJECT_ANALYSIS_NEXT_SPEC_kor.md): 분석 산출물에서 fuzz 후보로 이어지는 흐름

## 1. 현황 진단

### 강점

- 소스 단위 fuzz 후보 발굴이 두텁다. [`commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go)는 symbol, overlay domain, parameter strategy, sink signal, code observation(`copy_sink`, `probe_sink`, `dispatch_guard`, `size_guard`, `alloc_site`, `cleanup_path`, `state_publish`), branch outcome, virtual scenario를 plan 자료구조로 누적한다.
- 산출물 형식이 정형화돼 있다. `plan.json`, `report.md`, `harness.cpp`와 `.kernforge/fuzz/<campaign-id>/{corpus,crashes,coverage,reports,logs}` 표준이 존재한다.
- Campaign artifact graph와 finding dedup이 1급. [`fuzz_campaign.go:597`](cmd/kernforge/fuzz_campaign.go:597) `fuzzCampaignFindingDedupKey`, [`fuzz_campaign.go:914`](cmd/kernforge/fuzz_campaign.go:914) `buildFuzzCampaignArtifactGraph`가 native result, evidence, source anchor, verification gate, tracked feature gate를 한 그래프로 묶는다.
- Coverage gap inference와 docs catalog feedback이 이미 들어가 있다. `FUZZ_TARGETS.md` 랭킹이 다음 라운드 분석에 재사용된다.

### 한계

- **엔진 선택지가 사실상 하나다.** [`commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `functionFuzzBuildExecutionArgs`는 `clang`/`clang-cl`만 지원하고 결과적으로 `libFuzzer + ASan/UBSan` 단일 프로필이다. AFL++/WinAFL/honggfuzz는 plan의 `secondary_engines`/`notes`에만 등장하고 실제 wrapper가 없다.
- ~~**Fuzz 실행이 "한 번 짧게" 모델이다.**~~ → **P0-3 완료**: `Execution.Profile` 필드 + `functionFuzzRunArgs` 분기로 `smoke(20s) / extended(600s, fork=2) / repro(-runs=1 -error_exitcode=88) / minimize(-minimize_crash=1)` 4가지 프로필을 지원한다. 단, background shell job 하나로 실행한 뒤 crash dir 파일 개수만 폴링하는 구조 자체는 동일하다.
- ~~**Corpus 라이프사이클이 없다.**~~ → **P0-2 완료**: `functionFuzzWriteSeedCorpusWithProvenance`가 parameter class별 boundary seed + scenario별 seed를 결정적으로 생성하고 `corpus_manifest.json`에 sha256/규칙/소스 위치를 기록한다. 단, `-merge=1` dedup wrapper, replay, import provenance(외부 corpus 흡수)는 아직 없다.
- **Crash triage가 native 단계에서 부분 적용**. → **P0-3 일부 완료**: `/fuzz-func repro <id> [--input <crash>]`, `/fuzz-func minimize <id> [--input <crash>]` 서브커맨드가 추가됐다. 단, bucket(top-3 frame hash 등)과 promote(finding 승격)는 별도 `/fuzz-crash` 명령군에서 처리할 예정.
- **Sanitizer/libFuzzer 로그 파서가 없다.** `BuildLogPath`/`RunLogPath`를 tee로 받지만 `ERROR: AddressSanitizer:`, `SUMMARY: libFuzzer:`, UBSan `runtime error:` 같은 신호를 정규화해 fingerprint로 묶는 경로가 없다. (다음 단계 — P0-4)
- ~~**Source 사실 -> fuzz 자산 변환이 아깝다.**~~ → **P0-1 완료**: `functionFuzzWriteDictionary`가 `code_observations`, `sink_signals`, `parameter_strategies`, `virtual_scenarios`에서 정수 상수(+2/4/8바이트 LE 인코딩), 문자열 리터럴, ALL_CAPS 식별자를 추출해 libFuzzer dict로 떨어뜨리고, `functionFuzzRunArgs`가 `-dict=` 를 자동 부착한다. 단, structure-aware grammar(LPM/Protobuf)는 P2.

## 2. 차별화 축

일반 fuzz 엔진이 약하고 Kernforge가 잘하는 영역에 자원을 집중한다.

1. **소스 사실 -> fuzz 자산 변환**
   - enum/magic/IOCTL code/`STATUS_*`/format token을 dictionary로 결정적으로 떨어뜨린다.
   - struct layout(packed/aligned, length-prefix)을 grammar 또는 LPM/Protobuf 스키마로 떨어뜨린다.
   - guard predicate(`if (len > N) return`, `if (header != MAGIC) return`)에서 boundary value 코퍼스를 생성한다.

2. **소스 invariant -> runtime oracle**
   - `code_observations`의 size guard/cleanup path/state publish 조건을 harness에 추가 assertion으로 emit해서 crash 없는 invariant 위반도 잡는다.

3. **Windows/anti-cheat first-class**
   - IOCTL dispatch tree, ETW provider schema, Unreal RPC unpack 같은 도메인 grammar는 일반 엔진이 흉내내기 어렵다.

## 3. 우선순위별 강화 방안

### P0 — 한 PR 단위로 즉시 가치가 나오는 항목

1. ✅ **Source-derived dictionary 자동 생성** — 구현 완료 (2026-05-18)
   - 새 파일 [`cmd/kernforge/commands_fuzz_func_corpus.go`](cmd/kernforge/commands_fuzz_func_corpus.go) `functionFuzzWriteDictionary`가 `code_observations`(`size_guard/dispatch_guard/alloc_site/copy_sink/probe_sink` 우선), `sink_signals`, `parameter_strategies`, `virtual_scenarios.{Title, ConcreteInputs, BranchFacts, Invariants, BranchOutcomes, SourceExcerpt.Snippet}`를 순회해 `<artifact_dir>/dict.txt`를 libFuzzer 포맷(`label="..."`)으로 emit한다.
   - 추출 대상:
     - 정수 상수 hex 텍스트 (`"0x1000"`) + 2/4/8바이트 little-endian 인코딩 (`"\x00\x10\x00\x00"` 등)
     - 문자열 리터럴 (큰따옴표 안의 ASCII)
     - ALL_CAPS 식별자 (`STATUS_BUFFER_TOO_SMALL`, `IOCTL_DEVICE_INIT`, `NTSTATUS_*` 등)
   - 우선순위 기반 정렬, dedup, 최대 256개 캡.
   - [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `functionFuzzRunArgs`가 `Execution.DictionaryPath`가 비어있지 않을 때만 `-dict=<dict.txt>`를 자동 부착한다. dict가 emit할 게 없으면 파일 자체를 만들지 않고 `DictionaryPath`를 클리어한다.

2. ✅ **Deterministic boundary corpus** — 구현 완료 (2026-05-18)
   - [`cmd/kernforge/commands_fuzz_func_corpus.go`](cmd/kernforge/commands_fuzz_func_corpus.go) `functionFuzzWriteSeedCorpusWithProvenance`가 기존 3개 하드코드 seed를 교체한다.
   - baseline 3개(`seed-empty.bin`, `seed-pattern.bin`, `seed-length-prefix.bin`)에 더해 parameter class별로 seed를 결정적으로 생성:
     - `length / scalar_int`: `zero / one / max-u32 / max-minus-1 / signed-min / signed-max / off-by-one / very-large`
     - `buffer / pointer / string / opaque`: `empty / byte-one / short-header / null-term-injected / oversized-4k / very-large-64k / ascii-path-like / format-tokens`
     - `enum_or_flags`: `zero / all-bits / high-bit / single-bit / dense-bits`
     - `handle`: `zero / invalid-handle / pseudo-handle`
     - `boolean / scalar_float / container`: 각 클래스별 대표값
   - `virtual_scenarios`(상위 8개)에서 `ConcreteInputs`/`BranchFacts`/제목을 합쳐 `seed-scenario-XX-<slug>.bin`도 떨군다.
   - 파일명은 `seed-param-<idx>-<param-name>-<rule>.bin`, `seed-scenario-XX-<slug>.bin`으로 통일.
   - `<artifact_dir>/corpus_manifest.json`에 각 seed의 `{name, rule, param_class, param_name, scenario, size, sha256, origin, source_file, source_line, description}`과 사용된 dictionary 토큰을 함께 기록한다.

3. ✅ **Multi-stage run profile (smoke / extended / repro / minimize)** — 구현 완료 (2026-05-18)
   - `FunctionFuzzExecution`에 `Profile`, `DictionaryPath`, `CorpusManifestPath`, `CrashInputPath` 4개 필드 추가, `normalizeFunctionFuzzExecution`에서 화이트리스트 검증.
   - `functionFuzzRunArgs`가 profile별로 분기:
     - `smoke`: `-max_total_time=20 -timeout=5 -print_final_stats=1` (기존 동작 유지, CI 친화)
     - `extended`: `-max_total_time=600 -timeout=15 -fork=2 -ignore_crashes=1 -print_corpus_stats=1`
     - `repro`: 단일 crash 입력을 positional arg로, `-runs=1 -timeout=30 -error_exitcode=88`
     - `minimize`: `-minimize_crash=1 -runs=100000 -timeout=30` + crash 입력
   - CLI 서브커맨드 추가:
     - `/fuzz-func continue [<id>] [--profile smoke|extended|repro|minimize]` — 기존 continue + profile 전환
     - `/fuzz-func repro [<id>] [--input <crash>]` — repro 프로필로 재실행 (crash 경로 미지정 시 crash dir 첫 파일 자동 선택)
     - `/fuzz-func minimize [<id>] [--input <crash>]` — minimize 프로필
   - 프로필 전환 시 `functionFuzzApplyProfile`이 `Execution.RunArgv/RunCommand`를 다시 빌드하고 PowerShell runner script(`run_fuzz.ps1`)를 갱신한 뒤 background job을 재시작한다.

4. ⏳ **Sanitizer / libFuzzer 로그 파서 -> finding 정규화** — 다음 작업
   - 새 파일 `cmd/kernforge/commands_fuzz_func_log_parser.go`에 파서 추가.
   - 패턴:
     - `==N==ERROR: AddressSanitizer: <kind>`
     - `SUMMARY: AddressSanitizer: <kind> <addr> in <func>`
     - `SUMMARY: libFuzzer: <kind>`
     - UBSan `<file>:<line>:<col>: runtime error: <msg>`
   - 결과(sanitizer kind, top-3 frame, source:line, raw summary)를 [`fuzz_campaign.go:510`](cmd/kernforge/fuzz_campaign.go:510) finding 정규화 경로로 흘려서 `fuzzCampaignFindingDedupKey` fingerprint가 채워지게 한다.

### P1 — 다음 마일스톤 단위

5. **`/fuzz-crash` 명령군 신설** (`list | repro | minimize | bucket | promote`)
   - `bucket` 키: (sanitizer kind, top-3 frame hash, source:line).
   - `promote`는 crash를 `investigation finding`으로 승격하고 persistent memory feedback과 evidence graph에 연결한다.

6. **`/fuzz-corpus` 명령군** (`list | import | dedup | minimize | replay`)
   - 1차로 libFuzzer `-merge=1` wrapper 하나만 만들어도 dedup/minimize가 동시에 해결된다.
   - import 시 sha256/size/source/sensitive 플래그를 corpus manifest에 기록한다.

7. **AFL++ wrapper** (옵셔널 빌드)
   - [`commands_fuzz_func.go:9818`](cmd/kernforge/commands_fuzz_func.go:9818) `functionFuzzBuildExecutionArgs`에 `style == "afl-clang-fast"`를 추가한다.
   - `LLVMFuzzerTestOneInput` 시그니처는 유지하고 persistent mode 매크로만 emit한다.
   - run 명령은 `afl-fuzz -i corpus -o out -- ./harness @@` 형태로 분리한다.
   - Windows는 WSL 또는 Linux remote build를 1차 지원한다.

8. **Coverage trend & plateau detector**
   - [`fuzz_campaign.go`](cmd/kernforge/fuzz_campaign.go)의 `collectFuzzCampaignCoverageReports`가 cumulative edge count time series를 manifest에 적도록 확장한다.
   - plateau 판정 (예: 5분간 +0.5% 미만)이면 `proactive_suggestions`에 dictionary 보강 / seed 추가 / target split 추천을 등록한다.

### P2 — Kernforge 진짜 해자

9. **IOCTL grammar DSL**
   - YAML 또는 JSON 한 포맷으로 device path, IOCTL code, METHOD_BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER, 입출력 버퍼 필드 스키마, handle lifecycle, privilege requirement를 표현한다.
   - source-scan이 dispatch table을 보고 grammar 초안을 emit하고, 사용자가 검토한 뒤 `/fuzz-driver run`이 실행한다.
   - VM snapshot/revert 훅과 bugcheck/WER 캡처는 별도 P2지만 grammar 자체가 우선이다.

10. **Static <-> Fuzz 양방향 루프**
    - Static finding(root cause pattern hit, security overlay)에서 함수 시그니처를 추출해 `/fuzz-func --from-finding <id>`로 자동 생성한다.
    - Crash fingerprint(파일:라인, sink kind)에서 Semgrep/CodeQL 초안 query를 emit한다.
    - 이미 `root_cause_patterns` 인프라가 있으므로 연결만 하면 된다.

11. **Long-running fuzz daemon + PR gate**
    - `kernforge fuzz-daemon` 백그라운드: campaign queue, workers, checkpoint, coverage tail event를 `.kernforge/events/<session>.jsonl`로 emit한다.
    - PR gate는 regression corpus replay + 짧은 smoke만 통과 조건으로 둔다.

## 4. 실제로 손댈 코드 지점

### 완료된 항목 (P0-1 ~ P0-3)

| 변경 | 실제 위치 | 상태 |
| --- | --- | --- |
| Dictionary emit | [`cmd/kernforge/commands_fuzz_func_corpus.go`](cmd/kernforge/commands_fuzz_func_corpus.go) `functionFuzzWriteDictionary` + `functionFuzzCollectDictionaryEntries` | ✅ |
| Boundary corpus + manifest | [`cmd/kernforge/commands_fuzz_func_corpus.go`](cmd/kernforge/commands_fuzz_func_corpus.go) `functionFuzzWriteSeedCorpusWithProvenance` + `functionFuzzBuildBoundarySeeds` + `functionFuzzSeedsForParameter` + `functionFuzzSeedsForScenario` | ✅ |
| Run profile 분기 | [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `functionFuzzRunArgs` (smoke/extended/repro/minimize 4분기) | ✅ |
| Profile 필드 + normalize | [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `FunctionFuzzExecution`에 `Profile`, `DictionaryPath`, `CorpusManifestPath`, `CrashInputPath` 추가 + `normalizeFunctionFuzzExecution`에서 화이트리스트 검증 | ✅ |
| Plan execution 배선 | [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `planFunctionFuzzExecution`이 dict → corpus(+manifest) → runner script 순으로 생성, `functionFuzzEnsureExecutionArtifactDirs`도 dict/manifest 디렉터리 포함 | ✅ |
| Repro/minimize CLI | [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `handleFuzzFuncCommand` switch + `handleFunctionFuzzContinue`(–profile 파싱) + `handleFunctionFuzzReplayProfile` + `functionFuzzApplyProfile` + `functionFuzzResolveCrashInput` | ✅ |
| Completion 라벨 | [`cmd/kernforge/completion.go`](cmd/kernforge/completion.go) `fuzz-func` 서브커맨드 맵에 `repro`/`minimize`/`continue --profile extended` 항목 추가 | ✅ |
| 단위 테스트 | [`cmd/kernforge/commands_fuzz_func_corpus_test.go`](cmd/kernforge/commands_fuzz_func_corpus_test.go) — dict 출력/공집합 처리, manifest 결정성/sha256, profile 분기, `--profile`/`--input` 파서 7개 케이스 | ✅ |

### 남은 항목

| 변경 | 위치 |
| --- | --- |
| Sanitizer parser | 새 파일 `cmd/kernforge/commands_fuzz_func_log_parser.go` + [`cmd/kernforge/fuzz_campaign.go:510`](cmd/kernforge/fuzz_campaign.go:510) finding 정규화 호출 |
| 엔진 style 추가 (AFL++) | [`cmd/kernforge/commands_fuzz_func.go`](cmd/kernforge/commands_fuzz_func.go) `functionFuzzBuildExecutionArgs` 분기 |
| `/fuzz-crash`, `/fuzz-corpus` 등록 | [`cmd/kernforge/main.go:6334`](cmd/kernforge/main.go:6334) 인근 case 추가 + [`cmd/kernforge/completion.go`](cmd/kernforge/completion.go) 라벨 |
| MCP 노출 | [`cmd/kernforge/mcp_server.go:633`](cmd/kernforge/mcp_server.go:633) `kernforge_fuzz_func` 옆에 새 tool |

## 5. 첫 한 입 — 구현 완료

원래 계획했던 "권장 첫 한 입" 묶음(P0-1 + P0-2 + P0-3)이 2026-05-18에 한 묶음으로 들어갔다. `commands_fuzz_func_corpus.go`(신규)에 dict/boundary corpus 생성을, `commands_fuzz_func.go`에 profile 분기와 신규 서브커맨드를 배선했고, `commands_fuzz_func_corpus_test.go`로 7개 단위 테스트를 추가했다. 전체 패키지 테스트(`go test ./cmd/kernforge/`)는 통과한다.

다음 한 입은 P0-4 sanitizer/libFuzzer 로그 파서다. crash가 떨어졌을 때 fingerprint(top-3 frame + source:line + sanitizer kind)를 추출해 campaign manifest의 `fuzzCampaignFindingDedupKey`에 흘려야 native + source 양쪽 dedup이 채워진다. 이게 들어가면 `/fuzz-crash` 명령군의 `bucket`/`promote` 도 자연스럽게 따라온다.

## 6. 성공 조건 진척도

1. ✅ `/fuzz-func`가 dict + boundary corpus를 결정적으로 떨어뜨리고, dict 변화가 corpus manifest의 `dictionary` 필드에 남는다. 단위 테스트 `TestFunctionFuzzWriteSeedCorpusWithProvenanceProducesBoundarySeeds`가 결정성과 sha256 일치를 검증한다.
2. 🟡 `/fuzz-func continue <id> --profile extended`로 background job 진입까지는 들어갔다. 단, plateau detector(`+0.5% 미만 5분`)는 P1 항목이라 아직 없다.
3. 🟡 `/fuzz-func minimize <id> --input <crash>` + `/fuzz-func repro <id> --input <crash>`로 crash 입력을 minimize/repro까지 끌고 가는 흐름은 완성. 단, sanitizer fingerprint 자동 dedup은 P0-4 sanitizer parser 차례.
4. ⏳ AFL++ 빌드 옵션 부재 시 조용한 비활성화 동작은 P1 wrapper 작업과 함께.

## 7. 운영 주의점

- 모든 run은 binary hash, corpus hash, sanitizer/verifier 옵션, dictionary hash를 manifest에 남겨야 재현 가능하다.
- corpus는 보안 민감 데이터일 수 있다. import provenance와 sensitive flag가 없으면 export 정책을 자동 차단한다.
- Windows driver fuzzing은 격리 환경이 전제다. P2 IOCTL grammar 작업은 isolated VM 강제와 reboot/crash budget 가드를 함께 설계한다.
- CI 게이트는 항상 smoke + regression replay에 한정한다. 장시간 discovery fuzzing은 daemon 또는 별도 worker로 분리한다.
