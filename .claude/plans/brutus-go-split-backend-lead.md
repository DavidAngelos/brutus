# Brutus.go File Split -- Architecture Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Split the 906-line `pkg/brutus/brutus.go` into well-organized, cohesive files with clear single-responsibility boundaries.

**Architecture:** Decompose by domain concern -- types/config/entry-point, plugin registry, analyzer registry, worker pool engine, LLM utilities, and banner detection. All files remain in the same Go package (`package brutus`), so no import changes required within the package.

**Tech Stack:** Go 1.24.6, errgroup, rate limiter, sync primitives

---

## Verified Source Evidence

All analysis below is based on direct reading of the source files in this session.

### Source File Inventory (pkg/brutus/)

| File | Lines | Package | Test Package |
|---|---|---|---|
| `brutus.go` | 906 | `brutus` (internal) | `brutus` (internal) in `brutus_test.go`, `lockout_test.go`, `ratelimit_test.go` |
| `errors.go` | 37 | `brutus` | `brutus_test` (external) in `errors_test.go` |
| `target.go` | 24 | `brutus` | `brutus_test` (external) in `target_test.go` |
| `defaults.go` | 37 | `brutus` | `brutus` (internal) in `defaults_test.go` |

### brutus.go Structure (line ranges from source read)

| Lines | Section | Content |
|---|---|---|
| 1-49 | Package doc + imports | License, package doc, 17 imports |
| 50-68 | Imports block | context, errors, fmt, math/rand, net/http, regexp, sort, strings, sync, sync/atomic, time, badkeys, errgroup, rate |
| 70-75 | Constants | `MaxBannerLength`, `MaxPasswordLength` |
| 77-96 | Context Keys | `contextKey` type, `tlsModeContextKey`, `ContextWithTLSMode()`, `TLSModeFromContext()` |
| 98-175 | Core Types | `Credential`, `Config`, `Result`, `LLMConfig`, `BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `AnalyzerFactory` |
| 177-214 | Plugin Interfaces | `Plugin`, `KeyPlugin`, `PluginFactory` |
| 216-278 | Plugin Registry | `pluginRegistryMu`, `pluginRegistry` map, `Register()`, `GetPlugin()`, `ListPlugins()`, `ResetPlugins()` |
| 279-301 | Analyzer Registry | `analyzerRegistryMu`, `analyzerRegistry` map, `RegisterAnalyzer()`, `GetAnalyzerFactory()` |
| 303-379 | Standard Banners | `standardBanners` map, `IsStandardBanner()` |
| 381-439 | Config Validation | `applyDefaults()`, `validate()` |
| 441-472 | Entry Point | `Brute()` function |
| 474-543 | Credential Generation | `credential` struct, `generateCredentials()`, `generateKeyCredentials()`, `reorderForSpray()` |
| 545-571 | Worker Dispatch | `runWorkers()`, `isHTTPProtocol()` |
| 573-689 | Worker Pool Core | `executeWorkerPool()` -- the main concurrency engine |
| 691-723 | Default Worker Flow | `runWorkersDefault()` |
| 725-824 | LLM Worker Flow | `runWorkersWithLLM()`, `captureBanner()`, `createAnalyzer()`, `runWorkersWithCredentials()` |
| 826-905 | LLM Utilities | `BuildPrompt()`, `SanitizeBanner()`, `ValidateSuggestions()`, `IsValidPassword()` |

---

## Dependency Graph Analysis

### Function Call Graph (who calls whom)

```
Brute()
  --> cfg.validate()
      --> cfg.applyDefaults()
          --> DefaultCredentials()  [defaults.go]
  --> GetPlugin()
  --> runWorkers()
      --> ContextWithTLSMode()
      --> isHTTPProtocol()
      --> runWorkersWithLLM()
      |   --> captureBanner()
      |   --> IsStandardBanner()
      |       --> isHTTPProtocol()
      |   --> createAnalyzer()
      |       --> GetAnalyzerFactory()
      |   --> analyzer.Analyze()
      |   --> generateCredentials()
      |   --> runWorkersWithCredentials()
      |       --> executeWorkerPool()
      |   --> runWorkersDefault()  [fallback paths]
      --> runWorkersDefault()
          --> generateCredentials()
          --> generateKeyCredentials()
          --> reorderForSpray()
          --> executeWorkerPool()

executeWorkerPool()
  --> rate.NewLimiter()
  --> plug.Test() / plug.TestKey()  [via KeyPlugin type assertion]
```

### Shared Package-Level State

| Variable | Type | Used By | Guarded By |
|---|---|---|---|
| `pluginRegistryMu` | `sync.RWMutex` | `Register`, `GetPlugin`, `ListPlugins`, `ResetPlugins` | itself |
| `pluginRegistry` | `map[string]PluginFactory` | `Register`, `GetPlugin`, `ListPlugins`, `ResetPlugins` | `pluginRegistryMu` |
| `analyzerRegistryMu` | `sync.RWMutex` | `RegisterAnalyzer`, `GetAnalyzerFactory` | itself |
| `analyzerRegistry` | `map[string]AnalyzerFactory` | `RegisterAnalyzer`, `GetAnalyzerFactory` | `analyzerRegistryMu` |
| `standardBanners` | `map[string][]string` | `IsStandardBanner` | read-only after init |

### Internal (unexported) Types

| Type/Var | Used By | Notes |
|---|---|---|
| `credential` struct | `generateCredentials`, `generateKeyCredentials`, `reorderForSpray`, `executeWorkerPool`, `runWorkersDefault`, `runWorkersWithLLM`, `runWorkersWithCredentials` | Core internal type -- used across worker and LLM code |
| `contextKey` type | `ContextWithTLSMode`, `TLSModeFromContext` | Small, tied to context helpers |
| `tlsModeContextKey` const | `ContextWithTLSMode`, `TLSModeFromContext` | Small, tied to context helpers |

---

## Proposed Split

### Design Decisions

1. **`credential` struct stays with the worker pool** -- it is the internal work-unit consumed by `executeWorkerPool()`. The generation functions (`generateCredentials`, `generateKeyCredentials`, `reorderForSpray`) are tightly coupled to it and to the worker pool, so they belong together.

2. **Analyzer interfaces (`BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `AnalyzerFactory`) move to `brutus.go` with core types** -- they are PUBLIC types referenced by external analyzers (e.g., `internal/analyzers/claude/claude.go`). Keeping them with the public type definitions is the right place. They do NOT belong with the LLM utilities (those are implementation details) nor with the registry (the registry stores factories, but the interface definition is a type concern).

3. **Plugin interfaces (`Plugin`, `KeyPlugin`, `PluginFactory`) stay in `brutus.go`** -- same reasoning as above, they are core public contracts.

4. **`isHTTPProtocol()` moves to `banners.go`** -- it is used by both `IsStandardBanner()` and `runWorkers()`. Banner detection is its primary domain. The workers file will import it (same package, no import needed).

5. **`executeWorkerPool` and worker functions remain unexported** -- they are internal implementation details. The public API is `Brute()`. No reason to export the concurrency machinery.

6. **`runWorkersWithCredentials` is a trivial 3-line wrapper** -- during the split, it should be inlined into `runWorkersWithLLM` and removed. This is a DRY improvement: the function adds no value.

7. **Context helpers (`ContextWithTLSMode`, `TLSModeFromContext`) stay in `brutus.go`** -- they are public API used by plugins. Only 20 lines, not worth a separate file.

### File Layout (After Split)

```
pkg/brutus/
  brutus.go        (~190 lines) - Package doc, types, config, entry point
  registry.go      (~100 lines) - Plugin registry + Analyzer registry
  workers.go       (~280 lines) - Worker pool engine + credential generation
  llm.go           (~110 lines) - LLM banner analysis flow + utilities
  banners.go       (~75 lines)  - Standard banner detection + isHTTPProtocol
  defaults.go      (37 lines)   - UNCHANGED
  errors.go        (37 lines)   - UNCHANGED
  target.go        (24 lines)   - UNCHANGED
  brutus_test.go   (255 lines)  - UNCHANGED (all tests still compile)
  lockout_test.go  (327 lines)  - UNCHANGED
  ratelimit_test.go(264 lines)  - UNCHANGED
  defaults_test.go (165 lines)  - UNCHANGED
  errors_test.go   (77 lines)   - UNCHANGED
  target_test.go   (103 lines)  - UNCHANGED
```

---

## Detailed File Specifications

### File 1: `brutus.go` (~190 lines)

**Responsibility:** Package documentation, public type definitions, config validation, and the `Brute()` entry point.

**Content (by current line ranges):**

| Current Lines | What | Notes |
|---|---|---|
| 1-49 | License + package doc | Keep the package-level doc comment |
| 51-68 | Imports | Reduced -- remove `math/rand`, `regexp`, `sort`, `sync`, `sync/atomic`, `errgroup`, `rate`; keep `context`, `errors`, `fmt`, `net/http`, `strings`, `time`, `badkeys` |
| 70-75 | Constants `MaxBannerLength`, `MaxPasswordLength` | Move to `llm.go` -- they are LLM-specific (banner sanitization and password validation) |
| 77-96 | Context key type + `ContextWithTLSMode` + `TLSModeFromContext` | Keep here -- public API for plugins |
| 98-175 | `Credential`, `Config`, `Result`, `LLMConfig`, `BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `AnalyzerFactory` | Keep here -- core public types |
| 177-214 | `Plugin`, `KeyPlugin`, `PluginFactory` | Keep here -- core public interfaces |
| 381-439 | `applyDefaults()`, `validate()` | Keep here -- Config methods |
| 441-472 | `Brute()` | Keep here -- public entry point |

**Imports needed:** `context`, `errors`, `fmt`, `net/http`, `strings`, `time`, `github.com/praetorian-inc/brutus/pkg/badkeys`

**Key architectural note:** `Brute()` calls `runWorkers()` which will be in `workers.go`. Since they are in the same package, no import is needed. Same for `GetPlugin()` from `registry.go`.

### File 2: `registry.go` (~100 lines)

**Responsibility:** Plugin registry and Analyzer registry -- both follow the same pattern (mutex-protected map of factory functions).

**Content (by current line ranges):**

| Current Lines | What |
|---|---|
| 216-278 | Plugin registry: `pluginRegistryMu`, `pluginRegistry`, `Register()`, `GetPlugin()`, `ListPlugins()`, `ResetPlugins()` |
| 279-301 | Analyzer registry: `analyzerRegistryMu`, `analyzerRegistry`, `RegisterAnalyzer()`, `GetAnalyzerFactory()` |

**Imports needed:** `fmt`, `sort`, `sync`

**Why combine both registries in one file:** They are the same pattern (mutex + map + register/get), small enough to fit, and conceptually both are "registry" code. Separating them into `plugin_registry.go` and `analyzer_registry.go` would be over-splitting for ~50 lines each.

### File 3: `workers.go` (~280 lines)

**Responsibility:** The concurrency engine -- credential generation, worker pool execution, and the default/dispatch flow.

**Content (by current line ranges):**

| Current Lines | What | Notes |
|---|---|---|
| 474-484 | `credential` struct | Internal work-unit type |
| 486-543 | `generateCredentials()`, `generateKeyCredentials()`, `reorderForSpray()` | Credential generation helpers |
| 545-560 | `runWorkers()` | Dispatch function (calls `runWorkersWithLLM` or `runWorkersDefault`) |
| 573-689 | `executeWorkerPool()` | Core concurrency engine |
| 691-723 | `runWorkersDefault()` | Default credential flow |

**Imports needed:** `context`, `math/rand`, `sync`, `sync/atomic`, `time`, `golang.org/x/sync/errgroup`, `golang.org/x/time/rate`

**Key note:** `runWorkers()` calls `isHTTPProtocol()` (in `banners.go`) and `runWorkersWithLLM()` (in `llm.go`). Both are same-package, no import issues.

**`isHTTPProtocol()` reference:** `runWorkers()` at line 553 calls `isHTTPProtocol(cfg.Protocol)`. This function will be in `banners.go`. Same package, no issue.

### File 4: `llm.go` (~110 lines)

**Responsibility:** LLM-enhanced brute force flow and LLM utility functions (prompt building, sanitization, validation).

**Content (by current line ranges):**

| Current Lines | What | Notes |
|---|---|---|
| 70-75 | Constants `MaxBannerLength`, `MaxPasswordLength` | Moved FROM brutus.go -- LLM-specific constants |
| 725-777 | `runWorkersWithLLM()` | LLM-enhanced flow |
| 779-800 | `captureBanner()` | Banner capture helper |
| 802-817 | `createAnalyzer()` | Analyzer factory lookup |
| 819-824 | `runWorkersWithCredentials()` | **INLINE INTO `runWorkersWithLLM()` and DELETE** -- see architectural improvement below |
| 826-905 | `BuildPrompt()`, `SanitizeBanner()`, `ValidateSuggestions()`, `IsValidPassword()` | LLM utility functions |

**Imports needed:** `context`, `regexp`, `strings`

**Architectural improvement -- inline `runWorkersWithCredentials`:**

Current code at lines 819-824:
```go
func runWorkersWithCredentials(ctx context.Context, cfg *Config, plug Plugin, credentials []credential, llmSuggestions []string) ([]Result, error) {
    return executeWorkerPool(ctx, cfg, plug, credentials, llmSuggestions)
}
```

This is a pure pass-through wrapper. In `runWorkersWithLLM()` at line 776, replace:
```go
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)
```
with:
```go
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

This removes an unnecessary indirection layer (DRY principle -- the abstraction adds no value).

### File 5: `banners.go` (~75 lines)

**Responsibility:** Standard banner detection patterns and HTTP protocol classification.

**Content (by current line ranges):**

| Current Lines | What |
|---|---|
| 303-379 | `standardBanners` map, `IsStandardBanner()` |
| 562-571 | `isHTTPProtocol()` |

**Imports needed:** `strings`

---

## Test File Impact Analysis

### Test Files -- NO Changes Required

All test files in `pkg/brutus/` use `package brutus` (internal tests) or `package brutus_test` (external tests). Since all new files are in the same `package brutus`, all symbols remain accessible.

| Test File | Package | Tests Functions From | Impact |
|---|---|---|---|
| `brutus_test.go` | `brutus` (internal) | `IsStandardBanner`, `Config.validate`, `captureBanner`, `mockHTTPPlugin` | NO CHANGE -- all symbols accessible |
| `lockout_test.go` | `brutus` (internal) | `ResetPlugins`, `Register`, `Brute`, `reorderForSpray`, `credential` struct, mock plugins | NO CHANGE -- `credential` in `workers.go`, registries in `registry.go`, `Brute` in `brutus.go` -- all same package |
| `ratelimit_test.go` | `brutus` (internal) | `Register`, `ResetPlugins`, `Brute`, mock plugins | NO CHANGE -- same package access |
| `defaults_test.go` | `brutus` (internal) | `DefaultCredentials`, `Config.applyDefaults`, `Config.validate` | NO CHANGE -- `defaults.go` unchanged, `validate`/`applyDefaults` in `brutus.go` |
| `errors_test.go` | `brutus_test` (external) | `brutus.ClassifyAuthError` | NO CHANGE -- `errors.go` unchanged |
| `target_test.go` | `brutus_test` (external) | `brutus.ParseTarget` | NO CHANGE -- `target.go` unchanged |

**Critical verification point:** `lockout_test.go` directly references the unexported `credential` struct and `reorderForSpray` function. After the split, these move to `workers.go` but remain in `package brutus`, so the tests compile without any modifications.

---

## Circular Dependency Check

Since all files are in the same Go package (`brutus`), there are no import-level circular dependencies possible. However, let me verify the call-graph has no logical cycles.

**Cross-file call references after split:**

| From File | Calls In | Functions Called |
|---|---|---|
| `brutus.go` | `registry.go` | `GetPlugin()` |
| `brutus.go` | `workers.go` | `runWorkers()` |
| `workers.go` | `banners.go` | `isHTTPProtocol()` |
| `workers.go` | `llm.go` | `runWorkersWithLLM()` |
| `llm.go` | `workers.go` | `executeWorkerPool()`, `generateCredentials()` |
| `llm.go` | `banners.go` | `IsStandardBanner()` |
| `llm.go` | `registry.go` | `GetAnalyzerFactory()` |
| `llm.go` | `workers.go` | `runWorkersDefault()` (fallback paths) |

**Cycle analysis:** `workers.go` calls `llm.go` (`runWorkersWithLLM`) and `llm.go` calls back to `workers.go` (`executeWorkerPool`, `runWorkersDefault`, `generateCredentials`). This is a logical bidirectional dependency.

**Verdict:** This is fine in Go because they are the same package. There are no circular imports. The bidirectional call pattern is inherent to the design (dispatch layer calls LLM flow, LLM flow calls back to shared execution engine). If these were separate packages, we would need to refactor, but within one package this is idiomatic.

---

## Implementation Tasks

### Task 1: Create `banners.go`

**Step 1:** Create `pkg/brutus/banners.go` with:
- License header (copy from `brutus.go` lines 1-13)
- `package brutus`
- Import `"strings"`
- Move `standardBanners` map (lines 308-342)
- Move `IsStandardBanner()` function (lines 352-379)
- Move `isHTTPProtocol()` function (lines 564-571)

**Step 2:** Run `go build ./pkg/brutus/` -- verify it compiles.

**Step 3:** Run `go test ./pkg/brutus/ -run TestIsStandardBanner` -- verify banner tests pass.

**Step 4:** Commit: `refactor(brutus): extract banner detection to banners.go`

**Exit Criteria:**
- [ ] `banners.go` contains exactly 3 items: `standardBanners`, `IsStandardBanner`, `isHTTPProtocol`
- [ ] `go build ./pkg/brutus/` succeeds with exit code 0
- [ ] `go test ./pkg/brutus/ -run TestIsStandardBanner` passes

---

### Task 2: Create `registry.go`

**Step 1:** Create `pkg/brutus/registry.go` with:
- License header
- `package brutus`
- Import `"fmt"`, `"sort"`, `"sync"`
- Move plugin registry vars (lines 220-223): `pluginRegistryMu`, `pluginRegistry`
- Move `Register()` (lines 228-237)
- Move `GetPlugin()` (lines 242-253)
- Move `ListPlugins()` (lines 257-268)
- Move `ResetPlugins()` (lines 272-277)
- Move analyzer registry vars (lines 283-286): `analyzerRegistryMu`, `analyzerRegistry`
- Move `RegisterAnalyzer()` (lines 290-294)
- Move `GetAnalyzerFactory()` (lines 297-301)

**Step 2:** Run `go build ./pkg/brutus/` -- verify it compiles.

**Step 3:** Run `go test ./pkg/brutus/ -run "TestMaxAttempts|TestSprayMode|TestRateLimit"` -- verify tests that use `Register`/`ResetPlugins` still pass.

**Step 4:** Commit: `refactor(brutus): extract plugin and analyzer registries to registry.go`

**Exit Criteria:**
- [ ] `registry.go` contains both plugin and analyzer registries (4 + 2 = 6 functions, 4 package vars)
- [ ] `go build ./pkg/brutus/` succeeds with exit code 0
- [ ] `go test ./pkg/brutus/` passes (full suite)

---

### Task 3: Create `workers.go`

**Step 1:** Create `pkg/brutus/workers.go` with:
- License header
- `package brutus`
- Imports: `"context"`, `"math/rand"`, `"sync"`, `"sync/atomic"`, `"time"`, `"golang.org/x/sync/errgroup"`, `"golang.org/x/time/rate"`
- Move `credential` struct (lines 479-484)
- Move `generateCredentials()` (lines 487-500)
- Move `generateKeyCredentials()` (lines 503-516)
- Move `reorderForSpray()` (lines 520-543)
- Move `runWorkers()` (lines 546-560)
- Move `executeWorkerPool()` (lines 576-689)
- Move `runWorkersDefault()` (lines 693-723)

**Step 2:** Run `go build ./pkg/brutus/` -- verify it compiles.

**Step 3:** Run `go test ./pkg/brutus/ -run "TestReorderForSpray|TestMaxAttempts|TestSprayMode|TestRateLimit"` -- verify worker/credential tests pass.

**Step 4:** Commit: `refactor(brutus): extract worker pool engine to workers.go`

**Exit Criteria:**
- [ ] `workers.go` contains `credential` struct + 6 functions
- [ ] `go build ./pkg/brutus/` succeeds with exit code 0
- [ ] `go test ./pkg/brutus/` passes (full suite)

---

### Task 4: Create `llm.go`

**Step 1:** Create `pkg/brutus/llm.go` with:
- License header
- `package brutus`
- Imports: `"context"`, `"regexp"`, `"strings"`
- Move constants `MaxBannerLength`, `MaxPasswordLength` (lines 71-74) -- these are LLM-specific
- Move `runWorkersWithLLM()` (lines 732-777) **with inline fix** (see step 2)
- Move `captureBanner()` (lines 781-800)
- Move `createAnalyzer()` (lines 805-817)
- Move `BuildPrompt()` (lines 831-854)
- Move `SanitizeBanner()` (lines 857-874)
- Move `ValidateSuggestions()` (lines 877-898)
- Move `IsValidPassword()` (lines 901-905)

**Step 2 (Architectural improvement):** Inline `runWorkersWithCredentials` into `runWorkersWithLLM`.

In the moved `runWorkersWithLLM()`, change line 776 from:
```go
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)
```
to:
```go
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

Do NOT move `runWorkersWithCredentials()` -- it is eliminated.

**Step 3:** Run `go build ./pkg/brutus/` -- verify it compiles.

**Step 4:** Run `go test ./pkg/brutus/` -- verify full test suite passes.

**Step 5:** Commit: `refactor(brutus): extract LLM flow and utilities to llm.go`

**Exit Criteria:**
- [ ] `llm.go` contains 2 constants + 6 functions (NOT 7 -- `runWorkersWithCredentials` is eliminated)
- [ ] `runWorkersWithCredentials` does NOT exist anywhere in the codebase
- [ ] `go build ./pkg/brutus/` succeeds with exit code 0
- [ ] `go test ./pkg/brutus/` passes (full suite)

---

### Task 5: Clean up `brutus.go`

**Step 1:** After tasks 1-4, `brutus.go` should contain only:
- License header + package doc (lines 1-49)
- Reduced imports (remove unused: `math/rand`, `regexp`, `sort`, `sync`, `sync/atomic`, `errgroup`, `rate`)
- Context key helpers (lines 77-96)
- Core types: `Credential`, `Config`, `Result`, `LLMConfig`, `BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `AnalyzerFactory` (lines 98-175)
- Plugin interfaces: `Plugin`, `KeyPlugin`, `PluginFactory` (lines 177-214)
- Config methods: `applyDefaults()`, `validate()` (lines 381-439)
- Entry point: `Brute()` (lines 441-472)

**Step 2:** Verify the section comment blocks are updated. Remove stale section headers like `// Worker Pool Implementation` since that code is now in `workers.go`.

**Step 3:** Update the import block to only include what `brutus.go` needs:
```go
import (
    "context"
    "errors"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/praetorian-inc/brutus/pkg/badkeys"
)
```

Note: `net/http` is needed for `http.Header` in the `BannerInfo` struct.

**Step 4:** Run `go build ./pkg/brutus/` -- verify it compiles.

**Step 5:** Run `go test ./pkg/brutus/ -v` -- verify ALL tests pass.

**Step 6:** Run `go vet ./pkg/brutus/` -- verify no issues.

**Step 7:** Commit: `refactor(brutus): clean up brutus.go after file split`

**Exit Criteria:**
- [ ] `brutus.go` is under 200 lines
- [ ] No duplicate function definitions across any files (verify: `grep -c "^func " pkg/brutus/*.go`)
- [ ] `go build ./pkg/brutus/` succeeds with exit code 0
- [ ] `go test ./pkg/brutus/ -v` passes with 0 failures
- [ ] `go vet ./pkg/brutus/` reports no issues
- [ ] No test files were modified

---

### Task 6: Full Verification

**Step 1:** Run the complete test suite across the entire module:
```bash
go test ./...
```

**Step 2:** Verify no tests were modified:
```bash
git diff --name-only -- '*_test.go'
```
Expected: empty output (no test files changed).

**Step 3:** Verify file count and sizes:
```bash
wc -l pkg/brutus/*.go | sort -n
```
Expected: 8 `.go` files (brutus.go, banners.go, defaults.go, errors.go, llm.go, registry.go, target.go, workers.go), all under 300 lines, total approximately equal to original total.

**Step 4:** Verify no function exists in multiple files:
```bash
grep "^func " pkg/brutus/*.go | sort
```
Expected: each function appears exactly once.

**Step 5:** Commit message for squash (if squashing): `refactor(brutus): split brutus.go into domain-cohesive files`

**Exit Criteria:**
- [ ] `go test ./...` passes with 0 failures
- [ ] 0 test files modified (verify: `git diff --name-only -- '*_test.go'` is empty)
- [ ] 8 `.go` files in `pkg/brutus/` (non-test)
- [ ] Each function defined exactly once across all files
- [ ] `brutus.go` under 200 lines (verify: `wc -l pkg/brutus/brutus.go`)

---

## Summary Table

| File | Approximate Lines | Key Contents | Imports from stdlib/deps |
|---|---|---|---|
| `brutus.go` | ~190 | Package doc, types, interfaces, config validation, `Brute()` | context, errors, fmt, net/http, strings, time, badkeys |
| `registry.go` | ~100 | Plugin + Analyzer registries (vars, Register, Get, List, Reset) | fmt, sort, sync |
| `workers.go` | ~280 | `credential` struct, generation funcs, worker pool, dispatch | context, math/rand, sync, sync/atomic, time, errgroup, rate |
| `llm.go` | ~110 | LLM flow, banner capture, prompt building, sanitization, validation | context, regexp, strings |
| `banners.go` | ~75 | `standardBanners` map, `IsStandardBanner()`, `isHTTPProtocol()` | strings |
| `defaults.go` | 37 | UNCHANGED | embed, strings |
| `errors.go` | 37 | UNCHANGED | fmt, strings |
| `target.go` | 24 | UNCHANGED | net |

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Moving `credential` struct breaks test compilation | Verified: `lockout_test.go` uses `package brutus` (internal) -- same package, no issue |
| Moving constants changes API | `MaxBannerLength` and `MaxPasswordLength` are public constants moving between files in same package -- no API change |
| Inlining `runWorkersWithCredentials` breaks behavior | The function is a pure pass-through; inlining is semantically identical |
| Future developers confused by file organization | Each file has a clear section comment at the top describing its responsibility |

---

## Metadata

```json
{
  "agent": "backend-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-02-14T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/brutus/.claude/plans",
  "skills_invoked": [
    "using-skills",
    "enforcing-evidence-based-analysis",
    "writing-plans",
    "gateway-backend",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "brainstorming",
    "persisting-agent-outputs",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni",
    "debugging-systematically",
    "using-todowrite"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/backend/structuring-go-projects/SKILL.md",
    ".claude/skill-library/development/backend/go-best-practices/SKILL.md",
    ".claude/skill-library/development/backend/reviewing-backend-implementations/SKILL.md",
    ".claude/skill-library/analysis/behavior-first-architecture-analysis/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/brutus/brutus.go:1-906",
    "pkg/brutus/errors.go:1-37",
    "pkg/brutus/target.go:1-24",
    "pkg/brutus/defaults.go:1-37",
    "pkg/brutus/brutus_test.go:1-255",
    "pkg/brutus/lockout_test.go:1-327",
    "pkg/brutus/ratelimit_test.go:1-264",
    "pkg/brutus/defaults_test.go:1-165",
    "pkg/brutus/errors_test.go:1-77",
    "pkg/brutus/target_test.go:1-103"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Implement the 6-task file split according to this plan. Each task is self-contained with its own commit. No test files should be modified."
  }
}
```
