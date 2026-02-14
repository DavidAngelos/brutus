# Brutus.go File Split - Capability Reviewer Feedback

## Review Result
REVIEW_APPROVED_WITH_RECOMMENDATIONS

Both plans are architecturally sound and will achieve the goal of splitting `brutus.go` into maintainable files. However, the **capability-lead plan is recommended** with specific modifications from the backend-lead plan.

---

## Executive Summary

**Recommended approach:** Capability-lead plan structure (5 files) with backend-lead's architectural improvements (inline wrapper elimination, documented thread-safety concerns).

**Key differences:**
1. **File count:** Capability-lead (5 files) vs Backend-lead (6 files, includes `banners.go`)
2. **LLM isolation strategy:** Capability-lead (security-focused file headers) vs Backend-lead (separate `llm.go` with utilities)
3. **Architectural improvements:** Backend-lead identifies `runWorkersWithCredentials` as eliminable wrapper
4. **Test file splitting:** Capability-lead includes test file reorganization, Backend-lead does not

**Verdict:** Merge both plans - use capability-lead's file structure but incorporate backend-lead's architectural improvements.

---

## 1. Security Boundary Assessment

### Both Plans Create Proper Security Boundaries

**Shared security properties:**
- LLM prompt injection defense surface isolated (either in `llm.go` or consolidated `workers.go`)
- Plugin registry correctly mutex-protected in `registry.go`
- Worker pool concurrency correctly preserved
- No new security vulnerabilities introduced

### Capability-Lead Security Advantages

**✅ LLM security documentation (lines 577-586 in capability-lead `llm.go`):**
```go
// SECURITY NOTE: This file is the prompt injection defense surface.
// SanitizeBanner and ValidateSuggestions are the primary controls against
// malicious LLM output. Any hardening of LLM input/output processing
// should be concentrated in this file.
```

This explicit security surface documentation is **superior** for future auditing. Backend-lead plan lacks this.

**✅ Thread-safety documentation (capability-lead Task 5, Step 2):**
Adds explicit thread-safety contract to `Plugin` interface:
```go
// Thread Safety: Plugin instances may be shared across concurrent goroutines
// in the worker pool. Implementations MUST be safe for concurrent use.
```

Backend-lead plan also includes this (Task 5, Step 2), so both plans address Finding 2 (HIGH).

### Backend-Lead Security Advantage

**✅ Constants moved to LLM file (backend-lead lines 70-75):**
```go
const (
    MaxBannerLength   = 500  // LLM-specific (banner sanitization)
    MaxPasswordLength = 32   // LLM-specific (password validation)
)
```

Backend-lead correctly identifies these as LLM-specific. Capability-lead leaves them in `brutus.go`, which is less semantically correct.

**Recommendation:** Adopt backend-lead's constant placement.

---

## 2. Plumbing Verification

### Cross-File Function Calls

Both plans correctly identify all cross-file dependencies. Verified against source:

| Caller                     | Callee                    | File After Split                                 | Both Plans Correct? |
|---------------------------|---------------------------|--------------------------------------------------|---------------------|
| `Brute()` (brutus.go:466) | `runWorkers()` (546)     | brutus.go → workers.go                           | ✅ Yes              |
| `Brute()` (brutus.go:458) | `GetPlugin()` (242)      | brutus.go → registry.go                          | ✅ Yes              |
| `runWorkers()` (553)      | `isHTTPProtocol()` (564) | workers.go → banners.go (backend) OR workers.go (capability) | ⚠️ Differ (see below) |
| `runWorkers()` (555)      | `runWorkersWithLLM()` (732) | workers.go → workers.go                          | ✅ Yes              |
| `runWorkersWithLLM()` (737) | `IsStandardBanner()` (352) | workers.go → banners.go (backend) OR workers.go (capability) | ⚠️ Differ (see below) |
| `runWorkersWithLLM()` (743) | `createAnalyzer()` (805)  | workers.go → llm.go                              | ✅ Yes              |
| `runWorkersWithLLM()` (776) | `runWorkersWithCredentials()` (821) | workers.go → workers.go                          | ⚠️ Backend proposes elimination |
| `createAnalyzer()` (811)  | `GetAnalyzerFactory()` (297) | llm.go → registry.go                             | ✅ Yes              |
| `claude.go:76`            | `BuildPrompt()` (831)    | External → llm.go                                | ✅ Yes              |
| `claude.go:76`            | `SanitizeBanner()` (857) | External → llm.go                                | ✅ Yes              |
| `claude.go:134`           | `ValidateSuggestions()` (877) | External → llm.go                                | ✅ Yes              |

### Critical Plumbing Issue: `isHTTPProtocol()` Placement

**Backend-lead approach (separate `banners.go`):**
- Lines 564-571 of `isHTTPProtocol()` move to new `banners.go`
- `runWorkers()` at line 553 calls cross-file: `workers.go` → `banners.go`
- `IsStandardBanner()` at line 359 calls same-file: `banners.go` → `banners.go`

**Capability-lead approach (keep in `workers.go`):**
- `isHTTPProtocol()` stays in `workers.go` alongside `runWorkers()`
- All calls are same-file
- `IsStandardBanner()` at line 352 calls cross-file: `banners.go` → `workers.go`

**Analysis:**
```go
// Current usage (brutus.go:553)
if cfg.LLMConfig != nil && cfg.LLMConfig.Enabled && isHTTPProtocol(cfg.Protocol) {
    return runWorkersWithLLM(ctx, cfg, plug)
}

// Current usage (brutus.go:359)
if isHTTPProtocol(protocol) {
    return false  // HTTP protocols always need LLM analysis
}
```

**Verdict:** Backend-lead is semantically correct. `isHTTPProtocol()` is fundamentally a **protocol classification** function for banner detection, not a worker dispatch concern. The fact that `runWorkers()` uses it doesn't change its semantic domain. Analogy: `strings.Contains()` is a string function even if called from HTTP code.

**However:** Capability-lead's practical argument is also valid - `isHTTPProtocol()` has zero dependencies and is 9 lines. Creating a separate file for 9 lines + `standardBanners` map + `IsStandardBanner()` (~55 lines total) is marginal.

**Recommendation:** Keep backend-lead's `banners.go` because:
1. Semantic correctness: banner detection is a distinct domain
2. Future extensibility: Banner classification logic will grow (custom patterns, regex, etc.)
3. YAGNI doesn't apply: The file is already non-trivial (~75 lines)

### Shared Mutable State

Both plans correctly handle all shared mutable state:

| Variable | Type | Guarded By | Placement After Split | Both Plans Correct? |
|----------|------|------------|----------------------|---------------------|
| `pluginRegistryMu` | `sync.RWMutex` | itself | registry.go | ✅ Yes |
| `pluginRegistry` | `map[string]PluginFactory` | `pluginRegistryMu` | registry.go | ✅ Yes |
| `analyzerRegistryMu` | `sync.RWMutex` | itself | registry.go | ✅ Yes |
| `analyzerRegistry` | `map[string]AnalyzerFactory` | `analyzerRegistryMu` | registry.go | ✅ Yes |
| `standardBanners` | `map[string][]string` | read-only after init | banners.go (backend) OR workers.go (capability) | ✅ Yes (semantics differ) |

**Verification:** Both plans preserve mutex-protected access patterns. No data races introduced.

### Internal (Unexported) Types

| Type | Used By Functions | Placement After Split | Both Plans Correct? |
|------|------------------|----------------------|---------------------|
| `credential` struct | `generateCredentials`, `generateKeyCredentials`, `reorderForSpray`, `executeWorkerPool`, `runWorkersDefault`, `runWorkersWithLLM`, `runWorkersWithCredentials` | workers.go | ✅ Yes |
| `contextKey` type | `ContextWithTLSMode`, `TLSModeFromContext` | brutus.go | ✅ Yes |
| `tlsModeContextKey` const | `ContextWithTLSMode`, `TLSModeFromContext` | brutus.go | ✅ Yes |

**Verification:** Both plans correctly keep `credential` struct in `workers.go`. The struct is the internal work-unit for the worker pool and should remain co-located with `executeWorkerPool()`.

---

## 3. Consumer Impact Analysis

### Verified Consumers (from source reads)

| Consumer | Imports From `brutus` | Impact After Split | Both Plans Safe? |
|----------|----------------------|-------------------|------------------|
| `ssh.go:26` | `brutus.Register`, `brutus.Plugin`, `brutus.Result`, `brutus.ClassifyAuthError` | All remain exported in same package | ✅ Yes |
| `http.go:34` | `brutus.Register`, `brutus.Plugin`, `brutus.Result`, `brutus.TLSModeFromContext` | All remain exported in same package | ✅ Yes |
| `claude.go:26` | `brutus.RegisterAnalyzer`, `brutus.BannerAnalyzer`, `brutus.BannerInfo`, `brutus.BuildPrompt`, `brutus.SanitizeBanner`, `brutus.ValidateSuggestions`, `brutus.LLMConfig` | All remain exported in same package | ✅ Yes |
| `main.go:30` | `brutus.Brute`, `brutus.Config`, `brutus.LLMConfig`, `brutus.Credential`, `brutus.Result`, `brutus.GetAnalyzerFactory`, `brutus.CredentialAnalyzer`, `brutus.BannerInfo` | All remain exported in same package | ✅ Yes |

**Verdict:** Both plans are **zero-impact** to external consumers. All files remain in `package brutus`, so all exported symbols remain accessible via `brutus.SymbolName`.

**Test file impact:**
- Backend-lead: Claims no test file changes needed (correct - `package brutus` internal tests can access unexported symbols)
- Capability-lead: Proposes splitting test files to match source organization (Task 6) - this is a **quality improvement**, not a requirement

**Recommendation:** Adopt capability-lead's test file split (Task 6). Test organization should mirror source organization for maintainability.

---

## 4. Plan Comparison: Where They Disagree

### Disagreement 1: File Count (5 vs 6)

**Backend-lead (6 files):**
```
brutus.go        (~190 lines) - Types, config, entry point
registry.go      (~100 lines) - Plugin + Analyzer registries
workers.go       (~280 lines) - Worker pool engine
llm.go           (~110 lines) - LLM flow + utilities
banners.go       (~75 lines)  - Banner detection + isHTTPProtocol
+ defaults.go, errors.go, target.go (unchanged)
```

**Capability-lead (5 files):**
```
brutus.go        (~175 lines) - Types, config, entry point, TLS context
registry.go      (~95 lines)  - Plugin + Analyzer registries
workers.go       (~285 lines) - Worker pool + LLM flow + captureBanner + isHTTPProtocol
llm.go           (~105 lines) - LLM constants + createAnalyzer + utilities
banners.go       (~55 lines)  - standardBanners + IsStandardBanner ONLY
+ defaults.go, errors.go, target.go (unchanged)
```

**Analysis:**

| Metric | Backend-lead | Capability-lead |
|--------|-------------|-----------------|
| Files in `brutus/` (non-test, non-unchanged) | 5 new | 5 new |
| `isHTTPProtocol` placement | `banners.go` (semantic correctness) | `workers.go` (co-location with caller) |
| LLM flow placement | `llm.go` (isolation) | `workers.go` (flow continuity) |
| `runWorkersWithLLM`, `captureBanner` | `workers.go` (orchestration) | `workers.go` (orchestration) |

**Wait, I miscounted:** Both plans result in 5 new files. Backend-lead's `banners.go` is matched by capability-lead's modified organization.

**Recommendation:** Backend-lead's semantic organization (`banners.go` for protocol classification) is preferable.

### Disagreement 2: LLM Function Placement

**Backend-lead (lines 202-217):**
```
workers.go:
  - credential struct
  - generateCredentials, generateKeyCredentials, reorderForSpray
  - runWorkers, executeWorkerPool, runWorkersDefault

llm.go:
  - MaxBannerLength, MaxPasswordLength constants
  - runWorkersWithLLM, captureBanner, createAnalyzer
  - BuildPrompt, SanitizeBanner, ValidateSuggestions, IsValidPassword
```

**Capability-lead (lines 204-218):**
```
workers.go:
  - credential struct
  - generateCredentials, generateKeyCredentials, reorderForSpray
  - runWorkers, executeWorkerPool, runWorkersDefault
  - runWorkersWithLLM, captureBanner, runWorkersWithCredentials

llm.go:
  - MaxBannerLength, MaxPasswordLength constants
  - createAnalyzer (bridging function)
  - BuildPrompt, SanitizeBanner, ValidateSuggestions, IsValidPassword
```

**Key difference:** `runWorkersWithLLM` and `captureBanner` placement.

**Backend-lead argument (lines 183-185):**
> `runWorkersWithLLM` is fundamentally a worker pool orchestration function that happens to call LLM APIs. Moving it to llm.go would split the worker flow across two files.

**Capability-lead argument (lines 181-185):**
> `runWorkersWithLLM` is fundamentally worker orchestration. `captureBanner` is part of the worker flow. `createAnalyzer` is LLM configuration logic.

**Analysis:** Both arguments are valid. This is a **cohesion vs coupling** tradeoff:
- Backend-lead: Maximizes LLM isolation (security surface in one file)
- Capability-lead: Maximizes worker flow continuity (orchestration in one file)

**Function dependency analysis:**
```
runWorkersWithLLM() calls:
  - captureBanner() [small, 19 lines, minimal logic]
  - IsStandardBanner() [banner detection, logically belongs with standardBanners]
  - createAnalyzer() [LLM-specific factory, 12 lines]
  - generateCredentials() [workers.go]
  - executeWorkerPool() [workers.go]
```

**Verdict:** Capability-lead is correct. `runWorkersWithLLM()` is worker orchestration. The fact that it calls LLM utilities doesn't change its nature - it manages the worker pool flow. Backend-lead's approach would create unnecessary coupling between `workers.go` (which needs `runWorkersWithLLM` for dispatch) and `llm.go`.

**Recommendation:** Adopt capability-lead's placement: `runWorkersWithLLM` + `captureBanner` in `workers.go`, utilities in `llm.go`.

### Disagreement 3: `runWorkersWithCredentials` Wrapper

**Backend-lead (lines 218-238):**
```go
// Identifies lines 819-824 as a pure pass-through wrapper:
func runWorkersWithCredentials(...) ([]Result, error) {
    return executeWorkerPool(ctx, cfg, plug, credentials, llmSuggestions)
}

// Proposes inlining at line 776:
// BEFORE:
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)

// AFTER:
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

**Capability-lead (lines 100, 215, 513):**
Keeps `runWorkersWithCredentials` unchanged, moves it to `workers.go` verbatim.

**Analysis:**
```bash
# Verify wrapper is pure pass-through (from brutus.go:821-824)
func runWorkersWithCredentials(ctx context.Context, cfg *Config, plug Plugin, credentials []credential, llmSuggestions []string) ([]Result, error) {
    return executeWorkerPool(ctx, cfg, plug, credentials, llmSuggestions)
}

# Usage count:
grep -n "runWorkersWithCredentials" brutus.go
# 821:func runWorkersWithCredentials(...)  [definition]
# 776:    return runWorkersWithCredentials(...)  [single call site]
```

**Verdict:** Backend-lead is correct. This is a **DRY violation** (the abstraction adds no value). The function:
1. Has exactly ONE call site
2. Performs zero transformations
3. Adds zero error handling
4. Provides zero business logic

**Recommendation:** Inline `runWorkersWithCredentials` as proposed by backend-lead (Task 4, Step 2).

### Disagreement 4: Test File Splitting

**Backend-lead (line 262):**
```
Test Files -- NO Changes Required

All test files use `package brutus` (internal tests) or `package brutus_test` (external tests).
Since all new files are in the same `package brutus`, all symbols remain accessible.
```

**Capability-lead (Task 6, lines 869-951):**
```
Task 6: Split test files

Move tests to match source file organization:
- TestIsStandardBanner → banners_test.go
- TestCaptureBanner_EmptyUsernames + mockHTTPPlugin → workers_test.go
- TestConfigValidate → stays in brutus_test.go
```

**Analysis:**

Backend-lead is **technically correct** - test files will compile unchanged because `package brutus` internal tests can access all unexported symbols.

Capability-lead is **architecturally correct** - test file organization should mirror source organization for maintainability.

**From `brutus_test.go`:**
```go
// Line 25-95: TestIsStandardBanner
// Tests the IsStandardBanner function (currently in brutus.go, will be in banners.go)

// Line 212-239: TestCaptureBanner_EmptyUsernames
// Tests the captureBanner function (currently in brutus.go, will be in workers.go)

// Line 97-210: TestConfigValidate
// Tests Config.validate method (stays in brutus.go)
```

**Recommendation:** Adopt capability-lead's test file split (Task 6). While not required for compilation, it improves maintainability and follows Go convention (tests for `foo.go` live in `foo_test.go`).

---

## 5. Missing Items (Both Plans Overlooked)

### Finding 1: Import Block Duplication

Both plans mention "remove unused imports" but neither addresses the **import block duplication** issue.

**Current brutus.go imports (lines 51-68):**
```go
import (
    "context"
    "errors"
    "fmt"
    "math/rand"
    "net/http"
    "regexp"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/praetorian-inc/brutus/pkg/badkeys"

    "golang.org/x/sync/errgroup"
    "golang.org/x/time/rate"
)
```

**After split:** Every file will have 3-8 imports, and there will be overlap. Both plans should:
1. Document the final import list for each file
2. Verify no unused imports remain (both mention `go build` will catch this)

**Recommendation:** Add verification step: `go mod tidy && go build ./...` to ensure clean dependencies.

### Finding 2: Missing Verification of Test File Internal Symbols

**Backend-lead claims (lines 263-270):**
```
lockout_test.go directly references the unexported `credential` struct and `reorderForSpray` function.
After the split, these move to workers.go but remain in package brutus, so tests compile unchanged.
```

**Capability-lead does not verify this claim.**

**Verification from `lockout_test.go`:**
```bash
grep "credential" lockout_test.go
# Line 79: c := credential{username: "alice", password: "pass1"}
# Line 187: creds := []credential{...}
```

**Verdict:** Backend-lead's claim is correct. `lockout_test.go` uses `package brutus` (internal test), so it can access unexported `credential` struct and `reorderForSpray` function after they move to `workers.go`.

**Recommendation:** No action needed, but capability-lead's plan should note this in the test file section.

### Finding 3: Missing Documentation Update for Public Constants

**Both plans move `MaxBannerLength` and `MaxPasswordLength` from `brutus.go` (lines 70-75) to `llm.go`.**

**Current godoc comment (brutus.go:71-74):**
```go
const (
    // MaxBannerLength limits banner size to prevent prompt injection
    MaxBannerLength = 500
    // MaxPasswordLength limits suggested password length
    MaxPasswordLength = 32
)
```

**Issue:** These are **exported constants** used by external analyzers:
```bash
# Verified in claude.go (no direct usage found)
grep -n "MaxBannerLength\|MaxPasswordLength" internal/analyzers/claude/claude.go
# No matches
```

**Wait, let me check `brutus.go` for internal usage:**
```bash
# From brutus.go:869, 882:
if len(cleaned) > MaxBannerLength {
    cleaned = cleaned[:MaxBannerLength]
}
if pwd == "" || len(pwd) > MaxPasswordLength {
    continue
}
```

**Verdict:** Constants are used internally by `SanitizeBanner()` and `ValidateSuggestions()`, which move to `llm.go`. Moving constants to `llm.go` is correct. Both plans handle this correctly.

**Recommendation:** No issue found.

---

## 6. Final Recommendation: Unified Merged Plan

**Use capability-lead plan structure with these modifications from backend-lead:**

### File Structure (Capability-Lead Base)

```
pkg/brutus/
  brutus.go        (~175 lines) - Package doc, types, config validation, Brute() entry point
  registry.go      (~95 lines)  - Plugin + Analyzer registries (mutex-protected)
  workers.go       (~285 lines) - Worker pool engine + LLM orchestration flow
  llm.go           (~105 lines) - LLM utilities (prompt, sanitize, validate)
  banners.go       (~55 lines)  - Standard banner detection + isHTTPProtocol
  defaults.go      (37 lines)   - UNCHANGED
  errors.go        (37 lines)   - UNCHANGED
  target.go        (24 lines)   - UNCHANGED
```

### Required Modifications from Backend-Lead Plan

1. **Inline `runWorkersWithCredentials`** (backend-lead Task 4, Step 2):
   ```go
   // In workers.go, line 776 of runWorkersWithLLM:
   // BEFORE:
   return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)

   // AFTER:
   return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
   ```
   **Rationale:** Pure pass-through wrapper with single call site. Adds no value.

2. **Move constants to llm.go** (backend-lead lines 157-158):
   ```go
   // brutus.go lines 70-75 → llm.go
   const (
       MaxBannerLength   = 500  // LLM-specific (banner sanitization)
       MaxPasswordLength = 32   // LLM-specific (password validation)
   )
   ```
   **Rationale:** Constants govern LLM behavior, not general brutus API.

3. **Add LLM security documentation** (capability-lead Task 3):
   ```go
   // llm.go file header
   // SECURITY NOTE: This file is the prompt injection defense surface.
   // SanitizeBanner and ValidateSuggestions are the primary controls against
   // malicious LLM output. Any hardening of LLM input/output processing
   // should be concentrated in this file.
   ```
   **Rationale:** Explicit security surface for auditing (addresses Finding 33).

4. **Add thread-safety documentation** (both plans):
   - Plugin interface godoc (capability-lead Task 5, Step 2)
   - Brute() function godoc (capability-lead Task 5, Step 3)
   **Rationale:** Addresses Finding 2 (HIGH).

5. **Split test files** (capability-lead Task 6):
   - `banners_test.go` ← TestIsStandardBanner
   - `workers_test.go` ← TestCaptureBanner + mockHTTPPlugin
   **Rationale:** Test organization matches source organization.

### Implementation Order

1. **Task 1:** Create `registry.go` (both plans identical)
2. **Task 2:** Create `workers.go` (capability-lead base + inline wrapper fix)
3. **Task 3:** Create `llm.go` (capability-lead base + move constants from brutus.go + security header)
4. **Task 4:** Create `banners.go` (capability-lead base)
5. **Task 5:** Clean up `brutus.go` (capability-lead base + thread-safety docs)
6. **Task 6:** Split test files (capability-lead only)
7. **Task 7:** Full verification (both plans similar)

---

## 7. Verification Checklist

Before claiming complete:

- [ ] 8 source files in `pkg/brutus/` (excluding tests): brutus.go, registry.go, workers.go, llm.go, banners.go, defaults.go, errors.go, target.go
- [ ] 8 test files in `pkg/brutus/`: brutus_test.go, banners_test.go, workers_test.go, ratelimit_test.go, lockout_test.go, defaults_test.go, errors_test.go, target_test.go
- [ ] `go build ./pkg/brutus/` exits 0
- [ ] `go test ./pkg/brutus/ -count=1 -race` passes with 0 failures
- [ ] `go vet ./pkg/brutus/` reports no issues
- [ ] No function defined in multiple files (verify: `grep -rn '^func ' pkg/brutus/*.go | sort -t: -k3`)
- [ ] No duplicate type definitions (verify: `grep -rn '^type ' pkg/brutus/*.go | sort -t: -k3`)
- [ ] No test files modified beyond Task 6 split (verify: `git diff -- '*_test.go'`)
- [ ] No unused imports (verified by `go build`)
- [ ] No source file exceeds 300 lines (verify: `wc -l pkg/brutus/*.go`)
- [ ] `runWorkersWithCredentials` function does NOT exist in any file (verify: `grep -r 'func runWorkersWithCredentials' pkg/brutus/`)
- [ ] `MaxBannerLength` and `MaxPasswordLength` constants are in `llm.go` (verify: `grep -n 'MaxBannerLength' pkg/brutus/llm.go`)
- [ ] Thread-safety documentation present in Plugin interface (verify: `grep -A5 'Thread Safety' pkg/brutus/brutus.go`)

---

## 8. Risk Assessment

### Low Risk Items (Both Plans)

✅ **Same package architecture** - No import path changes, zero consumer impact
✅ **Mutex-protected registries** - Thread-safety preserved
✅ **Test compatibility** - Internal tests can access unexported symbols after split
✅ **No logic changes** - Pure file moves with no behavioral modifications (except inline wrapper removal)

### Medium Risk Items (Merged Plan)

⚠️ **Inlining `runWorkersWithCredentials`** - Low risk but requires careful testing
- **Mitigation:** Full test suite must pass after Task 2 (`go test ./pkg/brutus/ -race`)

⚠️ **Test file splitting** - Could introduce test discovery issues if not done carefully
- **Mitigation:** Run tests after Task 6 to verify all tests still discovered

### High Risk Items (None)

No high-risk changes identified. The split is mechanical file organization with no algorithmic changes.

---

## Metadata

```json
{
  "agent": "capability-reviewer",
  "output_type": "code-review",
  "timestamp": "2026-02-14T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/brutus/.claude/plans",
  "skills_invoked": [
    "using-skills",
    "adhering-to-dry",
    "adhering-to-yagni",
    "analyzing-cyclomatic-complexity",
    "calibrating-time-estimates",
    "discovering-reusable-code",
    "debugging-systematically",
    "enforcing-evidence-based-analysis",
    "persisting-agent-outputs",
    "verifying-before-completion",
    "gateway-backend",
    "gateway-capabilities"
  ],
  "library_skills_read": [],
  "source_files_verified": [
    "pkg/brutus/brutus.go:1-906",
    "internal/plugins/ssh/ssh.go:1-226",
    "internal/plugins/http/http.go:1-286",
    "internal/analyzers/claude/claude.go:1-150",
    "cmd/brutus/main.go:1-1341",
    ".claude/plans/brutus-go-split-backend-lead.md:1-575",
    ".claude/plans/brutus-go-split-capability-lead.md:1-1161"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Implement the merged plan: capability-lead structure with backend-lead architectural improvements (inline wrapper, move constants, add security docs). Both plans were sound; this merges their strengths."
  }
}
```
