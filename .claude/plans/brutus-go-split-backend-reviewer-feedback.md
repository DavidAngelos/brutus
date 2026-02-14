# Brutus.go File Split - Architecture Review

**Reviewer:** backend-reviewer
**Date:** 2026-02-14
**Plans Reviewed:**
- `brutus-go-split-backend-lead.md` (backend-lead)
- `brutus-go-split-capability-lead.md` (capability-lead)

---

## Executive Summary

Both plans propose sound architectures with 5 files organized by domain concern. After analyzing the actual source code (`brutus.go` lines 1-906) and test files, I've identified 4 critical disagreements and verified that **BOTH plans have test impact claims that contradict the evidence**.

**Recommendation:** Merge both approaches with corrections.

---

## 1. Agreements

Both plans agree on:

### 1.1 Core File Structure

| File | Purpose | Both Plans Agree |
|------|---------|------------------|
| `brutus.go` | Types, config validation, `Brute()` entry point | ✅ |
| `registry.go` | Plugin + Analyzer registries | ✅ |
| `workers.go` | Worker pool engine + credential generation | ✅ |
| `llm.go` | LLM utilities (BuildPrompt, SanitizeBanner, etc.) | ✅ |
| `banners.go` | Standard banner detection + `isHTTPProtocol` | ✅ |

### 1.2 File Ownership - No Disputes

| Symbol | Both Plans Agree: Goes To |
|--------|---------------------------|
| `Plugin`, `KeyPlugin`, `PluginFactory` interfaces | `brutus.go` |
| `BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `AnalyzerFactory` | `brutus.go` |
| `Register`, `GetPlugin`, `RegisterAnalyzer`, `GetAnalyzerFactory` | `registry.go` |
| `credential` struct, `generateCredentials`, `generateKeyCredentials`, `reorderForSpray` | `workers.go` |
| `executeWorkerPool`, `runWorkersDefault` | `workers.go` |
| `BuildPrompt`, `SanitizeBanner`, `ValidateSuggestions`, `IsValidPassword` | `llm.go` |
| `standardBanners`, `IsStandardBanner`, `isHTTPProtocol` | `banners.go` |

### 1.3 Same-Package Strategy

Both plans keep all files in `package brutus` (no sub-packages), avoiding import changes for consumers.

### 1.4 No Test File Modifications (Initial Claim)

Both plans CLAIM no test file changes needed... but this is **INCORRECT** (see Disagreement 4).

---

## 2. Disagreements (Evidence-Based Analysis)

### Disagreement 1: Where `runWorkersWithLLM` and `captureBanner` Go

**Backend-lead:** `workers.go`
**Capability-lead:** `workers.go`

**Status:** ✅ **AGREEMENT** (Both put them in `workers.go`)

**Evidence from source:**
- `runWorkersWithLLM` (lines 732-777) orchestrates the worker pool by calling `executeWorkerPool` (line 776 via `runWorkersWithCredentials`)
- `captureBanner` (lines 781-800) makes a `plug.Test()` call to capture banner
- Both functions are worker orchestration logic, not pure LLM utilities

**Verdict:** Correct placement in `workers.go`.

---

### Disagreement 2: Where `createAnalyzer` Goes

**Backend-lead:** `llm.go` (lines 805-817 moved to `llm.go`)
**Capability-lead:** `llm.go` (lines 805-817 moved to `llm.go`)

**Status:** ✅ **AGREEMENT** (Both put it in `llm.go`)

**Evidence from source:**
- `createAnalyzer` (lines 805-817) is a 12-line function that bridges `LLMConfig` to the analyzer registry
- Called only from `runWorkersWithLLM` at line 743
- It's LLM configuration logic, not worker orchestration

**Verdict:** Correct placement in `llm.go`.

---

### Disagreement 3: `runWorkersWithCredentials` Inlining

**Backend-lead:** **INLINE and DELETE** — "This is a pure pass-through wrapper... removes unnecessary indirection layer (DRY principle)"

**Capability-lead:** **KEEP AS-IS** — "Consider inlining... but it has negligible cost and provides readability"

**Evidence from source (lines 819-824):**
```go
func runWorkersWithCredentials(ctx context.Context, cfg *Config, plug Plugin, credentials []credential, llmSuggestions []string) ([]Result, error) {
    return executeWorkerPool(ctx, cfg, plug, credentials, llmSuggestions)
}
```

**Analysis:**

✅ **Backend-lead is correct:** This is a 3-line wrapper that adds zero value. It exists at line 821-824 and is called ONLY from line 776 in `runWorkersWithLLM`:

```go
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)
```

**Replace with:**
```go
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

**DRY violation:** The abstraction adds no logic, no error handling, no transformation. It's indirection for indirection's sake.

**Readability argument rejected:** The function name `runWorkersWithCredentials` doesn't clarify anything that `executeWorkerPool` doesn't already convey. The call site becomes MORE clear after inlining:
- Before: `runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)` (ambiguous - is this different from executeWorkerPool?)
- After: `executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)` (clear - this is the worker pool)

**Verdict:** ✅ **INLINE AND DELETE** (backend-lead approach)

---

### Disagreement 4: Test File Splitting

**Backend-lead:** **NO TEST CHANGES** — "All test files... remain accessible... NO CHANGE"

**Capability-lead:** **SPLIT TESTS** — Create `banners_test.go`, `workers_test.go`

**Evidence from actual test files:**

**From `brutus_test.go` (lines 1-255):**
- Lines 25-95: `TestIsStandardBanner` — Tests `IsStandardBanner()` function
- Lines 97-210: `TestConfigValidate` — Tests `Config.validate()` method
- Lines 212-239: `TestCaptureBanner_EmptyUsernames` — Tests `captureBanner()` function
- Lines 241-254: `mockHTTPPlugin` helper

**From `lockout_test.go` (lines 1-327):**
- Tests `reorderForSpray`, `MaxAttempts`, `SprayMode` — All reference unexported `credential` struct

**From `ratelimit_test.go` (lines 1-264):**
- Tests rate limiting, jitter, context cancellation

**Analysis:**

❌ **Backend-lead is WRONG:** Claiming "NO CHANGE" contradicts Go best practices:
- `TestIsStandardBanner` tests a function in `banners.go` but lives in `brutus_test.go`
- `TestCaptureBanner_EmptyUsernames` tests a function in `workers.go` but lives in `brutus_test.go`
- After the split, these tests are orphaned from their source files

✅ **Capability-lead is CORRECT:** Tests should colocate with the files they test:
- `TestIsStandardBanner` → `banners_test.go` (tests `IsStandardBanner` in `banners.go`)
- `TestCaptureBanner_EmptyUsernames` + `mockHTTPPlugin` → `workers_test.go` (tests `captureBanner` in `workers.go`)
- `TestConfigValidate` stays in `brutus_test.go` (tests `Config.validate` in `brutus.go`)

**Why this matters:**
1. **Discoverability:** Tests next to implementation (Go convention)
2. **Maintainability:** File renames/moves keep tests aligned
3. **Clarity:** `banners_test.go` signals "tests for banners.go"

**Objection addressed:** "But `lockout_test.go` and `ratelimit_test.go` test the public API `Brute()`, not internal functions."

**Counter:** Those tests exercise `Brute()` AS the integration test, but they also directly test unexported functions:
- `lockout_test.go:166` — `TestReorderForSpray` calls `reorderForSpray(tt.input)` directly
- The test imports `package brutus` (internal tests) specifically to access unexported functions

**However**, `lockout_test.go` and `ratelimit_test.go` can stay as-is because:
- They test complete workflows (MaxAttempts, SprayMode, rate limiting)
- The primary intent is integration testing, not unit testing internals
- Moving them would split integration tests across files

**Verdict:** ✅ **SPLIT TESTS** — Create `banners_test.go` and `workers_test.go` as capability-lead proposes.

**Test file changes required:**
1. Create `banners_test.go` with `TestIsStandardBanner` (brutus_test.go lines 25-95)
2. Create `workers_test.go` with `TestCaptureBanner_EmptyUsernames` + `mockHTTPPlugin` (brutus_test.go lines 212-254)
3. Trim `brutus_test.go` to only contain `TestConfigValidate` (lines 97-210)
4. Leave `lockout_test.go` and `ratelimit_test.go` unchanged (integration tests)

---

### Disagreement 5: Task Ordering

**Backend-lead:** Start with `banners.go` (Task 1), then `registry.go` (Task 2)

**Capability-lead:** Start with `registry.go` (Task 1), then `workers.go` (Task 2)

**Analysis:**

Both orderings work, but **registry.go first** has a slight advantage:
- Registry has ZERO dependencies on other extraction targets
- Banners depends on `isHTTPProtocol` being moved (creates temporary state)

**Practical impact:** Negligible. Both orders complete successfully.

**Verdict:** 🤷 **EITHER WORKS** — Slight preference for `registry.go` first (capability-lead) for dependency simplicity.

---

## 3. Issues Both Plans Missed

### Issue 1: Constants Placement Ambiguity

**Backend-lead:** "Move `MaxBannerLength` and `MaxPasswordLength` to `llm.go` — LLM-specific constants"

**Capability-lead:** Same as backend-lead

**Evidence from source:**
- Line 72: `MaxBannerLength = 500` — Used by `SanitizeBanner` (line 869) in LLM utilities
- Line 74: `MaxPasswordLength = 32` — Used by `ValidateSuggestions` (line 882) in LLM utilities

**Analysis:** ✅ **CORRECT** — Both are used exclusively by LLM functions, not by core brutus logic. Moving to `llm.go` is correct.

**However, both plans MISS the export documentation:**

Neither plan mentions updating the godoc comments for these constants when moving them. The constants are EXPORTED and used by external analyzers (e.g., `internal/analyzers/claude/claude.go` uses `brutus.SanitizeBanner` which references `MaxBannerLength`).

**Correction needed:**
```go
// In llm.go
const (
    // MaxBannerLength limits banner size to prevent prompt injection.
    // This constant is exported for use by external analyzer implementations.
    MaxBannerLength = 500

    // MaxPasswordLength limits suggested password length.
    // This constant is exported for validation in analyzer implementations.
    MaxPasswordLength = 32
)
```

---

### Issue 2: Import Cleanup Timing

**Backend-lead:** "Defer import cleanup to Task 5"

**Capability-lead:** "Remove unused imports in each task"

**Evidence:**
- After extracting `registry.go` (Task 1), `brutus.go` no longer needs `"sort"` or `"sync"`
- But `brutus.go` STILL needs `"fmt"` (for `Brute()` error wrapping at line 449)

**Analysis:**

✅ **Backend-lead is safer:** Removing imports incrementally can cause build failures if the analysis is wrong. Deferring to Task 5 (final cleanup) ensures:
1. All extractions complete first
2. Unused imports verified by `go build` (compiler error on unused imports)
3. Single commit for import cleanup

**Verdict:** Defer import cleanup to Task 5.

---

### Issue 3: Line Count Estimates Differ Slightly

**Backend-lead:** `brutus.go` ~190 lines, `llm.go` ~110 lines
**Capability-lead:** `brutus.go` ~175 lines, `llm.go` ~105 lines

**Source evidence:** `brutus.go` is 906 lines total.

**Breakdown from source:**
- Types + interfaces (lines 70-214): ~145 lines
- Config validation (lines 385-439): ~55 lines
- `Brute()` entry point (lines 445-472): ~28 lines
- License header + package doc (lines 1-49): ~49 lines
- TLS context helpers (lines 77-96): ~20 lines

**Total:** ~145 + 55 + 28 + 49 + 20 = **~297 lines** for `brutus.go`

❌ **Both plans underestimate** — They forgot to account for:
- Import block (~18 lines)
- Section separator comments (~10 lines)
- Blank lines between sections (~15 lines)

**Corrected estimate:** `brutus.go` will be **~250 lines**, not ~175-190.

**Impact:** Low — still under 300 lines, meets size goals.

---

### Issue 4: Thread Safety Documentation

**Capability-lead:** Adds thread-safety documentation to `Plugin` interface and `Brute()` function (Task 5, Step 2-3)

**Backend-lead:** Adds thread-safety documentation to `runWorkers()` function in `workers.go`

**Analysis:**

✅ **Capability-lead is MORE CORRECT:**

The thread-safety contract is an **interface contract**, not an implementation detail. Documenting it on the `Plugin` interface (in `brutus.go`) makes it visible to:
1. Plugin authors (who implement `Plugin`)
2. Users reading the public API docs

Documenting it only in `runWorkers()` (unexported, in `workers.go`) hides it from plugin authors.

**Backend-lead's approach** documents the implementation side (workers.go) but misses the contract side (Plugin interface).

**Verdict:** Follow capability-lead — document on `Plugin` interface AND `Brute()` function.

---

## 4. Critical Corrections Required

Both plans need these corrections:

### Correction 1: Test File Splitting (MANDATORY)

**Backend-lead plan (Task 6):** Change from "NO CHANGES" to:

```markdown
## Task 6: Split test files

Create `banners_test.go` and `workers_test.go` to colocate tests with their source files.

**Step 1:** Create `pkg/brutus/banners_test.go`
- Move `TestIsStandardBanner` from `brutus_test.go` (lines 25-95)

**Step 2:** Create `pkg/brutus/workers_test.go`
- Move `TestCaptureBanner_EmptyUsernames` from `brutus_test.go` (lines 212-239)
- Move `mockHTTPPlugin` from `brutus_test.go` (lines 241-254)

**Step 3:** Trim `brutus_test.go`
- Remove moved tests, keep only `TestConfigValidate` (lines 97-210)

**Step 4:** Leave `lockout_test.go` and `ratelimit_test.go` unchanged
- These are integration tests for the public API
```

**Capability-lead plan (Task 6):** Already correct, but clarify:
- `lockout_test.go` and `ratelimit_test.go` stay unchanged (they're integration tests)

---

### Correction 2: Inline `runWorkersWithCredentials` (MANDATORY)

**Capability-lead plan (Task 2, Step 1):** Change "Deferred Items" section:

```markdown
### `runWorkersWithCredentials` inlining

**Status:** DEFERRED to separate PR

**Rationale:** Trivial wrapper, but inlining during file split mixes refactors.

**Action for this PR:** Move function to `workers.go` as-is.
**Action for followup PR:** Inline into `runWorkersWithLLM` at line 776.
```

Change to:

```markdown
### `runWorkersWithCredentials` inlining

**Status:** INLINE IN THIS PR (Task 2)

**In `runWorkersWithLLM` (workers.go), line 776, replace:**
```go
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)
```

**With:**
```go
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

**Delete `runWorkersWithCredentials` function entirely (do NOT move to workers.go).**
```

**Backend-lead plan:** Already correct (Task 4, Step 2).

---

### Correction 3: Thread Safety Documentation Placement

**Backend-lead plan (Task 3, Step 1):** Remove thread-safety note from `runWorkers()` in `workers.go`.

**Add to Task 5 (brutus.go cleanup) instead:**

```markdown
**Step 2:** Add thread-safety documentation to `Plugin` interface

Add godoc to `Plugin` interface (brutus.go):

```go
// Plugin defines the interface for authentication protocol implementations.
// Each plugin must implement credential testing for a specific protocol (SSH, FTP, etc.).
//
// Thread Safety: Plugin instances may be shared across concurrent goroutines
// in the worker pool. Implementations MUST be safe for concurrent use.
// Stateless plugins (the common case) are inherently safe. If a plugin
// maintains mutable state, it must use its own synchronization (e.g., sync.Mutex).
```

**Step 3:** Add thread-safety note to `Brute()` function

```go
// Brute executes a brute force attack using the provided configuration.
//
// The plugin is resolved once and shared across all worker goroutines.
// See the Plugin interface documentation for thread-safety requirements.
```

**Capability-lead plan:** Already correct (Task 5, Steps 2-3).

---

## 5. Final Verdict

**Merge both plans with corrections:**

| Decision Point | Use This Plan | With Correction |
|----------------|---------------|-----------------|
| File structure (5 files) | ✅ Both agree | None |
| `runWorkersWithCredentials` | ✅ Backend-lead | Inline and delete |
| Test file splitting | ✅ Capability-lead | Clarify integration tests stay |
| Task ordering | 🤷 Either works | Slight preference: capability-lead (registry first) |
| Thread safety docs | ✅ Capability-lead | Plugin interface + Brute() |
| `createAnalyzer` placement | ✅ Both agree (llm.go) | None |
| `runWorkersWithLLM`/`captureBanner` placement | ✅ Both agree (workers.go) | None |

---

## 6. Recommended Implementation Order

Follow **capability-lead task ordering** with **backend-lead's inline approach**:

1. **Task 1:** Create `registry.go` (backend-lead Task 2 = capability-lead Task 1)
2. **Task 2:** Create `workers.go` with `runWorkersWithCredentials` inlined (backend-lead Task 3 + Task 4 Step 2)
3. **Task 3:** Create `llm.go` (backend-lead Task 4)
4. **Task 4:** Create `banners.go` (backend-lead Task 1)
5. **Task 5:** Trim `brutus.go` with thread-safety docs (backend-lead Task 5 + capability-lead corrections)
6. **Task 6:** Split test files (capability-lead Task 6 — MANDATORY, not optional)
7. **Task 7:** Full verification (both plans agree)

---

## 7. Metadata

```json
{
  "agent": "backend-reviewer",
  "output_type": "code-review",
  "timestamp": "2026-02-14T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/brutus/.claude/plans",
  "skills_invoked": [
    "adhering-to-dry",
    "adhering-to-yagni",
    "analyzing-cyclomatic-complexity",
    "enforcing-evidence-based-analysis",
    "verifying-before-completion"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/backend/reviewing-backend-implementations/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/brutus/brutus.go:1-906",
    "pkg/brutus/brutus_test.go:1-255",
    "pkg/brutus/lockout_test.go:1-327",
    "pkg/brutus/ratelimit_test.go:1-264"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Implement using merged plan: capability-lead task ordering + backend-lead inline approach + test splitting corrections"
  }
}
```
