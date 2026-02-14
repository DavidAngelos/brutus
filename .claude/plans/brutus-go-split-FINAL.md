# Brutus.go File Split - Final Merged Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Split the 906-line `pkg/brutus/brutus.go` into 5 domain-cohesive files with proper security boundaries, correct export surfaces, and zero consumer impact.

**Architecture:** Same-package split (`package brutus`). No sub-packages, no import path changes for any consumer. LLM utilities isolated for future build-tag gating. Thread-safety contract documented per Finding 2.

**Tech Stack:** Go 1.24, errgroup, golang.org/x/time/rate

**Source Plans:**
- `brutus-go-split-backend-lead.md` (backend-lead)
- `brutus-go-split-capability-lead.md` (capability-lead)
- `brutus-go-split-backend-reviewer-feedback.md` (backend-reviewer)
- `brutus-go-split-capability-reviewer-feedback.md` (capability-reviewer)

---

```json
{
  "plan_metadata": {
    "feature": "brutus-go-split",
    "created": "2026-02-14T00:00:00Z",
    "total_tasks": 7,
    "estimated_time": "1.5-2 hours",
    "dependencies": [],
    "reviews": ["backend-lead", "capability-lead", "backend-reviewer", "capability-reviewer"]
  }
}
```

---

## Architecture Decisions (Consensus)

### D1: Same package, no sub-packages
All files remain in `package brutus`. No consumer changes. Sub-package for LLM evaluated and rejected (YAGNI -- zero external deps in LLM code).

### D2: LLM isolation via file boundaries
`llm.go` is designed so `//go:build !nollm` / `//go:build nollm` build tags can be added later without touching any other file. Not implemented now.

### D3: Worker pool owns credential generation
`credential` struct, `generateCredentials`, `generateKeyCredentials`, `reorderForSpray` all stay with `executeWorkerPool` in `workers.go`. The LLM orchestration flow (`runWorkersWithLLM`, `captureBanner`) also stays in `workers.go` because it's worker orchestration, not LLM utility code.

### D4: `isHTTPProtocol` goes to banners.go
Semantically a protocol classification function for banner detection. Called from both `runWorkers` (workers.go) and `IsStandardBanner` (banners.go). Same package, no import issue.

### D5: Inline `runWorkersWithCredentials` (backend-lead, approved by both reviewers)
Lines 821-824 are a pure pass-through wrapper with a single call site. Inline into `runWorkersWithLLM` and delete.

### D6: Move constants to llm.go (backend-lead, approved by both reviewers)
`MaxBannerLength` and `MaxPasswordLength` are used exclusively by LLM functions (`SanitizeBanner`, `ValidateSuggestions`). Not general brutus API.

### D7: Thread-safety documented on Plugin interface (capability-lead, approved by both reviewers)
Finding 2 (HIGH) addressed by adding godoc to `Plugin` interface and `Brute()` function. Architectural fix (factory-per-worker) deferred to separate PR.

### D8: Split test files to match source organization (capability-lead, approved by both reviewers)
`TestIsStandardBanner` -> `banners_test.go`, `TestCaptureBanner_EmptyUsernames` -> `workers_test.go`. Integration tests (`lockout_test.go`, `ratelimit_test.go`) stay as-is.

### D9: Defer import cleanup to Task 5 (backend-reviewer recommendation)
Don't remove imports from brutus.go incrementally. Wait until all extractions complete, then clean up in one pass. Compiler catches unused imports.

---

## File Layout (After Split)

```
pkg/brutus/
  brutus.go        (~250 lines) - Package doc, types, interfaces, config validation, Brute() entry point
  registry.go      (~100 lines) - Plugin registry + Analyzer registry
  workers.go       (~270 lines) - Worker pool engine + credential generation + LLM orchestration flow
  llm.go           (~105 lines) - LLM constants, createAnalyzer, BuildPrompt, SanitizeBanner, ValidateSuggestions, IsValidPassword
  banners.go       (~75 lines)  - standardBanners map, IsStandardBanner, isHTTPProtocol
  defaults.go      (37 lines)   - UNCHANGED
  errors.go        (37 lines)   - UNCHANGED
  target.go        (24 lines)   - UNCHANGED
```

---

## Detailed Function/Type Assignments

### brutus.go (~250 lines)

| Current Lines | Symbol | Type |
|---------------|--------|------|
| 1-49 | License + package doc + imports | Header |
| 82-83 | `contextKey`, `tlsModeContextKey` | Unexported type/const |
| 86-96 | `ContextWithTLSMode()`, `TLSModeFromContext()` | Exported funcs |
| 101-105 | `Credential` | Exported struct |
| 108-127 | `Config` | Exported struct |
| 130-144 | `Result` | Exported struct |
| 147-152 | `LLMConfig` | Exported struct |
| 155-157 | `BannerAnalyzer` | Exported interface |
| 160-164 | `CredentialAnalyzer` | Exported interface |
| 167-172 | `BannerInfo` | Exported struct |
| 175 | `AnalyzerFactory` | Exported type |
| 184-197 | `Plugin` | Exported interface (+ thread-safety docs) |
| 204-209 | `KeyPlugin` | Exported interface |
| 214 | `PluginFactory` | Exported type |
| 385-439 | `applyDefaults()`, `validate()` | Unexported methods on *Config |
| 446-472 | `Brute()` | Exported func (+ thread-safety docs) |

### registry.go (~100 lines)

| Current Lines | Symbol | Type |
|---------------|--------|------|
| 220-223 | `pluginRegistryMu`, `pluginRegistry` | Unexported vars |
| 228-237 | `Register()` | Exported func |
| 242-253 | `GetPlugin()` | Exported func |
| 257-268 | `ListPlugins()` | Exported func |
| 272-277 | `ResetPlugins()` | Exported func |
| 283-286 | `analyzerRegistryMu`, `analyzerRegistry` | Unexported vars |
| 290-294 | `RegisterAnalyzer()` | Exported func |
| 297-301 | `GetAnalyzerFactory()` | Exported func |

### workers.go (~270 lines)

| Current Lines | Symbol | Type |
|---------------|--------|------|
| 479-484 | `credential` struct | Unexported type |
| 487-500 | `generateCredentials()` | Unexported func |
| 503-516 | `generateKeyCredentials()` | Unexported func |
| 520-543 | `reorderForSpray()` | Unexported func |
| 546-560 | `runWorkers()` | Unexported func |
| 576-689 | `executeWorkerPool()` | Unexported func |
| 693-723 | `runWorkersDefault()` | Unexported func |
| 732-777 | `runWorkersWithLLM()` | Unexported func (**line 776 inlined**) |
| 781-800 | `captureBanner()` | Unexported func |
| ~~821-824~~ | ~~`runWorkersWithCredentials()`~~ | **DELETED (inlined)** |

### llm.go (~105 lines)

| Current Lines | Symbol | Type |
|---------------|--------|------|
| 70-75 | `MaxBannerLength`, `MaxPasswordLength` | Exported consts (moved from brutus.go) |
| 805-817 | `createAnalyzer()` | Unexported func |
| 831-854 | `BuildPrompt()` | Exported func |
| 857-874 | `SanitizeBanner()` | Exported func |
| 877-898 | `ValidateSuggestions()` | Exported func |
| 901-905 | `IsValidPassword()` | Exported func |

### banners.go (~75 lines)

| Current Lines | Symbol | Type |
|---------------|--------|------|
| 308-342 | `standardBanners` | Unexported var (read-only map) |
| 352-379 | `IsStandardBanner()` | Exported func |
| 564-571 | `isHTTPProtocol()` | Unexported func |

---

## Cross-File Call Graph (After Split)

```
brutus.go:
  Brute() --> registry.go:GetPlugin()
  Brute() --> workers.go:runWorkers()

workers.go:
  runWorkers() --> banners.go:isHTTPProtocol()
  runWorkers() --> workers.go:runWorkersWithLLM()
  runWorkers() --> workers.go:runWorkersDefault()
  runWorkersDefault() --> workers.go:generateCredentials()
  runWorkersDefault() --> workers.go:generateKeyCredentials()
  runWorkersDefault() --> workers.go:reorderForSpray()
  runWorkersDefault() --> workers.go:executeWorkerPool()
  runWorkersWithLLM() --> workers.go:captureBanner()
  runWorkersWithLLM() --> banners.go:IsStandardBanner()
  runWorkersWithLLM() --> llm.go:createAnalyzer()
  runWorkersWithLLM() --> workers.go:generateCredentials()
  runWorkersWithLLM() --> workers.go:executeWorkerPool()  [INLINED]
  runWorkersWithLLM() --> workers.go:runWorkersDefault()  [fallback]

llm.go:
  createAnalyzer() --> registry.go:GetAnalyzerFactory()

banners.go:
  IsStandardBanner() --> banners.go:isHTTPProtocol()
```

No circular imports (same package). Bidirectional workers.go <-> llm.go calls are valid within same package.

---

## Task 1: Create registry.go

**Files:**
- Create: `pkg/brutus/registry.go`
- Modify: `pkg/brutus/brutus.go` (remove lines 216-301)

**Step 1:** Create `pkg/brutus/registry.go` with:
- License header (copy from brutus.go lines 1-13)
- `package brutus`
- Imports: `"fmt"`, `"sort"`, `"sync"`
- Move plugin registry: `pluginRegistryMu`, `pluginRegistry` vars (lines 220-223)
- Move `Register()` (lines 228-237)
- Move `GetPlugin()` (lines 242-253)
- Move `ListPlugins()` (lines 257-268)
- Move `ResetPlugins()` (lines 272-277)
- Move analyzer registry: `analyzerRegistryMu`, `analyzerRegistry` vars (lines 283-286)
- Move `RegisterAnalyzer()` (lines 290-294)
- Move `GetAnalyzerFactory()` (lines 297-301)

**Step 2:** Remove lines 216-301 from brutus.go. Do NOT clean up imports yet (deferred to Task 5).

**Step 3:** Run `go build ./pkg/brutus/ && go test ./pkg/brutus/ -count=1`

**Step 4:** Commit: `refactor(brutus): extract plugin and analyzer registries to registry.go`

**Exit Criteria:**
- [ ] `registry.go` has exactly 6 exported functions + 4 package vars
- [ ] `go build ./pkg/brutus/` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes

---

## Task 2: Create workers.go

**Files:**
- Create: `pkg/brutus/workers.go`
- Modify: `pkg/brutus/brutus.go` (remove worker pool section)

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
- Move `runWorkersWithLLM()` (lines 732-777)
- Move `captureBanner()` (lines 781-800)
- **DO NOT move `runWorkersWithCredentials()` (lines 821-824) -- it is being eliminated**

**Step 2 (Architectural improvement):** In the moved `runWorkersWithLLM()`, replace line 776:

```go
// BEFORE:
return runWorkersWithCredentials(ctx, cfg, plug, allCreds, suggestions)

// AFTER:
return executeWorkerPool(ctx, cfg, plug, allCreds, suggestions)
```

Delete `runWorkersWithCredentials` from brutus.go entirely (do NOT move it).

**Step 3:** Remove all moved lines from brutus.go. Leave `isHTTPProtocol` (lines 564-571) and `createAnalyzer` (lines 805-817) temporarily -- they move in Tasks 3 and 4.

**Step 4:** Run `go build ./pkg/brutus/ && go test ./pkg/brutus/ -count=1 -race`

**Step 5:** Commit: `refactor(brutus): extract worker pool engine to workers.go

Inline runWorkersWithCredentials pass-through wrapper into
runWorkersWithLLM for DRY compliance (single call site, zero logic).`

**Exit Criteria:**
- [ ] `workers.go` has `credential` struct + 8 functions (NOT 9 -- wrapper eliminated)
- [ ] `runWorkersWithCredentials` does NOT exist in any file
- [ ] `go build ./pkg/brutus/` exits 0
- [ ] `go test ./pkg/brutus/ -count=1 -race` passes

---

## Task 3: Create llm.go

**Files:**
- Create: `pkg/brutus/llm.go`
- Modify: `pkg/brutus/brutus.go` (remove LLM utilities + createAnalyzer + constants)

**Step 1:** Create `pkg/brutus/llm.go` with:
- License header
- Security surface file header comment:

```go
// llm.go contains LLM integration utilities for banner analysis and credential suggestion.
//
// SECURITY NOTE: This file is the prompt injection defense surface.
// SanitizeBanner and ValidateSuggestions are the primary controls against
// malicious LLM output. Any hardening of LLM input/output processing
// should be concentrated in this file.
//
// BUILD TAG READINESS: This file has no external dependencies beyond stdlib.
// It can be guarded with "//go:build !nollm" in the future, with a companion
// llm_stub.go providing no-op fallbacks under "//go:build nollm".
```

- `package brutus`
- Imports: `"regexp"`, `"strings"`
- Move constants `MaxBannerLength`, `MaxPasswordLength` (lines 70-75 from brutus.go)
- Move `createAnalyzer()` (lines 805-817 from brutus.go)
- Move `BuildPrompt()` (lines 831-854)
- Move `SanitizeBanner()` (lines 857-874) with enhanced security godoc:

```go
// SanitizeBanner removes control chars and limits length to prevent prompt injection.
//
// SECURITY: This function is the first line of defense against prompt injection
// via crafted service banners. Known limitations (Finding 33):
// - Does not detect semantic injection patterns (e.g., "ignore previous instructions")
// - Triple-quote removal is necessary but not sufficient for all LLM providers
// - Consider adding structured output enforcement in future hardening
```

- Move `ValidateSuggestions()` (lines 877-898)
- Move `IsValidPassword()` (lines 901-905)

**Step 2:** Remove the moved lines from brutus.go. Do NOT clean up imports yet.

**Step 3:** Run `go build ./pkg/brutus/ && go test ./pkg/brutus/ -count=1`

**Step 4:** Commit: `refactor(brutus): extract LLM utilities to llm.go

Isolates prompt construction, banner sanitization, and suggestion
validation into a dedicated file. Establishes a clear security
surface for prompt injection defenses (Finding 33) and enables
future build-tag isolation for LLM-free builds.`

**Exit Criteria:**
- [ ] `llm.go` has 2 constants + 5 functions
- [ ] `MaxBannerLength` and `MaxPasswordLength` NOT in brutus.go
- [ ] `go build ./pkg/brutus/` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes

---

## Task 4: Create banners.go

**Files:**
- Create: `pkg/brutus/banners.go`
- Modify: `pkg/brutus/brutus.go` (remove banner section + isHTTPProtocol)

**Step 1:** Create `pkg/brutus/banners.go` with:
- License header
- `package brutus`
- Import: `"strings"`
- Move `standardBanners` map (lines 308-342)
- Move `IsStandardBanner()` (lines 352-379)
- Move `isHTTPProtocol()` (lines 564-571)

**Step 2:** Remove the moved lines from brutus.go.

**Step 3:** Run `go build ./pkg/brutus/ && go test ./pkg/brutus/ -count=1`

**Step 4:** Commit: `refactor(brutus): extract banner detection to banners.go`

**Exit Criteria:**
- [ ] `banners.go` has 1 var + 2 functions
- [ ] `go build ./pkg/brutus/` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes

---

## Task 5: Clean up brutus.go

**Files:**
- Modify: `pkg/brutus/brutus.go` (clean imports, add documentation)

**What remains after Tasks 1-4:**
- License header + package doc
- Import block (needs cleanup)
- TLS context helpers (lines 82-96)
- All types: Credential, Config, Result, LLMConfig, BannerAnalyzer, CredentialAnalyzer, BannerInfo, AnalyzerFactory, Plugin, KeyPlugin, PluginFactory
- Config methods: applyDefaults, validate
- Brute() entry point

**Step 1:** Clean up import block. Remove all imports that moved to other files:
- Remove: `"math/rand"`, `"regexp"`, `"sort"`, `"sync"`, `"sync/atomic"`, `"golang.org/x/sync/errgroup"`, `"golang.org/x/time/rate"`
- Keep: `"context"`, `"errors"`, `"fmt"`, `"net/http"`, `"strings"`, `"time"`, `"github.com/praetorian-inc/brutus/pkg/badkeys"`

**Step 2:** Add thread-safety documentation to `Plugin` interface:

```go
// Plugin defines the interface for authentication protocol implementations.
// Each plugin must implement credential testing for a specific protocol (SSH, FTP, etc.).
//
// Thread Safety: Plugin instances may be shared across concurrent goroutines
// in the worker pool. Implementations MUST be safe for concurrent use.
// Stateless plugins (the common case) are inherently safe. If a plugin
// maintains mutable state, it must use its own synchronization (e.g., sync.Mutex).
type Plugin interface {
    Name() string
    Test(ctx context.Context, target, username, password string, timeout time.Duration) *Result
}
```

**Step 3:** Add thread-safety note to `Brute()`:

```go
// Brute executes a brute force attack using the provided configuration.
//
// The plugin is resolved once via GetPlugin and shared across all worker goroutines.
// See the Plugin interface documentation for thread-safety requirements.
func Brute(cfg *Config) ([]Result, error) {
```

**Step 4:** Remove any stale section comments (e.g., "// Worker Pool Implementation").

**Step 5:** Run `go vet ./pkg/brutus/ && go build ./... && go test ./pkg/brutus/ -count=1 -race`

**Step 6:** Commit: `refactor(brutus): clean brutus.go to types, config, and entry point

Final step of the file split. brutus.go now contains only:
- Package documentation and core types
- Config validation methods
- Brute() entry point

Added thread-safety documentation to Plugin interface (Finding 2)
and Brute() function to clarify concurrent usage contract.`

**Exit Criteria:**
- [ ] brutus.go under 260 lines
- [ ] brutus.go has 5 functions: `ContextWithTLSMode`, `TLSModeFromContext`, `applyDefaults`, `validate`, `Brute`
- [ ] Thread-safety godoc present on `Plugin` interface
- [ ] `go vet ./pkg/brutus/` exits 0
- [ ] `go build ./...` exits 0
- [ ] `go test ./pkg/brutus/ -count=1 -race` passes

---

## Task 6: Split test files

**Files:**
- Create: `pkg/brutus/banners_test.go`
- Create: `pkg/brutus/workers_test.go`
- Modify: `pkg/brutus/brutus_test.go`

**Step 1:** Create `pkg/brutus/banners_test.go`:
- Move `TestIsStandardBanner` from `brutus_test.go` (lines 25-95)
- Package: `package brutus` (internal test)
- Imports: `"testing"`, `"github.com/stretchr/testify/assert"`

**Step 2:** Create `pkg/brutus/workers_test.go`:
- Move `TestCaptureBanner_EmptyUsernames` from `brutus_test.go` (lines 212-239)
- Move `mockHTTPPlugin` helper from `brutus_test.go` (lines 241-254)
- Package: `package brutus` (internal test)
- Imports: `"context"`, `"testing"`, `"time"`, `"github.com/stretchr/testify/assert"`

**Step 3:** Trim `brutus_test.go`:
- Remove moved tests. Only `TestConfigValidate` (lines 97-210) remains.
- Update imports if needed.

**Step 4:** Leave `lockout_test.go` and `ratelimit_test.go` UNCHANGED (integration tests for public API).

**Step 5:** Run `go test ./pkg/brutus/ -v -count=1`

**Step 6:** Commit: `refactor(brutus): split test files to match source file organization`

**Exit Criteria:**
- [ ] 8 test files: brutus_test.go, banners_test.go, workers_test.go, ratelimit_test.go, lockout_test.go, defaults_test.go, errors_test.go, target_test.go
- [ ] Each test file tests functions from its corresponding source file
- [ ] `go test ./pkg/brutus/ -v -count=1` passes

---

## Task 7: Full Verification

**No file changes. Verification only.**

**Step 1:** Verify file inventory:
```bash
ls pkg/brutus/*.go | grep -v _test.go | wc -l
# Expected: 8 (brutus, registry, workers, llm, banners, defaults, errors, target)
```

**Step 2:** Verify no duplicate symbols:
```bash
grep -rn '^func ' pkg/brutus/*.go | grep -v _test.go | sort -t: -k3
# Each function appears exactly once
```

**Step 3:** Verify deleted function is gone:
```bash
grep -r 'func runWorkersWithCredentials' pkg/brutus/
# Expected: no output
```

**Step 4:** Verify constants placement:
```bash
grep -n 'MaxBannerLength\|MaxPasswordLength' pkg/brutus/llm.go
# Expected: both constants in llm.go
```

**Step 5:** Verify thread-safety docs:
```bash
grep -A3 'Thread Safety' pkg/brutus/brutus.go
# Expected: thread-safety godoc on Plugin interface
```

**Step 6:** Verify line counts:
```bash
wc -l pkg/brutus/*.go | grep -v _test.go | sort -n
# Expected: all under 300 lines
```

**Step 7:** Full test suite with race detector:
```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go vet ./...
go build ./...
go test ./... -count=1 -race
```

**Step 8:** Verify no test files were modified beyond Task 6:
```bash
git diff --name-only HEAD~2 -- '*_test.go'
# Expected: only brutus_test.go, banners_test.go, workers_test.go
```

**Exit Criteria:**
- [ ] 8 source files in `pkg/brutus/` (excluding tests)
- [ ] 8 test files in `pkg/brutus/`
- [ ] 0 duplicate function definitions
- [ ] `runWorkersWithCredentials` does NOT exist
- [ ] `MaxBannerLength`/`MaxPasswordLength` in `llm.go`
- [ ] Thread-safety docs on `Plugin` interface
- [ ] No source file exceeds 300 lines
- [ ] `go vet ./...` exits 0
- [ ] `go build ./...` exits 0
- [ ] `go test ./... -count=1 -race` passes with 0 failures

---

## Deferred Items (NOT in This Plan)

### Finding 2 (HIGH): Factory-per-worker fix
The proper fix is to pass `PluginFactory` to `executeWorkerPool` instead of a shared `Plugin` instance. This requires signature changes and test mock updates. Separate PR.

### Finding 33 (HIGH): Banner sanitization hardening
`SanitizeBanner` is now positioned in `llm.go` for targeted hardening. Future work:
1. Semantic injection pattern detection
2. Unicode normalization
3. Structured output enforcement (JSON schema on LLM response)
4. Character whitelist (printable ASCII only)

### Build tag isolation for LLM
`llm.go` is ready for `//go:build !nollm` gating. A stub file (`llm_stub.go` with `//go:build nollm`) can provide no-op fallbacks. No changes to other files needed.

### main.go split (C1)
1340-line CLI split into `runner.go`, `output.go`, `pipeline.go`, `ai.go`. Separate PR after brutus.go split lands.

---

## Metadata

```json
{
  "plan_type": "merged-final",
  "created": "2026-02-14T00:00:00Z",
  "contributors": [
    "backend-lead (architecture plan)",
    "capability-lead (architecture plan)",
    "backend-reviewer (review + corrections)",
    "capability-reviewer (review + corrections)"
  ],
  "merge_decisions": {
    "file_structure": "both plans agree (5 files)",
    "task_ordering": "capability-lead (registry first)",
    "inline_wrapper": "backend-lead (delete runWorkersWithCredentials)",
    "constant_placement": "backend-lead (llm.go)",
    "test_splitting": "capability-lead (banners_test.go, workers_test.go)",
    "thread_safety_docs": "capability-lead (Plugin interface)",
    "security_docs": "capability-lead (llm.go header)",
    "import_cleanup": "backend-reviewer (defer to Task 5)",
    "line_count_estimate": "backend-reviewer correction (~250 not ~175)"
  },
  "status": "ready_for_execution"
}
```
