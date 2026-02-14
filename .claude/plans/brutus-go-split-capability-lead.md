# Brutus pkg/brutus/brutus.go File Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Split the 906-line `pkg/brutus/brutus.go` into 5 focused files with clean security boundaries, proper LLM isolation, and correct export surfaces.

**Architecture:** The single `brutus.go` file contains 6 distinct responsibility areas crammed together: types/config, plugin+analyzer registries, worker pool engine, LLM orchestration flow, LLM utilities (prompt/sanitize/validate), and standard banner detection. This split separates them along security-domain boundaries while keeping everything in the same `brutus` package (no import changes for any consumer). The LLM-related code is isolated into files that could be guarded by build tags in the future.

**Tech Stack:** Go 1.24, errgroup, golang.org/x/time/rate, stdlib only (no new dependencies)

---

## Table of Contents

1. [Evidence Summary](#evidence-summary)
2. [Architecture Decisions](#architecture-decisions)
3. [File Map: Current to Proposed](#file-map-current-to-proposed)
4. [Security Boundary Analysis](#security-boundary-analysis)
5. [Task 1: Create registry.go](#task-1-create-registrygo)
6. [Task 2: Create workers.go](#task-2-create-workersgo)
7. [Task 3: Create llm.go](#task-3-create-llmgo)
8. [Task 4: Create banners.go](#task-4-create-bannersgo)
9. [Task 5: Trim brutus.go to types + entry point](#task-5-trim-brutusgo-to-types--entry-point)
10. [Task 6: Split test files](#task-6-split-test-files)
11. [Task 7: Verification pass](#task-7-verification-pass)
12. [Deferred Items and Architectural Notes](#deferred-items-and-architectural-notes)

---

## Evidence Summary

### Verified Source Files (all read with Read tool)

| File | Lines | Purpose |
|------|-------|---------|
| `pkg/brutus/brutus.go` | 906 | Monolith being split |
| `pkg/brutus/errors.go` | 37 | ClassifyAuthError helper |
| `pkg/brutus/target.go` | 24 | ParseTarget helper |
| `pkg/brutus/defaults.go` | 37 | DefaultCredentials + embedded wordlists |
| `pkg/brutus/brutus_test.go` | 255 | Tests for IsStandardBanner, Config.validate, captureBanner |
| `pkg/brutus/ratelimit_test.go` | 264 | Tests for rate limiting, jitter, context cancellation |
| `pkg/brutus/lockout_test.go` | 327 | Tests for MaxAttempts, SprayMode, reorderForSpray |
| `pkg/brutus/defaults_test.go` | 165 | Tests for DefaultCredentials, applyDefaults |
| `pkg/brutus/errors_test.go` | (exists) | Tests for ClassifyAuthError |
| `pkg/brutus/target_test.go` | (exists) | Tests for ParseTarget |
| `internal/plugins/ssh/ssh.go` | 226 | Plugin consumer: uses `brutus.Register`, `brutus.Plugin`, `brutus.KeyPlugin`, `brutus.ClassifyAuthError`, `brutus.Result` |
| `internal/plugins/http/http.go` | 286 | Plugin consumer: uses `brutus.Register`, `brutus.Plugin`, `brutus.TLSModeFromContext`, `brutus.Result` |
| `internal/plugins/init.go` | 43 | Side-effect import hub for all plugins |
| `internal/analyzers/claude/claude.go` | 150 | Analyzer consumer: uses `brutus.RegisterAnalyzer`, `brutus.BannerAnalyzer`, `brutus.BannerInfo`, `brutus.BuildPrompt`, `brutus.SanitizeBanner`, `brutus.ValidateSuggestions`, `brutus.LLMConfig` |
| `internal/analyzers/init.go` | 23 | Side-effect import hub for all analyzers |
| `cmd/brutus/main.go` | 1341 | CLI: uses `brutus.Brute`, `brutus.Config`, `brutus.LLMConfig`, `brutus.Credential`, `brutus.Result`, `brutus.GetAnalyzerFactory`, `brutus.CredentialAnalyzer`, `brutus.BannerInfo` |
| `pkg/builtins/builtins.go` | 12 | Convenience side-effect import |
| `go.mod` | 75 | Module: `github.com/praetorian-inc/brutus`, Go 1.24 |

### Verified Exported API Surface (from brutus.go lines 70-905)

**Types (lines 70-176):**
- `MaxBannerLength` (const, line 72)
- `MaxPasswordLength` (const, line 74)
- `contextKey` (unexported, line 82)
- `tlsModeContextKey` (unexported, line 83)
- `ContextWithTLSMode` (func, line 86)
- `TLSModeFromContext` (func, line 91)
- `Credential` (struct, line 101-105)
- `Config` (struct, line 108-127)
- `Result` (struct, line 130-144)
- `LLMConfig` (struct, line 147-152)
- `BannerAnalyzer` (interface, line 155-157)
- `CredentialAnalyzer` (interface, line 160-164)
- `BannerInfo` (struct, line 167-172)
- `AnalyzerFactory` (type, line 175)
- `Plugin` (interface, line 184-197)
- `KeyPlugin` (interface, line 204-209)
- `PluginFactory` (type, line 214)

**Plugin Registry (lines 220-278):**
- `pluginRegistryMu` (unexported var, line 221)
- `pluginRegistry` (unexported var, line 222)
- `Register` (func, line 228)
- `GetPlugin` (func, line 242)
- `ListPlugins` (func, line 257)
- `ResetPlugins` (func, line 272)

**Analyzer Registry (lines 283-301):**
- `analyzerRegistryMu` (unexported var, line 283)
- `analyzerRegistry` (unexported var, line 284)
- `RegisterAnalyzer` (func, line 290)
- `GetAnalyzerFactory` (func, line 297)

**Standard Banners (lines 308-379):**
- `standardBanners` (unexported var, line 308)
- `IsStandardBanner` (func, line 352)

**Config Validation (lines 385-439):**
- `applyDefaults` (method on *Config, line 388)
- `validate` (method on *Config, line 413)

**Brute Force Entry Point (lines 445-472):**
- `Brute` (func, line 446)

**Worker Pool (lines 478-824):**
- `credential` (unexported struct, line 479-484)
- `generateCredentials` (unexported func, line 487)
- `generateKeyCredentials` (unexported func, line 503)
- `reorderForSpray` (unexported func, line 520)
- `runWorkers` (unexported func, line 546)
- `isHTTPProtocol` (unexported func, line 564)
- `executeWorkerPool` (unexported func, line 576)
- `runWorkersDefault` (unexported func, line 693)
- `runWorkersWithLLM` (unexported func, line 732)
- `captureBanner` (unexported func, line 781)
- `createAnalyzer` (unexported func, line 805)
- `runWorkersWithCredentials` (unexported func, line 821)

**LLM Utilities (lines 830-905):**
- `BuildPrompt` (func, line 831)
- `SanitizeBanner` (func, line 857)
- `ValidateSuggestions` (func, line 877)
- `IsValidPassword` (func, line 901)

### Verified Consumers of Exported Symbols

| Symbol | Consumers |
|--------|-----------|
| `Register` | All 22 plugin init() funcs (ssh, http, ftp, etc.) |
| `Plugin`, `KeyPlugin` | All plugin struct implementations |
| `PluginFactory` | All plugin init() funcs |
| `GetPlugin`, `ListPlugins`, `ResetPlugins` | brutus.go internal, test files |
| `RegisterAnalyzer` | claude.go:38, perplexity, vision init() funcs |
| `GetAnalyzerFactory` | cmd/brutus/main.go:1026,1087 and brutus.go:811 |
| `BannerAnalyzer`, `CredentialAnalyzer` | claude.go, perplexity.go, vision.go, cmd/brutus/main.go |
| `BannerInfo` | claude.go:74, cmd/brutus/main.go:1106,1134 |
| `BuildPrompt` | claude.go:76 |
| `SanitizeBanner` | claude.go:76 |
| `ValidateSuggestions` | claude.go:134 |
| `LLMConfig` | cmd/brutus/main.go:159,172,179 |
| `Credential` | cmd/brutus/main.go:766,769,1123-1125, defaults.go |
| `Config`, `Brute`, `Result` | cmd/brutus/main.go throughout |
| `ContextWithTLSMode`, `TLSModeFromContext` | http.go:93, brutus.go:548 |
| `ClassifyAuthError` | ssh.go:224, and many other plugins |
| `IsStandardBanner` | brutus.go:737 internal only |
| `IsValidPassword` | No external consumer found (only ValidateSuggestions) |

### Assumptions (Not Directly Verified)

| Assumption | Why Unverified | Risk if Wrong |
|------------|----------------|---------------|
| No external consumer calls `IsValidPassword` directly | Searched with Grep but could miss indirect consumers outside this repo | If wrong, must keep exported; mitigation: keep exported for now |
| Test files reference only symbols in same package (package brutus) | All test files use `package brutus` so they have access to unexported symbols | No risk - same package |

---

## Architecture Decisions

### Decision 1: Same package, no sub-packages

**Rationale:** All files remain in `package brutus`. This is a Tier 1 architecture (<10 files) per the `enforcing-go-capability-architecture` skill. Creating sub-packages would force import path changes across 22+ plugin files and the CLI. The code sharing between workers and LLM orchestration (the `credential` struct, `executeWorkerPool`) makes package boundaries painful. YAGNI applies: sub-packages can be introduced later if the package grows beyond 10 files.

**Implication:** Zero import changes in any consumer. All plugins, analyzers, CLI, and builtins continue to import `"github.com/praetorian-inc/brutus/pkg/brutus"` unchanged.

### Decision 2: LLM isolation via file boundaries, not build tags (yet)

**Rationale:** The LLM utilities (`BuildPrompt`, `SanitizeBanner`, `ValidateSuggestions`, `IsValidPassword`) have zero external dependencies (pure string manipulation). The LLM orchestration flow (`runWorkersWithLLM`, `captureBanner`, `createAnalyzer`) depends only on the analyzer registry which is also dependency-free. Build tags would add complexity for zero dependency savings today. However, the file split is designed so that build tags CAN be added later by:
1. Adding `//go:build !nollm` to `llm.go`
2. Creating a `llm_stub.go` with `//go:build nollm` that provides no-op fallbacks
3. No changes to any other file

**Implication:** File boundaries are the isolation mechanism now. Build tag readiness is a design property, not an implementation requirement.

### Decision 3: Worker pool gets credential generation

**Rationale:** `generateCredentials`, `generateKeyCredentials`, and `reorderForSpray` are pure functions that produce the input to `executeWorkerPool`. They are conceptually "worker pool preparation" and have no dependencies outside the package. Separating them into a `credentials.go` file was considered but rejected because:
1. They are only called from `runWorkersDefault` and `runWorkersWithLLM` (both in workers.go)
2. The `credential` struct (unexported) would need to be in a shared file anyway
3. YAGNI: 3 small functions don't justify a separate file

### Decision 4: `isHTTPProtocol` goes to banners.go

**Rationale:** `isHTTPProtocol` is called from two places: `runWorkers` (workers.go) to decide LLM flow, and `IsStandardBanner` (banners.go) to handle HTTP protocols. Since its purpose is protocol classification for banner/LLM decisions, it belongs with banner logic. Workers.go will call it cross-file (same package, no issue).

### Decision 5: Keep `runWorkersWithLLM` and `captureBanner` in workers.go, not llm.go

**Rationale:** `runWorkersWithLLM` is fundamentally a worker pool orchestration function that happens to call LLM APIs. It calls `executeWorkerPool`, manages credentials, and interacts with `runWorkersDefault` as a fallback. Moving it to llm.go would split the worker flow across two files. Instead, llm.go contains only the LLM utilities (prompt building, sanitization, validation) and the `createAnalyzer` factory helper. This keeps the worker pool flow readable in one file while isolating the LLM-specific string processing.

**Revised after analysis:** `createAnalyzer` is a 12-line function that bridges LLM config to analyzer registry. It belongs in llm.go since it's LLM configuration logic, not worker orchestration. `captureBanner` captures the banner for LLM analysis but is part of the worker flow, so it stays in workers.go.

### Decision 6: Thread-safety documentation approach for Finding 2

**Rationale:** Finding 2 (HIGH) identified that a shared mutable plugin instance is passed to concurrent workers via `plug` parameter. The current architecture creates a fresh plugin per `GetPlugin` call (factory pattern, line 252: `return factory(), nil`), but `Brute()` creates one instance and shares it. The split should:
1. Document the thread-safety requirement on the `Plugin` interface
2. Add a godoc comment on `Brute()` explaining the shared instance pattern
3. NOT change the architecture (that's a separate fix, not a file split)

### Decision 7: Position SanitizeBanner for future hardening (Finding 33)

**Rationale:** Finding 33 (HIGH) identified that `SanitizeBanner` is insufficient for LLM prompt injection. By placing it in `llm.go` alongside `BuildPrompt`, it creates a clear "LLM security surface" file where future hardening (e.g., additional injection patterns, structured output enforcement) can be concentrated. The file header comment will note the security-sensitive nature.

---

## File Map: Current to Proposed

### Source: `pkg/brutus/brutus.go` (906 lines)

| Line Range | Content | Destination File | Rationale |
|------------|---------|-----------------|-----------|
| 1-68 | Package doc + imports | `brutus.go` (trimmed) | Package-level documentation stays at entry point |
| 70-76 | Constants (MaxBannerLength, MaxPasswordLength) | `llm.go` | These constants govern LLM behavior (banner limits, password limits) |
| 82-96 | Context keys (TLS mode) | `brutus.go` | Cross-cutting context concern, used by types/config |
| 98-214 | Types: Credential, Config, Result, LLMConfig, BannerAnalyzer, CredentialAnalyzer, BannerInfo, AnalyzerFactory, Plugin, KeyPlugin, PluginFactory | `brutus.go` | Core types are the package's primary API surface |
| 220-278 | Plugin Registry: pluginRegistryMu, pluginRegistry, Register, GetPlugin, ListPlugins, ResetPlugins | `registry.go` | Self-contained registry with its own mutex |
| 283-301 | Analyzer Registry: analyzerRegistryMu, analyzerRegistry, RegisterAnalyzer, GetAnalyzerFactory | `registry.go` | Same pattern, same file |
| 308-379 | Standard Banners: standardBanners map, IsStandardBanner, isHTTPProtocol (from 564-571) | `banners.go` | Protocol detection and banner classification |
| 385-439 | Config validation: applyDefaults, validate | `brutus.go` | Methods on Config struct, belong with the type |
| 446-472 | Brute entry point | `brutus.go` | Public API entry point |
| 478-824 | Worker pool: credential struct, generateCredentials, generateKeyCredentials, reorderForSpray, runWorkers, executeWorkerPool, runWorkersDefault, runWorkersWithLLM, captureBanner, runWorkersWithCredentials | `workers.go` | Complete worker pool engine |
| 564-571 | isHTTPProtocol | `banners.go` | Protocol classification (moved from middle of workers section) |
| 805-817 | createAnalyzer | `llm.go` | LLM configuration bridge |
| 831-905 | LLM Utilities: BuildPrompt, SanitizeBanner, ValidateSuggestions, IsValidPassword | `llm.go` | LLM security surface |

### Proposed File Sizes (estimated)

| File | Estimated Lines | Content |
|------|----------------|---------|
| `brutus.go` | ~175 | Package doc, imports, TLS context, all types/interfaces, Config methods, Brute() |
| `registry.go` | ~95 | Plugin registry + Analyzer registry |
| `workers.go` | ~285 | credential struct, generation, reorder, all runWorkers*, executeWorkerPool, captureBanner |
| `llm.go` | ~105 | Constants, createAnalyzer, BuildPrompt, SanitizeBanner, ValidateSuggestions, IsValidPassword |
| `banners.go` | ~55 | standardBanners map, IsStandardBanner, isHTTPProtocol |
| `errors.go` | 37 | Unchanged |
| `target.go` | 24 | Unchanged |
| `defaults.go` | 37 | Unchanged |
| **Total** | ~813 | ~906 original minus removed duplication in imports |

### Unchanged Files

- `pkg/brutus/errors.go` - No changes
- `pkg/brutus/target.go` - No changes
- `pkg/brutus/defaults.go` - No changes

---

## Security Boundary Analysis

### Boundary 1: Core Engine (brutus.go + workers.go)

These files contain the brute-force engine with no LLM dependencies. They handle:
- Configuration validation
- Credential generation (Cartesian products, spray reordering)
- Concurrent worker pool with rate limiting, jitter, max attempts
- Context cancellation and early stopping

**Security properties:** Rate limiting, lockout protection (MaxAttempts), TLS mode enforcement.

### Boundary 2: LLM Integration (llm.go)

This file contains all code that constructs LLM prompts and processes LLM output. It is the **prompt injection defense surface**.

**Security properties:**
- `SanitizeBanner` - Strips control chars, ANSI codes, triple quotes (Finding 33: needs hardening)
- `ValidateSuggestions` - Whitelist filtering on LLM-suggested passwords
- `IsValidPassword` - Character allowlist enforcement
- `BuildPrompt` - Prompt template construction

**Future hardening point:** All LLM input/output processing is in one file. A security review of prompt injection defenses only needs to audit this single file.

### Boundary 3: Plugin/Analyzer Registry (registry.go)

Thread-safe registration with `sync.RWMutex`. Isolated from business logic.

**Security properties:** Factory pattern ensures fresh instances per `GetPlugin` call (relevant to Finding 2). The registry itself is correctly thread-safe.

### Boundary 4: Banner Detection (banners.go)

Protocol classification and known-banner matching. Determines whether LLM analysis is triggered.

**Security properties:** Controls the gate between "use defaults" and "use LLM". A false negative here (treating a custom banner as standard) means LLM analysis is skipped - safe failure mode.

---

## Task 1: Create registry.go

**Files:**
- Create: `pkg/brutus/registry.go`
- Modify: `pkg/brutus/brutus.go` (remove lines 216-301)

**What moves:**

From `brutus.go`, extract lines 216-301 (the section between `// Plugin Registry` and end of `// Analyzer Registry`):

```go
// Lines 216-278: Plugin Registry section
// Lines 279-301: Analyzer Registry section
```

**Step 1: Create `pkg/brutus/registry.go`**

Create the file with the following content. The copyright header is the same as brutus.go lines 1-13. The package is `brutus`. The imports needed are `fmt`, `sort`, `sync`.

```go
// Copyright 2026 Praetorian Security, Inc.
// [full Apache 2.0 header - copy from brutus.go lines 1-13]

package brutus

import (
	"fmt"
	"sort"
	"sync"
)

// =============================================================================
// Plugin Registry
// =============================================================================

var (
	pluginRegistryMu sync.RWMutex
	pluginRegistry   = make(map[string]PluginFactory)
)

// Register adds a plugin factory to the registry.
// This function should be called from plugin init() functions.
// Panics if a plugin with the same name is already registered.
//
// Thread Safety: This function acquires a write lock on the plugin registry.
// It is safe to call concurrently, but is typically called during init().
func Register(name string, factory PluginFactory) {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	if _, exists := pluginRegistry[name]; exists {
		panic(fmt.Sprintf("brutus: plugin %q already registered", name))
	}

	pluginRegistry[name] = factory
}

// GetPlugin retrieves a plugin by name and returns a new instance.
// Returns an error if the plugin is not found.
// Each call returns a fresh instance from the factory.
func GetPlugin(name string) (Plugin, error) {
	pluginRegistryMu.RLock()
	factory, exists := pluginRegistry[name]
	pluginRegistryMu.RUnlock()

	if !exists {
		available := ListPlugins()
		return nil, fmt.Errorf("unknown protocol %q (available: %v)", name, available)
	}

	return factory(), nil
}

// ListPlugins returns a sorted list of all registered plugin names.
// The list is sorted to ensure deterministic output in error messages.
func ListPlugins() []string {
	pluginRegistryMu.RLock()
	defer pluginRegistryMu.RUnlock()

	names := make([]string, 0, len(pluginRegistry))
	for name := range pluginRegistry {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

// ResetPlugins clears all registered plugins.
// This function is intended for testing only.
func ResetPlugins() {
	pluginRegistryMu.Lock()
	defer pluginRegistryMu.Unlock()

	pluginRegistry = make(map[string]PluginFactory)
}

// =============================================================================
// Analyzer Registry
// =============================================================================

var (
	analyzerRegistryMu sync.RWMutex
	analyzerRegistry   = make(map[string]AnalyzerFactory)
)

// RegisterAnalyzer registers an analyzer factory for a provider name.
// This is called by analyzer implementations in their init() functions.
func RegisterAnalyzer(provider string, factory AnalyzerFactory) {
	analyzerRegistryMu.Lock()
	defer analyzerRegistryMu.Unlock()
	analyzerRegistry[provider] = factory
}

// GetAnalyzerFactory retrieves the factory for a given provider
func GetAnalyzerFactory(provider string) AnalyzerFactory {
	analyzerRegistryMu.RLock()
	defer analyzerRegistryMu.RUnlock()
	return analyzerRegistry[provider]
}
```

**Step 2: Remove lines 216-301 from brutus.go**

Delete the `// Plugin Registry` section header through the end of `GetAnalyzerFactory`. Also remove `"fmt"`, `"sort"`, and `"sync"` from brutus.go imports ONLY IF they are no longer needed (they will still be needed - `fmt` for Brute error wrapping, `sync` for workers.go which hasn't been extracted yet). Defer import cleanup to Task 5.

**Step 3: Run tests**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./pkg/brutus/ -v -count=1
```

Expected: All existing tests pass. No test references registry internals directly (they use the exported `Register`, `ResetPlugins`, etc.).

**Step 4: Run build**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go build ./...
```

Expected: Build succeeds with exit 0.

**Step 5: Commit**

```bash
git add pkg/brutus/registry.go pkg/brutus/brutus.go
git commit -m "refactor(brutus): extract plugin and analyzer registries to registry.go"
```

**Exit Criteria:**
- [ ] 1 new file created: `pkg/brutus/registry.go` containing exactly 6 exported functions: Register, GetPlugin, ListPlugins, ResetPlugins, RegisterAnalyzer, GetAnalyzerFactory (verify: `grep -c '^func ' pkg/brutus/registry.go` returns 6)
- [ ] 0 exported functions from registry remain in brutus.go (verify: `grep -c 'func Register\|func GetPlugin\|func ListPlugins\|func ResetPlugins\|func RegisterAnalyzer\|func GetAnalyzerFactory' pkg/brutus/brutus.go` returns 0)
- [ ] `go build ./...` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes with 0 failures

---

## Task 2: Create workers.go

**Files:**
- Create: `pkg/brutus/workers.go`
- Modify: `pkg/brutus/brutus.go` (remove worker pool section)

**What moves:**

From `brutus.go`, extract the entire Worker Pool Implementation section. This includes:

| Lines | Function/Type | Notes |
|-------|--------------|-------|
| 478-484 | `credential` struct | Unexported, only used by worker functions |
| 487-500 | `generateCredentials` | Pure function |
| 503-516 | `generateKeyCredentials` | Pure function |
| 520-543 | `reorderForSpray` | Pure function |
| 546-560 | `runWorkers` | Dispatch function (calls isHTTPProtocol from banners.go) |
| 576-689 | `executeWorkerPool` | Core engine |
| 693-723 | `runWorkersDefault` | Default flow |
| 732-777 | `runWorkersWithLLM` | LLM-enhanced flow (calls createAnalyzer from llm.go) |
| 781-800 | `captureBanner` | Banner capture for LLM |
| 821-824 | `runWorkersWithCredentials` | Thin wrapper |

**NOTE:** `isHTTPProtocol` (lines 564-571) does NOT go here. It goes to `banners.go` (Task 4). `createAnalyzer` (lines 805-817) does NOT go here. It goes to `llm.go` (Task 3).

**Step 1: Create `pkg/brutus/workers.go`**

Imports needed: `context`, `math/rand`, `sync`, `sync/atomic`, `time`, `golang.org/x/sync/errgroup`, `golang.org/x/time/rate`.

```go
// Copyright 2026 Praetorian Security, Inc.
// [full Apache 2.0 header]

package brutus

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// =============================================================================
// Worker Pool Implementation
// =============================================================================

// credential represents a username/password or username/key combination to test.
type credential struct {
	username     string
	password     string
	key          []byte // SSH private key (optional, for key-based auth)
	llmSuggested bool   // True if this credential was suggested by LLM
}

// [paste generateCredentials - lines 487-500 verbatim]
// [paste generateKeyCredentials - lines 503-516 verbatim]
// [paste reorderForSpray - lines 520-543 verbatim]

// runWorkers executes credential testing using a bounded worker pool.
//
// Thread Safety Note: The plug parameter is shared across all concurrent workers.
// Plugin implementations MUST be safe for concurrent use. The factory pattern in
// GetPlugin returns fresh instances, but Brute() shares a single instance.
// Stateless plugins (the common case) are inherently safe. Stateful plugins
// must use their own synchronization.
// [paste runWorkers - lines 546-560 verbatim]

// [paste executeWorkerPool - lines 576-689 verbatim]
// [paste runWorkersDefault - lines 693-723 verbatim]
// [paste runWorkersWithLLM - lines 732-777 verbatim]
// [paste captureBanner - lines 781-800 verbatim]
// [paste runWorkersWithCredentials - lines 821-824 verbatim]
```

**Step 2: Remove lines 478-824 from brutus.go** (except isHTTPProtocol at 564-571, which moves in Task 4, and createAnalyzer at 805-817, which moves in Task 3).

For now, temporarily leave `isHTTPProtocol` and `createAnalyzer` in brutus.go. They will be moved in Tasks 3 and 4.

**Step 3: Run tests**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./pkg/brutus/ -v -count=1 -race
```

Expected: All tests pass. The `-race` flag validates concurrent access patterns.

**Step 4: Run build**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go build ./...
```

**Step 5: Commit**

```bash
git add pkg/brutus/workers.go pkg/brutus/brutus.go
git commit -m "refactor(brutus): extract worker pool engine to workers.go"
```

**Exit Criteria:**
- [ ] 1 new file created: `pkg/brutus/workers.go` containing the `credential` struct and 8 functions (verify: `grep -c '^func \|^type credential' pkg/brutus/workers.go` returns 9 - 8 funcs + 1 type)
- [ ] 0 worker pool functions remain in brutus.go (verify: `grep -c 'func executeWorkerPool\|func runWorkers\|func generateCredentials\|func runWorkersDefault\|func runWorkersWithLLM\|func captureBanner\|func runWorkersWithCredentials\|func generateKeyCredentials\|func reorderForSpray' pkg/brutus/brutus.go` returns 0)
- [ ] `go build ./...` exits 0
- [ ] `go test ./pkg/brutus/ -count=1 -race` passes with 0 failures

---

## Task 3: Create llm.go

**Files:**
- Create: `pkg/brutus/llm.go`
- Modify: `pkg/brutus/brutus.go` (remove LLM utilities + createAnalyzer + constants)

**What moves:**

| Lines | Symbol | Notes |
|-------|--------|-------|
| 70-75 | `MaxBannerLength`, `MaxPasswordLength` constants | Govern LLM behavior |
| 805-817 | `createAnalyzer` | LLM configuration bridge |
| 831-854 | `BuildPrompt` | Prompt construction |
| 857-874 | `SanitizeBanner` | **Security-sensitive**: prompt injection defense |
| 877-898 | `ValidateSuggestions` | LLM output validation |
| 901-905 | `IsValidPassword` | Character allowlist |

**Step 1: Create `pkg/brutus/llm.go`**

Imports needed: `regexp`, `strings`.

```go
// Copyright 2026 Praetorian Security, Inc.
// [full Apache 2.0 header]

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
package brutus

import (
	"regexp"
	"strings"
)

const (
	// MaxBannerLength limits banner size to prevent prompt injection.
	MaxBannerLength = 500
	// MaxPasswordLength limits suggested password length.
	MaxPasswordLength = 32
)

// createAnalyzer creates the appropriate LLM analyzer based on provider configuration.
// Returns nil if provider is unknown or configuration is invalid.
// Analyzers must register themselves using RegisterAnalyzer() in their init() functions.
func createAnalyzer(cfg *LLMConfig) BannerAnalyzer {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	factory := GetAnalyzerFactory(cfg.Provider)
	if factory == nil {
		return nil
	}

	return factory(cfg)
}

// BuildPrompt constructs the LLM prompt for banner analysis.
// [paste lines 831-854 verbatim]

// SanitizeBanner removes control chars and limits length to prevent prompt injection.
//
// SECURITY: This function is the first line of defense against prompt injection
// via crafted service banners. Known limitations (Finding 33):
// - Does not detect semantic injection patterns (e.g., "ignore previous instructions")
// - Triple-quote removal is necessary but not sufficient for all LLM providers
// - Consider adding structured output enforcement in future hardening
// [paste lines 857-874 verbatim]

// ValidateSuggestions ensures LLM output is safe.
// [paste lines 877-898 verbatim]

// IsValidPassword checks for safe characters.
// [paste lines 901-905 verbatim]
```

**Step 2: Remove the extracted lines from brutus.go**

Remove lines 70-75 (constants), 805-817 (createAnalyzer), and 831-905 (LLM utilities) from brutus.go. Also remove `"regexp"` from brutus.go imports (only used by LLM utilities).

**Step 3: Run tests**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./pkg/brutus/ -v -count=1
```

**Step 4: Run build**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go build ./...
```

**Step 5: Commit**

```bash
git add pkg/brutus/llm.go pkg/brutus/brutus.go
git commit -m "refactor(brutus): extract LLM utilities to llm.go

Isolates prompt construction, banner sanitization, and suggestion
validation into a dedicated file. This establishes a clear security
surface for prompt injection defenses (Finding 33) and enables
future build-tag isolation for LLM-free builds."
```

**Exit Criteria:**
- [ ] 1 new file created: `pkg/brutus/llm.go` containing 5 functions and 2 constants (verify: `grep -c '^func \|MaxBannerLength\|MaxPasswordLength' pkg/brutus/llm.go` returns 7)
- [ ] 0 LLM functions remain in brutus.go (verify: `grep -c 'func BuildPrompt\|func SanitizeBanner\|func ValidateSuggestions\|func IsValidPassword\|func createAnalyzer\|MaxBannerLength\|MaxPasswordLength' pkg/brutus/brutus.go` returns 0)
- [ ] `go build ./...` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes with 0 failures

---

## Task 4: Create banners.go

**Files:**
- Create: `pkg/brutus/banners.go`
- Modify: `pkg/brutus/brutus.go` (remove banner section + isHTTPProtocol)

**What moves:**

| Lines | Symbol | Notes |
|-------|--------|-------|
| 308-342 | `standardBanners` map | Protocol-specific banner patterns |
| 352-379 | `IsStandardBanner` | Exported, used only internally currently |
| 564-571 | `isHTTPProtocol` | Unexported, called from runWorkers (workers.go) and IsStandardBanner |

**Step 1: Create `pkg/brutus/banners.go`**

Imports needed: `strings`.

```go
// Copyright 2026 Praetorian Security, Inc.
// [full Apache 2.0 header]

package brutus

import "strings"

// =============================================================================
// Standard Banner Detection
// =============================================================================

// standardBanners contains known standard banner patterns for each protocol.
// [paste lines 308-342 verbatim]

// IsStandardBanner checks if a banner matches known standard patterns for the protocol.
// [paste lines 352-379 verbatim, including full godoc]

// isHTTPProtocol returns true if the protocol uses HTTP Basic Auth
// and can benefit from LLM-based application detection.
func isHTTPProtocol(protocol string) bool {
	switch protocol {
	case "http", "https", "couchdb", "elasticsearch", "influxdb":
		return true
	default:
		return false
	}
}
```

**Step 2: Remove lines 308-379 and 564-571 from brutus.go**

**Step 3: Run tests**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./pkg/brutus/ -v -count=1
```

**Step 4: Run build**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go build ./...
```

**Step 5: Commit**

```bash
git add pkg/brutus/banners.go pkg/brutus/brutus.go
git commit -m "refactor(brutus): extract banner detection to banners.go"
```

**Exit Criteria:**
- [ ] 1 new file created: `pkg/brutus/banners.go` containing 2 functions and 1 var (verify: `grep -c '^func \|^var standardBanners' pkg/brutus/banners.go` returns 3)
- [ ] 0 banner functions remain in brutus.go (verify: `grep -c 'func IsStandardBanner\|func isHTTPProtocol\|standardBanners' pkg/brutus/brutus.go` returns 0)
- [ ] `go build ./...` exits 0
- [ ] `go test ./pkg/brutus/ -count=1` passes with 0 failures

---

## Task 5: Trim brutus.go to types + entry point

**Files:**
- Modify: `pkg/brutus/brutus.go` (clean up imports, verify final state)

**What remains in brutus.go after Tasks 1-4:**

1. Package documentation comment (lines 15-49)
2. Import block (trimmed to only what's needed)
3. TLS context keys and functions (lines 82-96)
4. All type definitions: Credential, Config, Result, LLMConfig, BannerAnalyzer, CredentialAnalyzer, BannerInfo, AnalyzerFactory, Plugin, KeyPlugin, PluginFactory (lines 98-214)
5. Config methods: applyDefaults, validate (lines 385-439)
6. Brute entry point (lines 446-472)

**Step 1: Clean up imports in brutus.go**

The remaining code in brutus.go needs these imports only:
- `"context"` - for Brute's context.Background()
- `"errors"` - for validate() errors.New
- `"fmt"` - for Brute's error wrapping
- `"net/http"` - for BannerInfo.Headers field
- `"time"` - for Config.Timeout, Config.Jitter

The following imports should be REMOVED from brutus.go (they moved to other files):
- `"math/rand"` -> workers.go
- `"regexp"` -> llm.go
- `"sort"` -> registry.go
- `"strings"` -> llm.go, banners.go
- `"sync"` -> registry.go, workers.go
- `"sync/atomic"` -> workers.go
- `"golang.org/x/sync/errgroup"` -> workers.go
- `"golang.org/x/time/rate"` -> workers.go
- `"github.com/praetorian-inc/brutus/pkg/badkeys"` -> stays in brutus.go (used by applyDefaults)

**Step 2: Add thread-safety documentation to Plugin interface**

Add the following godoc enhancement to the Plugin interface (currently at line 184):

```go
// Plugin defines the interface for authentication protocol implementations.
// Each plugin must implement credential testing for a specific protocol (SSH, FTP, etc.).
//
// Thread Safety: Plugin instances may be shared across concurrent goroutines
// in the worker pool. Implementations MUST be safe for concurrent use.
// Stateless plugins (the common case) are inherently safe. If a plugin
// maintains mutable state, it must use its own synchronization (e.g., sync.Mutex).
//
// Optional Key-Based Authentication:
// Plugins may optionally implement the KeyPlugin interface for key-based authentication.
// If a plugin implements KeyPlugin, the worker pool will automatically use it when
// Config.Keys is provided.
```

**Step 3: Add thread-safety note to Brute function**

Enhance the Brute godoc:

```go
// Brute executes a brute force attack using the provided configuration.
//
// The plugin is resolved once and shared across all worker goroutines.
// See the Plugin interface documentation for thread-safety requirements.
```

**Step 4: Verify final brutus.go line count**

```bash
wc -l pkg/brutus/brutus.go
```

Expected: approximately 170-180 lines.

**Step 5: Run full test suite**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./... -count=1 -race
```

Expected: ALL tests pass across ALL packages (including integration tests, plugin tests, etc.).

**Step 6: Run vet and build**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go vet ./...
go build ./...
```

**Step 7: Commit**

```bash
git add pkg/brutus/brutus.go
git commit -m "refactor(brutus): clean brutus.go to types, config, and entry point

Final step of the file split. brutus.go now contains only:
- Package documentation
- Core types (Config, Result, Plugin, etc.)
- Config validation methods
- Brute() entry point

Added thread-safety documentation to Plugin interface (Finding 2)
and Brute() function to clarify concurrent usage contract."
```

**Exit Criteria:**
- [ ] `pkg/brutus/brutus.go` is under 200 lines (verify: `wc -l pkg/brutus/brutus.go` returns < 200)
- [ ] brutus.go contains exactly 1 exported function (`Brute`) and 2 unexported methods (`applyDefaults`, `validate`) (verify: `grep -c '^func ' pkg/brutus/brutus.go` returns 5 - Brute, ContextWithTLSMode, TLSModeFromContext, applyDefaults, validate)
- [ ] `go vet ./...` exits 0
- [ ] `go build ./...` exits 0
- [ ] `go test ./... -count=1 -race` passes with 0 failures

---

## Task 6: Split test files

**Files:**
- Create: `pkg/brutus/registry_test.go` (if registry tests exist in brutus_test.go)
- Create: `pkg/brutus/banners_test.go`
- Create: `pkg/brutus/llm_test.go`
- Modify: `pkg/brutus/brutus_test.go`

**Analysis of current test distribution:**

| Test File | Tests | Should Move To |
|-----------|-------|---------------|
| `brutus_test.go` | `TestIsStandardBanner` | `banners_test.go` |
| `brutus_test.go` | `TestConfigValidate` | stays in `brutus_test.go` |
| `brutus_test.go` | `TestCaptureBanner_EmptyUsernames` + `mockHTTPPlugin` | `workers_test.go` |
| `ratelimit_test.go` | TestRateLimit*, TestJitter* | rename to `workers_ratelimit_test.go` OR leave (tests exercise Brute which is the public API) |
| `lockout_test.go` | TestMaxAttempts*, TestSprayMode*, TestReorderForSpray | same - leave in place (they test public API Brute + unexported reorderForSpray) |
| `defaults_test.go` | all | stays |
| `errors_test.go` | all | stays |
| `target_test.go` | all | stays |

**Decision:** Only move tests that directly test functions in the new files. Tests that exercise `Brute()` as integration tests stay where they are (they test the public API regardless of which file the internals live in).

**Step 1: Create `pkg/brutus/banners_test.go`**

Move `TestIsStandardBanner` from brutus_test.go.

```go
package brutus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// [paste TestIsStandardBanner - brutus_test.go lines 25-95 verbatim]
```

**Step 2: Create `pkg/brutus/workers_test.go`**

Move `TestCaptureBanner_EmptyUsernames` and `mockHTTPPlugin` from brutus_test.go.

```go
package brutus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// [paste TestCaptureBanner_EmptyUsernames - brutus_test.go lines 212-239 verbatim]
// [paste mockHTTPPlugin - brutus_test.go lines 241-254 verbatim]
```

**Step 3: Trim brutus_test.go**

Remove the moved tests. Only `TestConfigValidate` (lines 97-210) remains.

**Step 4: Verify no LLM-specific tests exist in brutus_test.go**

Currently there are no tests for `BuildPrompt`, `SanitizeBanner`, `ValidateSuggestions`, or `IsValidPassword` in brutus_test.go. These functions are tested indirectly through integration tests in `internal/analyzers/claude/` and `internal/plugins/http/llm_integration_test.go`. No `llm_test.go` needs to be created for this split.

**Step 5: Run tests**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./pkg/brutus/ -v -count=1
```

**Step 6: Commit**

```bash
git add pkg/brutus/banners_test.go pkg/brutus/workers_test.go pkg/brutus/brutus_test.go
git commit -m "refactor(brutus): split test files to match source file organization"
```

**Exit Criteria:**
- [ ] 2 new test files created: `banners_test.go`, `workers_test.go` (verify: `ls pkg/brutus/*_test.go | wc -l` returns 8 - brutus, banners, workers, ratelimit, lockout, defaults, errors, target)
- [ ] `go test ./pkg/brutus/ -v -count=1` passes with 0 failures
- [ ] Each test file tests functions from its corresponding source file

---

## Task 7: Verification pass

**No file changes. Verification only.**

**Step 1: Verify file inventory**

```bash
ls -la pkg/brutus/*.go | grep -v _test.go
```

Expected files:
```
pkg/brutus/banners.go
pkg/brutus/brutus.go
pkg/brutus/defaults.go
pkg/brutus/errors.go
pkg/brutus/llm.go
pkg/brutus/registry.go
pkg/brutus/target.go
pkg/brutus/workers.go
```

That is 8 source files (Tier 1 architecture: <10 files, single package).

**Step 2: Verify no duplicate symbols**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
grep -rn '^func ' pkg/brutus/*.go | grep -v _test.go | sort -t: -k3
```

Verify no function name appears in more than one file.

**Step 3: Verify all imports resolve**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go vet ./...
```

**Step 4: Full test suite with race detector**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go test ./... -count=1 -race
```

**Step 5: Verify no unused imports**

```bash
cd /Users/nathansportsman/capabilities/modules/brutus
go build ./...
```

Go compiler will error on unused imports.

**Step 6: Verify line counts**

```bash
wc -l pkg/brutus/*.go | grep -v _test.go | sort -n
```

Expected approximate distribution:
```
  24 pkg/brutus/target.go
  37 pkg/brutus/defaults.go
  37 pkg/brutus/errors.go
  55 pkg/brutus/banners.go
  95 pkg/brutus/registry.go
 105 pkg/brutus/llm.go
 175 pkg/brutus/brutus.go
 285 pkg/brutus/workers.go
 813 total
```

**Exit Criteria:**
- [ ] 8 source files in `pkg/brutus/` (excluding test files) (verify: `ls pkg/brutus/*.go | grep -v _test.go | wc -l` returns 8)
- [ ] 0 duplicate function definitions across files (verify: grep command above shows no duplicates)
- [ ] `go vet ./...` exits 0
- [ ] `go build ./...` exits 0
- [ ] `go test ./... -count=1 -race` passes with 0 failures
- [ ] No source file exceeds 300 lines (verify: `wc -l pkg/brutus/*.go | grep -v _test.go` shows all under 300)

---

## Deferred Items and Architectural Notes

### Finding 2 (HIGH): Shared mutable plugin instance

**Status:** Documented, not fixed in this split.

The `Brute()` function (brutus.go) resolves one plugin instance and passes it to `runWorkers` (workers.go) which shares it across all goroutines in `executeWorkerPool`. This split adds thread-safety documentation to the `Plugin` interface and `Brute()` function, making the contract explicit.

**Proper fix (separate PR):** Change `Brute()` to pass the `PluginFactory` to `executeWorkerPool` instead of a single instance, creating a fresh plugin per worker goroutine. This would require:
1. Changing `executeWorkerPool` signature to accept `PluginFactory` instead of `Plugin`
2. Each goroutine calling `factory()` to get its own instance
3. Updating all test mocks

### Finding 33 (HIGH): Banner sanitization insufficient for LLM prompt injection

**Status:** Positioned for hardening, not fixed in this split.

`SanitizeBanner` is now in `llm.go` with security documentation. Future hardening should add:
1. Semantic injection pattern detection (e.g., "ignore previous", "system prompt")
2. Maximum line count limit (not just total length)
3. Unicode normalization to prevent homoglyph attacks
4. Structured output enforcement (JSON schema validation on LLM response)

### Finding 7 (MEDIUM): ClassifyAuthError false positives with "535"

**Status:** Unchanged. `ClassifyAuthError` lives in `errors.go` and is not affected by this split. The fix would be to change from substring matching to exact-match or regex patterns in plugin-specific indicator lists.

### Sub-package evaluation for LLM isolation

**Evaluated and rejected for now.** Creating `pkg/brutus/llm/` sub-package would require:
1. Exporting `createAnalyzer` (currently unexported, called from workers.go)
2. Moving `BannerAnalyzer`, `CredentialAnalyzer`, `BannerInfo`, `LLMConfig`, `AnalyzerFactory` to avoid circular imports
3. All analyzer implementations would need to import both `brutus` and `brutus/llm`

This creates more complexity than it solves. The file-level isolation in `llm.go` is sufficient for the current architecture. Revisit if LLM dependencies grow beyond stdlib.

### Build tag strategy for LLM-free builds

**Design ready, implementation deferred.** When needed:

```go
// llm.go
//go:build !nollm

// llm_stub.go
//go:build nollm
package brutus

const MaxBannerLength = 500
const MaxPasswordLength = 32

func createAnalyzer(_ *LLMConfig) BannerAnalyzer { return nil }
func BuildPrompt(_, _ string) string             { return "" }
func SanitizeBanner(banner string) string         { return banner }
func ValidateSuggestions(_ []string) []string      { return nil }
func IsValidPassword(_ string) bool               { return false }
```

This requires no changes to any other file in the split.

### `runWorkersWithCredentials` is a trivial wrapper

**Noted.** `runWorkersWithCredentials` (workers.go) is a 3-line function that just calls `executeWorkerPool`. It exists to provide a named abstraction for the LLM flow. Consider inlining it into `runWorkersWithLLM` in a future cleanup, but it has negligible cost and provides readability.

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-02-14T00:00:00Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/brutus/.claude/plans",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "gateway-backend",
    "persisting-agent-outputs",
    "brainstorming",
    "writing-plans",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni",
    "debugging-systematically"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/capabilities/enforcing-go-capability-architecture/SKILL.md",
    ".claude/skill-library/development/capabilities/reviewing-capability-implementations/SKILL.md",
    ".claude/skill-library/development/capabilities/implementing-go-plugin-registries/SKILL.md",
    ".claude/skill-library/development/backend/structuring-go-projects/SKILL.md",
    ".claude/skill-library/development/backend/go-best-practices/SKILL.md"
  ],
  "source_files_verified": [
    "pkg/brutus/brutus.go:1-906",
    "pkg/brutus/errors.go:1-37",
    "pkg/brutus/target.go:1-24",
    "pkg/brutus/defaults.go:1-37",
    "pkg/brutus/brutus_test.go:1-255",
    "pkg/brutus/ratelimit_test.go:1-264",
    "pkg/brutus/lockout_test.go:1-327",
    "pkg/brutus/defaults_test.go:1-165",
    "internal/plugins/ssh/ssh.go:1-226",
    "internal/plugins/http/http.go:1-286",
    "internal/plugins/init.go:1-43",
    "internal/analyzers/claude/claude.go:1-150",
    "internal/analyzers/init.go:1-23",
    "cmd/brutus/main.go:1-1341",
    "pkg/builtins/builtins.go:1-12",
    "go.mod:1-75"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Implement this plan task-by-task. All 7 tasks are sequential (each depends on the previous). Run tests after each task. The plan is pure file moves with no logic changes except added documentation."
  }
}
```
