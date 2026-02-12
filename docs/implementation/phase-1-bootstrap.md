# Phase 1: Core Library and Bootstrap Chain

**Plan Phases:** 1 (Core Library) + 2 (Bootstrap Chain)

## Objective

Build the foundational Nix library (`lib/`) and the full bootstrap chain (`stdenv/bootstrap/`) that takes AOS from binary seeds (hex0, ~357 bytes) to a working glibc 2.39, entirely in Nix. This replaces the Docker-based Guix build environment from the original design. No Docker, no nixpkgs -- everything from scratch.

## Prerequisites

- A working Nix installation (stable, no experimental features required)
- Git configured for the repository
- Familiarity with the Nix language and derivation model
- Understanding of the full-source bootstrap concept (Mes, TinyCC, GCC chain)

## Deliverables

### Core Library (`lib/`)

- `lib/default.nix` -- Library entry point composing all modules
- `lib/trivial.nix` -- `id`, `const`, `flip`, `pipe`, and other combinators
- `lib/lists.nix` -- List utilities (map, filter, fold, sort, unique, etc.)
- `lib/attrsets.nix` -- Attrset utilities (mapAttrs, filterAttrs, recursiveUpdate, etc.)
- `lib/strings.nix` -- String utilities (concatStrings, split, hasPrefix, etc.)
- `lib/types.nix` -- Option type definitions for the module system
- `lib/modules.nix` -- Module evaluation engine (evalModules with explicit layers)
- `lib/derivations.nix` -- `mkDerivation` with clean inputs (`buildDeps`, `runtimeDeps`, `propagatedDeps`) and structured phases

### Bootstrap Chain (`stdenv/bootstrap/`)

- `stdenv/bootstrap/seeds.nix` -- hex0 + kaem binary seeds as fixed-output derivation
- `stdenv/bootstrap/stage1-mescc-tools.nix` -- hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem
- `stdenv/bootstrap/stage2-mes.nix` -- GNU Mes (Scheme interpreter + MesCC)
- `stdenv/bootstrap/stage3-tinycc.nix` -- TinyCC 0.9.27 (compiled by MesCC)
- `stdenv/bootstrap/stage4-gcc46.nix` -- GCC 4.6.4 (C only, compiled by TinyCC)
- `stdenv/bootstrap/stage5-gcc75.nix` -- GCC 7.5.0 (C + C++, compiled by GCC 4.6.4)
- `stdenv/bootstrap/stage6-glibc.nix` -- glibc 2.39 (compiled by GCC 7.5.0)

## Detailed Task Checklist

### 1.1 Core Library -- Utility Functions

- [ ] Create `lib/default.nix` that imports and composes all sub-modules
- [ ] Write `lib/trivial.nix`: `id`, `const`, `flip`, `pipe`, `mapNullable`
- [ ] Write `lib/lists.nix`: `map`, `filter`, `foldl'`, `concatMap`, `unique`, `sort`, `head`, `tail`, `length`, `elem`, `flatten`, `isList`, `range`, `genList`
- [ ] Write `lib/attrsets.nix`: `mapAttrs`, `filterAttrs`, `recursiveUpdate`, `attrNames`, `attrValues`, `hasAttr`, `getAttr`, `optionalAttrs`, `nameValuePair`, `listToAttrs`, `isAttrs`, `mapAttrsToList`, `zipAttrsWith`
- [ ] Write `lib/strings.nix`: `concatStrings`, `concatStringsSep`, `concatMapStrings`, `hasPrefix`, `hasSuffix`, `removePrefix`, `removeSuffix`, `replaceStrings`, `splitString`, `toLower`, `toUpper`, `isString`, `optionalString`, `escapeShellArg`
- [ ] Keep the library minimal -- only what the package set and module system actually need, not a port of nixpkgs's 15,000 lines

### 1.2 Core Library -- Type System

- [ ] Write `lib/types.nix` with option type definitions:
  - [ ] `types.bool`, `types.int`, `types.str`, `types.path`
  - [ ] `types.listOf`, `types.attrsOf`, `types.nullOr`
  - [ ] `types.enum`, `types.either`
  - [ ] `types.port` (int in range 1-65535)
  - [ ] Each type: `check` function, `merge` function, `description` string

### 1.3 Core Library -- Module Evaluation Engine

- [ ] Write `lib/modules.nix` implementing `evalModules`:
  - [ ] Input: `{ modules; pkgs; lib; }`
  - [ ] Modules are functions: `{ config, pkgs, lib, ... }: { options = {...}; config = {...}; }`
  - [ ] Options have: `type`, `default`, `description`
  - [ ] No `mkDefault` / `mkForce` / `mkOverride` -- later modules simply override earlier ones
  - [ ] Support `lib.mkIf condition attrset` for conditional config
  - [ ] Error messages include module file path and option path
  - [ ] Explicit layer ordering (module defaults -> base -> variant -> site-specific)
  - [ ] Target: ~300 lines, not nixpkgs's ~1500

### 1.4 Core Library -- Derivation Builder

- [ ] Write `lib/derivations.nix` implementing `mkDerivation`:
  - [ ] Clean input names: `buildDeps`, `runtimeDeps`, `propagatedDeps`
  - [ ] Structured phases: ordered list of `{ name; script; }` records
  - [ ] Single `.override` mechanism (attrset or function `old -> new`)
  - [ ] `lib.replacePhase`, `lib.addPhaseAfter`, `lib.addPhaseBefore` helpers
  - [ ] Automatic `$out` setup, `$src` extraction
  - [ ] Configurable `storeDir` (default `/nix/store`, not hardcoded)
  - [ ] `fetchurl` and `fetchgit` source fetchers
  - [ ] `mkShell` for development environments
  - [ ] Target: ~200 lines

### 1.5 Bootstrap Stage 0 -- Binary Seeds

- [ ] Write `stdenv/bootstrap/seeds.nix`
- [ ] Define hex0 + kaem seeds as a fixed-output derivation
- [ ] Source: `bootstrap-seeds` repository (oriansj/bootstrap-seeds)
- [ ] Pin version and SHA-256 hash
- [ ] Extract x86_64-specific seed binaries
- [ ] Uses `builtins.derivation` directly (no stdenv yet -- we are bootstrapping it)
- [ ] Verify: the seeds derivation builds and contains hex0 and kaem binaries

### 1.6 Bootstrap Stage 1 -- MesCC-Tools

- [ ] Write `stdenv/bootstrap/stage1-mescc-tools.nix`
- [ ] Build mescc-tools using only the bootstrap seeds
- [ ] Chain: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet
- [ ] Uses `builtins.derivation` directly
- [ ] Source: mescc-tools repository, pinned version
- [ ] Verify: M2-Planet can compile C programs

### 1.7 Bootstrap Stage 2 -- GNU Mes

- [ ] Write `stdenv/bootstrap/stage2-mes.nix`
- [ ] Build GNU Mes 0.27 using mescc-tools (M2-Planet compiles mes.c)
- [ ] Uses `builtins.derivation` directly
- [ ] Verify: Mes can interpret Scheme and compile C via MesCC

### 1.8 Bootstrap Stage 3 -- TinyCC

- [ ] Write `stdenv/bootstrap/stage3-tinycc.nix`
- [ ] Build TinyCC 0.9.27 using MesCC
- [ ] Uses `builtins.derivation` directly
- [ ] Verify: TinyCC can compile simple C programs

### 1.9 Bootstrap Stage 4 -- GCC 4.6.4

- [ ] Write `stdenv/bootstrap/stage4-gcc46.nix`
- [ ] Build GCC 4.6.4 (C only, no C++) using TinyCC
- [ ] Include a minimal bootstrap glibc as input
- [ ] Uses `builtins.derivation` directly
- [ ] Verify: GCC 4.6.4 can compile a "hello world" program

### 1.10 Bootstrap Stage 5 -- GCC 7.5.0

- [ ] Write `stdenv/bootstrap/stage5-gcc75.nix`
- [ ] Build GCC 7.5.0 (C + C++) using GCC 4.6.4
- [ ] Configure: `--enable-languages=c,c++`, `--disable-multilib`
- [ ] Uses `builtins.derivation` directly
- [ ] Verify: GCC 7.5.0 can compile C and C++ programs

### 1.11 Bootstrap Stage 6 -- glibc 2.39

- [ ] Write `stdenv/bootstrap/stage6-glibc.nix`
- [ ] Build glibc 2.39 using GCC 7.5.0
- [ ] Configure flags for server hardening:
  - [ ] `--enable-kernel=5.15` (minimum kernel version)
  - [ ] `--enable-stack-protector=strong`
  - [ ] `--enable-bind-now` (full RELRO)
  - [ ] `--enable-static-nss`
  - [ ] `--enable-cet` (Control-flow Enforcement)
  - [ ] `--disable-werror`
- [ ] Install UTF-8 locales (en_US.UTF-8, C.UTF-8)
- [ ] Propagated dep: linux-headers
- [ ] Verify: libc.so exists and is functional; locale generation succeeded

### 1.12 Verification

- [ ] `nix-instantiate --eval --strict -A lib ./default.nix` -- library evaluates without error
- [ ] `nix-build -A pkgs.hello` (or a minimal test package) -- full pipeline works
- [ ] `aos build bootstrap.glibc` -- the entire bootstrap chain completes
- [ ] No references to nixpkgs or any external Nix code in the entire tree
- [ ] Document the complete DAG of bootstrap stages

## Acceptance Criteria

1. All `lib/` modules evaluate correctly and provide the functions needed by the package set and module system
2. The module evaluation engine supports typed options, explicit layer ordering, and conditional config
3. `mkDerivation` supports clean input names (`buildDeps`, `runtimeDeps`, `propagatedDeps`) and structured phases
4. All bootstrap stages (0-6) build from source without any binary substitutes
5. The final bootstrap glibc 2.39 includes server hardening flags (stack protector, RELRO, CET)
6. No external inputs are used -- every source URL and hash is pinned in `pkgs/sources.nix`
7. The `default.nix` entry point can be evaluated with standard `nix-build` / `nix-instantiate` (no flakes)

## Key Design Decisions

### Why No Docker

The original Phase 1 used Docker to run `guix-daemon`. With Nix, Docker is eliminated entirely:
- The `nix-daemon` manages the `/nix/store` directly
- No container overhead, no volume management, no platform emulation
- Reproducibility comes from the Nix build sandbox, not from Docker image pinning

### Why No nixpkgs

AOS builds everything from scratch for several reasons:
- Full control over the build graph from binary seeds to production packages
- Corrects known nixpkgs design mistakes (input naming, override mechanisms, phase model)
- No 300,000+ package evaluation overhead -- only the ~80 packages AOS needs
- The bootstrap chain guarantees reproducibility from first principles

### Module System Improvements Over NixOS

The module system in `lib/modules.nix` corrects known NixOS issues:
- No `mkDefault` / `mkForce` / `mkOverride` with arbitrary priority numbers
- Later modules override earlier ones via standard Nix attrset merge (`//`)
- ~10 total modules vs NixOS's ~1500
- No activation scripts -- everything is declarative
- Explicit module list (no auto-discovery)

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Bootstrap stage failure (obscure build error in early stages) | High | Blocks all progress | Follow the proven version chain (hex0 -> Mes -> TinyCC -> GCC 4.6.4 -> GCC 7.5.0 -> glibc); same chain as Guix, translated to Nix |
| Module evaluation engine has subtle bugs | Medium | System configs evaluate incorrectly | Extensive eval tests in `tests/eval.nix`; keep the engine minimal (~300 lines) |
| `mkDerivation` structured phases are too rigid | Low | Packages need escape hatches | Phases are a list -- packages can always provide a custom list; `replacePhase` helper for surgical overrides |
| Full bootstrap takes too long (>12 hours) | Medium | Slow iteration | Nix's content-addressed store caches intermediate results; only changed stages rebuild |
| Source tarball hash mismatches | Low | Blocks package definition | All hashes pinned in `pkgs/sources.nix`; verified against upstream |
