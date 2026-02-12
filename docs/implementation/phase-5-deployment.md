# Phase 5: CLI, Deployment, and Orchestration

**Plan Phase:** 10 (CLI + Deployment)

## Objective

Build the `aos` CLI (Rust), rewrite the justfile as a thin convenience layer over `aos` commands, and implement the deployment pipeline -- bundle generation, signing, and fleet update scripts. The `aos` CLI wraps standard `nix-build` / `nix-instantiate` with proper error handling, colored output, progress indication, and shell completions. No experimental Nix features are used.

## Prerequisites

- Phase 1-4 complete: Packages build, systems evaluate, images produce bootable disks
- Rust toolchain available for building the CLI
- Understanding of clap derive API for subcommand hierarchy
- `default.nix` as the single entry point for all Nix operations

## Deliverables

### `aos` CLI (`cli/`)

- `cli/Cargo.toml` -- Crate manifest (clap, anyhow, thiserror, indicatif, console, serde_json)
- `cli/src/main.rs` -- Entry point, clap App setup
- `cli/src/cli.rs` -- Clap derive structs (Cli, Commands, SystemCmd, TestCmd)
- `cli/src/nix.rs` -- Nix subprocess wrapper (nix-build, nix-instantiate, nix-store)
- `cli/src/output.rs` -- Colored output, progress spinners, structured logging
- `cli/src/error.rs` -- Error types (thiserror: NixBuildError, NixEvalError, ImageBuildError)
- `cli/src/commands/` -- One module per subcommand:
  - `build.rs`, `system.rs`, `show.rs`, `graph.rs`, `lint.rs`
  - `test.rs`, `gc.rs`, `why_depends.rs`, `describe.rs`
  - `shell.rs`, `repl.rs`, `completions.rs`

### Justfile

- `justfile` -- Thin convenience layer over `aos` commands

### Development Shell

- `shell.nix` -- Development environment with AOS tools available

### Deployment Pipeline (`deploy/`)

- `deploy/bundle.nix` -- Nix derivation: compute delta, compress, package
- `deploy/sign.nix` -- Nix derivation: sign bundle with minisign
- `deploy/scripts/upload.sh` -- Upload signed bundle to update server
- `deploy/scripts/fleet-update.sh` -- Rolling fleet update with health checks

## Detailed Task Checklist

### 5.1 CLI Architecture

The CLI mirrors Guix's clean verb-based hierarchy (`guix build` -> `aos build`, `guix system image` -> `aos system image`), but wraps Nix instead of Guile.

- [ ] Set up `cli/Cargo.toml` with minimal dependencies:
  - [ ] `clap = { version = "4", features = ["derive", "env"] }`
  - [ ] `clap_complete = "4"` (shell completion generation)
  - [ ] `anyhow = "1"` (error handling with context)
  - [ ] `thiserror = "2"` (typed errors)
  - [ ] `indicatif = "0.17"` (progress bars and spinners)
  - [ ] `console = "0.15"` (terminal colors)
  - [ ] `serde = { version = "1", features = ["derive"] }`
  - [ ] `serde_json = "1"` (parse `nix --json` output)

### 5.2 CLI Subcommand Mapping

Each subcommand is a transparent wrapper around stable `nix-build` / `nix-instantiate`:

| Command | Nix invocation |
|---------|---------------|
| `aos build <pkg>` | `nix-build default.nix -A pkgs.<pkg>` |
| `aos build --all` | `nix-build default.nix -A pkgs` |
| `aos system build <v>` | `nix-build default.nix -A systems.<v>.toplevel` |
| `aos system image <v>` | `nix-build default.nix -A images.<v> -o output/aos-<v>.raw` |
| `aos system eval <v>` | `nix-instantiate --eval --strict --json -A systems.<v>` |
| `aos show <pkg>` | `nix-instantiate --eval --strict --json -A pkgs.<pkg>.meta` |
| `aos graph <pkg>` | `nix-build ... && nix-store --query --graph` |
| `aos lint [pkg]` | `nix-build default.nix -A checks.lint[.<pkg>]` |
| `aos test [layer] [suite]` | `nix-build default.nix -A checks[.<layer>[.<suite>]]` |
| `aos gc` | `nix-collect-garbage --delete-older-than 7d` |
| `aos why-depends <p> <d>` | `nix-store --query --referrers-closure / --graph` |
| `aos shell` | `nix-shell shell.nix` |
| `aos repl` | `nix repl default.nix` |
| `aos describe` | `git rev-parse + nix-instantiate --eval` |
| `aos completions <sh>` | `clap_complete` generation |

### 5.3 Nix Runner (`nix.rs`)

- [ ] Implement `NixRunner` struct:
  - [ ] `build(&self, attr: &str) -> Result<PathBuf>` -- build a Nix attribute
  - [ ] `eval(&self, attr: &str) -> Result<serde_json::Value>` -- evaluate to JSON
  - [ ] `store_query(&self, path: &Path, args: &[&str]) -> Result<String>` -- query store
  - [ ] Stream Nix subprocess output in real-time (not buffered)
  - [ ] Optional output filtering based on verbosity level
  - [ ] Locate `default.nix` relative to binary or via `AOS_ROOT` env var

### 5.4 Output and Error Handling

- [ ] `output.rs`:
  - [ ] Colored output using `console` crate
  - [ ] Progress spinners during long builds (indicatif)
  - [ ] Progress bars for multi-package builds
  - [ ] `--json` mode for machine-readable output
  - [ ] `--verbose` / `--quiet` global flags
- [ ] `error.rs`:
  - [ ] `NixBuildError` -- build failure with stderr context
  - [ ] `NixEvalError` -- evaluation failure with trace
  - [ ] `ImageBuildError` -- image build failure
- [ ] Exit codes: 0 = success, 1 = build/test failure, 2 = user error, 3 = nix not found

### 5.5 Individual Commands

- [ ] `commands/build.rs` -- package builds, `--all` for everything
- [ ] `commands/system.rs` -- `{build,image,eval}` subcommands
- [ ] `commands/show.rs` -- package metadata display
- [ ] `commands/graph.rs` -- dependency visualization (text or DOT format)
- [ ] `commands/lint.rs` -- package definition validation
- [ ] `commands/test.rs` -- test orchestration (eval, build, vm, fleet layers)
- [ ] `commands/gc.rs` -- garbage collection, `--list-generations`
- [ ] `commands/why_depends.rs` -- dependency chain debugging
- [ ] `commands/describe.rs` -- repo info (commit, package count, variants)
- [ ] `commands/shell.rs` -- development environment entry
- [ ] `commands/repl.rs` -- interactive Nix REPL
- [ ] `commands/completions.rs` -- shell completion generation (bash, zsh, fish)

### 5.6 Justfile

- [ ] Rewrite `justfile` as thin convenience layer over `aos` commands:
  - [ ] `build pkg` -> `aos build <pkg>`
  - [ ] `system-image variant` -> `aos system image <variant>`
  - [ ] `test` -> `aos test`
  - [ ] `cli-build` -> `cd cli && cargo build --release`
  - [ ] `quick variant` -> build CLI then build image
  - [ ] Direct Nix targets for bypassing CLI: `nix-build attr`, `nix-eval attr`

### 5.7 Development Shell

- [ ] `shell.nix` provides development environment:
  - [ ] Full AOS package set available via `pkgs`
  - [ ] `shellHook` prints available commands
  - [ ] Sets `AOS_ROOT` env var
  - [ ] Usage: `nix-shell` or `aos shell`

### 5.8 Deployment Pipeline

- [ ] Write `deploy/bundle.nix`:
  - [ ] Input: new system closure and old system closure
  - [ ] Compute delta: new store paths = new_closure - old_closure
  - [ ] Export new paths as NAR archives
  - [ ] Compress with zstd
  - [ ] Package into update bundle with manifest
- [ ] Write `deploy/sign.nix`:
  - [ ] Sign bundle with minisign (Ed25519)
  - [ ] Include public key for verification
- [ ] Write `deploy/scripts/upload.sh`:
  - [ ] Upload signed bundle to update server (HTTPS)
  - [ ] Update server manifest
- [ ] Write `deploy/scripts/fleet-update.sh`:
  - [ ] SSH to each machine: trigger update
  - [ ] Wait for health check pass before proceeding

### 5.9 Verification

- [ ] `cargo build --release` produces the `aos` binary
- [ ] `aos --help` shows all subcommands
- [ ] `aos completions bash` generates valid completions
- [ ] `aos build coreutils` invokes the correct `nix-build` command
- [ ] `aos system image server` produces a bootable image
- [ ] `aos test` orchestrates all test layers

## Acceptance Criteria

1. `aos` CLI builds with `cargo build --release`
2. All subcommands work as transparent wrappers around stable `nix-build` / `nix-instantiate`
3. `--json` flag produces machine-readable output on all commands
4. Shell completions generate correctly for bash, zsh, and fish
5. Progress spinners and colored output work during long builds
6. Error messages include context (which package, which phase)
7. `justfile` is a thin wrapper -- every target delegates to `aos`
8. Deployment bundle generation produces signed delta archives
9. No experimental Nix features are used anywhere

## Key Design Decisions

### Why Not Flakes

Flakes are the most contentious part of the Nix ecosystem. AOS avoids them because:
- Still "experimental" after years (the RFC was withdrawn)
- Copies entire repo into `/nix/store` on every evaluation
- Lock file format is complex and surprising
- Doesn't actually prevent non-determinism

The `aos` CLI provides everything flakes offer (build ergonomics, eval caching, shell integration) through a purpose-built Rust binary wrapping stable Nix primitives.

### Reproducibility Without Flakes

`default.nix` is the single entry point. It has no external inputs -- every source URL and hash is pinned in `pkgs/sources.nix`. The entire build is determined by the Git commit. No lock file needed because there are no floating inputs to lock.

### CLI Self-Bootstraps

The `aos` binary only needs Nix installed on the host. It locates `default.nix` relative to itself (or via `AOS_ROOT`) and invokes standard Nix commands. Even before the full package set builds, the CLI works.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rust toolchain not available on all build machines | Low | Can't build CLI | Provide pre-built binary; or build via Nix derivation in our package set |
| Nix subprocess output parsing is fragile | Medium | Errors not reported correctly | Parse exit codes and stderr; use `--json` where available |
| Fleet update races or partial failures | Medium | Inconsistent fleet state | Locking, health checks, automatic rollback |
| `nix repl` doesn't support `default.nix` argument on all Nix versions | Low | `aos repl` broken | Fall back to `nix-instantiate` + manual import |
