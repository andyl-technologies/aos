# APM Implementation Plan

## Overview

This plan implements `apm` (the AOS package manager) as `aos package` — a new
subcommand tree in the existing `aos` Rust CLI. The implementation is divided
into 6 phases, each sized for one Opus 4.6 context window for a team leader
coordinating sub-agents. Each phase contains 3-4 chunks, each sized for one
sub-agent context window.

## Existing Code to Reuse

The `aos` CLI already has infrastructure that APM builds on:

| Module | Reuse |
|--------|-------|
| `server/store.rs` | `NixStore` SQLite wrapper, `PathInfo` struct |
| `server/views.rs` | `ViewManager` GC root primitives (`create_gc_root`, `write_metadata`) |
| `server/sign.rs` | `NarInfoSigner` Ed25519 signing/verification |
| `server/compress.rs` | `Compression` enum, NAR streaming |
| `output.rs` | `Printer` with `--quiet`/`--json`/`--verbose` modes |
| `nix.rs` | `NixRunner` subprocess wrapper |
| `cli.rs` | Clap `Commands` enum (extend with `Package` variant) |
| `error.rs` | `AosError` enum (extend with APM variants) |

Dependencies already in Cargo.toml: `reqwest`, `sha2`, `ed25519-dalek`,
`rusqlite`, `toml`, `serde`/`serde_json`, `indicatif`, `zstd`, `tokio`,
`base64`, `hex`.

## New Module Structure

```
src/package/
├── mod.rs              Phase 1B   Subcommand dispatch
├── config.rs           Phase 1A   Config parsing (apm.conf, registries.d/)
├── types.rs            Phase 1A   Core data types
├── registry/
│   ├── mod.rs          Phase 1C   Registry manager
│   ├── parse.rs        Phase 1C   Package TOML parsing, hash index
│   ├── bundle.rs       Phase 2A   HTTP bundle transport
│   ├── git.rs          Phase 2B   Git transport
│   └── state.rs        Phase 2C   Update state, downgrade protection
├── download.rs         Phase 3A   Parallel NAR download engine
├── verify.rs           Phase 3B   Hash verification chain
├── store.rs            Phase 3C   Store import, GC root management
├── profile/
│   ├── mod.rs          Phase 4A   Generation lifecycle
│   ├── merge.rs        Phase 4B   FHS symlink merge engine
│   └── meta.rs         Phase 4C   Per-path metadata management
├── install.rs          Phase 5A   Install pipeline
├── remove.rs           Phase 5B   Remove and autoremove
├── update.rs           Phase 5C   Registry sync (apm update)
├── upgrade.rs          Phase 5C   Package upgrade
├── rollback.rs         Phase 5D   Generation rollback
├── hold.rs             Phase 5D   Hold/unhold management
├── clean.rs            Phase 5D   Cache and generation cleanup
├── query.rs            Phase 6A   Search, show, list
├── deps.rs             Phase 6B   Depends, rdepends, policy, files
├── security.rs         Phase 6C   TOFU, key management, signing
└── source.rs           Phase 6D   Source verification (apm verify/source)
```

## Phase Dependency Graph

```
Phase 1 ─── Foundation & Config
  │
  ├──► Phase 2 ─── Registry Sync
  │       │
  │       └──────────────────────────┐
  │                                  │
  └──► Phase 3 ─── Store Operations  │
          │                          │
          └──► Phase 4 ─── Profiles  │
                  │                  │
                  └──► Phase 5 ─── Core Commands ◄──┘
                          │
                          └──► Phase 6 ─── Queries, Security, Polish
```

Phases 2 and 3 can run in parallel (both depend only on Phase 1).
Phases 5 and 6 are sequential.

## Phase Summary

| Phase | Name | Chunks | Key Deliverable |
|-------|------|--------|-----------------|
| [1](phase-1-foundation.md) | Foundation & Config | 3 | Types, config, CLI scaffolding, TOML parsing |
| [2](phase-2-registry.md) | Registry Sync | 3 | Bundle + git transport, downgrade protection |
| [3](phase-3-store.md) | Store Operations | 3 | NAR download, verification, store import |
| [4](phase-4-profiles.md) | Profile Management | 3 | Generations, FHS merge, metadata |
| [5](phase-5-operations.md) | Core Commands | 4 | install, remove, update, upgrade, rollback |
| [6](phase-6-queries-security.md) | Queries & Security | 4 | search/show/list, TOFU, system profiles |

Total: 20 chunks across 6 phases.

## Conventions

- All new code goes under `src/package/`.
- Tests go in `#[cfg(test)] mod tests` at the bottom of each file, plus
  integration tests in `tests/package/` for cross-module flows.
- Error variants are added to `AosError` in `error.rs` as needed.
- All public functions return `Result<T, AosError>` (or `anyhow::Result`).
- Human output goes through `Printer`; machine output via `--json`.
- File I/O uses atomic write (write to temp + rename) for all state mutations.
