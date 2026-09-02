# ANDYL OS — Build Principles

## Contribution authorization

These rules apply before merging changes, independently of the file licenses
described below. The complete policy is in [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the
[`maintainer contributor-authorization guide`](docs/maintainers/contributor-licensing.md).

- Every external human contributor must have an active acceptance of the AOS
  External Contributor License Agreement bound to the contributor's stable
  GitHub user ID before merge.
- Current Andyl, Inc. employees contributing within their authorized employment
  scope are covered by Andyl's standard CIAA and a verified internal
  authorization record. They do not accept the external agreement.
- Contractors, former employees, and contributors whose employee authorization
  cannot be verified use the external path. A company email address alone is
  not proof of employee authorization.
- AOS does not use a separate organization-level contributor agreement. An
  external contributor must already have any employer permission needed to make
  the external agreement's grants and representations.
- The authorization check fails closed. Never merge when authorization is
  missing, disabled, superseded, mismatched, unavailable, or indeterminate, and
  never commit private employee or acceptance records to this repository.
- QEMU-side changes additionally require the DCO sign-off documented in
  [`CONTRIBUTING.md`](CONTRIBUTING.md); it does not replace contribution
  authorization.

## Crucible/QEMU license boundary

These invariants are mandatory for maintainers and automated agents. The
normative policy is
[`docs/legal/licensing.md`](docs/legal/licensing.md) and RFC-0010
[`37-licensing-process-boundary.md`](docs/rfcs/0010-crucible/37-licensing-process-boundary.md).

- The Apache-licensed Crucible host and GPL-side QEMU/plugin MUST remain
  separate processes. Their only integration surfaces are the versioned Unix
  socket control protocol and versioned shared-memory data protocol.
- Shared memory is a public process protocol. It MUST NOT contain native
  pointers, QEMU private structures, function/callback tables, Rust-native enum
  layouts, or other process-private objects. Cross-region references are checked
  offsets; changes require explicit compatibility/version handling.
- Code compiled into, linked into, or dynamically loaded by QEMU belongs to the
  applicable QEMU/GPL-compatible scope. Apache-only crates MUST NOT link QEMU,
  include QEMU headers, or expose QEMU callback entry points.
- Preserve QEMU's per-file licenses. The emulator is GPL-2.0-only as a combined
  work, while unmarked QEMU 10.0 source files default to GPL-2.0-or-later.
  Changes that create or remove QEMU files MUST update
  `pkgs/emulation/qemu-patches/LICENSES.md`.
- Do not publish `qemu-crucible` as a standalone store-path root. Publish the
  `crucible` suite, whose enforced release policy co-retains the matching
  `qemu-crucible-source` output. Publication checks scan the full closure, so
  plugin or unmarked wrapper roots are not valid bypasses. Keep generic
  unpatched QEMU unrestricted.
- `crucible-protocol` and `crucible-shmem` are permissive boundary components;
  neither may acquire a dependency on a QEMU implementation or QEMU headers.
- Boundary changes MUST pass `gate:abi-conformance` and
  `gate:license-boundary`. A distributed patched-QEMU binary MUST have a
  matching complete corresponding-source artifact; release automation fails
  closed when it is absent.

Guest assertion semantics and evaluation remain Apache host-side. QEMU/plugin
observation changes remain GPL-side and cross the boundary only through the
versioned shared-memory or doorbell protocol.

## Hermetic builds from source

All packages in this repository MUST be built hermetically from source using
only the bootstrap tools (gcc, glibc, coreutils, make, tar, bash, etc.) and
previously-built AOS packages. **No host tools. No upstream nixpkgs.**

- The bootstrap tools tarball (`stdenv/bootstrap-tools.nix`) provides the
  initial compiler toolchain (gcc, glibc, binutils) and core POSIX utilities.
- Every other tool — flex, bison, gperf, elfutils, python3, meson, ninja, go —
  must be built as an AOS package from source, using only bootstrap tools and
  other AOS packages as build dependencies.
- The `hostTools` pattern is **not used**. Do not import or reference nixpkgs
  packages in any build or test derivation.
- If a tool exists as an AOS package (e.g. socat, jq), **always use the AOS
  package** (`pkgs.socat`, `pkgs.jq`) — even in test harnesses that run on the
  host. Never pull a nixpkgs version of something we already build from source.
- The entire build system is fully self-hosted. **No nixpkgs dependencies
  exist** — not in packages, not in test tools (QEMU is built from source),
  not in the flake, and not in the dev shell.
- **No `/bin/sh`, `/bin/bash`, or `/usr/bin/env` paths.** All shell references
  must use AOS-built bash from the stdenv (`${bash}/bin/bash` or the `shell`
  parameter). The only exception is inside the source bootstrap chain
  (`stdenv/bootstrap/`) where the Nix sandbox's `/bin/sh` is the only option.
  Shebangs inside VM rootfs init scripts may use `/bin/sh` since the rootfs
  builder creates that symlink pointing to the AOS bash.

## Package structure

Each package is a Nix file that takes `{ mkDerivation, fetchurl, ... }` and
returns a derivation. Version, mirror URLs, and hash are colocated inline:

```nix
{ mkDerivation, fetchurl, make }:
let version = "X.Y.Z"; in
mkDerivation {
  pname = "foo";
  inherit version;
  src = fetchurl {
    urls = [ "https://..." ];
    hash = "sha256-...";
  };
  buildDeps = [ make ];
  runtimeDeps = [];
  phases = [ ... ];
}
```

- `buildDeps` — tools needed only at build time (compilers, build systems)
- `runtimeDeps` — libraries/tools needed at runtime (linked against)
- `propagatedDeps` — deps that propagate to downstream consumers

## Build environment

- The `ccWrapper` (defined in `pkgs/default.nix`) wraps bootstrap gcc to inject
  `-isystem`, `-B`, `-L`, `-Wl,-dynamic-linker`, `-Wl,-rpath` flags.
- Every `mkDerivation` automatically gets `ccWrapper` and `bootstrapTools` in
  its `buildDeps` — packages don't need to specify them.
- `C_INCLUDE_PATH`, `LIBRARY_PATH`, and `PKG_CONFIG_PATH` are set from all
  deps (build + runtime + propagated).
- The builder shell is `/bin/sh` (dash on NixOS). Bash-specific syntax in phase
  scripts will fail. Use `$CONFIG_SHELL` (bootstrap bash) for bash features.

## Module system

NixOS-style modules in `modules/` with `lib.evalModules`. System variants
compose modules in `systems/`. The `system.build.toplevel` derivation
assembles /etc, systemd units, and package symlinks.

## Package completeness

Do NOT remove features from packages to simplify builds. If a package needs a
dependency (e.g. rsync needs openssl, systemd needs SELinux/audit), build that
dependency correctly as an AOS package rather than disabling the feature. Do the
work of implementing packages and potentially large dependency chains in Nix
correctly. Stubbing is acceptable only for truly complex bootstrapping problems
(e.g. Go from-scratch bootstrap) and must be explicitly marked as TODO.

## The `aos` CLI tool

The `aos` CLI is a Rust tool (`crates/`) for working with this repo. Run it via
the Nix flake — do NOT use `cargo run` directly (it needs alejandra in PATH):

```sh
# Enter the dev shell (provides aos + just in PATH):
nix develop

# Or run a one-off command without entering the shell:
nix run . -- <subcommand>
```

### Incremental builds

`nix build` / `nix run` rebuild the whole `pkgs.aos` derivation hermetically and
are slow to iterate on. For a fast edit–build–run loop on the Rust code, build
with `cargo` in the dev-shell environment via `nix develop -c` — a single
non-interactive command (a bare `nix develop` only opens an interactive shell) —
then run the resulting binary directly:

```sh
# Build (incremental). `nix develop -c` execs its argument directly (no shell),
# so pass cargo the workspace with --manifest-path rather than `cd`-ing:
nix develop -c cargo build --manifest-path crates/Cargo.toml --bin aos   # or --bin apr / --bin apm

# Run the freshly built binary directly — its OpenSSL rpath is baked in:
crates/target/debug/aos <subcommand>
```

- **Build through `nix develop -c`.** The dev shell points `openssl-sys` at the
  AOS OpenSSL and bakes its `rpath` into the linked binary (via a per-target
  `CARGO_TARGET_*_RUSTFLAGS`), so it runs with no `patchelf` or
  `LD_LIBRARY_PATH`. A cargo build in a bare shell produces a binary that can't
  find OpenSSL at load time.
- **Run `crates/target/debug/<bin>` directly — not `cargo run`.** The rpath is
  baked in, so the binary finds OpenSSL on its own. `cargo run` would instead add
  the OpenSSL lib dir to `LD_LIBRARY_PATH` for the process it spawns; that leaks
  into the `nix` / `git` subprocesses the CLI shells out to and breaks them by
  overriding their own newer OpenSSL. (Wrap the run in `nix develop -c …` only to
  make the CLI use the AOS-built `nix` / `git` instead of the host's.)
- **Choose the tool by binary name.** `aos`, `apm`, and `apr` are independent
  entry points with disjoint parsers backed by shared Rust libraries. Build and
  run the exact binary whose command surface you are testing; there is no
  `aos package` compatibility path.
- `crates/target/debug/` is independent of the flake-installed `aos`; `nix run`
  and any installed CLI keep the last packaged build until rebuilt.

### Subcommands

| Command       | Description                                             |
|---------------|---------------------------------------------------------|
| `aos fmt`     | Auto-format all `.nix` files with alejandra              |
| `aos fmt --check` | Check formatting without modifying files           |
| `aos build`   | Build a system variant or package                       |
| `aos test`    | Run tests (eval, VM)                                    |
| `aos show`    | Show package/module information                         |
| `aos graph`   | Print the dependency graph                              |
| `aos lint`    | Lint Nix files for common issues                        |
| `aos gc`      | Garbage-collect old Nix store paths                     |
| `aos prefetch`| Prefetch a URL and print its hash                       |
| `aos describe`| Describe a package or module                            |
| `aos system`  | System variant operations                               |
| `aos repl`    | Open a Nix REPL with the AOS package set loaded         |
| `aos why-depends` | Explain why one derivation depends on another      |
| `aos completions` | Generate shell completions                         |

## Rust code style

These rules apply to every Rust crate under `crates/`. Write idiomatic Rust to
the standard of the Rust standard library and the largest, best-documented
projects in the ecosystem (for example, Tokio). The repository-wide coding
standard is in [`docs/code-style.md`](docs/code-style.md).

- **Treat all code as user-facing porcelain.** Document items with rustdoc that
  would look great on docs.rs and abide by all Rust documentation conventions —
  summary line, `# Examples`, `# Errors`, `# Panics` sections where applicable.
- **Avoid `unsafe` at all costs.** Use it only for an explicit, justified
  performance need, and document the invariants with a `// SAFETY:` comment.
- **Never use `.unwrap()` or `.expect()` in production code.** Use proper error
  handling — propagate with `?`, return `Result`, and model errors with proper
  types. (Tests and examples may use them where a panic is the intended signal.)
- **Use size as a design signal.** Reconsider a module's responsibilities as a
  hand-written file approaches 1,000 lines. Files beyond roughly 1,500 lines
  deserve a clear cohesion argument. Judge co-located `#[cfg(test)]` modules
  separately from their implementation. Functions have no hard line limit;
  review long functions for mixed abstraction levels and hidden operations.
- **Make code readable in semantic paragraphs.** `rustfmt` is the mechanical
  baseline, not the readability bar. Separate validation, transformation,
  effects, and result construction with names, helpers, and intentional blank
  lines.
- **Comment reasoning, not syntax.** Document invariants, protocol and ordering
  rules, fail-closed behavior, security decisions, and surprising tradeoffs.
  Do not use a comment-density quota or pad obvious code.

### Rust documentation standard

The concrete bar for "docs.rs quality" in this workspace:

- **Crate level**: `lib.rs` / `main.rs` carries a `//!` overview — what the
  crate does, a map of its modules, and how the pieces fit together.
- **Module level**: every `.rs` file carries a `//!` header naming what the
  module owns and its key concepts. Modules that own an on-disk or wire
  format (TOML schemas, narinfo, state JSON, pack layouts) show the format in
  a fenced example block.
- **Every public item** gets `///` rustdoc: a one-sentence third-person
  summary line, then detail paragraphs only where behavior is non-obvious.
  Public struct fields are documented wherever their meaning isn't
  self-evident — schema/config structs are data contracts and their field
  docs matter most.
- **`# Errors` on every public fn returning `Result`**, describing the
  conditions that produce errors. **`# Panics`** wherever a panic is
  reachable.
- **Tag every fenced block** in docs: ` ```text `, ` ```toml `, ` ```no_run `,
  or ` ```ignore `. Untagged blocks become doctests that compile and run in
  the hermetic `pkgs.aos` build — a format example with an untagged fence is
  a build failure. Add runnable `# Examples` only when they compile against
  public API alone; prefer `no_run`.
- **Clap derive caveat**: doc comments on `#[derive(Parser/Subcommand/Args)]`
  containers and their fields become `--help` output. Do not add container
  `///` docs (document the surrounding module instead), and treat field doc
  edits as user-facing CLI changes — keep them short, imperative, accurate.
- **Private items**: document non-obvious helpers briefly; don't pad
  trivial one-liners.
- **Intra-doc links** (`` [`Item`] ``) only to items that exist and are
  visible from the linking item — links from public docs to private items
  warn. Prefer ASCII punctuation in comments.
- Documenting existing code is a **comments-only** activity: never reorder,
  rename, or reformat code in a docs pass. If a doc claim contradicts the
  code, fix the doc to match observed behavior and flag the discrepancy in
  the PR rather than changing the code.

## Nix code style

Nix source follows [`docs/code-style.md`](docs/code-style.md), including the
repository's Dendritic module organization. In addition to the hermetic build
and package rules above:

- Under `modules/`, organize auto-discovered top-level modules by feature and
  keep each feature's options, configuration, and checks together. System
  variants compose features; `_`-prefixed paths hold deliberately imported
  implementation details. `callPackage`-style expressions under `pkgs/` remain
  the deliberate non-module exception.
- Reconsider a hand-written file's responsibilities around 1,000 lines and
  expect a clear cohesion argument beyond roughly 1,500 lines.
- Treat embedded shell blocks around 150 lines as a prompt to consider named
  phase scripts, helper builders, or focused check derivations without
  weakening hermeticity.
- Make dependencies visible in function argument sets and use named
  intermediate values instead of broad `with` scopes or deeply nested
  anonymous expressions.
- Use intentional blank lines to separate inputs, policy, derived values,
  phases, and outputs. Alejandra formatting is necessary but not sufficient.
- Comment non-obvious bootstrap, sandbox, dependency, platform, protocol, and
  closure decisions. Comments explain why; names and structure explain what.

Existing difficult code is context, not precedent. Feature work should leave
the local design no worse and improve it where that is safe and proportionate.

## Testing

- `nix-build -A checks.eval` — pure evaluation checks
- `nix-build -A checks.vm.boot` — VM boot test using QEMU direct kernel boot
- VM tests use `mkfs.ext4 -d` (sandbox-compatible, no losetup/mount)
- VM tests require `requiredSystemFeatures = [ "kvm" ]`
