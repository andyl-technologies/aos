# ANDYL OS — Build Principles

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
  packages in any build derivation.
- Test infrastructure (QEMU, socat, etc.) is the only exception — these run on
  the host and are not part of the AOS image or build closure.

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
- Builds run on a remote NixOS builder: `--store ssh-ng://dylan@builder-hil1-319ea92d`
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

The `aos` CLI is a Rust tool (`cli/`) for working with this repo. Run it via
the Nix flake — do NOT use `cargo run` directly (it needs nixfmt in PATH):

```sh
# Enter the dev shell (provides aos + nixfmt in PATH, installs pre-commit hook):
nix develop

# Or run a one-off command without entering the shell:
nix run . -- <subcommand>
```

### Subcommands

| Command       | Description                                             |
|---------------|---------------------------------------------------------|
| `aos fmt`     | Auto-format all `.nix` files with nixfmt                |
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
| `aos shell`   | Enter a dev shell with a package's deps                 |
| `aos repl`    | Open a Nix REPL with the AOS package set loaded         |
| `aos why-depends` | Explain why one derivation depends on another      |
| `aos completions` | Generate shell completions                         |

### Pre-commit hook

The dev shell installs a pre-commit hook that auto-formats `.nix` files and
re-stages them before committing. The hook is defined in `dev/shell.nix` and
written to `.git/hooks/pre-commit` on `nix develop`.

## Testing

- `nix-build -A checks.eval` — pure evaluation checks
- `nix-build -A checks.vm.boot` — VM boot test using QEMU direct kernel boot
- VM tests use `mkfs.ext4 -d` (sandbox-compatible, no losetup/mount)
- VM tests require `requiredSystemFeatures = [ "kvm" ]`
