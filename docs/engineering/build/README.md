# Build system

Every AOS package is built hermetically from source. The compiler toolchain
starts from a reviewed `hex0` seed, and every later tool is an AOS derivation
built only from earlier AOS derivations. The rules for package authors are in
[`AGENTS.md`](../../../AGENTS.md#hermetic-builds-from-source); this section
explains how the build machinery implements them.

- [Toolchain ladder](toolchain-ladder.md) covers the source bootstrap, the GCC
  version tiers, the per-tier standard environment, and the rules that keep each
  tier's outputs trustworthy.
- [Rust builds](rust-builds.md) covers reusable Cargo dependency artifacts,
  their compatibility contract, development caches, and parallel Rust tests.

## Layers

```text
stdenv/bootstrap/    hex0 seed -> stage0 tools -> Mes -> TinyCC -> GCC 2.95.3 era tools (i686)
stdenv/toolchains/   GCC tiers 3.4.6 -> 16.2.0, each built by its predecessor
stdenv/default.nix   wraps the final tier into the global stdenv
pkgs/default.nix     package set: mkDerivation plus language builders
```

`stdenv/phases.nix` owns the shared phase scripts (unpack, configure, build,
install, fixup) and the language phase generators such as the Cargo phases.
`stdenv/cc-wrapper.nix` owns compiler flag injection: include and library
search paths, `-B`, the dynamic linker, rpaths, and hardening flags.
`stdenv/tier-stdenv.nix` instantiates that wrapper for a toolchain tier.
Packages never hand-write those flags; they list their dependencies in
`buildDeps`, `runtimeDeps`, and `propagatedDeps`, and the wrapper and
environment are derived from those lists.

`lib/derivations.nix` implements `mkDerivation`, which runs the declared phases
under the stdenv's shell and `PATH`. `pkgs/default.nix` layers the language
builders on top of it: `mkCargoPackage` and its artifact and test variants,
`mkGoPackage`, and `mkBazelPackage`.
