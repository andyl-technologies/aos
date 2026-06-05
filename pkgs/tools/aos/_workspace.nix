##! Shared definition of the `crates/` Cargo workspace source and its
##! pre-fetched, vendored dependency set.
##!
##! Centralising these here keeps a single source of truth for the
##! `cargoDeps` fixed-output hash, which is consumed both by the `aos`
##! package (`pkgs/tools/aos/aos.nix`) and by the Rust CI checks
##! (`lib/testing/rust.nix`). The hash is a function of `Cargo.lock`
##! alone, so every consumer resolves to the identical vendor directory.
##!
##! Usage:
##!   let ws = import ./_workspace.nix { inherit fetchCargoDeps; };
##!   in ws.src        # the cleaned crates/ tree (no target/, no .git)
##!      ws.cargoDeps   # the vendored dependency directory
{fetchCargoDeps}: rec {
  # The Cargo workspace source tree, with build artefacts and VCS metadata
  # filtered out so edits to `target/` never invalidate the source hash.
  src = builtins.path {
    path = ../../../crates;
    name = "aos-crates-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };

  # Vendored crates.io dependencies, fetched once and reused by every
  # cargo invocation (build, test, clippy, fmt, doc) in --offline mode.
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };
}
