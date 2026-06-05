##! lib/testing/rust.nix — Rust CI checks for the `aos` CLI workspace.
##!
##! Surfaces the Cargo workspace's formatting, linting, test, and doc
##! gates as first-class Nix derivations so they live in the same
##! centralised `checks` namespace as every other AOS check. Each runs
##! fully offline against the vendored dependency set and uses only the
##! AOS-built Rust toolchain (`pkgs.rust` + `pkgs.rust.dev`) — no host
##! tools, no nixpkgs.
##!
##! Usage:
##!   nix-build -A checks.cargo-fmt      # rustfmt --check
##!   nix-build -A checks.cargo-clippy   # clippy, warnings denied
##!   nix-build -A checks.cargo-test     # cargo test --workspace
##!   nix-build -A checks.cargo-doc      # cargo doc, broken links denied
{
  pkgs,
  lib,
}: let
  inherit (pkgs) rust openssl protobuf perl pkg-config git;

  # Shared crates workspace source + vendored deps (single hash, defined
  # alongside the `aos` package).
  workspace = import ../../pkgs/tools/aos/_workspace.nix {
    inherit (pkgs) fetchCargoDeps;
  };
  inherit (workspace) src cargoDeps;

  # Environment every cargo invocation needs: locate the AOS-built OpenSSL
  # and protoc rather than probing the (non-existent) host toolchain.
  # Mirrors the `aos` package's preBuild exactly.
  cargoEnv = ''
    export OPENSSL_DIR="${openssl}"
    export OPENSSL_LIB_DIR="${openssl}/lib"
    export OPENSSL_INCLUDE_DIR="${openssl}/include"
    export OPENSSL_NO_VENDOR=1
    export OPENSSL_STATIC=0
    export PROTOC="${protobuf}/bin/protoc"
  '';

  # Point cargo at the vendored directory and forbid any network access,
  # so the check is hermetic and reproducible. Mirrors the fetchCargoDeps
  # branch of stdenv/phases.nix:cargoPhases.
  configurePhase = {
    name = "configure";
    script = ''
      export CARGO_HOME="$TMPDIR/cargo"
      export CARGO_NET_OFFLINE=true
      mkdir -p "$CARGO_HOME" .cargo
      printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
        > .cargo/config.toml
      ${cargoEnv}
    '';
  };

  # Build one Rust check derivation.
  #
  #   name        attribute / store name (e.g. "cargo-clippy")
  #   buildDeps   extra packages on PATH beyond the Rust toolchain
  #   checkScript shell running the actual gate; a non-zero exit fails CI
  mkRustCheck = {
    name,
    buildDeps ? [],
    checkScript,
  }:
    pkgs.mkDerivation {
      pname = name;
      version = "0.1.0";
      inherit src;

      # `rust.dev` carries cargo-fmt / cargo-clippy / clippy-driver /
      # rustfmt; `rust` (out) carries cargo / rustc / rustdoc and the libs
      # the dev tools dlopen at runtime.
      buildDeps = [rust rust.dev] ++ buildDeps;

      phases = [
        {
          name = "unpack";
          script = ''
            cp -r "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        configurePhase
        {
          name = "check";
          script = checkScript;
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            echo "${name}: passed" > "$out/result"
          '';
        }
      ];

      # Nothing is installed into $out except a marker, so the default
      # strip/patchelf fixups have nothing to do — skip them.
      dontStrip = true;
      dontPatchELF = true;

      meta = {
        description = "Rust CI check: ${name}";
      };
    };

  # Build deps for checks that actually compile the workspace (clippy,
  # test, doc) — they run build scripts for openssl-sys and tonic/prost.
  compileDeps = [perl pkg-config openssl protobuf git];
in {
  # `cargo fmt --check` — no compilation, so it needs no build deps.
  cargo-fmt = mkRustCheck {
    name = "cargo-fmt";
    checkScript = ''
      echo "==> cargo fmt --all --check"
      cargo fmt --all --check
      echo "==> formatting OK"
    '';
  };

  # `cargo clippy` across the whole workspace and all targets, with every
  # lint warning promoted to an error.
  cargo-clippy = mkRustCheck {
    name = "cargo-clippy";
    buildDeps = compileDeps;
    checkScript = ''
      echo "==> cargo clippy --workspace --all-targets -- -D warnings"
      cargo clippy \
        --workspace \
        --all-targets \
        --frozen \
        --offline \
        -j"$NIX_BUILD_CORES" \
        -- -D warnings
      echo "==> clippy clean"
    '';
  };

  # `cargo test --workspace`.
  cargo-test = mkRustCheck {
    name = "cargo-test";
    buildDeps = compileDeps;
    checkScript = ''
      echo "==> cargo test --workspace"
      cargo test \
        --workspace \
        --frozen \
        --offline \
        -j"$NIX_BUILD_CORES"
      echo "==> tests passed"
    '';
  };

  # `cargo doc` with broken intra-doc links denied — enforces the rustdoc
  # quality bar from AGENTS.md ("treat all code as user-facing porcelain").
  cargo-doc = mkRustCheck {
    name = "cargo-doc";
    buildDeps = compileDeps;
    checkScript = ''
      echo "==> cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings)"
      export RUSTDOCFLAGS="-D warnings"
      cargo doc \
        --workspace \
        --no-deps \
        --frozen \
        --offline \
        -j"$NIX_BUILD_CORES"
      echo "==> docs build clean"
    '';
  };
}
