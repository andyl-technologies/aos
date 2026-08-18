##! aos-hub — multi-tenant AOS registry management hub (RFC-0004)
##!
##! Builds the `aos-hub` and `aos-hub-egress` binaries from the shared `crates/` cargo
##! workspace, mirroring `pkgs/tools/aos/aos.nix`. The hub is a self-contained
##! axum server: a sqlite database (rusqlite, bundled) plus a `file://`/HTTP
##! surface reader, so unlike `aos` it shells out to no external tools at
##! runtime and needs no PATH wrapper — `$out/bin/aos-hub` is the
##! complete artifact.
##!
##! Hermetic, like every package here: the toolchain is the AOS-built
##! `pkgs.rust`, dependencies are vendored by `fetchCargoDeps`, and the only
##! native build inputs are `pkg-config`/`openssl` (the `reqwest` rustls stack
##! still links `openssl-sys` transitively through the workspace) and
##! `protobuf` (the `aos-proto` build script runs `protoc` to generate the
##! `aos.hub.v1` ConnectRPC stubs).
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
  openssl,
  perl,
  pkg-config,
  protobuf,
  zlib,
  aos-hub-console-dist,
}: let
  version = "0.1.0";
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  src = builtins.path {
    path = repoRoot;
    name = "aos-hub-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base
      != "target"
      && base != ".git"
      && (
        pathString
        == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
      );
  };
in
  mkCargoPackage {
    pname = "aos-hub";
    inherit version src;

    # Build the hub package's control-plane and fixed egress binaries.
    # PostgreSQL is the strongly-consistent shared nonce store for replicated
    # aos-hub-egress deployments. SQLite remains available for a singleton.
    cargoFlags = "-p aos-hub --features postgres";

    # The workspace's vendored dependency set. This hash is the
    # The lockfile-aware vendor output over the whole workspace Cargo.lock is
    # shared in shape with `aos.nix` but is its own derivation. Regenerate with
    # `nix build` once and copy the reported `got:` hash here (the lockfile
    # gained `hmac` for the phase-4 webhook HMAC signatures).
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "aos-vendor-${version}";
      sourceRoot = "source/crates";
      hash = "sha256-HpIXteO0Adw3+VmLING6Fd5vDHrGHUt+KQ8gZ312bkU=";
    };

    buildDeps = [perl pkg-config openssl protobuf];
    # rusqlite is built with the `bundled` feature (its own sqlite amalgamation).
    # libgit2 still links zlib for compressed Git objects.
    runtimeDeps = [openssl zlib];

    preBuild = ''
      cd crates
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
      export AOS_HUB_CONSOLE_JS="${aos-hub-console-dist}/hub-console.js"
      export AOS_HUB_CONSOLE_WASM="${aos-hub-console-dist}/hub-console_bg.wasm"
      export AOS_HUB_CONSOLE_CSS="${aos-hub-console-dist}/hub-console.css"
    '';

    # The workspace test suite is exercised by the `aos` package's
    # `cargoTestFlags = "--workspace"`; this derivation only needs to compile
    # and install the hub binary, so it skips the (redundant) test run.
    doCheck = false;

    meta = {
      description = "aos-hub — multi-tenant AOS registry management hub";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
