##! aos-hub — multi-tenant AOS registry management hub (RFC-0004)
##!
##! Builds the `aos-hub` binary from the shared `crates/` cargo
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
##! `aos.registry.v1` ConnectRPC stubs).
{
  mkCargoPackage,
  fetchCargoDeps,
  openssl,
  perl,
  pkg-config,
  protobuf,
}: let
  version = "0.1.0";
  src = builtins.path {
    path = ../../../crates;
    name = "aos-crates-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
in
  mkCargoPackage {
    pname = "aos-hub";
    inherit version src;

    # Build only the hub binary out of the workspace.
    cargoFlags = "-p aos-hub";

    # The workspace's vendored dependency set. This hash is the
    # `fetchCargoDeps` fixed-output over the whole workspace Cargo.lock; it is
    # shared in shape with `aos.nix` but is its own derivation. Regenerate with
    # `nix build` once and copy the reported `got:` hash here (the lockfile
    # gained `hmac` for the phase-4 webhook HMAC signatures).
    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-k0mK+JO/PJNV2L/hzIpiT/ALzsRVQqir8dU3f99452Q=";
    };

    buildDeps = [perl pkg-config openssl protobuf];
    # rusqlite is built with the `bundled` feature (its own sqlite amalgamation),
    # so the only runtime native library is openssl.
    runtimeDeps = [openssl];

    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
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
