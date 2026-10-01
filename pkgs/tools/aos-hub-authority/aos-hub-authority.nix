##! aos-hub-authority — dedicated retained per-authority Native issuer
##!
##! Builds only the separate authority process using the AOS Rust/toolchain,
##! SQLite, OpenSSL and vendored workspace dependencies. Console inputs remain
##! genuine dependencies of the linked Hub library. Runtime credentials,
##! installation manifests and journals are never embedded in this artifact.
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  openssl,
  perl,
  pkg-config,
  protobuf,
  sqlite,
  zlib,
  aos-hub-console-dist,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPerl =
    if isDarwinCross
    then buildPackages.perl
    else perl;
  buildPkgConfig =
    if isDarwinCross
    then buildPackages.pkg-config
    else pkg-config;
  buildProtobuf =
    if isDarwinCross
    then buildPackages.protobuf
    else protobuf;
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  src = builtins.path {
    path = repoRoot;
    name = "aos-hub-authority-workspace-src";
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
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-bFrGLJz08aNxlYogCpbDOy9Oh7uFIcLXm4lMe5Ce9no=";
  };
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_HUB_CONSOLE_JS = "${aos-hub-console-dist}/hub-console.js";
    AOS_HUB_CONSOLE_WASM = "${aos-hub-console-dist}/hub-console_bg.wasm";
    AOS_HUB_CONSOLE_CSS = "${aos-hub-console-dist}/hub-console.css";
  };
  cargoArtifactContract = {
    family = "aos-hub-authority-native-release";
    targets = ["aos-hub-authority"];
    features = [];
    nativeInputs = map toString [openssl sqlite buildPkgConfig buildProtobuf aos-hub-console-dist];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-hub-authority-native-artifacts";
    inherit version cargoDeps cargoEnv cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "aos-hub-authority-native-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoFlags = "-p aos-hub --bin aos-hub-authority";
    buildDeps = [buildPerl buildPkgConfig openssl sqlite buildProtobuf aos-hub-console-dist];
    runtimeDeps = [openssl sqlite zlib];
  };
in
  mkCargoPackage {
    pname = "aos-hub-authority";
    inherit version src;

    # Retained authority state belongs to this separate private process.
    # The ordinary Hub/egress executables remain in the ordinary Hub package.
    cargoFlags = "-p aos-hub --bin aos-hub-authority";

    inherit cargoDeps cargoArtifacts cargoEnv cargoArtifactContract;
    cargoRoot = "crates";

    buildDeps = [buildPerl buildPkgConfig openssl sqlite buildProtobuf];
    # libgit2 still links zlib for compressed Git objects.
    runtimeDeps = [openssl sqlite zlib];

    # Actual HTTP/persistence tests are qualified separately. Artifact creation
    # alone establishes neither retained-volume ownership nor provider readiness.
    doCheck = false;

    meta = {
      description = "Dedicated Native authority issuer with private retained SQLite state";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
