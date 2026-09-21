##! aos-hub — multi-tenant AOS registry management hub (RFC-0004)
##!
##! Builds the `aos-hub` and `aos-hub-egress` binaries from the shared `crates/` cargo
##! workspace, mirroring `pkgs/tools/aos/aos.nix`. The hub is a self-contained
##! axum server: a sqlite database (rusqlite with the AOS SQLite library) plus
##! a `file://`/HTTP surface reader, so unlike `aos` it shells out to no external
##! tools at runtime and needs no PATH wrapper — `$out/bin/aos-hub` is the
##! complete artifact.
##!
##! Hermetic, like every package here: the toolchain is the AOS-built
##! `pkgs.rust`, dependencies are vendored by `fetchCargoDeps`, and the only
##! native build inputs are `pkg-config`, `openssl`, and `sqlite` (the `reqwest`
##! rustls stack still links `openssl-sys` transitively through the workspace) and
##! `protobuf` (the `aos-proto` build script runs `protoc` to generate the
##! `aos.hub.v1` ConnectRPC stubs).
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
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
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
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
    family = "aos-hub-native-postgres-release";
    features = ["postgres"];
    nativeInputs = map toString [openssl sqlite buildPkgConfig buildProtobuf aos-hub-console-dist];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-hub-native-postgres-artifacts";
    inherit version cargoDeps cargoEnv cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "aos-hub-native-postgres-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoFlags = "-p aos-hub --features postgres";
    buildDeps = [buildPerl buildPkgConfig openssl sqlite buildProtobuf aos-hub-console-dist];
    runtimeDeps = [openssl sqlite zlib];
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "aos-hub";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents Usage.";
        "files" = {};
        "input" = "The packaged aos-hub command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-hub\",\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Usage\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"aos-hub operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-hub operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing its main operation.";
        "files" = {};
        "input" = "A aos-hub invocation containing an unsupported command-line option.";
        "operation" = "Parse the unknown option without starting a service or contacting a remote endpoint.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-hub\",\"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-hub rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-hub rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    # Build the hub package's control-plane and fixed egress binaries.
    # PostgreSQL is the strongly-consistent shared nonce store for replicated
    # aos-hub-egress deployments. SQLite remains available for a singleton.
    cargoFlags = "-p aos-hub --features postgres";

    inherit cargoDeps cargoArtifacts cargoEnv cargoArtifactContract;
    cargoRoot = "crates";

    buildDeps = [buildPerl buildPkgConfig openssl sqlite buildProtobuf];
    # libgit2 still links zlib for compressed Git objects.
    runtimeDeps = [openssl sqlite zlib];

    abilities = ./_aos-hub;

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
