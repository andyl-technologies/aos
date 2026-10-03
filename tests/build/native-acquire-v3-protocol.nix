##! Qualifies the complete native SourceProvider protocol suite without shared compiler state.
{
  pkgs,
  lib,
}: let
  src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
in
  pkgs.mkCargoPackage {
    pname = "aos-native-acquire-v3-protocol-check";
    version = "1";
    inherit src;
    # Reuse the unchanged workspace vendor closure, not Mount's compiled
    # artifacts or its service/fixture build dependencies.
    cargoDeps = pkgs.aos-sandbox-mountd.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoArtifacts = null;
    sharedBuildCache = false;
    cargoEnv.RUST_TEST_THREADS = "1";

    # The ordinary sandbox-local target remains private to this derivation.
    # Debug preserves existing fixture guards; cargo test includes all unit,
    # integration/golden, and doc tests rather than a V3-only test filter.
    cargoBuildCommands = [
      "test --no-run --frozen --offline -j1 -p aos-sandbox-source-provider-protocol"
    ];
    cargoTestFlags = "-j1 -p aos-sandbox-source-provider-protocol";
    buildType = "debug";
    checkType = "debug";
    doCheck = true;
    installBins = false;
    installLibs = false;
    runtimeDeps = [];

    preConfigure = ''
      test -z "''${CARGO_TARGET_DIR:-}"
      test -z "''${RUSTC_WRAPPER:-}"
      test -z "''${RUSTC_WORKSPACE_WRAPPER:-}"
      test "''${CARGO_INCREMENTAL:-0}" = 0
    '';
  }
