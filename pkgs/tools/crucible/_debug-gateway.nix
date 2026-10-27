##! Selects the standalone GPL gateway without evaluating the Apache suite.
{
  lib,
  stdenv,
  callPackage,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  rust,
  pkg-config,
  sqlite,
  buildPackages,
  buildDriver ? "cargo",
}: let
  version = "0.1.0";
  src = import ./_source.nix {inherit lib;};
  cargoDeps = aosWorkspaceVendor;
  cargoWorkspaceMembers = import ./_workspace.nix {inherit lib;};
  buildRustDev =
    if stdenv.isCross
    then buildPackages.rust.dev
    else rust.dev;
  buildPkgConfig =
    if stdenv.isCross
    then buildPackages.pkg-config
    else pkg-config;
  withBuildDriver = selected: callPackage ./_debug-gateway.nix {buildDriver = selected;};
  # The real Apache client remains a separate executable in GPL tests.
  qemuTestOracle = callPackage ./_qemu-test-oracle.nix {};
  debugGatewayArtifactContract = {
    family = "crucible-gpl-debug-gateway-release-and-test";
    nativeInputs = map toString [buildRustDev buildPkgConfig sqlite];
    licenseScope = "GPL-2.0-only";
  };
  debugGatewayCargoEnv = {LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";};
  debugGatewayArtifacts = mkCargoArtifacts {
    pname = "crucible-debug-gateway-artifacts";
    inherit version cargoDeps cargoWorkspaceMembers;
    cargoArtifactContract = debugGatewayArtifactContract;
    cargoEnv = debugGatewayCargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "crucible-debug-gateway-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-qemu-debug-gateway"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p crucible-qemu-debug-gateway"
    ];
    buildDeps = [buildRustDev buildPkgConfig sqlite];
    runtimeDeps = [sqlite];
  };
  packageArguments = {
    pname = "crucible-debug-gateway";
    inherit version src;

    inherit cargoDeps cargoWorkspaceMembers;
    cargoArtifacts = debugGatewayArtifacts;
    cargoArtifactContract = debugGatewayArtifactContract;
    cargoEnv = debugGatewayCargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-qemu-debug-gateway";
    cargoTestFlags = "-p crucible-qemu-debug-gateway";
    doCheck = true;
    buildDeps = [buildRustDev buildPkgConfig sqlite];
    runtimeDeps = [sqlite];

    postBuild = lib.optionalString (!stdenv.isCross) ''
      export CRUCIBLE_QEMU_TEST_ORACLE=${qemuTestOracle}/bin/crucible-qemu-test-oracle
    '';
    preInstall = ''
      unset CRUCIBLE_QEMU_TEST_ORACLE
    '';

    postInstall = ''
      mkdir -p "$out/share/licenses/crucible-debug-gateway"
      cp ${../../../LICENSES/GPL-2.0-only.txt} \
        "$out/share/licenses/crucible-debug-gateway/GPL-2.0.txt"
      cp ${../../../LICENSES/MIT.txt} \
        "$out/share/licenses/crucible-debug-gateway/MIT.txt"
      cat > "$out/share/licenses/crucible-debug-gateway/COMPONENT" <<'LICENSE_SCOPE'
      crucible-debug-gateway is a standalone QEMU RSP mediation process.
      SPDX-License-Identifier: GPL-2.0-only
      crucible-qemu-protocol is used under its MIT option.
      LICENSE_SCOPE
    '';

    meta = {
      description = "GPL-side persistent Crucible debugger gateway";
      homepage = "https://github.com/andyl/andyl-os";
      license = "GPL-2.0-only";
      mainProgram = "crucible-debug-gateway";
    };
    passthru = {
      inherit withBuildDriver;
      buildDriver = "cargo";
    };
  };
  cargoPackage = mkCargoPackage packageArguments;
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./_debug-gateway-bazel.nix {
        inherit packageArguments;
        cargoFallback = cargoPackage;
      }
    else cargoPackage
