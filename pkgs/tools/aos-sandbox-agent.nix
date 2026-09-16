##! aos-sandbox-agent — dormant independently packaged guest executable
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandbox-agent-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-+KiwQYF3bLrJwHf8X5PgT23l5+evxJdpbC935PnGNeI=";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-agent-native";
    checkType = "debug";
    nativeInputs = [];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-agent-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-agent-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-agent --bin aos-sandbox-agent"
    ];
    buildDeps = [];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-agent";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-agent --bin aos-sandbox-agent";
    doCheck = false;
    buildDeps = [];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-agent"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps;
      dormant = true;
    };

    meta = {
      description = "Dormant independently packaged AOS sandbox guest agent";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
