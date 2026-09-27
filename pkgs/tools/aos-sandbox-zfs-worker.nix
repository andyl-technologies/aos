##! aos-sandbox-zfs-worker — typed cgroup-contained OpenZFS executor
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  protobuf,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  buildProtobuf =
    if stdenv.isCross
    then buildPackages.protobuf
    else protobuf;
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandbox-zfs-worker-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-r3jzI/1SdhuuLOtide3L/cwdFBQFmFj0JPOmqDvBMVY=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-zfs-worker-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-zfs-worker-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-zfs-worker-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-zfs-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-workspace-pin-worker"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-workspace-pin-observer"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-workspace-root-initializer"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-guest-root-publisher"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --bin aos-sandbox-held-snapshot-reader"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };

  # The physical tree probe is a separate test root. Production builds never
  # enable its feature or install its privilege-bearing snapshot CLI.
  heldTreeFixtureContract = {
    family = "aos-sandbox-held-tree-fixture-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  heldTreeFixtureArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-held-tree-fixture-artifacts";
    inherit version cargoDeps cargoEnv;
    cargoArtifactContract = heldTreeFixtureContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-held-tree-fixture-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-storage --features held-tree-fixture --bin aos-sandbox-held-tree-fixture"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
  heldTreeFixture = mkCargoPackage {
    pname = "aos-sandbox-held-tree-fixture";
    inherit version src cargoDeps cargoEnv;
    cargoArtifacts = heldTreeFixtureArtifacts;
    cargoArtifactContract = heldTreeFixtureContract;
    cargoRoot = "crates";
    checkType = "debug";
    cargoFlags = "-p aos-sandbox-storage --features held-tree-fixture --bin aos-sandbox-held-tree-fixture";
    doCheck = false;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
    postInstall = ''
      test -x "$out/bin/aos-sandbox-held-tree-fixture"
      test ! -e "$out/bin/aos-sandbox-zfs-worker"
    '';
    meta = {
      description = "VM-only held ZFS snapshot tree measurement probe";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-zfs-worker";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    checkType = "debug";
    cargoFlags = "-p aos-sandbox-storage";
    cargoTestFlags = "-p aos-sandbox-storage";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-zfs-worker"
      test -x "$out/bin/aos-sandbox-workspace-pin-worker"
      test -x "$out/bin/aos-sandbox-workspace-pin-observer"
      test -x "$out/bin/aos-sandbox-workspace-root-initializer"
      test -x "$out/bin/aos-sandbox-guest-root-publisher"
      test -x "$out/bin/aos-sandbox-held-snapshot-reader"
      test ! -e "$out/bin/aos-sandbox-held-tree-fixture"
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv heldTreeFixture;
    };

    meta = {
      description = "Typed cgroup-contained OpenZFS transaction worker";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
