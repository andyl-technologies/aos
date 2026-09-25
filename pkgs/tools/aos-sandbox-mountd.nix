##! aos-sandbox-mountd — descriptor-only sandbox mount broker and helper
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  protobuf,
  elfutils,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildProtobuf =
    if isDarwinCross
    then buildPackages.protobuf
    else protobuf;
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandbox-mountd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-ogfEFgD8LdDL/ipEtk1pzIhxERPssTSliQcN5yXt/YY=";
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    # Startup capture requires a GNU build ID in the exact running executable.
    RUSTFLAGS = "-C link-arg=-Wl,--build-id=sha1";
  };
  cargoArtifactContract = {
    family = "aos-sandbox-mountd-native";
    checkType = "debug";
    nativeInputs = map toString [buildProtobuf];
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandbox-mountd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandbox-mountd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-sandbox-mountd"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount --bin aos-sandbox-mount-helper"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount"
    ];
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
  };
in
  mkCargoPackage {
    pname = "aos-sandbox-mountd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-broker-session-security --bin aos-sandbox-mountd"
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount --bin aos-sandbox-mount-helper"
    ];
    cargoTestFlags = "-p aos-sandbox-mount";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf elfutils];
    runtimeDeps = [];

    postInstall = ''
      test -x "$out/bin/aos-sandbox-mountd"
      test -x "$out/bin/aos-sandbox-mount-helper"
      notes=$(${elfutils}/bin/eu-readelf --notes "$out/bin/aos-sandbox-mountd")
      printf '%s\n' "$notes" | grep -Fq 'GNU_BUILD_ID'
      printf '%s\n' "$notes" | grep -Eq 'Build ID: [0-9a-f]{40}$'
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    meta = {
      description = "Descriptor-only sandbox mount broker and namespace helper";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
