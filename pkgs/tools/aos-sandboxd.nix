##! aos-sandboxd — unprivileged sandbox node controller
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  mkDerivation,
  coreutils,
  git,
  aos-git-helper,
  protobuf,
  stdenv,
  buildPackages,
  nixOnlineStoreReader ? null,
  aos-nix-runtime-tpm-helpers ? null,
}: let
  version = "0.1.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildProtobuf =
    if isDarwinCross
    then buildPackages.protobuf
    else protobuf;
  buildCoreutils =
    if stdenv.isCross
    then buildPackages.coreutils
    else coreutils;
  gitHelperImages = import ./_aos-git-helper-images.nix {
    inherit mkDerivation git aos-git-helper;
    coreutils = buildCoreutils;
  };
  mechanicsFeature = "--features aos-sandbox/git-helper-mechanics";
  onlineSelected = nixOnlineStoreReader != null;
  onlineFeature = lib.optionalString onlineSelected ",aos-sandbox-broker-session-security/online-nix";
  selectedFeatures = mechanicsFeature + onlineFeature;
  onlineBin = lib.optionalString onlineSelected " --bin aos-sandbox-nixd";
  onlineInputs = lib.optionals onlineSelected [nixOnlineStoreReader aos-nix-runtime-tpm-helpers];
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-sandboxd-vendor-${version}";
    sourceRoot = "source/crates";
    hash = import ./crucible/_cargo-deps-hash.nix;
  };
  cargoEnv = {
    PROTOC = "${buildProtobuf}/bin/protoc";
    AOS_GIT_HELPER_SELECTION_HEADER = "${gitHelperImages}/selected-images.rs";
  } // lib.optionalAttrs onlineSelected {
    AOS_NIX_ONLINE_STORE_READER_HEADER = "${nixOnlineStoreReader}/selected-reader.rs";
    AOS_NIX_CONTROLLER_TPM_HELPER = "${aos-nix-runtime-tpm-helpers}/libexec/aos-nix-controller-tpm-helper";
    AOS_NIX_OWNER_TPM_HELPER = "${aos-nix-runtime-tpm-helpers}/libexec/aos-nix-owner-tpm-helper";
  };
  cargoArtifactContract = {
    family = "aos-sandboxd-native";
    checkType = "debug";
    nativeInputs = map toString ([buildProtobuf gitHelperImages aos-git-helper git] ++ onlineInputs);
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-sandboxd-artifacts";
    inherit version cargoDeps cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-sandboxd-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES ${selectedFeatures} -p aos-sandbox-broker-session-security --bin aos-sandboxd --bin aos-sandbox-git-gateway --bin aos-sandbox-entitlement-sign --bin aos-sandbox-policy-authorityd --bin aos-sandbox-cache-signerd --bin aos-sandbox-source-signerd --bin aos-sandbox-policy-key-pin --bin aos-view-publisher --bin aos-sandbox-nix-floor-provision${onlineBin}"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${selectedFeatures} -p aos-sandbox -p aos-sandbox-broker-session-security"
    ];
    buildDeps = [buildProtobuf gitHelperImages] ++ onlineInputs;
    runtimeDeps = [aos-git-helper git] ++ onlineInputs;
  };
in
  assert !onlineSelected || aos-nix-runtime-tpm-helpers != null;
  mkCargoPackage {
    pname = "aos-sandboxd";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoFlags = "${selectedFeatures} -p aos-sandbox-broker-session-security --bin aos-sandboxd --bin aos-sandbox-git-gateway --bin aos-sandbox-entitlement-sign --bin aos-sandbox-policy-authorityd --bin aos-sandbox-cache-signerd --bin aos-sandbox-source-signerd --bin aos-sandbox-policy-key-pin --bin aos-view-publisher --bin aos-sandbox-nix-floor-provision${onlineBin}";
    checkType = "debug";
    # Keep the core suite when moving process ownership into the transport crate.
    cargoTestFlags = "${selectedFeatures} -p aos-sandbox -p aos-sandbox-broker-session-security";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [buildProtobuf gitHelperImages] ++ onlineInputs;
    runtimeDeps = [aos-git-helper git] ++ onlineInputs;

    postInstall = ''
      test -x "$out/bin/aos-sandboxd"
      test -x "$out/bin/aos-sandbox-git-gateway"
      test -x "$out/bin/aos-sandbox-entitlement-sign"
      test -x "$out/bin/aos-sandbox-policy-authorityd"
      test -x "$out/bin/aos-sandbox-cache-signerd"
      test -x "$out/bin/aos-sandbox-source-signerd"
      test -x "$out/bin/aos-sandbox-policy-key-pin"
      test -x "$out/bin/aos-view-publisher"
      test -x "$out/bin/aos-sandbox-nix-floor-provision"
    '' + lib.optionalString onlineSelected ''
      test -x "$out/bin/aos-sandbox-nixd"
      test -f ${nixOnlineStoreReader}/selected-reader.rs
    '';

    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    } // lib.optionalAttrs onlineSelected {inherit nixOnlineStoreReader;};

    meta = {
      description = "Unprivileged AOS sandbox node controller";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
