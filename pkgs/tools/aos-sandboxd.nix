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
  onlineSelected = nixOnlineStoreReader != null;
  roleBins = {
    controller = ["aos-sandboxd"];
    git = ["aos-sandbox-git-gateway"];
    entitlement = ["aos-sandbox-entitlement-sign"];
    policy = ["aos-sandbox-policy-authorityd"];
    policy-key-pin = ["aos-sandbox-policy-key-pin"];
    cache-signer = ["aos-sandbox-cache-signerd"];
    source-signer = ["aos-sandbox-source-signerd"];
    publisher = ["aos-view-publisher"];
    nix-provision = ["aos-sandbox-nix-floor-provision"];
    nix = ["aos-sandbox-nixd"];
  };
  serviceRoles =
    [
      "controller"
      "git"
      "entitlement"
      "policy"
      "policy-key-pin"
      "cache-signer"
      "source-signer"
      "publisher"
      "nix-provision"
    ]
    ++ lib.optional onlineSelected "nix";
  roleFlags = role:
    "--no-default-features --features aos-sandbox-services/${role}"
    + lib.optionalString (role == "controller") ",aos-sandbox/git-helper-mechanics"
    + lib.optionalString (onlineSelected && role == "controller") ",aos-sandbox-services/online-nix";
  controllerRoleFlags = roleFlags "controller";
  roleTestPackages = role:
    "-p aos-sandbox-services"
    + lib.optionalString (role == "policy-key-pin") " -p aos-sandbox-policy"
    + lib.optionalString (role == "cache-signer") " -p aos-sandbox-cache-signer"
    + lib.optionalString (role == "source-signer") " -p aos-sandbox-source-signer";

  # Separate Cargo invocations prevent role features from unifying merely
  # because these independently confined executables share an output package.
  roleBuildCommands = map (role:
    "build --release --frozen --offline -j$NIX_BUILD_CORES ${roleFlags role} -p aos-sandbox-services "
    + lib.concatStringsSep " " (map (bin: "--bin ${bin}") roleBins.${role}))
  serviceRoles;
  roleTestCommands = map (role: "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${roleFlags role} ${roleTestPackages role}") serviceRoles;
  coreTestCommand = "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${controllerRoleFlags} -p aos-sandbox -p aos-sandbox-broker-session-security";
  onlineInputs = lib.optionals onlineSelected [nixOnlineStoreReader aos-nix-runtime-tpm-helpers];
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib fetchCargoVendor;};
  inherit (workspaceCargo) src cargoDeps;
  cargoEnv =
    {
      PROTOC = "${buildProtobuf}/bin/protoc";
      AOS_GIT_HELPER_SELECTION_HEADER = "${gitHelperImages}/selected-images.rs";
    }
    // lib.optionalAttrs onlineSelected {
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
    cargoBuildCommands = roleBuildCommands ++ roleTestCommands ++ [coreTestCommand];
    buildDeps = [buildProtobuf gitHelperImages] ++ onlineInputs;
    runtimeDeps = [aos-git-helper git] ++ onlineInputs;
  };
in
  assert !onlineSelected || aos-nix-runtime-tpm-helpers != null;
    mkCargoPackage {
      pname = "aos-sandboxd";
      inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
      cargoRoot = "crates";
      # Only production build artifacts enter the installed executable set.
      # Test targets are compiled by cargoArtifacts and each role's check selection.
      cargoBuildCommands = roleBuildCommands;
      cargoFlags = "${controllerRoleFlags} -p aos-sandbox-services --bin aos-sandboxd";
      checkType = "debug";
      # The Controller role and retained integration suites keep their own tests.
      cargoTestFlags = "${controllerRoleFlags} -p aos-sandbox-services -p aos-sandbox -p aos-sandbox-broker-session-security";
      cargoTestFlagSets =
        [
          "${controllerRoleFlags} -p aos-sandbox-services -p aos-sandbox -p aos-sandbox-broker-session-security"
        ]
        ++ map (role: "${roleFlags role} ${roleTestPackages role}")
        (lib.filter (role: role != "controller") serviceRoles);
      cargoNextest = true;
      doCheck = true;
      buildDeps = [buildProtobuf gitHelperImages] ++ onlineInputs;
      runtimeDeps = [aos-git-helper git] ++ onlineInputs;

      postInstall =
        ''
          test -x "$out/bin/aos-sandboxd"
          test -x "$out/bin/aos-sandbox-git-gateway"
          test -x "$out/bin/aos-sandbox-entitlement-sign"
          test -x "$out/bin/aos-sandbox-policy-authorityd"
          test -x "$out/bin/aos-sandbox-cache-signerd"
          test -x "$out/bin/aos-sandbox-source-signerd"
          test -x "$out/bin/aos-sandbox-policy-key-pin"
          test -x "$out/bin/aos-view-publisher"
          test -x "$out/bin/aos-sandbox-nix-floor-provision"
        ''
        + lib.optionalString onlineSelected ''
          test -x "$out/bin/aos-sandbox-nixd"
          test -f ${nixOnlineStoreReader}/selected-reader.rs
        '';

      passthru =
        {
          inherit cargoArtifacts cargoDeps cargoEnv;
        }
        // lib.optionalAttrs onlineSelected {inherit nixOnlineStoreReader;};

      meta = {
        description = "Unprivileged AOS sandbox node controller";
        homepage = "https://github.com/andyl/andyl-os";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
