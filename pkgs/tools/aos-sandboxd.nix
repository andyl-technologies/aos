##! aos-sandboxd — unprivileged sandbox node controller
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  mkDerivation,
  coreutils,
  git,
  aos-git-helper,
  aos-method46-tpm-helper,
  systemd,
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
  # Publisher is the protected crate's executable, not a Services feature.
  rolePackage = role:
    if role == "publisher"
    then "aos-sandbox-publisher"
    else "aos-sandbox-services";
  roleFlags = role:
    "--no-default-features"
    + lib.optionalString (role != "publisher") " --features aos-sandbox-services/${role}"
    + lib.optionalString (role == "controller") ",aos-sandbox-controller-domain/git-helper-mechanics"
    + lib.optionalString (onlineSelected && role == "controller") ",aos-sandbox-services/online-nix";
  controllerRoleFlags = roleFlags "controller";
  roleTestFlags = role:
    roleFlags role
    + lib.optionalString (role == "publisher") " --features aos-sandbox-publisher/kernel-tests";
  roleTestPackages = role:
    "-p ${rolePackage role}"
    + lib.optionalString (role == "controller") " -p aos-sandbox-controller-domain -p aos-sandbox-broker-session-security -p aos-sandbox-controller-runtime"
    + lib.optionalString (role == "policy-key-pin") " -p aos-sandbox-policy"
    + lib.optionalString (role == "cache-signer") " -p aos-sandbox-cache-signer"
    + lib.optionalString (role == "source-signer") " -p aos-sandbox-source-signer";

  # Separate Cargo invocations prevent role features from unifying merely
  # because these independently confined executables share an output package.
  roleBuildCommands = map (role:
    "build --release --frozen --offline -j$NIX_BUILD_CORES ${roleFlags role} -p ${rolePackage role} "
    + lib.concatStringsSep " " (map (bin: "--bin ${bin}") roleBins.${role}))
  serviceRoles;
  roleTestCommands = map (role: "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${roleTestFlags role} ${roleTestPackages role}") serviceRoles;
  onlineInputs = lib.optionals onlineSelected [nixOnlineStoreReader aos-nix-runtime-tpm-helpers];
  # The installed Controller owns the same pinned Required-floor helper and
  # original PID1 image used by the production packaged CLI.
  requiredFloorInputs = lib.optionals stdenv.hostPlatform.isLinux [aos-method46-tpm-helper systemd];
  workspaceCargo = import ./aos/_workspace-cargo.nix {inherit lib aosWorkspaceVendor;};
  inherit (workspaceCargo) src cargoDeps;
  cargoEnv =
    {
      PROTOC = "${buildProtobuf}/bin/protoc";
      AOS_GIT_HELPER_SELECTION_HEADER = "${gitHelperImages}/selected-images.rs";
    }
    // lib.optionalAttrs stdenv.hostPlatform.isLinux {
      AOS_METHOD46_TPM_HELPER = "${aos-method46-tpm-helper}/libexec/aos-method46-tpm-helper";
      AOS_METHOD46_TPM_PID1 = "${systemd}/lib/systemd/systemd";
    }
    // lib.optionalAttrs onlineSelected {
      AOS_NIX_ONLINE_STORE_READER_HEADER = "${nixOnlineStoreReader}/selected-reader.rs";
      AOS_NIX_CONTROLLER_TPM_HELPER = "${aos-nix-runtime-tpm-helpers}/libexec/aos-nix-controller-tpm-helper";
      AOS_NIX_OWNER_TPM_HELPER = "${aos-nix-runtime-tpm-helpers}/libexec/aos-nix-owner-tpm-helper";
    };
  cargoArtifactContract = {
    family = "aos-sandboxd-native";
    checkType = "debug";
    nativeInputs = map toString ([buildProtobuf gitHelperImages aos-git-helper git] ++ onlineInputs ++ requiredFloorInputs);
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
    cargoBuildCommands = roleBuildCommands ++ roleTestCommands;
    buildDeps = [buildProtobuf] ++ onlineInputs ++ requiredFloorInputs;
    runtimeDeps = [aos-git-helper git] ++ onlineInputs ++ requiredFloorInputs;
  };
in
  assert !onlineSelected || aos-nix-runtime-tpm-helpers != null;
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
        ];
        target = [];
        role = "public-package";
      };
      pname = "aos-sandboxd";
      inherit version src cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
      cargoRoot = "crates";
      # Only production build artifacts enter the installed executable set.
      # Test targets are compiled by cargoArtifacts and each role's check selection.
      cargoBuildCommands = roleBuildCommands;
      cargoFlags = "${controllerRoleFlags} -p aos-sandbox-services --bin aos-sandboxd";
      checkType = "debug";
      # The Controller role and retained integration suites keep their own tests.
      cargoTestFlags = "${controllerRoleFlags} -p aos-sandbox-services -p aos-sandbox-controller-domain -p aos-sandbox-broker-session-security -p aos-sandbox-controller-runtime";
      cargoTestFlagSets =
        [
          "${controllerRoleFlags} -p aos-sandbox-services -p aos-sandbox-controller-domain -p aos-sandbox-broker-session-security -p aos-sandbox-controller-runtime"
        ]
        ++ map (role: "${roleTestFlags role} ${roleTestPackages role}")
        (lib.filter (role: role != "controller") serviceRoles);
      cargoNextest = true;
      # Protected native ancestry cases run outside the Nix build sandbox.
      cargoNextestProfile = "nix-sandbox";
      # Match the workspace native test runner; installed stack limits stay fixed.
      RUST_MIN_STACK = "33554432";
      doCheck = true;
      buildDeps = [buildProtobuf] ++ onlineInputs ++ requiredFloorInputs;
      runtimeDeps = [aos-git-helper git] ++ onlineInputs ++ requiredFloorInputs;

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
