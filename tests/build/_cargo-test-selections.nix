# Pure check-builder contract: role selections must not unify Cargo graphs.
let
  phases = import ../../stdenv/phases.nix;
  checks = arguments:
    builtins.filter (phase: phase.name == "check")
    (phases.cargoPhases ({cargoDeps = "unused";} // arguments));
  script = arguments: (builtins.head (checks arguments)).script;
  matches = expression: value: builtins.match expression value != null;
  scalar = script {cargoTestFlags = "-p first";};
  singleton = script {cargoTestFlagSets = ["-p first"];};
  selections = {
    cargoTestFlagSets = ["-p first --features controller" "-p second --features policy"];
  };
  cargo = script selections;
  nextest = script (selections // {cargoNextest = "selected-nextest";});
  invalid = value: !(builtins.tryEval (script {cargoTestFlagSets = value;})).success;

  lib = import ../../lib {system = "x86_64-linux";};
  capturePackage = arguments: arguments // {outPath = "/test/${arguments.pname}";};
  captureVendor = arguments: arguments // {outPath = "/test/${arguments.name}";};

  # Capture every actual role recipe while retaining optional input defaults.
  roleRecipes = [
    ../../pkgs/tools/aos-sandboxd.nix
    ../../pkgs/tools/aos-storaged.nix
    ../../pkgs/tools/aos-source-providerd.nix
    ../../pkgs/tools/aos-sandbox-ownershipd.nix
    ../../pkgs/tools/aos-sandbox-mountd.nix
    ../../pkgs/tools/aos-sandbox-hostd.nix
    ../../pkgs/tools/aos-sandbox-guardian.nix
    ../../pkgs/tools/aos-sandbox-agent.nix
    ../../pkgs/tools/aos-sandbox-zfs-worker.nix
    ../../pkgs/tools/aos-sandbox-runtime-publisher.nix
    ../../pkgs/tools/aos-sandbox-kernel-export-ownerd.nix
    ../../pkgs/tools/aos-netd.nix
  ];
  rolePackage = recipe: let
    packageFunction = import recipe;
    formals = builtins.functionArgs packageFunction;
    requiredNames = lib.filter (name: !formals.${name}) (builtins.attrNames formals);
    dependencies = lib.genAttrs requiredNames (name: "unused-${name}");
  in
    packageFunction (builtins.intersectAttrs formals (dependencies
      // {
        inherit lib;
        mkCargoPackage = capturePackage;
        mkCargoArtifacts = capturePackage;
        mkCargoDummySource = _: "unused-dummy-source";
        fetchCargoVendor = captureVendor;
        mkDerivation = capturePackage;
        git = capturePackage {
          pname = "git";
          version = "2.55.0";
        };
        stdenv = {
          isCross = false;
          hostPlatform = {
            isDarwin = false;
            isLinux = true;
          };
        };
        buildPackages = dependencies;
      }));
  rolePackages = map rolePackage roleRecipes;
  expectedVendorArguments = {
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    name = "aos-vendor-0.1.0";
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };
  sharedVendorRetained = package:
    builtins.removeAttrs package.cargoDeps ["outPath"]
    == expectedVendorArguments
    && package.src == expectedVendorArguments.src
    && package.cargoArtifacts.cargoDeps == package.cargoDeps
    && package.passthru.cargoDeps == package.cargoDeps;
  roleArtifactFamilies = map (package: package.cargoArtifactContract.family) rolePackages;

  controllerPackage = online:
    import ../../pkgs/tools/aos-sandboxd.nix ({
        inherit lib;
        mkCargoPackage = capturePackage;
        mkCargoArtifacts = capturePackage;
        mkCargoDummySource = _: "unused-dummy-source";
        fetchCargoVendor = _: "unused-vendor";
        mkDerivation = capturePackage;
        coreutils = "unused-coreutils";
        git = capturePackage {
          pname = "git";
          version = "2.55.0";
        };
        aos-git-helper = "unused-git-helper";
        protobuf = "unused-protobuf";
        stdenv = {
          isCross = false;
          hostPlatform.isDarwin = false;
        };
        buildPackages = {};
      }
      // lib.optionalAttrs online {
        nixOnlineStoreReader = "unused-reader";
        aos-nix-runtime-tpm-helpers = "unused-tpm-helpers";
      });

  controllerSelectionsRetained = online: let
    package = controllerPackage online;
    roles = ["controller" "git" "entitlement" "policy" "policy-key-pin" "cache-signer" "source-signer" "publisher" "nix-provision"] ++ lib.optional online "nix";
    selectedRoles = command:
      lib.filter (role: matches ".*(--features |,)aos-sandbox-services/${role}([,[:space:]].*)?" command) roles;
    independentRoles = commands:
      lib.all (command: lib.length (selectedRoles command) == 1) commands
      && lib.all (role: lib.length (lib.filter (command: builtins.elem role (selectedRoles command)) commands) == 1) roles;
    signerTestsRetained = role: packageName: commands: let
      selected = lib.filter (command: builtins.elem role (selectedRoles command)) commands;
    in
      lib.length selected
      == 1
      && lib.all (lib.hasInfix "-p ${packageName}") selected;
    artifactCommands = package.cargoArtifacts.cargoBuildCommands;
    artifactBuilds = lib.filter (lib.hasPrefix "build ") artifactCommands;
    artifactTests = lib.filter (lib.hasPrefix "test --no-run ") artifactCommands;
    policyBuilds = lib.filter (command: builtins.elem "policy" (selectedRoles command)) artifactBuilds;
    keyPinBuilds = lib.filter (command: builtins.elem "policy-key-pin" (selectedRoles command)) artifactBuilds;
    roleArtifactTests = lib.filter (lib.hasInfix "-p aos-sandbox-services") artifactTests;
    coreArtifactTests = lib.filter (lib.hasInfix "-p aos-sandbox -p aos-sandbox-broker-session-security") artifactTests;
  in
    # Logged build executables are installed: test targets must stay in the
    # artifact producer and independent check selections, never this list.
    lib.all (lib.hasPrefix "build ") package.cargoBuildCommands
    && independentRoles package.cargoBuildCommands
    && artifactBuilds == package.cargoBuildCommands
    && selectedRoles "--features aos-sandbox-services/policy,aos-sandbox-services/policy-key-pin" == ["policy" "policy-key-pin"]
    && selectedRoles "--features aos-sandbox-services/policy-key-pin,aos-sandbox-services/policy" == ["policy" "policy-key-pin"]
    && policyBuilds == ["build --release --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features aos-sandbox-services/policy -p aos-sandbox-services --bin aos-sandbox-policy-authorityd"]
    && keyPinBuilds == ["build --release --frozen --offline -j$NIX_BUILD_CORES --no-default-features --features aos-sandbox-services/policy-key-pin -p aos-sandbox-services --bin aos-sandbox-policy-key-pin"]
    && independentRoles roleArtifactTests
    && signerTestsRetained "policy-key-pin" "aos-sandbox-policy" roleArtifactTests
    && signerTestsRetained "cache-signer" "aos-sandbox-cache-signer" roleArtifactTests
    && signerTestsRetained "source-signer" "aos-sandbox-source-signer" roleArtifactTests
    && lib.length coreArtifactTests == 1
    && independentRoles package.cargoTestFlagSets
    && signerTestsRetained "policy-key-pin" "aos-sandbox-policy" package.cargoTestFlagSets
    && signerTestsRetained "cache-signer" "aos-sandbox-cache-signer" package.cargoTestFlagSets
    && signerTestsRetained "source-signer" "aos-sandbox-source-signer" package.cargoTestFlagSets
    && lib.any (lib.hasInfix "-p aos-sandbox-services -p aos-sandbox -p aos-sandbox-broker-session-security") package.cargoTestFlagSets
    && package.doCheck
    && package.cargoNextest;

  # Capture the actual package arguments without building their dependencies.
  aosPackage = darwin: let
    packageFunction = import ../../pkgs/tools/aos/aos.nix;
    dependencies = lib.genAttrs (builtins.attrNames (builtins.functionArgs packageFunction)) (
      name: "unused-${name}"
    );
  in
    packageFunction (dependencies // {
      inherit lib;
      mkCargoPackage = capturePackage;
      mkCargoArtifacts = capturePackage;
      mkCargoDummySource = _: "unused-dummy-source";
      fetchCargoVendor = _: "unused-vendor";
      mkDerivation =
        if darwin
        then _: throw "Darwin test environment must not construct a Linux launcher"
        else capturePackage;
      stdenv = {
        isCross = darwin;
        hostPlatform = {
          isDarwin = darwin;
          isLinux = !darwin;
        };
      };
      buildPackages = dependencies;
    });
  networkPackage = import ../../pkgs/tools/aos-netd.nix {
    inherit lib;
    mkCargoPackage = capturePackage;
    mkCargoArtifacts = capturePackage;
    mkCargoDummySource = _: "unused-dummy-source";
    fetchCargoVendor = _: "unused-vendor";
    mkDerivation = capturePackage;
    protobuf = "unused-protobuf";
    stdenv = {
      isCross = false;
      hostPlatform = {
        isDarwin = false;
        isLinux = true;
      };
    };
    buildPackages = {};
  };
  launcher = import ../../pkgs/tools/aos/_network-test-launcher.nix {
    mkDerivation = capturePackage;
    version = "0.1.0";
  };
  launcherPath = "${launcher}/bin/no-setid-exec";
  launcherEnvironmentRetained = environment: let
    configure = builtins.head (builtins.filter (phase: phase.name == "configure") (
      phases.cargoPhases {
        cargoDeps = "unused";
        cargoEnv = environment;
      }
    ));
  in
    (environment.AOS_NO_SETID_TEST_LAUNCHER or null) == launcherPath
    && lib.hasInfix "export AOS_NO_SETID_TEST_LAUNCHER='${launcherPath}'" configure.script;
  nativeAos = aosPackage false;
  darwinAos = aosPackage true;
  nativeLauncherEnvironments = [
    nativeAos.cargoEnv
    nativeAos.cargoArtifacts.cargoEnv
    nativeAos.passthru.testTargets.cargoEnv
    networkPackage.cargoEnv
    networkPackage.cargoArtifacts.cargoEnv
  ];
  darwinEnvironments = [
    darwinAos.cargoEnv
    darwinAos.cargoArtifacts.cargoEnv
    darwinAos.passthru.testTargets.cargoEnv
  ];
in
  assert scalar == singleton;
  assert matches ".*AOS_CROSS_COMPILING.*" cargo;
  assert matches ".*cargo test.*-p first --features controller.*cargo test.*-p second --features policy.*" cargo;
  assert matches ".*cargo nextest run.*-p first --features controller.*cargo nextest run.*-p second --features policy.*" nextest;
  assert matches ".*--cargo-profile release.*" nextest;
  assert checks {
    doCheck = false;
    cargoTestFlagSets = [""];
  }
  == [];
  assert invalid [""];
  assert invalid [" \t\n"];
  assert invalid [1];
  assert invalid "not-a-list";
  assert lib.length rolePackages == 12;
  assert lib.all sharedVendorRetained rolePackages;
  assert lib.length (lib.unique roleArtifactFamilies) == 12;
  assert controllerSelectionsRetained false;
  assert controllerSelectionsRetained true;
  assert launcher.src == ../../crates/aos-sandbox-network/tests/no_setid_exec.c;
  assert launcher.buildDeps == [] && launcher.runtimeDeps == [];
  assert lib.hasInfix ''$CC -O2 -Wall -Wextra -Werror "$src" -o no-setid-exec'' (builtins.head launcher.phases).script;
  assert lib.all launcherEnvironmentRetained nativeLauncherEnvironments;
  assert lib.any (lib.hasInfix "-p aos-sandbox-network") nativeAos.passthru.testTargets.cargoBuildCommands;
  assert lib.any (lib.hasInfix "-p aos-sandbox-cache-signer") nativeAos.passthru.testTargets.cargoBuildCommands;
  assert lib.any (lib.hasInfix "-p aos-sandbox-guest-root-tree") nativeAos.passthru.testTargets.cargoBuildCommands;
  assert lib.any (lib.hasInfix "-p aos-sandbox-source-signer") nativeAos.passthru.testTargets.cargoBuildCommands;
  assert lib.any (lib.hasInfix "-p aos-sandbox-policy") nativeAos.passthru.testTargets.cargoBuildCommands;
  assert lib.any (lib.hasInfix "-p aos-sandbox-network") networkPackage.cargoArtifacts.cargoBuildCommands;
  assert lib.hasInfix "-p aos-sandbox-network" networkPackage.cargoTestFlags;
  assert lib.all (environment: !(environment ? AOS_NO_SETID_TEST_LAUNCHER)) darwinEnvironments; true
