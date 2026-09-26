##! tests/containers/eval.nix — Unified system/container contract checks
{
  pkgs,
  lib,
  mkSystem,
  serverModule,
  testingModule,
  aosSystem,
}: let
  evaluate = name: modules:
    mkSystem {
      inherit modules;
      systemName = name;
    };
  evaluateServer = module:
    evaluate "container-eval" [serverModule module];
  definitionFor = module: let
    evaluated = evaluateServer module;
    checked = evaluated.config.system.build.defaultContainer.definition;
  in
    if builtins.all (check: check.assertion) evaluated.config.aos.containers.definitions.aos.assertions
    then builtins.deepSeq checked evaluated.config.aos.containers.definitions.aos
    else throw "the container definition violates its schema assertions";
  trySchemaDefinition = changes: let
    checked = lib.evalModules {
      modules = [
        ../../pkgs/containers/_aos-oci-backend/container/schema.nix
        {config = builtins.removeAttrs aos ["assertions"];}
        {config = changes;}
      ];
    };
  in
    builtins.tryEval (builtins.deepSeq (
      if builtins.all (check: check.assertion) checked.config.assertions
      then checked.config
      else throw "the container definition violates its schema assertions"
    ) true);
  trySystem = modules: let
    evaluated = evaluate "container-system-negative" modules;
  in
    builtins.tryEval (builtins.deepSeq evaluated.config.system.build.toplevel true);
  invalidSystemName = let
    evaluated = mkSystem {
      modules = [serverModule];
      systemName = "invalid.name";
    };
  in
    builtins.tryEval (builtins.deepSeq evaluated.config.system.build.toplevel true);

  server = evaluateServer {};
  userland = evaluate "userland-eval" [
    serverModule
    {aos.boot.initrd.abilityHandoff.enable = lib.mkForce false;}
  ];
  testing = evaluate "aos-testing-eval" [testingModule];
  aos = definitionFor {};
  testingAos = testing.config.aos.containers.definitions.aos;
  testingChannels = builtins.map (channel: let
    evaluated = evaluate "testing-channel-eval" [testingModule {aos.release.channel = channel;}];
  in {
    inherit channel;
    profile = evaluated.config.aos.release;
    container = evaluated.config.aos.containers.definitions.aos;
  }) ["edge" "candidate" "stable"];
  systemPackageSlice = server.config.aos.containers.systemPackageSlice;

  fixture = evaluateServer ({config, ...}: let
    targetPlatform = pkgs.stdenv.hostPlatform.constraints;
    backend = config.aos.artifacts.backend;
  in {
    aos.image.allowTestArtifacts = true;
    aos.image.testArtifactRoots = [pkgs.python3];
    aos.containers.definitions.custom =
      (backend.defaultDefinition {
        inherit lib pkgs targetPlatform;
        systemPackageSlice = config.aos.containers.systemPackageSlice;
      })
      .config
      // {
        name = "custom";
      };
  });
  fixturePolicy = fixture.config.aos.containers.definitions.aos.runtimePolicy;
  customPolicy = fixture.config.aos.containers.definitions.custom.runtimePolicy;
  fixtureAudit = fixture.config.system.build.containers.aos.checks.runtimeAudit;
  customAudit = fixture.config.system.build.containers.custom.checks.runtimeAudit;
  unmarkedTestRoots = trySchemaDefinition {
    runtimePolicy.testArtifactRoots = [pkgs.python3];
  };

  mismatchedSystem =
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then "aarch64-linux"
    else "x86_64-linux";

  mismatchedPlatform = trySchemaDefinition {
    platform.aosSystem = lib.mkForce mismatchedSystem;
  };
  duplicateLayer = trySchemaDefinition {
    layers = lib.mkForce [
      {
        name = "same";
        roots = [pkgs.aos];
      }
      {
        name = "same";
        roots = [pkgs.bash];
      }
    ];
  };
  emptyEntrypoint = trySchemaDefinition {
    runtime.entrypoint = lib.mkForce [];
  };
  duplicateRoot = trySchemaDefinition {
    packageRoots = lib.mkForce [pkgs.aos pkgs.aos];
  };
  emptyRoots = trySchemaDefinition {
    packageRoots = lib.mkForce [];
  };
  duplicateFacadeCollision = trySchemaDefinition {
    filesystem.allowedFacadeCollisions = lib.mkForce ["kill" "kill"];
  };
  hostFacade = trySchemaDefinition {
    filesystem.facade = lib.mkForce [
      {
        name = "bad";
        target = "/usr/local/bin/bad";
      }
    ];
  };
  baseImage = trySchemaDefinition {
    baseImage = "docker.io/library/debian:latest";
  };
  relativeDirectory = trySchemaDefinition {
    filesystem.directories = lib.mkForce [
      {path = "../escape";}
    ];
  };
  traversalDirectory = trySchemaDefinition {
    filesystem.directories = lib.mkForce [
      {path = "/root/../escape";}
    ];
  };
  unsafeRepository = trySchemaDefinition {
    publication.repository = lib.mkForce "Team/../aos%2flatest";
  };
  shellEntrypoint = trySchemaDefinition {
    runtime.entrypoint = lib.mkForce ["aos --help"];
  };
  imageDefaultRuntimeGrant = trySchemaDefinition {
    abilities.runtimeGrants = ["host-manager"];
  };
  overrideSource = pkgs.writeTextFile {
    name = "container-evidence-override-test-source";
    text = "source\n";
  };
  mismatchedEvidenceOverrideOutput = trySchemaDefinition {
    publication.evidenceOverrides = [
      {
        output = pkgs.aos;
        outputName = "bin";
        pname = "aos";
        inherit (pkgs.aos) version;
        licenses = ["Apache-2.0"];
        sources = [overrideSource];
      }
    ];
  };
  invalidTestingRegistry = trySystem [
    testingModule
    {aos.release.registry = lib.mkForce "andyl/main";}
  ];
  invalidTestingChannel = trySystem [
    testingModule
    {aos.release.channel = lib.mkForce "unknown";}
  ];
  invalidTestingAlias = trySystem [
    testingModule
    {aos.release.clientName = lib.mkForce "testing";}
  ];
  invalidTestingUrl = trySystem [
    testingModule
    {aos.release.url = lib.mkForce "https://aos.andyl.org/andyl/main/";}
  ];
  invalidCases = {
    inherit
      mismatchedPlatform
      duplicateLayer
      duplicateRoot
      emptyRoots
      duplicateFacadeCollision
      emptyEntrypoint
      hostFacade
      baseImage
      relativeDirectory
      traversalDirectory
      unsafeRepository
      shellEntrypoint
      imageDefaultRuntimeGrant
      mismatchedEvidenceOverrideOutput
      invalidTestingRegistry
      invalidTestingChannel
      invalidTestingAlias
      invalidTestingUrl
      invalidSystemName
      ;
  };
  acceptedInvalidCases = builtins.attrNames (lib.filterAttrs (_: result: result.success) invalidCases);
  testingFilePaths = map (file: file.path) testingAos.filesystem.files;
  testingFileText = lib.concatMapStringsSep "\n" (file: file.text) testingAos.filesystem.files;
  containerFilePaths = map (file: file.path) aos.filesystem.files;
in
  assert aos.name == "aos";
  assert !aos.runtimePolicy.allowTestArtifacts;
  assert aos.runtimePolicy.testArtifactRoots == [];
  assert fixturePolicy.allowTestArtifacts;
  assert map builtins.toString fixturePolicy.testArtifactRoots == ["${pkgs.python3}"];
  assert !customPolicy.allowTestArtifacts;
  assert customPolicy.testArtifactRoots == [];
  assert fixtureAudit.ALLOW_TEST_ARTIFACTS == "1";
  assert map builtins.toString fixtureAudit.exportReferencesGraph.testArtifacts == ["${pkgs.python3}"];
  assert customAudit.ALLOW_TEST_ARTIFACTS == "0";
  assert customAudit.exportReferencesGraph.testArtifacts == [];
  assert !unmarkedTestRoots.success;
  assert builtins.attrNames server.config.system.build.containers == ["aos"];
  assert server.config.system.build.defaultContainer.coordination.definitionAttribute
  == "systems.container-eval.build.containers.aos";
  assert map builtins.toString aos.packageRoots
  == map builtins.toString (lib.uniqueBy builtins.toString (builtins.concatMap (layer: layer.roots) aos.layers));
  assert map builtins.toString (builtins.elemAt aos.layers 1).roots
  == map builtins.toString systemPackageSlice;
  assert !(builtins.elem (builtins.toString pkgs.qemu) (map builtins.toString aos.packageRoots));
  assert !(builtins.elem (builtins.toString pkgs.linux) (map builtins.toString aos.packageRoots));
  assert aos.packageManagement
  == {
    enable = true;
    bakedGcRoots = true;
  };
  assert aos.filesystem.allowedFacadeCollisions == [];
  assert map (entry: entry.name) aos.filesystem.facade == ["aos" "apm" "apr"];
  assert map (entry: entry.target) aos.filesystem.facade
  == ["${pkgs.aos}/bin/aos" "${pkgs.aos.apm}/bin/apm" "${pkgs.aos.apr}/bin/apr"];
  assert aos.runtime.environment.PATH == "/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin";
  assert aos.runtime.environment.NIX_REMOTE == "local";
  assert !userland.config.aos.boot.initrd.abilityHandoff.enable;
  assert !(userland.config.boot.initrd.systemd.services ? aos-ability-initrd-controller);
  assert !(userland.config.systemd.services ? aos-ability-host-receiver);
  assert builtins.all
  (service: !builtins.elem "aos-ability-host-receiver.service" (service.requires or []))
  (builtins.attrValues userland.config.systemd.services);
  assert !builtins.elem
  "/etc/systemd/system/aos-ability-initrd-controller.service"
  containerFilePaths;
  assert !builtins.elem
  "/etc/systemd/system/aos-ability-host-receiver.service"
  containerFilePaths;
  assert aos.runtime.environment.XDG_DATA_HOME == "/root/.local/share";
  assert aos.runtime.workingDirectory == "/work";
  assert (builtins.head aos.filesystem.directories).path == "/root";
  assert (builtins.head aos.filesystem.directories).mode == "0700";
  assert builtins.length aos.layers == 3;
  assert aos.platform.architecture
  == (
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then "amd64"
    else "arm64"
  );
  assert aos.platform.aosSystem == aosSystem;
  assert testing.config.aos.release.registry == "andyl/testing";
  assert testing.config.aos.system.version == "2026.9.0-dev.20260917.0";
  assert lib.hasInfix "\nID=aos\n" testing.config.environment.etc."os-release".text;
  assert lib.hasInfix "\nAOS_REGISTRY=andyl/testing\n" testing.config.environment.etc."os-release".text;
  assert testing.config.system.build.defaultContainer.coordination.definitionAttribute
  == "systems.aos-testing-eval.build.containers.aos";
  assert builtins.all (entry:
    entry.profile.registry
    == "andyl/testing"
    && entry.profile.channel == entry.channel
    && entry.container.publication.referenceTag == entry.channel
    && entry.container.runtime.environment.AOS_REGISTRY == "andyl/testing")
  testingChannels;
  assert testing.config.aos.release.url == "https://cdn.aos.andyl.org/andyl/testing/";
  assert testing.config.aos.apm.registries.andyl-testing.url == "https://cdn.aos.andyl.org/andyl/testing/";
  assert lib.hasInfix "https://cdn.aos.andyl.org/andyl/testing/" testingFileText;
  assert testing.config.aos.release.channel == "edge";
  assert builtins.attrNames testing.config.aos.apm.registries == ["andyl-testing"];
  assert testingAos.publication.repository == "aos-testing";
  assert testingAos.publication.releaseIdentity == testing.config.aos.system.version;
  assert testingAos.publication.referenceTag == "edge";
  assert testingAos.runtime.environment.AOS_RELEASE_TIER == "testing";
  assert testingAos.runtime.environment.AOS_REGISTRY == "andyl/testing";
  assert testingAos.runtime.environment.AOS_CHANNEL == "edge";
  assert testing.config.aos.release.rootEpoch == 1;
  assert testing.config.system.build.defaultContainer.definition.annotations."dev.andyl.aos.registry-root-epoch"
  == "1";
  assert testing.config.system.build.defaultContainer.definition.annotations."org.opencontainers.image.title"
  == "AOS Testing";
  assert lib.hasInfix
  "not for production"
  testing.config.system.build.defaultContainer.definition.annotations."org.opencontainers.image.description";
  assert builtins.all
  (path: builtins.elem path testingFilePaths)
  [
    "/etc/aos/release-profile"
    "/etc/apm/registries.d/andyl-testing.toml"
    "/etc/apm/trusted-keys.d/andyl-testing.pub"
    "/etc/issue"
  ];
  assert lib.hasInfix "ANDYL OS TESTING" testing.config.environment.etc.issue.text;
  assert !lib.hasInfix "andyl/main" testingFileText;
  assert acceptedInvalidCases == [] || throw "invalid container fixtures accepted: ${lib.concatStringsSep ", " acceptedInvalidCases}";
    pkgs.mkDerivation {
      pname = "aos-container-evaluator-check";
      version = "1";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          '';
        }
      ];
      meta.description = "Unified AOS system and container evaluator checks";
    }
