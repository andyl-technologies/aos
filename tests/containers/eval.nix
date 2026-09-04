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
    builtins.deepSeq checked evaluated.config.aos.containers.definitions.aos;
  tryDefinition = module:
    builtins.tryEval (builtins.deepSeq (definitionFor module) true);
  trySystem = modules: let
    evaluated = evaluate "container-system-negative" modules;
  in
    builtins.tryEval (builtins.deepSeq evaluated.config.system.build.toplevel true);

  server = evaluateServer {};
  testing = evaluate "aos-testing-eval" [testingModule];
  aos = definitionFor {};
  testingAos = testing.config.aos.containers.definitions.aos;
  goldenRoots = server.config.environment.systemPackages;
  mismatchedSystem =
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then "aarch64-linux"
    else "x86_64-linux";

  mismatchedPlatform = tryDefinition {
    aos.containers.definitions.aos.platform.aosSystem = lib.mkForce mismatchedSystem;
  };
  duplicateLayer = tryDefinition {
    aos.containers.definitions.aos.layers = lib.mkForce [
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
  emptyEntrypoint = tryDefinition {
    aos.containers.definitions.aos.runtime.entrypoint = lib.mkForce [];
  };
  duplicateRoot = tryDefinition {
    aos.containers.definitions.aos.packageRoots = lib.mkForce [pkgs.aos pkgs.aos];
  };
  emptyRoots = tryDefinition {
    aos.containers.definitions.aos.packageRoots = lib.mkForce [];
  };
  duplicateFacadeCollision = tryDefinition {
    aos.containers.definitions.aos.filesystem.allowedFacadeCollisions = lib.mkForce ["kill" "kill"];
  };
  hostFacade = tryDefinition {
    aos.containers.definitions.aos.filesystem.facade = lib.mkForce [
      {
        name = "bad";
        target = "/usr/local/bin/bad";
      }
    ];
  };
  baseImage = tryDefinition {
    aos.containers.definitions.aos.baseImage = "docker.io/library/debian:latest";
  };
  relativeDirectory = tryDefinition {
    aos.containers.definitions.aos.filesystem.directories = lib.mkForce [
      {path = "../escape";}
    ];
  };
  traversalDirectory = tryDefinition {
    aos.containers.definitions.aos.filesystem.directories = lib.mkForce [
      {path = "/root/../escape";}
    ];
  };
  unsafeRepository = tryDefinition {
    aos.containers.definitions.aos.publication.repository = lib.mkForce "Team/../aos%2flatest";
  };
  shellEntrypoint = tryDefinition {
    aos.containers.definitions.aos.runtime.entrypoint = lib.mkForce ["aos --help"];
  };
  overrideSource = pkgs.writeTextFile {
    name = "container-evidence-override-test-source";
    text = "source\n";
  };
  mismatchedEvidenceOverrideOutput = tryDefinition {
    aos.containers.definitions.aos.publication.evidenceOverrides = [
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
    {aos.release.channel = lib.mkForce "stable";}
  ];
  testingFilePaths = map (file: file.path) testingAos.filesystem.files;
  testingFileText = lib.concatMapStringsSep "\n" (file: file.text) testingAos.filesystem.files;
in
  assert aos.name == "aos";
  assert builtins.attrNames server.config.system.build.containers == ["aos"];
  assert map builtins.toString aos.packageRoots
  == map builtins.toString (lib.unique (goldenRoots ++ [pkgs.aos pkgs.aos.apm pkgs.aos.apr]));
  assert aos.packageManagement
  == {
    enable = true;
    bakedGcRoots = true;
  };
  assert aos.filesystem.allowedFacadeCollisions == ["kill"];
  assert map (entry: entry.name) aos.filesystem.facade == ["aos" "apm" "apr"];
  assert map (entry: entry.target) aos.filesystem.facade
  == ["${pkgs.aos}/bin/aos" "${pkgs.aos.apm}/bin/apm" "${pkgs.aos.apr}/bin/apr"];
  assert aos.runtime.environment.PATH == "/var/lib/profiles/per-user/root/current/bin:/var/lib/profiles/per-user/root/current/sbin:/usr/bin:/usr/sbin:/bin";
  assert aos.runtime.environment.NIX_REMOTE == "local";
  assert aos.runtime.environment.XDG_DATA_HOME == "/root/.local/share";
  assert aos.runtime.workingDirectory == "/work";
  assert (builtins.head aos.filesystem.directories).path == "/root";
  assert (builtins.head aos.filesystem.directories).mode == "0700";
  assert builtins.length aos.layers == 4;
  assert aos.platform.architecture
  == (
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then "amd64"
    else "arm64"
  );
  assert aos.platform.aosSystem == aosSystem;
  assert testing.config.aos.release.registry == "andyl/testing";
  assert testing.config.aos.release.channel == "edge";
  assert builtins.attrNames testing.config.aos.apm.registries == ["andyl-testing"];
  assert testingAos.publication.repository == "aos-testing";
  assert testingAos.publication.referenceTag == "edge";
  assert testingAos.runtime.environment.AOS_RELEASE_TIER == "testing";
  assert testingAos.runtime.environment.AOS_REGISTRY == "andyl/testing";
  assert testingAos.runtime.environment.AOS_CHANNEL == "edge";
  assert testing.config.aos.release.rootEpoch == 1;
  assert
    testing.config.system.build.defaultContainer.definition.annotations."dev.andyl.aos.registry-root-epoch"
    == "1";
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
  assert !mismatchedPlatform.success;
  assert !duplicateLayer.success;
  assert !duplicateRoot.success;
  assert !emptyRoots.success;
  assert !duplicateFacadeCollision.success;
  assert !emptyEntrypoint.success;
  assert !hostFacade.success;
  assert !baseImage.success;
  assert !relativeDirectory.success;
  assert !traversalDirectory.success;
  assert !unsafeRepository.success;
  assert !shellEntrypoint.success;
  assert !mismatchedEvidenceOverrideOutput.success;
  assert !invalidTestingRegistry.success;
  assert !invalidTestingChannel.success;
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
