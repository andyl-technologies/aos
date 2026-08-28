##! tests/containers/eval.nix — Closed container-evaluator contract checks
{
  pkgs,
  lib,
  goldenRoots,
  aosSystem,
}: let
  evaluator = import ../../lib/containers {inherit lib pkgs;};
  registered = import ../../containers {
    inherit lib pkgs goldenRoots aosSystem;
  };
  definitionFor = aosSystem:
    import ../../containers/aos.nix {
      inherit lib pkgs goldenRoots aosSystem;
    };
  evaluate = name: modules:
    evaluator.evalContainer {inherit name modules;};
  tryEvaluate = modules:
    builtins.tryEval (builtins.deepSeq (evaluate "negative" modules) true);
  mismatchedSystem =
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then "aarch64-linux"
    else "x86_64-linux";

  aos = evaluate "aos" [(definitionFor aosSystem)];
  mismatchedPlatform = tryEvaluate [(definitionFor mismatchedSystem)];
  duplicateLayer = tryEvaluate [
    (definitionFor aosSystem)
    {
      config.layers = lib.mkForce [
        {
          name = "same";
          roots = [pkgs.aos];
        }
        {
          name = "same";
          roots = [pkgs.bash];
        }
      ];
    }
  ];
  emptyEntrypoint = tryEvaluate [
    (definitionFor aosSystem)
    {config.runtime.entrypoint = lib.mkForce [];}
  ];
  duplicateRoot = tryEvaluate [
    (definitionFor aosSystem)
    {config.packageRoots = lib.mkForce [pkgs.aos pkgs.aos];}
  ];
  emptyRoots = tryEvaluate [
    (definitionFor aosSystem)
    {config.packageRoots = lib.mkForce [];}
  ];
  duplicateFacadeCollision = tryEvaluate [
    (definitionFor aosSystem)
    {config.filesystem.allowedFacadeCollisions = lib.mkForce ["kill" "kill"];}
  ];
  hostFacade = tryEvaluate [
    (definitionFor aosSystem)
    {
      config.filesystem.facade = lib.mkForce [
        {
          name = "bad";
          target = "/usr/local/bin/bad";
        }
      ];
    }
  ];
  baseImage = tryEvaluate [
    (definitionFor aosSystem)
    {config.baseImage = "docker.io/library/debian:latest";}
  ];
  relativeDirectory = tryEvaluate [
    (definitionFor aosSystem)
    {
      config.filesystem.directories = lib.mkForce [
        {path = "../escape";}
      ];
    }
  ];
  traversalDirectory = tryEvaluate [
    (definitionFor aosSystem)
    {
      config.filesystem.directories = lib.mkForce [
        {path = "/root/../escape";}
      ];
    }
  ];
  unsafeRepository = tryEvaluate [
    (definitionFor aosSystem)
    {config.publication.repository = "Team/../aos%2flatest";}
  ];
  shellEntrypoint = tryEvaluate [
    (definitionFor aosSystem)
    {config.runtime.entrypoint = lib.mkForce ["aos --help"];}
  ];
in
  assert aos.name == "aos";
  assert builtins.attrNames registered == ["aos"];
  assert aos.packageRoots == goldenRoots;
  assert aos.packageManagement
  == {
    enable = true;
    bakedGcRoots = true;
  };
  assert aos.filesystem.allowedFacadeCollisions == ["kill"];
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
  assert aos.platform.aosSystem == pkgs.stdenv.hostPlatform.system;
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
      meta.description = "Closed separate evaluator checks for AOS containers";
    }
