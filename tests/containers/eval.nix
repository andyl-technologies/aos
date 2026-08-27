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

  aos = evaluate "aos" [(definitionFor aosSystem)];
  arm = evaluate "aos" [(definitionFor "aarch64-linux")];
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
  assert builtins.length aos.layers == 4;
  assert aos.platform.architecture
  == (
    if aosSystem == "x86_64-linux"
    then "amd64"
    else "arm64"
  );
  assert arm.platform.architecture == "arm64";
  assert arm.platform.aosSystem == "aarch64-linux";
  assert !duplicateLayer.success;
  assert !duplicateRoot.success;
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
