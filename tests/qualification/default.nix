##! Shared regression entry points; these do not issue release admissions.
{
  pkgs,
  lib,
  build,
  fleet,
  container,
  releaseQualificationScenarios,
  releaseQualificationCaseScenarios,
  nativeAdapterMatrix,
}: let
  packageNames = pkgs.platformSupport.publicationEligibleNamesAny pkgs.allPackageNames;
  contract = import ../../qualification {
    inherit lib nativeAdapterMatrix;
    inherit packageNames;
  };
  available = {checks = {inherit build fleet container;};};
  resolve = path:
    builtins.foldl' (attrs: key: attrs.${key}) available (lib.splitString "." path);
  aggregate = name: checks:
    pkgs.mkDerivation {
      pname = "aos-qualification-${name}";
      version = "1";
      src = null;
      buildDeps = checks;
      phases = [
        {
          name = "record";
          script = ''
            mkdir -p "$out"
            printf '%s\n' 'Regression suite passed; fresh release observations are still required.' > "$out/result"
          '';
        }
      ];
    };
  groups = builtins.listToAttrs (map (requirement: {
    name = requirement.id;
    value = aggregate requirement.id (map resolve requirement.regressions);
  }) (builtins.filter (requirement: requirement.regressions != []) contract.requirements));
  policy = import ./policy.nix {inherit pkgs lib nativeAdapterMatrix;};
  executorWiring = import ./executor-wiring.nix {
    inherit pkgs lib contract fleet releaseQualificationScenarios releaseQualificationCaseScenarios;
  };
  nativeAdapterMatrixArtifact = pkgs.writeTextFile {
    name = "aos-qualification-native-adapter-matrix";
    destination = "/matrix-spec.json";
    text = nativeAdapterMatrix.canonical_json;
  };
  k3sBindings = import ./k3s-bindings.nix {inherit pkgs;};
in
  groups
  // {
    inherit policy;
    executor-wiring = executorWiring;
    native-adapter-matrix = nativeAdapterMatrixArtifact;
    k3s-bindings = k3sBindings;
    toolchain-hermeticity = aggregate "toolchain-hermeticity" [build.toolchain-boundaries.all build.native-sandbox-boundary];
    all = aggregate "all-regressions" ([policy executorWiring k3sBindings build.toolchain-boundaries.all build.native-sandbox-boundary] ++ builtins.attrValues groups);
    # Evaluating this inventory resolves every reference, including sparse
    # groups, before an expensive VM campaign starts.
    inventory = builtins.listToAttrs (map (requirement: {
        name = requirement.id;
        value =
          map (path: {
            inherit path;
            derivation = (resolve path).drvPath;
          })
          requirement.regressions;
      })
      contract.requirements);
  }
