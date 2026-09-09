##! Shared regression entry points; these do not issue release admissions.
{
  pkgs,
  lib,
  build,
  fleet,
  container,
  packageCoverage,
  releaseExecutor,
}: let
  packageNames = pkgs.platformSupport.publicationEligibleNamesAny pkgs.allPackageNames;
  contract = import ../../qualification {
    inherit lib;
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
  imageRecovery = builtins.head (
    builtins.filter (requirement: requirement.id == "image-update-recovery") contract.requirements
  );
  k3sBindings = import ./k3s-bindings.nix {inherit pkgs;};
in
  assert builtins.elem "checks.fleet.measured-boot" imageRecovery.regressions;
  assert (resolve "checks.fleet.measured-boot").drvPath == fleet.measured-boot.drvPath;
  groups
  // {
    policy = import ./policy.nix {inherit pkgs lib packageCoverage releaseExecutor;};
    k3s-bindings = k3sBindings;
    all = aggregate "all-regressions" ([(import ./policy.nix {inherit pkgs lib packageCoverage releaseExecutor;}) k3sBindings] ++ builtins.attrValues groups);
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
