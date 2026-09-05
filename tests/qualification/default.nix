##! Shared regression entry points; these do not issue release admissions.
{
  pkgs,
  lib,
  build,
  fleet,
  container,
}: let
  contract = import ../../qualification {packageNames = pkgs.allPackageNames;};
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
in
  groups
  // {
    policy = import ./policy.nix {inherit pkgs;};
    all = aggregate "all-regressions" ([(import ./policy.nix {inherit pkgs;})] ++ builtins.attrValues groups);
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
