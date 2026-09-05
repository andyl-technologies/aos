##! Classifies the complete package inventory and owns its functional gates.
{
  config,
  lib,
  packageNames,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};
in {
  options.qualification = {
    packageRules = lib.mkOption {
      type = lib.types.attrsOf types.packageRule;
      default = {};
      description = "Roles for every discovered package.";
    };
    integrityPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = ["aos" "bash" "coreutils" "systemd" "linux" "nix" "openssl" "openssh" "chrony" "e2fsprogs" "cryptsetup" "tpm2-tools"];
      description = "Roots whose dependencies inherit system-integrity obligations.";
    };
    workloadPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = ["nginx" "containerd" "runc"];
      description = "Roots requiring the full declared workload lifecycle.";
    };
  };
  config.qualification = {
    requirements = {
      package-function = {
        checks = ["anonymous-download" "closure-verification" "functional-behavior" "dependency-obligations" "permissions-and-confinement"];
        invalidated_by = ["subject" "policy" "executor" "environment"];
        method = "automated";
        phase = "staging";
        production_only = false;
        regressions = ["checks.fleet.apm-e2e"];
        scope = "packages";
      };
    };
    packageRules = builtins.listToAttrs (map (name: {
        inherit name;
        value.role = lib.mkDefault (
          if builtins.elem name cfg.integrityPackages
          then "system-integrity"
          else if builtins.elem name cfg.workloadPackages
          then "qualified-workload"
          else "general-catalog"
        );
      })
      packageNames);
    assertions = [
      {
        assertion =
          builtins.attrNames cfg.packageRules
          == builtins.sort builtins.lessThan packageNames
          && builtins.all (rule: rule.inherit_dependency_obligations) (builtins.attrValues cfg.packageRules);
        message = "Package roles must cover the inventory and inherit dependency obligations.";
      }
    ];
  };
}
