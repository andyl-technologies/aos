##! Owns typed immutable BPF policy selection and its native lifecycle.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.security.ebpfNetworkPolicy;
  policiesType = lib.types.listOf (lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Unique policy identity used to own BPF pins.";
      };
      policy = lib.mkOption {
        type = lib.types.str;
        description = "Immutable policy document path in the selected package closure.";
      };
      object = lib.mkOption {
        type = lib.types.str;
        description = "Immutable BPF object path in the selected package closure.";
      };
      cgroup = lib.mkOption {
        type = lib.types.str;
        description = "Target path beneath the unified cgroup hierarchy.";
      };
    };
  });
in {
  options.aos.security.ebpfNetworkPolicy = {
    enable = lib.mkEnableOption "the selected BPF policy set";
    policies = lib.mkOption {
      type = policiesType;
      default = [];
      description = "Policies realized together by the package-owned loader.";
    };
  };

  config.aos.abilities.ebpfNetworkPolicy.operations.ensure = {
    input.options.policies = lib.mkOption {
      type = policiesType;
      description = "Exact immutable policy set to establish and retain.";
    };
    result.options.loaded = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Policy names whose expected BPF pins are present.";
    };
    handler.program = package // {mainProgram = "aos-ebpf-net-policy-provider";};
    effects.host = lib.mkIf (cfg.enable && cfg.policies != []) {
      input.policies = lib.sort (left: right: left.name < right.name) cfg.policies;
    };
  };
}
