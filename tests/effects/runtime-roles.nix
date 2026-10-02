##! Authored server and edge roles replayed through actual retained packages.
{
  pkgs,
  lib,
}: let
  policy = pkgs.aos-host-policy;
  packages = [
    policy
    pkgs.systemd
    pkgs.chrony
    pkgs.openssh
    pkgs.audit
    pkgs.nftables
    pkgs.aos-network-ruleset-provider
    pkgs.aos-ebpf-lsm-policy
  ];
  evaluate = role: operator:
    lib.evalPackageModules {
      inherit packages;
      scope = ["test" "runtime-role" role];
      operatorModules = [
        "${policy.module}/baseline/${role}.nix"
        operator
      ];
    };
  edge = evaluate "edge" {aos.roles.edge.enable = true;};
  server = evaluate "server" {aos.roles.server.enable = true;};
  baseline = evaluate "edge" {};
  identityEvaluation = lib.evalModules {
    inherit lib pkgs;
    specialArgs = {
      inherit pkgs;
      packageModulesAvailable = true;
    };
    modules = [
      ../../modules/base/system.nix
      {
        config._module.strict = false;
        options.environment.etc = lib.mkOption {
          type = lib.types.attrs;
          default = {};
        };
        options.aos.release.enabled = lib.mkOption {
          type = lib.types.bool;
          default = false;
        };
        config.aos.release.enabled = false;
      }
    ];
  };
  generatedIdentity = identityEvaluation.config.environment.etc."os-release".text;
  override = evaluate "edge" {
    aos.roles.edge.enable = true;
    aos.services.ssh.enable = false;
    aos.kernel.sysctl."vm.swappiness" = "25";
  };
  effects = evaluation: ability: operation:
    builtins.filter (node: builtins.elem ability node.identity && builtins.elem operation node.identity) (builtins.attrValues evaluation.config.aos.activation.graph.nodes);
  hasManager = evaluation: name:
    builtins.any (node:
      (
        if node.input.manager_identity == null
        then node.input.service
        else node.input.manager_identity.name
      )
      == name) (effects evaluation "serviceManagement" "realize");
in {
  generatedIdentityUsesRetainedNativeLibrary = builtins.elem "AOS_PACKAGE_MODULE_LIBRARY=${lib.packageModuleLibrary}" (lib.splitString "\n" generatedIdentity) && !lib.hasInfix "AOS_MODULE_ABI=" generatedIdentity;
  baselineServicesRemainOptional = !baseline.config.aos.services.chrony.enable && !baseline.config.aos.services.ssh.enable;
  edgeRoleEnablesOriginalServices = edge.config.aos.services.chrony.enable && edge.config.aos.services.ssh.enable && hasManager edge "chronyd" && hasManager edge "sshd";
  edgeRoleConvergesConservativeTunables = edge.config.aos.kernel.sysctl."vm.swappiness" == "10" && edge.config.aos.kernel.sysctl."vm.vfs_cache_pressure" == "200" && builtins.length (effects edge "kernelTunables" "ensure") == 1;
  selectedSecurityPresetIsEffective = edge.config.aos.security.level == "standard" && edge.config.aos.security.audit.enable && edge.config.aos.networkPolicy.enable && edge.config.aos.security.hardening.enable && !edge.config.aos.security.hardening.coreDump.enable;
  serverRetainsExactRegistryIdentity = server.config.aos.abilities.identity.operations.group.effects.server-registry.input.requested_id == 800 && server.config.aos.abilities.identity.operations.principal.effects.server-registry.input.requested_id == 800 && server.config.aos.abilities.identity.operations.principal.effects.server-registry.input.primary_group.output == "name";
  operatorCanOverrideRoleDefaults = !override.config.aos.services.ssh.enable && !hasManager override "sshd" && override.config.aos.kernel.sysctl."vm.swappiness" == "25";
}
