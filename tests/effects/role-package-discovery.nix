##! Keeps package discovery typed while admitting role workloads only after resolution.
{
  lib,
  pkgs,
}: let
  policy = pkgs.aos-host-policy;
  baselinePackages = [policy pkgs.aos-ebpf-lsm-policy pkgs.systemd pkgs.audit pkgs.nftables pkgs.aos-network-ruleset-provider];
  configuration = {
    aos.roles.server.enable = true;
    # This package-owned option is unavailable until OpenSSH is acquired.
    aos.services.ssh.port = 2222;
  };
  evaluate = packages: checkDefinitions: operator:
    lib.evalPackageModules {
      inherit packages checkDefinitions;
      scope = ["test" "role-package-discovery"];
      operatorModules = [
        "${policy.module}/baseline/server.nix"
        operator
      ];
    };
  discovery = evaluate baselinePackages false configuration;
  incomplete = evaluate baselinePackages true configuration;
  resolved = evaluate (baselinePackages ++ [pkgs.openssh pkgs.chrony]) true configuration;
  malformedName = evaluate baselinePackages false {
    aos.roles.server.enable = true;
    aos.apm.desiredPackages = ["../untrusted"];
  };
  mistyped = evaluate baselinePackages false {
    aos.roles.server.enable = true;
    aos.apm.desiredPackages = [42];
  };
  succeeds = value: (builtins.tryEval (builtins.deepSeq value true)).success;
  packages = evaluated: evaluated.config.aos.apm.desiredPackages;
  services = resolved.config.aos.abilities.serviceManagement.operations.realize.effects;
in {
  discoveryProjectsRoleRequirements = packages discovery == ["openssh" "chrony"];
  incompleteStrictGraphRejects = !succeeds incomplete.deployment.graph;
  resolvedGraphIsValid = succeeds resolved.deployment.graph;
  resolvedServicesUseAcquiredSchemas = resolved.config.aos.services.ssh.port == 2222 && services ? ssh && services ? chrony;
  discoveredRequirementsStayTyped = !succeeds (packages mistyped);
  malformedPackageNamesReject = !succeeds (packages malformedName);
}
