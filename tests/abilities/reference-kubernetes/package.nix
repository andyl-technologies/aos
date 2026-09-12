##! Structured K3s, Cilium, and Longhorn packages for native activation.
{
  lib,
  mkDerivation,
  kubernetesRuntime,
  systemdRuntime,
  transitionTransform ? transition: transition,
}: let
  contracts = import ../../../pkgs/kubernetes/_ability-contracts.nix {inherit lib;};

  k3sArtifact = ../../../pkgs/kubernetes/_k3s-ability-provider;
  ciliumArtifact = ./providers/cilium;
  longhornArtifact = ./providers/longhorn;
  systemdArtifact = ./providers/systemd;
  kubernetesArtifact = ./providers/kubernetes;

  mkPackage = pname: src: abilityPackage:
    mkDerivation {
      inherit pname src abilityPackage;
      version = "1.0.0";
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${pname}"
            printf '%s\n' 'structured Kubernetes ability fixture' > "$out/share/${pname}/README"
          '';
        }
      ];
      meta = {
        description = "Structured Kubernetes ability fixture package";
        license = "Apache-2.0";
      };
    };
in {
  cilium = mkPackage "ability-reference-cilium" ciliumArtifact contracts.contributorPackage;

  longhorn = mkPackage "ability-reference-longhorn" longhornArtifact contracts.contributorPackage;

  k3s = mkPackage "ability-reference-k3s" k3sArtifact (contracts.k3sPackage {
    providerArtifact = k3sArtifact;
    inherit transitionTransform;
  });

  systemd = mkPackage "ability-reference-systemd-bootstrap" systemdArtifact (
    contracts.systemdPackage systemdRuntime
  );

  kubernetes = mkPackage "ability-reference-kubernetes-terminal" kubernetesArtifact (
    contracts.kubernetesPackage kubernetesRuntime
  );
}
