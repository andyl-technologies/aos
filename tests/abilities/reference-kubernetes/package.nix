##! Structured K3s, Cilium, and Longhorn packages for native activation.
{
  lib,
  mkDerivation,
  kubernetesRuntime,
  systemdRuntime,
  effectQualification ? false,
  providerStateQualification ? false,
  transitionTransform ? transition: transition,
  bootstrapMatrix ? false,
  qualificationObserver ? null,
}: let
  contracts = import ../../../pkgs/kubernetes/_ability-contracts.nix {inherit lib;};
  packageRuntimeSelector = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };
  qualificationSupport =
    if qualificationObserver == null
    then null
    else import ../_native-adapter-qualification.nix {
      inherit lib;
      observerPackage = qualificationObserver;
    };
  conformanceFamilies = [
    "authority-revocation"
    "dependent-effect"
    "durability-recovery"
    "foreign-resource"
    "incarnation-replacement"
    "provider-state-transfer"
  ];
  qualificationFor = adapter: observationKind: scope: {
    inherit adapter conformanceFamilies observationKind scope;
    observer = qualificationSupport.observer;
  };
  withQualification = name: adapter: observationKind: scope: abilities:
    if qualificationSupport == null
    then abilities
    else
      lib.recursiveUpdate abilities {
        config.aos.abilities.implementations.${name}.qualification = qualificationFor adapter observationKind scope;
      };

  k3sArtifact = ../../../pkgs/kubernetes/_k3s-ability-provider;
  ciliumArtifact = ./providers/cilium;
  longhornArtifact = ./providers/longhorn;
  systemdArtifact = ./providers/systemd;
  kubernetesArtifact = ./providers/kubernetes;

  mkPackage = pname: src: runtimeDeps: abilities:
    mkDerivation {
      inherit pname src runtimeDeps abilities;
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
  cilium = mkPackage "ability-reference-cilium" ciliumArtifact [] contracts.contributorPackage;

  longhorn = mkPackage "ability-reference-longhorn" longhornArtifact [] contracts.contributorPackage;

  k3s = mkPackage "ability-reference-k3s" k3sArtifact [] (contracts.k3sPackage {
    inherit bootstrapMatrix effectQualification providerStateQualification transitionTransform;
  });

  systemd = mkPackage "ability-reference-systemd-bootstrap" systemdArtifact (
    [systemdRuntime] ++ lib.optional (qualificationObserver != null) qualificationObserver
  ) (withQualification "systemd-bootstrap" "systemd-bootstrap" "systemd" "bootstrap-manager" (
    contracts.systemdPackage packageRuntimeSelector
  ));

  kubernetes = mkPackage "ability-reference-kubernetes-terminal" kubernetesArtifact (
    [systemdRuntime kubernetesRuntime] ++ lib.optional (qualificationObserver != null) qualificationObserver
  ) (withQualification "kubernetes" "kubernetes-object" "kubernetes" "kubernetes-cluster" (
    contracts.kubernetesPackage packageRuntimeSelector
  ));
}
