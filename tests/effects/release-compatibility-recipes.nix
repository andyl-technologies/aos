##! Exercises package and host release documentation through ordinary recipes.
{pkgs}: let
  package = name: source: dependencies: extra:
    pkgs.mkDerivation ({
        pname = name;
        version = "9.2.0";
        src = null;
        phases = [];
        module = source;
        moduleDeps = dependencies;
      }
      // extra);
  interface = package "release-interface" ./release-compatibility/interface [] {};
  consumer = package "release-consumer" ./release-compatibility/consumer [
    {
      package = interface;
      packageVersion = "^9.0";
    }
  ] {osVersion = "^0.1";};
  moduleless = pkgs.mkDerivation {
    pname = "moduleless-release-requester";
    version = "1.0.0";
    src = null;
    phases = [];
    osVersion = "^0.1";
  };
  lib = import ../../lib {system = pkgs.stdenv.hostPlatform.system;};
  hostRelease = {
    name = "aos";
    version = "0.1.8";
  };
  bundleFor = osRelease:
    import ../../pkgs/containers/_aos-oci-backend/deployment-bundle.nix {
      inherit lib pkgs osRelease;
      packages = [moduleless];
      scope = ["test" "release-bundle"];
      system = lib.platform.system;
      graph = {nodes = {};};
    };
  lock = import ../../lib/packages/resolution-lock.nix {packages = [consumer];};
  reference = consumer.documentation;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
in {
  envelopesUsePackageReleases = assert interface.deployment.package.version == "9.2.0";
  assert !(interface.deployment ? abilityExports);
  assert consumer.deployment.osVersion == "^0.1"; true;
  referenceUsesPackageRequirements = assert reference.moduleRequirements
  == [
    {
      owner = consumer.pname;
      package = interface.pname;
      packageVersion = "^9.0";
    }
  ];
  assert reference.osRequirements
  == [
    {
      owner = consumer.pname;
      osVersion = "^0.1";
    }
  ];
  assert !(reference ? abilityContracts); true;
  modulelessReleaseDocumentation = assert moduleless.deployment.osVersion == "^0.1";
  assert moduleless.documentation.osRequirements
  == [
    {
      owner = moduleless.pname;
      osVersion = "^0.1";
    }
  ]; true;
  invalidOsRangeRejected = assert rejects (package "invalid-os-release" ./release-compatibility/interface [] {osVersion = "not-a-range";}).deployment; true;
  bundleChecksHostRelease = assert (bundleFor hostRelease).nativeResolvedPackages.system == lib.platform.system;
  assert rejects (bundleFor null).nativeResolvedPackages;
  assert rejects
  (bundleFor {
    name = "aos";
    version = "0.2.0";
  }).nativeResolvedPackages; true;
  bundleRetainsHostRelease = assert (bundleFor hostRelease).nativeEvaluationDescriptor.nativeEvaluationInputs.osRelease == hostRelease; true;
  modulelessEnvelopeIsRetained = let
    bundle = bundleFor hostRelease;
    envelopes = bundle.nativeEvaluationDescriptor.nativePackageEnvelopes;
  in
    assert builtins.attrNames envelopes == [(builtins.unsafeDiscardStringContext (builtins.toString moduleless))];
    assert builtins.elem (builtins.toString moduleless.deploymentArtifact) bundle.nativeTransaction.inputs; true;
  lockUsesPublishedSources = assert (builtins.head lock.edges).requirement == builtins.head consumer.deployment.moduleDependencies;
  assert (builtins.head lock.edges).selected == interface.deployment.module;
  assert lock.requesters.${builtins.unsafeDiscardStringContext (builtins.toString consumer)} == builtins.toString consumer.deploymentArtifact; true;
}
