##! Exercises generated contracts through the ordinary package builder.
{pkgs}: let
  package = name: source: dependencies:
    pkgs.mkDerivation {
      pname = name;
      version = "9.2.0";
      src = null;
      phases = [];
      module = source;
      moduleDeps = dependencies;
    };
  interface = package "version-interface" ./ability-versions/interface [];
  consumer = package "version-consumer" ./ability-versions/consumer [
    {
      package = interface;
      abilities.versioned = "^1.4";
    }
  ];
  lock = import ../../lib/packages/resolution-lock.nix {packages = [consumer];};
  reference = consumer.documentation;
in {
  exportsAreGenerated = assert interface.deployment.abilityExports == {versioned.version = "1.4.2";};
  assert consumer.deployment.abilityExports == {}; true;
  referenceUsesNativeDeclarations = assert reference.abilityContracts.versioned
  == {
    version = "1.4.2";
    owner = interface.pname;
  };
  assert reference.moduleRequirements
  == [
    {
      owner = consumer.pname;
      package = interface.pname;
      abilities.versioned = "^1.4";
    }
  ]; true;
  lockUsesPublishedSources = assert (builtins.head lock.edges).requirement == builtins.head consumer.deployment.moduleDependencies;
  assert (builtins.head lock.edges).selected == interface.deployment.module;
  assert lock.requesters.${builtins.unsafeDiscardStringContext (builtins.toString consumer)} == builtins.toString consumer.deploymentArtifact; true;
}
