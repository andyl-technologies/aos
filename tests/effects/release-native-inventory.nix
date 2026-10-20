##! Checks native release artifact identities and module source retention without building.
{pkgs}: let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  artifact = name:
    builtins.derivation {
      inherit name;
      system = pkgs.bash.system;
      builder = "${pkgs.bash}/bin/bash";
      args = ["-c" ''${pkgs.coreutils}/bin/mkdir -p "$out"''];
    };
  source = toString (payload "demo-source");
  moduleSource = toString (payload "demo-module");
  deployment = artifact "demo-deployment";
  demoOutput = (artifact "demo").out // {deploymentArtifact = deployment;};
  demo =
    (artifact "demo")
    // {
      version = "1.0";
      outputs = ["out"];
      src = source;
      module = moduleSource;
      out = demoOutput;
      deploymentArtifact = deployment;
      documentationArtifact = artifact "demo-documentation";
      qualificationArtifact = artifact "demo-qualification";
      platformSupport = {
        build = [];
        host = [];
        target = [];
        role = "public-package";
      };
      meta = {
        description = "Native release fixture";
        license = "MIT";
        maintainers = ["fixture"];
      };
    };
  packages = {inherit demo;};
  policy = import ../../pkgs/_target-policy.nix {
    inherit lib packages;
    releasePlatforms = ["x86_64-linux"];
  };
  selection = {
    system = "x86_64-linux";
    inherit packages;
    names = ["demo"];
  };
  inventory = policy.releaseDerivations selection;
  entry = builtins.head inventory.packages;
  roots = policy.releaseDerivationRoots selection;
  noModule = policy.releaseDerivations (selection // {packages.demo = demo // {module = null;};});
in
  assert !(entry ? contract);
  assert entry.deployment.derivation == demo.deploymentArtifact.drvPath;
  assert entry.module_documentation.store_path == demo.documentationArtifact.outPath;
  assert builtins.length entry.outputs == 1;
  assert (builtins.head entry.outputs).deployment == entry.deployment;
  assert entry.source_store_paths == builtins.sort builtins.lessThan [source moduleSource];
  assert entry.qualification.store_path == demo.qualificationArtifact.outPath;
  assert builtins.length roots == 4;
  assert (builtins.head noModule.packages).source_store_paths == [source]; {nativeReleaseInventory = true;}
