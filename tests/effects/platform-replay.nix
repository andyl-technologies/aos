##! Verifies that image policy and retained native sources produce the same graph.
let
  repo = ../..;
  lib = import (repo + "/lib") {system = "x86_64-linux";};
  program = {
    type = "derivation";
    outPath = builtins.toString (builtins.path {
      path = ./fixtures;
      name = "native-handler-fixture";
    });
    meta.mainProgram = "handler";
  };
  source = path:
    builtins.path {
      inherit path;
      name = "native-replay-fixture";
    };
  artifact = name: module: {
    pname = name;
    version = "1";
    outPath = builtins.toString (builtins.path {
      path = ./fixtures;
      name = "native-${name}-fixture";
    });
    inherit module;
  };
  kmod = artifact "kmod" (source (repo + "/pkgs/system/_kmod-abilities"));
  tunables = artifact "tunables" (source (repo + "/pkgs/tools/_aos-kernel-tunable-provider"));
  lower = artifact "configuration-lower" (source (repo + "/pkgs/boot/_aos-configuration-lower"));
  policy =
    (artifact "policy" (source (repo + "/pkgs/system/_aos-host-policy")))
    // {
      moduleDeps = [kmod tunables lower (artifact "service-management" (source (repo + "/pkgs/system/_service-management")))];
    runtimeDeps = [(artifact "ca-certificates" null)];
    };
  serviceSource = source (repo + "/pkgs/system/_service-management");
  operatorSource = builtins.toFile "platform-operator-policy.nix" ''
    {lib, ...}: {
      imports = [
        ${policy.module}/baseline/common.nix
        ${./fixtures/platform-policy.nix}
      ];
      options.aos.security.ebpfLsm.enable = lib.mkOption {type=lib.types.bool;default=false;};
      aos.abilities.configuration.operations.file.handler.program = {type="derivation";outPath="${program.outPath}";meta.mainProgram="handler";};
      aos.abilities.network.operations.configure.handler.program = {type="derivation";outPath="${program.outPath}";meta.mainProgram="handler";};
    }
  '';
  buildBaseline = import (repo + "/pkgs/system/_aos-host-policy/build-baseline.nix") {
    inherit lib;
    pkgs = (import repo {}).pkgs;
    configurationLower = lower;
  };
  additions = buildBaseline {
    packages = [policy];
    configuration = [operatorSource];
    scope = ["profile" "fixture"];
  };
  treeSource = source ./fixtures;
  treeOperator = builtins.toFile "platform-tree-policy.nix" ''
    { aos.filesystems.etcTrees = [{target="fixture-tree";source="${treeSource}";}]; }
  '';
  treeAdditions = buildBaseline {
    packages = [policy];
    configuration = [operatorSource treeOperator];
    scope = ["profile" "fixture"];
  };
  configuration = [operatorSource] ++ additions.configuration;
  packages = [policy] ++ additions.packages;
  runtime = lib.evalPackageModules {
    scope = ["profile" "fixture"];
    inherit packages;
    operatorModules = configuration;
  };
  image = lib.evalModules {
    inherit lib;
    packageModules = (import (repo + "/lib/build/package-modules.nix") {}).closure packages;
    operatorModules = configuration;
    specialArgs = {
      packageModulesAvailable = true;
      pkgs.firmware = program;
    };
    modules = [(repo + "/lib/effects/module.nix") (repo + "/modules/base/kernel.nix") (repo + "/modules/base/networking.nix") {aos.activation.scope = ["profile" "fixture"];}];
  };
in
  assert runtime.config.aos.activation.graph == image.config.aos.activation.graph;
  assert builtins.length runtime.config.aos.activation.graph.order >= 5;
  assert (builtins.head additions.packages).passthru.nativeManagedPaths
  == [
    "pki/tls/certs/ca-bundle.crt"
    "profile"
    "security/limits.d/aos-hardening.conf"
    "ssl/certs/ca-bundle.crt"
    "ssl/certs/ca-certificates.crt"
  ];
  assert runtime.config.aos.configurationLower.baselineInventory == "${builtins.head additions.packages}/managed-paths.json";
  # Constructing the tree inventory must not read its build output or import
  # generated Nix, even though recording its leaves requires a traversal.
  assert builtins.isString (builtins.head treeAdditions.packages).drvPath;
  assert treeAdditions.configuration == [];
  assert runtime.config.aos.kernel.sysctl."net.core.wmem_max" == "9000000"; true
