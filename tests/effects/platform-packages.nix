##! Checks zram and privileged helper consumers against native package contracts.
let
  repo = ../..;
  lib = import (repo + "/lib") {system = "x86_64-linux";};
  source = path:
    builtins.path {
      inherit path;
      name = "native-platform-package-fixture";
    };
  artifact = name: module:
    {
      pname = name;
      version = "1";
      outPath = builtins.toString (builtins.path {path=./fixtures;name="native-${name}-fixture";});
      meta.mainProgram = "handler";
    }
    // lib.optionalAttrs (module != null) {inherit module;};
  service = artifact "service-management" (source (repo + "/pkgs/system/_service-management"));
  filesystem = artifact "filesystem" (source (repo + "/pkgs/filesystem/_aos-filesystem-provider"));
  kmod = artifact "kmod" (source (repo + "/pkgs/system/_kmod-abilities"));
  storage = artifact "storage-interface" (source (repo + "/pkgs/system/_storage-interface"));
  lower = artifact "lower" (source (repo + "/pkgs/boot/_aos-configuration-lower"));
  checks = artifact "runtime-checks" (source (repo + "/pkgs/system/_aos-runtime-checks"));
  utilLinux = artifact "util-linux" null;
  backend = artifact "backend" null;
  zram =
    (artifact "zram-generator" (source (repo + "/pkgs/system/_zram-generator")))
    // {
      moduleDeps = [backend service filesystem kmod storage checks];
      runtimeDeps = [utilLinux];
    };
  utempter =
    (artifact "libutempter" (source (repo + "/pkgs/libs/_libutempter")))
    // {
      moduleDeps = [backend service filesystem];
    };
  evaluated = lib.evalPackageModules {
    packages = [zram utempter];
    operatorModules = [
      (repo + "/pkgs/system/_systemd-abilities/packaged-unit.nix")
      {
        aos.zram.enable = true;
        aos.security.utempter.enable = true;
        aos.abilities.configuration.operations.file.handler.program = backend;
        aos.abilities.identity.operations.group.handler.program = backend;
        aos.abilities.packagedUnit.operations.ensure.handler.program = backend;
      }
    ];
    scope = ["profile" "platform-fixture"];
  };
  treeEvaluation = lib.evalPackageModules {
    packages = [lower];
    scope = ["profile" "tree-fixture"];
    operatorModules = [
      {
        aos.filesystems.etcTrees = [
          {
            target = "libvirt";
            source = source (repo + "/tests/effects/fixtures");
          }
        ];
      }
    ];
  };
  cfg = evaluated.config;
  effects = cfg.aos.abilities;
  setup = effects.packagedUnit.operations.ensure.effects.zram-setup;
  helper = effects.filesystem.operations.privilegedExecutable.effects.utempter;
in
  assert builtins.length cfg.aos.activation.graph.order == 6;
  assert setup.input.activation == "reference";
  assert setup.input.source == "${zram.outPath}/lib/systemd/system/systemd-zram-setup@.service";
  assert setup.input.search_path == ["${utilLinux.outPath}/bin" "${utilLinux.outPath}/sbin"];
  assert helper.input.source == "${utempter.outPath}/libexec/utempter/utempter";
  assert helper.input.mode == "2711";
  assert cfg.system.checks.zram.checks != [];
  assert treeEvaluation.config.aos.configurationLower.enable;
  assert builtins.length treeEvaluation.config.aos.activation.graph.order == 3;
  assert treeEvaluation.config.aos.configurationLower.ownership.etcTrees.libvirt == "@host"; true
