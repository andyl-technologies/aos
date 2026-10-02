##! Retains real native domain modules with inert payload identities for pure checks.
{lib}: let
  root = ../..;
  payload = import ../effects/_fixture-payload.nix;
  package = name: source: {
    type = "derivation";
    pname = name;
    version = "2.4.4";
    system = "x86_64-linux";
    outPath = payload name;
    module = builtins.path {
      path = source;
      name = "${name}-module";
    };
    meta.mainProgram = name;
  };
  artifact = name: (package name (root + /pkgs/system/_service-management)) // {module = null;};
  service = package "service-management" (root + /pkgs/system/_service-management);
  manager = package "manager" (root + /pkgs/system/_service-management);
  kmod = package "kmod" (root + /pkgs/system/_kmod-abilities);
  storage = package "storage-interface" (root + /pkgs/system/_storage-interface);
  tunables = package "aos-kernel-tunable-provider" (root + /pkgs/tools/_aos-kernel-tunable-provider);
  zfs = builtins.removeAttrs (artifact "zfs") ["module"];
  utilLinux = builtins.removeAttrs (artifact "util-linux") ["module"];
  zfsProvider =
    (package "aos-zfs-provider" (root + /pkgs/filesystem/_aos-zfs-provider))
    // {
      runtimeDeps = [zfs];
      moduleDeps = [service storage kmod tunables];
    };
  format = (package "aos-storage-format-provider" (root + /pkgs/tools/_aos-storage-format-provider)) // {runtimeDeps = [utilLinux];};
  mapping = package "aos-cryptsetup-provider" (root + /pkgs/security/_aos-cryptsetup-provider);
  crypto = (package "cryptsetup" (root + /pkgs/security/_cryptsetup)) // {moduleDeps = [service format mapping];};
  zfstools =
    (package "zfstools" (root + /pkgs/storage/_zfstools))
    // {
      runtimeDeps = [zfs];
      moduleDeps = [service storage];
    };
  metadata = package "aos-metadata-provider" (root + /pkgs/tools/_aos-metadata-provider);
  store = package "aos-nix-store-provider" (root + /pkgs/tools/_aos-nix-store-provider);
  aos =
    (builtins.removeAttrs (artifact "aos") ["module"])
    // {
      outputs = ["out" "packageRuntime"];
      packageRuntime = builtins.removeAttrs (artifact "aos-runtime") ["module"];
    };
  provisioning =
    (package "aos-storage-provisioning-provider" (root + /pkgs/system/_aos-storage-provisioning-provider))
    // {
      runtimeDeps = [
        (manager // {pname = "systemd";})
        utilLinux
        aos
        (artifact "mdadm")
        (artifact "e2fsprogs")
        (artifact "xfsprogs")
      ];
      moduleDeps = [metadata store service storage];
    };
  evaluate = {
    packages,
    modules ? [],
    evaluationInput ? null,
    evaluationInputs ? [],
  }:
    lib.evalPackageModules {
      inherit packages evaluationInput evaluationInputs;
      scope = ["test" "native-storage"];
      modules =
        [
          (args: import (root + /pkgs/system/_systemd-abilities/resource-handlers.nix) (args // {package = manager;}))
          {
            options.assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
            options.aos.boot.storage.backend = lib.mkOption {
              type = lib.types.str;
              default = "test";
            };
            options.aos.kernel.externalPackages = lib.mkOption {
              type = lib.types.attrsOf (lib.types.listOf lib.types.package);
              default = {};
              extensible = true;
            };
            options.aos.kernel.commandLineParts = lib.mkOption {
              type = lib.types.attrsOf (lib.types.listOf lib.types.str);
              default = {};
              extensible = true;
            };
            options.aos.initrdRuntime.artifacts = lib.mkOption {
              type = lib.types.attrsOf (lib.types.listOf lib.types.str);
              default = {};
              extensible = true;
            };
            options.aos.initrdRuntime.files = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.str);
              default = {};
              extensible = true;
            };
            options.aos.initrdRuntime.renderedFileTrees = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
              extensible = true;
            };
            config.aos.abilities = {
              serviceManagement.operations.realize.handler.program = manager;
              device.operations.present.handler.program = manager;
              network.operations.ready.handler.program = manager;
              network.operations.bootstrap.handler.program = manager;
            };
          }
        ]
        ++ modules;
    };
  find = evaluated: operation:
    builtins.filter (node: builtins.elem operation node.identity) (builtins.attrValues evaluated.deployment.graph.nodes);
  only = evaluated: operation: builtins.head (find evaluated operation);
  identity = node: builtins.hashString "sha256" (builtins.toJSON node.identity);
in {inherit evaluate only find identity zfsProvider crypto zfstools provisioning manager aos;}
