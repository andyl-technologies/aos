##! Native policy graphs and support contracts evaluated without host mutation.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  package = {
    _type = "aos-package-artifact";
    name = "aos-ebpf-lsm-policy";
    path = toString (payload "policy");
    outputs.out = toString (payload "policy");
    outPath = toString (payload "policy");
    meta.mainProgram = "aos-ebpf-lsm-provider";
  };
  evaluate = modules:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit package;};
      modules = [../../lib/effects/module.nix] ++ modules;
    };
  lsm = evaluate [
    ../../pkgs/security/_aos-ebpf-lsm-policy/module.nix
    {aos.security.ebpfLsm.enable = true;}
  ];
  network = evaluate [
    ../../pkgs/security/_aos-ebpf-net-policy/module.nix
    {
      aos.security.ebpfNetworkPolicy = {
        enable = true;
        policies = [
          {
            name = "sample";
            cgroup = "/sys/fs/cgroup/aos/sample";
            policy = "${package.path}/share/policy.json";
            object = "${package.path}/lib/policy.bpf.o";
          }
        ];
      };
    }
  ];
  metadata = evaluate [
    ../../pkgs/tools/_aos-metadata-provider/module.nix
    {
      aos.abilities.metadata.operations.detect.effects.platform.input = {
        blkid = "${package.path}/bin/blkid";
        mount = "${package.path}/bin/mount";
        umount = "${package.path}/bin/umount";
      };
    }
  ];
  store = evaluate [
    ../../pkgs/tools/_aos-nix-store-provider/module.nix
    {
      aos.abilities.nixStoreDatabase.operations.converge.effects.boot.input.registration = {
        path = "/aos-registration";
        required = true;
      };
      aos.abilities.contentAddressedObject.operations.commit.effects.manifest = {
        lifetime = "persistent";
        input = {
          name = "manifest";
          media_type = "application/json";
          content = "{}";
        };
      };
    }
  ];
  support = evaluate [
    ../../pkgs/system/_service-management/identity.nix
    ../../pkgs/system/_service-management/network.nix
    ../../pkgs/system/_service-management/device.nix
    ({config, ...}: {
      aos.abilities.identity.operations = {
        group.handler.program = package;
        group.effects.daemon.input.name = "daemon";
        principal.handler.program = package;
        principal.effects.daemon.input = {
          name = "daemon";
          primary_group = config.aos.abilities.identity.operations.group.effects.daemon.outputs.name;
        };
      };
    })
  ];
  onlyNode = evaluated: builtins.head (builtins.attrValues evaluated.config.aos.activation.graph.nodes);
  principal =
    builtins.head (builtins.filter (node: builtins.elem "principal" node.identity)
      (builtins.attrValues support.config.aos.activation.graph.nodes));
in {
  lsmUsesNativeHandler = (onlyNode lsm).handler.executable == "${package.path}/bin/aos-ebpf-lsm-provider";
  lsmHasTypedResult = (onlyNode lsm).results.loaded.kind == "list";
  networkRetainsCgroup = (builtins.head (onlyNode network).input.policies).cgroup == "/sys/fs/cgroup/aos/sample";
  metadataSelectsOwnProgram = (onlyNode metadata).handler.executable == "${package.path}/bin/aos-metadata-acquisition-provider";
  storeGraphHasBothNativeOperations = builtins.length store.config.aos.activation.graph.order == 2;
  accountResultCreatesDependency = builtins.length principal.dependencies == 1;
}
