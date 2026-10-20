# Verifies that VM disks forward system module and firmware packages to the
# shared rootfs builder. The sentinel packages need not contain usable kernel
# objects: this check inspects the realized derivation recipe rather than
# booting an image.
{
  pkgs,
  lib,
  mkSystem,
}: let
  vm = import ./vm.nix {inherit pkgs lib;};

  kernelModuleSentinel = pkgs.mkDerivation {
    pname = "vm-rootfs-kernel-module-sentinel";
    version = "0";
    src = null;
    phases = [];
  };
  firmwareSentinel = pkgs.mkDerivation {
    pname = "vm-rootfs-firmware-sentinel";
    version = "0";
    src = null;
    phases = [];
  };

  probeSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.kernel.modulePackages = [kernelModuleSentinel];
      aos.kernel.firmwarePackages = [firmwareSentinel];
    }
  ];
  probeDisk = vm.mkTestDisk {
    name = "rootfs-adapter-probe";
    system = probeSystem;
  };
  rootfsBuilder = builtins.elemAt probeDisk.passthru.rootfs.args 1;
  managerInit = probeSystem.config.aos.manager.selected.configuration.rootfs.initExecutable;

  adapterContract =
    if !(lib.hasInfix "cp -a ${kernelModuleSentinel}/lib/modules/. rootfs/usr/lib/modules/" rootfsBuilder)
    then throw "VM rootfs adapter did not forward configured kernel module packages"
    else if !(lib.hasInfix "cp -a ${firmwareSentinel}/lib/firmware/. rootfs/usr/lib/firmware/" rootfsBuilder)
    then throw "VM rootfs adapter did not forward configured firmware packages"
    else if !(lib.hasInfix "ln -sfn ${lib.escapeShellArg (builtins.toString managerInit)} rootfs/usr/bin/init" rootfsBuilder)
    then throw "VM rootfs adapter did not use the selected manager's init executable"
    else if probeDisk.system != pkgs.stdenv.buildPlatform.system
    then throw "VM disk assembly must execute on the native build platform"
    else "module, firmware, selected manager, and native assembly inputs forwarded";
in
  pkgs.mkDerivation {
    pname = "vm-rootfs-adapter-check";
    version = "0";
    src = null;

    phases = [
      {
        name = "check";
        script = ''
          mkdir -p $out
          echo ${lib.escapeShellArg adapterContract} > $out/result
        '';
      }
    ];
  }
