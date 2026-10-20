##! Exercises selected release-directory staging through the real rootfs populate phase.
{
  pkgs,
  lib,
}: let
  release = "7.2.3-qualification";
  moduleFixture = name:
    pkgs.mkDerivation {
      pname = "rootfs-${name}-module-fixture";
      version = "0";
      src = null;
      outputChecks = {};
      buildDeps = [pkgs.cc pkgs.coreutils];
      phases = [
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out/lib/modules/${release}/kernel/qualification"
            cat > module.c <<'SOURCE'
            __attribute__((section(".modinfo"), used))
            static const char license[] = "license=GPL";
            __attribute__((section(".modinfo"), used))
            static const char module_name[] = "name=${name}";
            int init_module(void) { return 0; }
            void cleanup_module(void) {}
            SOURCE
            cc -c -fno-pic -fno-stack-protector module.c \
              -o "$out/lib/modules/${release}/kernel/qualification/${name}.ko"
            printf '%s\n' 'kernel/qualification/${name}.ko' > "$out/lib/modules/${release}/modules.order"
            touch "$out/lib/modules/${release}/modules.builtin" \
              "$out/lib/modules/${release}/modules.builtin.modinfo"
            ln -s /unavailable-kernel-build "$out/lib/modules/${release}/build"
            ln -s /unavailable-kernel-source "$out/lib/modules/${release}/source"
            ${pkgs.kmod}/sbin/depmod -b "$out" ${release}
          '';
        }
      ];
    };
  kernelPackage = moduleFixture "base";
  externalPackage = moduleFixture "external";
  moduleTree = "${kernelPackage}/lib/modules/${release}";
  toplevel = pkgs.mkDerivation {
    pname = "rootfs-module-toplevel-fixture";
    version = "0";
    src = null;
    outputChecks = {};
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/host-deployment"
          printf '%s\n' fixture > "$out/host-deployment/identity"
        '';
      }
    ];
  };
  system.config = {
    system.build = {inherit toplevel;};
    aos = {
      configurationLower.enable = false;
      boot = {
        stageInputPaths.host.bundle = "/usr/lib/aos/host/deployment";
        stageInputPaths.receivedInitrd.bundle = "/usr/lib/aos/initrd/deployment";
        initrd.abilityHandoff.enable = false;
      };
    };
  };
  population = merged: let
    rootfs = import ../../pkgs/system/_systemd-abilities/platform/_rootfs-builder.nix {
      inherit pkgs lib system;
      closureInfoFor = lib.build.closureInfo {inherit pkgs;};
      kernel = {
        package = kernelPackage;
        configuration = {inherit release moduleTree;};
      };
      pname = "rootfs-module-${
        if merged
        then "merged"
        else "ordinary"
      }-population";
      kernelModulePackages = lib.optional merged externalPackage;
      postPopulate = ''
        test -d rootfs/usr/lib/modules
        test ! -L rootfs/usr/lib/modules
        ${
          if merged
          then ''
            test -d rootfs/usr/lib/modules/${release}
            test ! -L rootfs/usr/lib/modules/${release}
            cmp rootfs/lib/modules/${release}/kernel/qualification/external.ko \
              ${externalPackage}/lib/modules/${release}/kernel/qualification/external.ko
            test ! -e rootfs/lib/modules/${release}/build
            test ! -L rootfs/lib/modules/${release}/build
            test ! -e rootfs/lib/modules/${release}/source
            test ! -L rootfs/lib/modules/${release}/source
            ${pkgs.kmod}/sbin/modprobe --dirname rootfs --set-version ${release} \
              --show-depends external > external-dependencies
            grep -F 'kernel/qualification/external.ko' external-dependencies
          ''
          else ''
            test -L rootfs/usr/lib/modules/${release}
            test "$(readlink rootfs/usr/lib/modules/${release})" = ${lib.escapeShellArg moduleTree}
          ''
        }
        cmp rootfs/lib/modules/${release}/kernel/qualification/base.ko \
          ${moduleTree}/kernel/qualification/base.ko
        test -s rootfs/lib/modules/${release}/modules.dep.bin
        ${pkgs.kmod}/sbin/modprobe --dirname rootfs --set-version ${release} \
          --show-depends base > base-dependencies
        grep -F 'kernel/qualification/base.ko' base-dependencies
        mkdir -p "$out"
        printf '%s\n' PASS > "$out/result"
      '';
    };
  in
    rootfs.overrideAttrs (previous: {
      # Run the production population and its caller hook without constructing an image.
      phases = builtins.filter (phase: phase.name == "populate") previous.phases;
      outputChecks = {};
      buildDeps = previous.buildDeps ++ [pkgs.kmod pkgs.grep pkgs.diffutils];
    });
  ordinary = population false;
  merged = population true;
in
  pkgs.mkDerivation {
    pname = "rootfs-kernel-modules-check";
    version = "0";
    src = null;
    outputChecks = {};
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          test "$(cat ${ordinary}/result)" = PASS
          test "$(cat ${merged}/result)" = PASS
          mkdir -p "$out"
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  }
