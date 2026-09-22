{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleQemuPackage",
  taskIds ? ["T-PKG-2"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  pkgsDefault = builtins.readFile ../../pkgs/default.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginPackageNix = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  simAccelPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch;
  shmemPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch;

  qemuProbeFor = overrides:
    import ../../pkgs/emulation/qemu.nix ({
        inherit lib;
        mkDerivation = args: let
          passthru = args.passthru or {};
        in
          args // passthru;
        fetchurl = args: args;
        gnumake = null;
        bash = "/aos-bash";
        perl = "/aos-perl";
        pkg-config = null;
        meson = null;
        ninja = null;
        python3 = "/aos-python3";
        stdenv = {
          isCross = false;
          hostPlatform = {
            isDarwin = false;
            isLinux = true;
            constraints.cpu = "x86_64";
          };
        };
        buildPackages = {};
        setuptools = null;
        distlib = null;
        python3-pygdbmi = null;
        glib = null;
        pixman = null;
        zlib = null;
        libslirp = null;
        dtc = null;
        libcap-ng = null;
        libusb1 = null;
        libgcrypt = null;
        gnutls = null;
        fuse3 = null;
        gcc-libs = "/aos-gcc-libs";
        libisoburn = null;
        mtools = null;
        socat = null;
        zstd = null;
        samba-smbd = {
          outPath = "/aos-samba-smbd";
          version = "4.24.7";
          src = {
            outputHash = "sha256-Rbd0ekdFLv8rIVmkTMY+tDaQ0zn9EGkIjgI6AV/tBsc=";
            outputHashAlgo = "sha256";
          };
        };
      }
      // overrides);

  productionQemu = qemuProbeFor {};
  patchedQemu = qemuProbeFor {
    pname = "qemu-crucible";
    enablePlugins = true;
    applyCruciblePatch = true;
  };
  referenceQemu = qemuProbeFor {
    pname = "qemu-crucible-reference";
    enablePlugins = true;
    applyCruciblePatch = false;
  };
  unexpectedSmbdFlag = builtins.tryEval (
    patchedQemu.normalizeSambaSmbdConfigureFlag
    patchedQemu.sambaSmbdExecutable
    "--smbd=/aos-samba-smbd/bin/other"
  );
  alternateSmbdIdentityFlag =
    patchedQemu.normalizeSambaSmbdConfigureFlag
    "bin/other"
    "--smbd=/aos-samba-smbd/bin/other";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    lib.optionals (atomicPatch.qemuVersion != "11.1.1") [
      "pkgs/emulation/qemu-patches/_atomic-patch.nix: QEMU pin ${atomicPatch.qemuVersion} differs from required 11.1.1"
    ]
    ++ lib.optionals (productionQemu.version != patchedQemu.version) [
      "pkgs.qemu and pkgs.qemu-crucible do not share the same QEMU version"
    ]
    ++ lib.optionals (productionQemu.src.hash != patchedQemu.src.hash) [
      "pkgs.qemu and pkgs.qemu-crucible do not share the same QEMU source hash"
    ]
    ++ lib.optionals (referenceQemu.src.hash != patchedQemu.src.hash) [
      "pkgs.qemu-crucible-reference and pkgs.qemu-crucible do not share the same QEMU source hash"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_atomic_patch_applied=false" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must remain unpatched by default"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugins_enabled=false" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must not enable plugin support by default"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must not advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_atomic_patch_applied=true" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must apply the Crucible atomic patch"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugins_enabled=true" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must enable plugin support"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=qemu-crucible" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_atomic_patch_applied=false" referenceQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: inertness reference QEMU must be unpatched"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" referenceQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: inertness reference QEMU must not advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(builtins.elem "--target-list=x86_64-softmmu,aarch64-softmmu" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: missing x86_64-softmmu,aarch64-softmmu target-list configure flag"
    ]
    ++ lib.optionals (!(builtins.elem "--target-list=x86_64-softmmu,aarch64-softmmu,i386-linux-user,x86_64-linux-user,aarch64-linux-user,riscv64-linux-user" productionQemu.qemuConfigureFlags)) [
      "pkgs.qemu: missing Linux-user target-list configure flag"
    ]
    ++ lib.optionals (!(builtins.elem "--enable-linux-user" productionQemu.qemuConfigureFlags)) [
      "pkgs.qemu: Linux package does not enable Linux-user emulation"
    ]
    ++ lib.optionals (!(builtins.elem "--disable-linux-user" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: patched package must remain softmmu-only"
    ]
    ++ lib.optionals (!(builtins.elem "--disable-linux-user" referenceQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible-reference: inertness reference must remain softmmu-only"
    ]
    ++ lib.optionals (!(builtins.elem "--extra-ldflags=-Wl,--push-state,--no-as-needed,-l:libgcc_s.so.1,--pop-state" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: missing retained libgcc_s thread-exit dependency"
    ]
    ++ lib.optionals (!(builtins.elem "--enable-plugins" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: missing plugin configure flag"
    ]
    ++ lib.optionals (!(builtins.elem "--smbd=/aos-samba-smbd/sbin/smbd" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: real configure flags do not retain the Samba executable"
    ]
    ++ lib.optionals (!(builtins.elem "--smbd=@aos-samba-smbd@/sbin/smbd" patchedQemu.qemuConfigureIdentityFlags)) [
      "pkgs.qemu-crucible: configure identity does not normalize the Samba store path"
    ]
    ++ lib.optionals (!(hasInfix "samba_smbd_version=4.24.7" patchedQemu.qemuConfigureIdentityMaterial)) [
      "pkgs.qemu-crucible: configure identity omits the Samba version"
    ]
    ++ lib.optionals (!(hasInfix "samba_smbd_source_hash=sha256-Rbd0ekdFLv8rIVmkTMY+tDaQ0zn9EGkIjgI6AV/tBsc=" patchedQemu.qemuConfigureIdentityMaterial)) [
      "pkgs.qemu-crucible: configure identity omits the Samba source hash"
    ]
    ++ lib.optionals (!(hasInfix "samba_smbd_recipe_hash=${patchedQemu.sambaSmbdRecipeHash}" patchedQemu.qemuConfigureIdentityMaterial)) [
      "pkgs.qemu-crucible: configure identity omits the Samba build recipe hash"
    ]
    ++ lib.optionals unexpectedSmbdFlag.success [
      "pkgs.qemu-crucible: configure identity accepts an unexpected Samba executable"
    ]
    ++ lib.optionals (alternateSmbdIdentityFlag == "--smbd=@aos-samba-smbd@/sbin/smbd") [
      "pkgs.qemu-crucible: a changed Samba executable does not change identity material"
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-2 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleQemuPackage`";
      }
    ]
    ++ failuresFor "pkgs/default.nix" pkgsDefault [
      {
        label = "qemu-crucible explicit package override";
        needle = "qemu-crucible = mkQemuPackage";
      }
      {
        label = "qemu-crucible package name";
        needle = "pname = \"qemu-crucible\";";
      }
      {
        label = "qemu-crucible plugin support";
        needle = "enablePlugins = true;";
      }
      {
        label = "qemu-crucible patch opt-in";
        needle = "applyCruciblePatch = true;";
      }
      {
        label = "qemu-crucible-reference package";
        needle = "qemu-crucible-reference = mkQemuPackage";
      }
      {
        label = "qemu-crucible-reference patch opt-out";
        needle = "applyCruciblePatch = false;";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "production QEMU is unpatched by default";
        needle = "applyCruciblePatch ? false";
      }
      {
        label = "patch phase is gated by package argument";
        needle = "if applyCruciblePatch";
      }
      {
        label = "patch phase consumes the atomic artifact";
        needle = "< \${atomicPatchPath}";
      }
      {
        label = "pinned upstream source URL";
        needle = "https://download.qemu.org/qemu-";
      }
      {
        label = "pinned upstream source hash";
        needle = "hash = atomicPatch.qemuSourceHash;";
      }
      {
        label = "sim capability metadata";
        needle = "qemu_sim_capability=" + "$" + "{qemuSimCapability}";
      }
      {
        label = "build identity metadata";
        needle = "qemu_build_id=" + "$" + "{qemuBuildIdentity}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch" simAccelPatch [
      {
        label = "sim accelerator type";
        needle = "TYPE_SIM_ACCEL";
      }
      {
        label = "sim accelerator ops";
        needle = "ACCEL_OPS_NAME(\"sim\")";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch" shmemPatch [
      {
        label = "shmem block device file";
        needle = "block/crucible-shmem.c";
      }
      {
        label = "shmem block driver name";
        needle = "crucible-shmem";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix [
      {
        label = "matched qemu package dependency";
        needle = "qemu-crucible";
      }
      {
        label = "matched qemu header probe";
        needle = "header=\"" + "$" + "{qemu-crucible}/include/qemu/qemu-plugin.h\"";
      }
      {
        label = "matched sim capability marker";
        needle = "qemu_sim_capability_marker=" + "$" + "{qemu-crucible}/share/aos/crucible/qemu-build-identity.env";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
      {
        label = "host tools pattern";
        needle = "hostTools";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 QEMU package check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-qemu-package";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
      ];

      passthru = {
        productionQemu = pkgs.qemu;
        qemuPackage = pkgs.qemu-crucible;
        referenceQemu = pkgs.qemu-crucible-reference;
        pluginPackage = pkgs.crucible-qemu-plugin;
      };

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            package=qemu-crucible
            qemu_version=${atomicPatch.qemuVersion}
            qemu_source_hash=${atomicPatch.qemuSourceHash}
            production_package=pkgs.qemu
            production_qemu_atomic_patch_applied=false
            patched_package=pkgs.qemu-crucible
            patched_qemu_atomic_patch_applied=true
            reference_package=pkgs.qemu-crucible-reference
            reference_qemu_atomic_patch_applied=false
            plugin_package=pkgs.crucible-qemu-plugin
            matched_pair=pkgs.qemu-crucible+pkgs.crucible-qemu-plugin
            target_list=x86_64-softmmu
            sim_capability_marker=qemu-crucible
            atomic_patch_manifest=pkgs/emulation/qemu-patches/_atomic-patch.nix
            RESULT
          '';
        }
      ];
    }
