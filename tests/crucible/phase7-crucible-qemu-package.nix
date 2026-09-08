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
  patchSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  simAccelPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch;
  shmemPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0015-crucible-blk-shmem.patch;

  qemuProbeFor = overrides:
    import ../../pkgs/emulation/qemu.nix ({
        inherit lib;
        mkDerivation = args: let
          passthru = args.passthru or {};
        in
          args // passthru;
        fetchurl = args: args;
        gnumake = null;
        pkg-config = null;
        meson = null;
        ninja = null;
        python3 = "/aos-python3";
        stdenv = {
          isCross = false;
          hostPlatform = {
            isDarwin = false;
            constraints.cpu = "x86_64";
          };
        };
        buildPackages = {};
        setuptools = null;
        distlib = null;
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
      }
      // overrides);

  productionQemu = qemuProbeFor {};
  patchedQemu = qemuProbeFor {
    pname = "qemu-crucible";
    enablePlugins = true;
    applyCruciblePatches = true;
  };
  referenceQemu = qemuProbeFor {
    pname = "qemu-crucible-reference";
    enablePlugins = true;
    applyCruciblePatches = false;
  };

  versionParts = map (part: builtins.fromJSON part) (lib.splitString "." patchSeries.qemuVersion);
  qemuMajorVersion = builtins.elemAt versionParts 0;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    lib.optionals (qemuMajorVersion < 10) [
      "pkgs/emulation/qemu-patches/_series.nix: QEMU pin ${patchSeries.qemuVersion} is older than 10.0"
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
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=false" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must remain unpatched by default"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugins_enabled=false" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must not enable plugin support by default"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" productionQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu: production QEMU must not advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=true" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must apply the Crucible patch series"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugins_enabled=true" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must enable plugin support"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=qemu-crucible" patchedQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible: patched QEMU must advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(hasInfix "qemu_crucible_patches_applied=false" referenceQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: inertness reference QEMU must be unpatched"
    ]
    ++ lib.optionals (!(hasInfix "qemu_sim_capability=none" referenceQemu.qemuBuildIdentityMaterial)) [
      "pkgs.qemu-crucible-reference: inertness reference QEMU must not advertise Crucible sim capability"
    ]
    ++ lib.optionals (!(builtins.elem "--target-list=x86_64-softmmu,aarch64-softmmu" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: missing x86_64-softmmu,aarch64-softmmu target-list configure flag"
    ]
    ++ lib.optionals (!(builtins.elem "--enable-plugins" patchedQemu.qemuConfigureFlags)) [
      "pkgs.qemu-crucible: missing plugin configure flag"
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
        needle = "qemu-crucible = callPackage ./emulation/qemu.nix";
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
        needle = "applyCruciblePatches = true;";
      }
      {
        label = "qemu-crucible-reference package";
        needle = "qemu-crucible-reference = callPackage ./emulation/qemu.nix";
      }
      {
        label = "qemu-crucible-reference patch opt-out";
        needle = "applyCruciblePatches = false;";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "production QEMU is unpatched by default";
        needle = "applyCruciblePatches ? false";
      }
      {
        label = "patch phase is gated by package argument";
        needle = "if applyCruciblePatches";
      }
      {
        label = "patch phase consumes canonical series";
        needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
      }
      {
        label = "pinned upstream source URL";
        needle = "https://download.qemu.org/qemu-";
      }
      {
        label = "pinned upstream source hash";
        needle = "hash = series.qemuSourceHash;";
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
    ++ failuresFor "pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch" simAccelPatch [
      {
        label = "sim accelerator type";
        needle = "TYPE_SIM_ACCEL";
      }
      {
        label = "sim accelerator ops";
        needle = "ACCEL_OPS_NAME(\"sim\")";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0015-crucible-blk-shmem.patch" shmemPatch [
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
            qemu_version=${patchSeries.qemuVersion}
            qemu_source_hash=${patchSeries.qemuSourceHash}
            production_package=pkgs.qemu
            production_qemu_patches_applied=false
            patched_package=pkgs.qemu-crucible
            patched_qemu_patches_applied=true
            reference_package=pkgs.qemu-crucible-reference
            reference_qemu_patches_applied=false
            plugin_package=pkgs.crucible-qemu-plugin
            matched_pair=pkgs.qemu-crucible+pkgs.crucible-qemu-plugin
            target_list=x86_64-softmmu
            sim_capability_marker=qemu-crucible
            patch_series_manifest=pkgs/emulation/qemu-patches/_series.nix
            RESULT
          '';
        }
      ];
    }
