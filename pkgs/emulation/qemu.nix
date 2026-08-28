##! qemu — Minimal QEMU for KVM-accelerated virtual machines (headless)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  setuptools,
  distlib,
  glib,
  pixman,
  zlib,
  libslirp,
  dtc,
  pname ? "qemu",
  enablePlugins ? false,
  applyCruciblePatches ? false,
  testOnlyNonDistributable ? false,
  testOnlyPostPatch ? null,
  series ? import ./qemu-patches/_series.nix,
}: let
  _testArtifactPolicy =
    if testOnlyNonDistributable && !applyCruciblePatches
    then throw "test-only QEMU artifacts require a tracked Crucible patch series"
    else null;
  _testMutationPolicy =
    if testOnlyPostPatch != null && !testOnlyNonDistributable
    then throw "QEMU test-only source mutations require a non-distributable test artifact"
    else null;
  version = series.qemuVersion;
  patchDir = ./qemu-patches;
  patchPath = file: patchDir + "/${file}";
  patchHashLine = patch: "${builtins.hashFile "sha256" (patchPath patch.file)}  ${patch.file}\n";
  patchSeriesHashMaterial = builtins.concatStringsSep "" (map patchHashLine series.patches);
  patchSeriesHash = builtins.hashString "sha256" patchSeriesHashMaterial;
  testMutationHash =
    if testOnlyPostPatch == null
    then "none"
    else builtins.hashFile "sha256" testOnlyPostPatch;
  patchBranchBundleHash = let
    actual = builtins.hashFile "sha256" series.patchBranchBundle;
  in
    if actual == series.patchBranchBundleSha256
    then actual
    else throw "QEMU patch branch bundle hash drifted: ${actual}";
  patchBranchCommits =
    map (patch: {
      inherit
        (patch)
        file
        branchCommit
        branchTree
        ;
      branchSubject = patch.branchSubject or (lib.removeSuffix ".patch" patch.file);
    })
    series.patches;
  patchBranchMaterial = builtins.toJSON {
    inherit
      (series)
      patchBranchRef
      patchBranchModel
      patchBranchBundleSha256
      patchBranchBaseCommit
      patchBranchBaseTree
      patchBranchHeadCommit
      ;
    inherit patchBranchCommits;
  };
  patchBranchMaterialHash = builtins.hashString "sha256" patchBranchMaterial;
  patchCount = builtins.length series.patchFiles;
  qemuNixHash = builtins.hashFile "sha256" ./qemu.nix;
  shmemLib = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  shmemGeneratedHeader = ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  shmemHeaderInstallPath = "include/aos/crucible/crucible_shmem_abi.h";
  shmemHeaderHash = builtins.hashFile "sha256" shmemGeneratedHeader;
  qemuSimCapability =
    if applyCruciblePatches
    then "qemu-crucible"
    else "none";
  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "qemu-crucible package failed to read ${label}"
    else builtins.head matches;
  shmemAbiVersion =
    lib.removeSuffix ";"
    (lib.removePrefix "pub const ABI_VERSION: u32 = " (
      firstLineWith "Crucible shmem ABI version" "pub const ABI_VERSION: u32 = " shmemLib
    ));
  shmemAbi = "crucible-shmem-abi-v${shmemAbiVersion}";
  pluginFlag =
    if enablePlugins
    then "--enable-plugins"
    else "--disable-plugins";
  qemuConfigureFlags = [
    "--target-list=x86_64-softmmu,aarch64-softmmu"
    "--enable-kvm"
    pluginFlag
    "--enable-slirp"
    "--enable-virtfs"
    "--disable-bsd-user"
    "--disable-linux-user"
    "--disable-docs"
    "--disable-guest-agent"
    "--disable-sdl"
    "--disable-gtk"
    "--disable-opengl"
    "--disable-virglrenderer"
    "--disable-vnc"
    "--disable-spice"
    "--disable-curses"
    "--disable-xen"
    "--disable-brlapi"
    "--disable-cap-ng"
    "--disable-libusb"
    "--disable-usb-redir"
    "--disable-vde"
    "--disable-nettle"
    "--disable-gcrypt"
    "--disable-gnutls"
    "--disable-libnfs"
    "--disable-libssh"
    "--disable-smartcard"
    "--disable-vhost-net"
    "--enable-fdt=system"
    "--audio-drv-list="
    "--enable-pie"
  ];
  qemuConfigureFlagsMaterial = builtins.concatStringsSep "\n" qemuConfigureFlags;
  qemuConfigureFlagsHash = builtins.hashString "sha256" "${qemuConfigureFlagsMaterial}\n";
  qemuConfigureFlagsScript = builtins.concatStringsSep " \\\n            " qemuConfigureFlags;
  qemuBuildIdentityMaterial = ''
    qemu_package=${pname}
    qemu_version=${version}
    qemu_source_hash=${series.qemuSourceHash}
    qemu_nix_hash=${qemuNixHash}
    qemu_configure_flags_hash=${qemuConfigureFlagsHash}
    qemu_configure_target_list=x86_64-softmmu,aarch64-softmmu
    qemu_patch_count=${toString patchCount}
    qemu_patch_series_hash=${patchSeriesHash}
    qemu_patch_branch_ref=${series.patchBranchRef}
    qemu_patch_branch_model=${series.patchBranchModel}
    qemu_patch_branch_bundle_hash=${patchBranchBundleHash}
    qemu_patch_branch_base_commit=${series.patchBranchBaseCommit}
    qemu_patch_branch_base_tree=${series.patchBranchBaseTree}
    qemu_patch_branch_head_commit=${series.patchBranchHeadCommit}
    qemu_patch_branch_material_hash=${patchBranchMaterialHash}
    qemu_plugins_enabled=${
      if enablePlugins
      then "true"
      else "false"
    }
    qemu_crucible_patches_applied=${
      if applyCruciblePatches
      then "true"
      else "false"
    }
    qemu_sim_capability=${qemuSimCapability}
    qemu_shmem_abi_version=${shmemAbiVersion}
    qemu_shmem_abi=${shmemAbi}
    qemu_shmem_header=${shmemHeaderInstallPath}
    qemu_shmem_header_hash=${shmemHeaderHash}
    qemu_test_mutation_hash=${testMutationHash}
  '';
  qemuBuildIdentity = builtins.hashString "sha256" qemuBuildIdentityMaterial;
  patchCommand = file: "      patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < ${patchPath file}\n";
  patchPhase =
    if applyCruciblePatches
    then
      builtins.concatStringsSep "" (map patchCommand series.patchFiles)
      + (
        if testOnlyPostPatch == null
        then ""
        else "      patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < ${testOnlyPostPatch}\n"
      )
    else "";
in
  assert _testArtifactPolicy == null;
  assert _testMutationPolicy == null;
    mkDerivation {
      inherit pname;
      inherit version;

      src = fetchurl {
        urls = [
          "https://download.qemu.org/qemu-${version}.tar.xz"
        ];
        hash = series.qemuSourceHash;
      };

      buildDeps = [
        gnumake
        pkg-config
        meson
        ninja
        python3
        setuptools
        distlib
        glib.dev
        glib.tools
      ];
      runtimeDeps = [
        glib
        pixman
        zlib
        libslirp
        dtc
      ];
      propagatedDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd qemu-${version}
            mkdir -p include/aos/crucible
            cp ${shmemGeneratedHeader} include/aos/crucible/crucible_shmem_abi.h
            grep -q '#define CRUCIBLE_SHMEM_ABI_VERSION ${shmemAbiVersion}u' \
              include/aos/crucible/crucible_shmem_abi.h
            cat > "$TMPDIR/qemu-crucible-shmem-abi-probe.c" <<'EOF'
            #include <aos/crucible/crucible_shmem_abi.h>

            #ifndef CRUCIBLE_SHMEM_ABI_VERSION
            #error "qemu-crucible generated shmem header must expose an ABI version"
            #endif

            #if CRUCIBLE_SHMEM_ABI_VERSION != CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION
            #error "qemu-crucible generated shmem header ABI version drifted"
            #endif

            CRUCIBLE_SHMEM_STATIC_ASSERT(
                sizeof(crucible_shmem_region_header) == CRUCIBLE_SHMEM_REGION_HEADER_SIZE,
                "qemu-crucible region header layout");
            CRUCIBLE_SHMEM_STATIC_ASSERT(
                offsetof(crucible_shmem_frame_entry, data) == CRUCIBLE_SHMEM_FRAME_ENTRY_DATA_OFFSET,
                "qemu-crucible frame data offset");

            int qemu_crucible_shmem_abi_probe(void)
            {
                return (int)CRUCIBLE_SHMEM_ABI_VERSION;
            }
            EOF
            cc -std=c11 -Iinclude \
              -DCRUCIBLE_EXPECTED_SHMEM_ABI_VERSION=${shmemAbiVersion} \
              -c "$TMPDIR/qemu-crucible-shmem-abi-probe.c" \
              -o "$TMPDIR/qemu-crucible-shmem-abi-probe.o"
            ${patchPhase}
            # Patch Python shebangs for Nix sandbox
            find . -type f -name '*.py' | while read f; do
              if head -1 "$f" | grep -q '^#!'; then
                sed -i "1s|#!/usr/bin/env python3|#!${python3}/bin/python3|" "$f"
                sed -i "1s|#!/usr/bin/python3|#!${python3}/bin/python3|" "$f"
              fi
            done
          '';
        }
        {
          name = "configure";
          script = ''
            export PYTHONPATH="${meson}/lib/python3/site-packages:${distlib}/lib/python3.14/site-packages:${setuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

            ./configure \
              --prefix=$out \
              --extra-cflags='-DQEMU_CRUCIBLE_BUILD_ID="${qemuBuildIdentity}" -DQEMU_CRUCIBLE_PATCH_SERIES_HASH="${patchSeriesHash}" -DQEMU_CRUCIBLE_SHMEM_HEADER_HASH="${shmemHeaderHash}"' \
              ${qemuConfigureFlagsScript}
          '';
        }
        {
          name = "build";
          script = ''
            make -j$NIX_BUILD_CORES
          '';
        }
        {
          name = "check";
          script =
            if applyCruciblePatches
            then ''
              build/tests/unit/test-rcu-list --tap -p /rcu/hot-fork/barrier
              build/tests/unit/test-aio --tap -p /aio/hot-fork/bh-timer-barrier
              build/tests/unit/test-block-backend --tap -p /block-backend/hot_fork_barrier
              build/tests/unit/test-block-backend --tap -p /block-backend/hot_fork_graph_writer_waits
            ''
            else ''
              true
            '';
        }
        {
          name = "install";
          script = ''
            make install

            if [ -f include/qemu/qemu-plugin.h ]; then
              mkdir -p "$out/include/qemu"
              install -m 644 include/qemu/qemu-plugin.h "$out/include/qemu/qemu-plugin.h"
            fi
            mkdir -p "$out/include/aos/crucible"
            install -m 644 include/aos/crucible/crucible_shmem_abi.h \
              "$out/${shmemHeaderInstallPath}"

            # Create qemu-kvm symlink for compatibility
            if [ -f "$out/bin/qemu-system-x86_64" ]; then
              ln -s qemu-system-x86_64 "$out/bin/qemu-kvm"
            fi

            mkdir -p "$out/share/aos/crucible"
            cat > "$out/share/aos/crucible/qemu-build-identity.env" <<'QEMU_BUILD_IDENTITY'
            qemu_package=${pname}
            qemu_version=${version}
            qemu_source_hash=${series.qemuSourceHash}
            qemu_nix_hash=${qemuNixHash}
            qemu_configure_flags_hash=${qemuConfigureFlagsHash}
            qemu_configure_target_list=x86_64-softmmu,aarch64-softmmu
            qemu_patch_count=${toString patchCount}
            qemu_patch_series_hash=${patchSeriesHash}
            qemu_patch_branch_ref=${series.patchBranchRef}
            qemu_patch_branch_model=${series.patchBranchModel}
            qemu_patch_branch_bundle_hash=${patchBranchBundleHash}
            qemu_patch_branch_base_commit=${series.patchBranchBaseCommit}
            qemu_patch_branch_base_tree=${series.patchBranchBaseTree}
            qemu_patch_branch_head_commit=${series.patchBranchHeadCommit}
            qemu_patch_branch_material_hash=${patchBranchMaterialHash}
            qemu_plugins_enabled=${
              if enablePlugins
              then "true"
              else "false"
            }
            qemu_crucible_patches_applied=${
              if applyCruciblePatches
              then "true"
              else "false"
            }
            qemu_sim_capability=${qemuSimCapability}
            qemu_shmem_abi_version=${shmemAbiVersion}
            qemu_shmem_abi=${shmemAbi}
            qemu_shmem_header=${shmemHeaderInstallPath}
            qemu_shmem_header_hash=${shmemHeaderHash}
            qemu_combined_work_license=GPL-2.0-only
            qemu_unmarked_source_default_license=GPL-2.0-or-later
            qemu_plugin_header_license=GPL-2.0-or-later
            qemu_shmem_header_license_option=MIT
            qemu_build_id=${qemuBuildIdentity}
            QEMU_BUILD_IDENTITY

            mkdir -p "$out/share/licenses/${pname}"
            install -m 644 COPYING "$out/share/licenses/${pname}/COPYING"
            install -m 644 LICENSE "$out/share/licenses/${pname}/LICENSE"
            install -m 644 ${../../LICENSES/GPL-2.0-or-later.txt} \
              "$out/share/licenses/${pname}/GPL-2.0-or-later.txt"
            install -m 644 ${../../LICENSES/MIT.txt} \
              "$out/share/licenses/${pname}/MIT.txt"
            ${lib.optionalString applyCruciblePatches ''
              install -m 644 ${./qemu-patches/LICENSES.md} \
                "$out/share/licenses/${pname}/AOS-PATCH-LICENSES.md"
            ''}
            cat > "$out/share/licenses/${pname}/AOS-MODIFICATIONS" <<'MODIFICATIONS'
            AOS package: ${pname}
            Upstream version: ${version}
            Modified QEMU: ${
              if applyCruciblePatches
              then "yes"
              else "no"
            }
            Ordered patch count: ${toString patchCount}
            Patch series identity: ${patchSeriesHash}
            ${
              if testOnlyNonDistributable
              then "Distribution status: non-distributable compatibility-test material"
              else "Corresponding source package: qemu-crucible-source"
            }
            QEMU combined work: GPL-2.0-only
            Unmarked QEMU source default: GPL-2.0-or-later
            Installed qemu-plugin.h: GPL-2.0-or-later
            Installed crucible_shmem_abi.h: MIT option of MIT OR Apache-2.0
            MODIFICATIONS
            ${lib.optionalString applyCruciblePatches ''
              mkdir -p "$out/nix-support"
              cat > "$out/nix-support/aos-release-policy" <<'RELEASE_POLICY'
              policy_version=1
              artifact_role=internal-component
              standalone_release=false
              release_via=${
                if testOnlyNonDistributable
                then "none-test-only"
                else "crucible"
              }
              corresponding_source_required=true
              corresponding_source_identity=${qemuBuildIdentity}
              publishable=${
                if testOnlyNonDistributable
                then "false"
                else "via-aggregate-only"
              }
              RELEASE_POLICY
            ''}
          '';
        }
      ];

      passthru = {
        standaloneRelease = !applyCruciblePatches && !testOnlyNonDistributable;
        inherit testOnlyNonDistributable;
        releaseVia =
          if applyCruciblePatches && !testOnlyNonDistributable
          then "crucible"
          else null;
        inherit
          qemuBuildIdentity
          qemuBuildIdentityMaterial
          qemuSimCapability
          qemuConfigureFlags
          qemuConfigureFlagsHash
          qemuConfigureFlagsMaterial
          qemuNixHash
          shmemAbi
          shmemAbiVersion
          shmemGeneratedHeader
          shmemHeaderHash
          shmemHeaderInstallPath
          patchBranchBundleHash
          patchBranchCommits
          patchBranchMaterial
          patchBranchMaterialHash
          patchSeriesHash
          patchSeriesHashMaterial
          series
          ;
      };

      checks = {
        testing,
        self,
        pkgs,
      }:
        if pname == "qemu-crucible"
        then let
          patchMicrotests = import ../../tests/crucible/phase2-patch-microtests.nix {
            inherit pkgs lib;
            qemuPackage = self;
            attrPath = "checks.integration.qemu-crucible-patch-microtests";
            taskIds = ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"];
            openTaskIds = [];
          };
        in {
          patch-microtests = patchMicrotests;
          qemu-inert = import ../../tests/crucible/phase2-qemu-inert.nix {
            inherit pkgs lib;
            inherit patchMicrotests;
            patchedQemu = self;
            referenceQemu = pkgs.qemu-crucible-reference;
            attrPath = "checks.integration.qemu-crucible-qemu-inert";
            taskIds = ["T-PLAN-3" "T-DET-23" "T-HARN-21" "T-PATCH-3"];
            openTaskIds = [];
            dependencies = [patchMicrotests];
          };
        }
        else {};

      meta = {
        description = "qemu — machine emulator and virtualizer (minimal KVM build)";
        homepage = "https://www.qemu.org";
        license = ["GPL-2.0-only" "GPL-2.0-or-later" "MIT" "BSD-2-Clause" "BSD-3-Clause"];
      };
    }
