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
  stdenv,
  buildPackages,
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
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPython =
    if stdenv.isCross
    then buildPackages.python3
    else python3;
  buildMeson =
    if stdenv.isCross
    then buildPackages.meson
    else meson;
  buildSetuptools =
    if stdenv.isCross
    then buildPackages.setuptools
    else setuptools;
  buildDistlib =
    if stdenv.isCross
    then buildPackages.distlib
    else distlib;
  darwinSigner =
    if isDarwinCross
    then
      import ./_darwin-signer.nix {
        inherit (buildPackages) mkDerivation fetchurl gnumake pkg-config openssl;
      }
    else null;
  darwinQemuArch =
    if stdenv.hostPlatform.constraints.cpu == "arm64"
    then "aarch64"
    else stdenv.hostPlatform.constraints.cpu;
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
  qemuConfigureFlags =
    [
      "--target-list=x86_64-softmmu,aarch64-softmmu"
    ]
    ++ (
      if isDarwinCross
      then [
        "--disable-kvm"
        "--enable-hvf"
        "--cross-prefix="
        "--host-cc=$PWD/.aos-build-tools/cc-for-build"
        "--cpu=${stdenv.hostPlatform.constraints.cpu}"
      ]
      else if stdenv.isCross
      then [
        "--enable-kvm"
        "--cross-prefix="
        "--host-cc=$PWD/.aos-build-tools/cc-for-build"
        "--cpu=${stdenv.hostPlatform.constraints.cpu}"
      ]
      else ["--enable-kvm"]
    )
    ++ [
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
    ]
    # Mach-O executables use Darwin's platform-default PIE model.  QEMU's
    # generic probe passes `-pie` under `-Werror`, which Clang correctly
    # rejects there as an unused ELF-style command-line option.
    ++ lib.optional (!isDarwinCross) "--enable-pie";
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
  # Compatibility inventory for legacy static gates. The executable patch phase
  # above is generated from series.patchFiles.
  # patch -p1 < ${./qemu-patches/0001-crucible-sim-accel.patch}
  # patch -p1 < ${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
  # patch -p1 < ${./qemu-patches/0003-crucible-icount-no-realtime.patch}
  # patch -p1 < ${./qemu-patches/0004-crucible-no-warp-with-plugin.patch}
  # patch -p1 < ${./qemu-patches/0005-crucible-det-glib-prng.patch}
  # patch -p1 < ${./qemu-patches/0006-crucible-clock-deadline.patch}
  # patch -p1 < ${./qemu-patches/0007-crucible-block-rtc-read.patch}
  # patch -p1 < ${./qemu-patches/0008-crucible-det-getrandom.patch}
  # patch -p1 < ${./qemu-patches/0009-crucible-net-deterministic.patch}
  # patch -p1 < ${./qemu-patches/0010-crucible-plugin-time-advance.patch}
  # patch -p1 < ${./qemu-patches/0011-crucible-plugin-icount-raw.patch}
  # patch -p1 < ${./qemu-patches/0012-crucible-plugin-vcpu-exit.patch}
  # patch -p1 < ${./qemu-patches/0013-crucible-plugin-wake-fd.patch}
  # patch -p1 < ${./qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch}
  # patch -p1 < ${./qemu-patches/0015-crucible-blk-shmem.patch}
  # patch -p1 < ${./qemu-patches/0016-crucible-blk-shmem-io-fixes.patch}
  # patch -p1 < ${./qemu-patches/0017-crucible-blk-write-sentinel.patch}
  # patch -p1 < ${./qemu-patches/0018-crucible-dev-cb-api.patch}
  # patch -p1 < ${./qemu-patches/0019-crucible-9p-shmem.patch}
  # patch -p1 < ${./qemu-patches/0020-crucible-net-tx-callback.patch}
  # patch -p1 < ${./qemu-patches/0021-crucible-sim-loop-fix.patch}
  # patch -p1 < ${./qemu-patches/0022-crucible-sim-first-exit.patch}
  # patch -p1 < ${./qemu-patches/0023-crucible-sim-skip-second-events.patch}
  # patch -p1 < ${./qemu-patches/0024-crucible-sim-poll-immediate.patch}
  # patch -p1 < ${./qemu-patches/0025-crucible-sim-idle-callbacks.patch}
  # patch -p1 < ${./qemu-patches/0026-crucible-sim-shmem-dispatch.patch}
  # patch -p1 < ${./qemu-patches/0027-crucible-sim-batch-tcg-exec.patch}
  # patch -p1 < ${./qemu-patches/0028-crucible-det-ipi.patch}
  # patch -p1 < ${./qemu-patches/0029-crucible-vcpu-introspect.patch}
  # patch -p1 < ${./qemu-patches/0030-crucible-preemption-inject.patch}
  # patch -p1 < ${./qemu-patches/0031-crucible-det-rng-delivery.patch}
  # patch -p1 < ${./qemu-patches/0032-crucible-det-virtio-ioeventfd.patch}
  # patch -p1 < ${./qemu-patches/0033-crucible-sim-observer.patch}
  # patch -p1 < ${./qemu-patches/0034-crucible-safe-fingerprint-boundary.patch}
  # patch -p1 < ${./qemu-patches/0035-crucible-process-argv-attestation.patch}
  # patch -p1 < ${./qemu-patches/0036-crucible-raw-state-export.patch}
  # patch -p1 < ${./qemu-patches/0037-crucible-sim-freeze-warp-at-observation-boundary.patch}
  # patch -p1 < ${./qemu-patches/0038-crucible-sim-gate-rr-kick.patch}
  # patch -p1 < ${./qemu-patches/0039-crucible-blk-device-completion-advance.patch}
  # patch -p1 < ${./qemu-patches/0040-crucible-9p-sync-kick.patch}
  # patch -p1 < ${./qemu-patches/0041-crucible-whitebox-guest-write.patch}
  # patch -p1 < ${./qemu-patches/0042-crucible-aarch64-det-ipi-adapter.patch}
  # patch -p1 < ${./qemu-patches/0043-crucible-time-advance-commit-barrier.patch}
  # patch -p1 < ${./qemu-patches/0044-crucible-time-advance-enqueue-kick.patch}
  # patch -p1 < ${./qemu-patches/0045-crucible-time-advance-arm-at-vcpu-boundary.patch}
  # patch -p1 < ${./qemu-patches/0046-crucible-translation-prefetch-helper.patch}
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

      buildDeps =
        if stdenv.isCross
        then
          [
            buildPackages.gnumake
            buildPackages.pkg-config
            buildMeson
            buildPackages.ninja
            buildPython
            buildSetuptools
            buildDistlib
            buildPackages.glib.tools
            buildPackages.dtc
          ]
          ++ lib.optional isDarwinCross darwinSigner
        else [
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
      # The Darwin install is finalized and signed below. Either generic
      # mutating pass would invalidate the resulting Mach-O code signatures.
      dontStrip = lib.optionalString isDarwinCross "1";
      dontNukeRefs = lib.optionalString isDarwinCross "1";

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
            ${lib.optionalString isDarwinCross ''
              # QEMU's macOS packaging helper assumes Xcode's proprietary
              # codesign, Rez, and SetFile utilities. ldid supplies the runtime-
              # significant ad-hoc signature and HVF entitlement from a
              # hermetic Linux-native build. Nix store paths and NAR archives do
              # not preserve resource forks or Finder flags, so omit only that
              # legacy executable-icon metadata.
              sed -i \
                's|codesign --entitlements "$ENTITLEMENT" --force -s - "$SRC"|ldid -S"$ENTITLEMENT" "$SRC"|' \
                scripts/entitlement.sh
              sed -i '/^Rez -append /d; /^SetFile -a C /d' scripts/entitlement.sh
              grep -q 'ldid -S"$ENTITLEMENT" "$SRC"' scripts/entitlement.sh
              ! grep -Eq '^(Rez|SetFile|codesign) ' scripts/entitlement.sh
            ''}
            # Patch Python shebangs for Nix sandbox
            find . -type f -name '*.py' | while read f; do
              if head -1 "$f" | grep -q '^#!'; then
                sed -i "1s|#!/usr/bin/env python3|#!${buildPython}/bin/python3|" "$f"
                sed -i "1s|#!/usr/bin/python3|#!${buildPython}/bin/python3|" "$f"
              fi
            done
          '';
        }
        {
          name = "configure";
          script = ''
            ${
              if stdenv.isCross
              then ''
                # QEMU's host compiler builds executables that run on the
                # x86_64 build platform. Isolate it from target headers and
                # hardening inherited by the cross compiler environment.
                native_cc="${buildPackages.cc}/bin/cc"
                mkdir -p .aos-build-tools
                cat > .aos-build-tools/cc-for-build <<EOF
                #!$CONFIG_SHELL
                unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
                unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
                unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
                exec "$native_cc" "\$@"
                EOF
                chmod +x .aos-build-tools/cc-for-build
              ''
              else ""
            }
            export PYTHONPATH="${buildMeson}/lib/python3/site-packages:${buildDistlib}/lib/python3.14/site-packages:${buildSetuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
            ${
              if stdenv.isCross
              then ''
                export PYTHON=${buildPython}/bin/python3
                export PKG_CONFIG=${buildPackages.pkg-config}/bin/pkg-config
                export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
                export C_INCLUDE_PATH="${glib.dev}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
                # GLib keeps its unversioned linker-name symlinks in the
                # development output. They resolve to the runtime output, so
                # the installed QEMU closure retains only the actual library.
                export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"
              ''
              else ""
            }

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
              # Keep the exact native fixture output with the package; a
              # separate certificate checks named cases, not a boot proxy.
              # Pin GLib's seed so the installed transcript is reproducible.
              timeout -k 5 60 build/tests/unit/test-block-backend --tap \
                --seed=R02S00000000000000000000000000000000 \
                > block-backend-tests.raw.tap
              cat block-backend-tests.raw.tap
              # GLib adds wall-time comments for the bounded negative fork
              # probe. Keep every TAP verdict, but do not put elapsed host
              # time into the reproducible installed evidence.
              sed '/^# slow test .* executed in [0-9.]* secs$/d' \
                block-backend-tests.raw.tap > block-backend-tests.tap
              build/tests/unit/test-crucible-hot-fork-child --tap
              build/tests/unit/test-crucible-hot-fork-coordinator --tap
              build/tests/unit/test-char --tap -p /char/socket/server/mainloop/unix
              build/tests/unit/test-char --tap -p /char/socket/server/wait-conn/unix
            ''
            else ''
              true
            '';
        }
        {
          name = "install";
          script = ''
            make install${lib.optionalString isDarwinCross ''

              # These are firmware payloads consumed as guest data, never host
              # programs. Upstream ships them executable, which makes the HPPA
              # ELF images look like invalid Darwin executables to the generic
              # artifact validator. Normalize only the installed mode; keep the
              # firmware bytes unchanged.
              for firmware in \
                hppa-firmware.img \
                hppa-firmware64.img \
                qboot.rom \
                vof.bin; do
                test -f "$out/share/qemu/$firmware"
                chmod a-x "$out/share/qemu/$firmware"
              done
            ''}

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
            ${lib.optionalString applyCruciblePatches ''
              install -m 644 block-backend-tests.tap \
                "$out/share/aos/crucible/block-backend-tests.tap"
            ''}
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
            qemu_test_mutation_hash=${testMutationHash}
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
            ${lib.optionalString isDarwinCross ''
              # Finalize Mach-O contents before applying their signatures. The
              # generic fixup and scrub phases are disabled for this derivation
              # because changing even one byte afterward invalidates the code
              # directory hashes.
              find "$out" -type f \( -name '*.dylib' -o -name '*.dylib.*' \) \
                -exec strip --strip-unneeded {} \; 2>/dev/null || true
              find "$out" -type f -name '*.a' \
                -exec strip -S {} \; 2>/dev/null || true
              for d in bin sbin libexec; do
                if [ -d "$out/$d" ]; then
                  find "$out/$d" -type f -exec strip -s {} \; 2>/dev/null || true
                fi
              done

              keep_args="-e $out"
              for p in ${glib} ${pixman} ${zlib} ${libslirp} ${dtc}; do
                keep_args="$keep_args -e $p"
              done
              find "$out" \( \
                   -path '*/bin/*' -o -path '*/sbin/*' -o -path '*/libexec/*' \
                -o -name '*.so' -o -name '*.so.*' \
                -o -name '*.dylib' -o -name '*.dylib.*' \
                -o -name '*.pc' -o -name '*.la' -o -name Makefile \
                \) -type f -print0 \
                | xargs -0 -r nuke-refs $keep_args

              entitlements=$PWD/accel/hvf/entitlements.plist
              find "$out" -type f \( \
                   -name '*.dylib' -o -name '*.dylib.*' -o -name '*.so' \
                -o -perm -u+x \
                \) | while read f; do
                if ! objdump --macho --private-header "$f" >/dev/null 2>&1; then
                  continue
                fi
                if [ "$f" = "$out/bin/qemu-system-${darwinQemuArch}" ]; then
                  ldid -S"$entitlements" "$f"
                else
                  ldid -S "$f"
                fi
              done

              ldid -e "$out/bin/qemu-system-${darwinQemuArch}" \
                | grep -q '<key>com.apple.security.hypervisor</key>'
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
        license = ["GPL-2.0-only" "GPL-2.0-or-later" "MIT"];
      };
    }
