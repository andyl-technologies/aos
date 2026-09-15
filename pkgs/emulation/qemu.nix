##! qemu — Minimal QEMU for KVM-accelerated virtual machines (headless)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  perl,
  pkg-config,
  meson,
  ninja,
  python3,
  python3-pygdbmi,
  setuptools,
  distlib,
  glib,
  pixman,
  zlib,
  libslirp,
  samba-smbd,
  dtc,
  libcap-ng,
  libusb1,
  libgcrypt,
  gnutls,
  fuse3,
  stdenv,
  buildPackages,
  pname ? "qemu",
  enablePlugins ? false,
  applyCruciblePatch ? false,
  testOnlyNonDistributable ? false,
  fullUpstreamTestSuiteOnly ? false,
  atomicPatch ? import ./qemu-patches/_atomic-patch.nix,
}: let
  _testArtifactPolicy =
    if testOnlyNonDistributable && !applyCruciblePatch
    then throw "test-only QEMU artifacts require the tracked Crucible atomic patch"
    else null;
  _fullTestSuitePolicy =
    if fullUpstreamTestSuiteOnly && (!applyCruciblePatch || !testOnlyNonDistributable)
    then throw "the full patched-QEMU test suite must be a non-distributable Crucible test artifact"
    else null;
  version = atomicPatch.qemuVersion;
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
  buildPygdbmi =
    if stdenv.isCross
    then buildPackages.python3-pygdbmi
    else python3-pygdbmi;
  buildBash =
    if stdenv.isCross
    then buildPackages.bash
    else bash;
  buildPerl =
    if stdenv.isCross
    then buildPackages.perl
    else perl;
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
  atomicPatchPath = patchDir + "/${atomicPatch.file}";
  atomicPatchHash = let
    actual = builtins.hashFile "sha256" atomicPatchPath;
  in
    if actual == atomicPatch.sha256
    then actual
    else throw "QEMU atomic patch hash drifted: ${actual}";
  patchBranchBundleHash = let
    actual = builtins.hashFile "sha256" atomicPatch.bundle;
  in
    if actual == atomicPatch.bundleSha256
    then actual
    else throw "QEMU patch branch bundle hash drifted: ${actual}";
  atomicPatchCommit = {
    inherit
      (atomicPatch)
      file
      commit
      tree
      subject
      ;
  };
  patchBranchMaterial = builtins.toJSON {
    inherit
      (atomicPatch)
      branchRef
      branchModel
      bundleSha256
      baseCommit
      baseTree
      ;
    inherit atomicPatchCommit;
  };
  patchBranchMaterialHash = builtins.hashString "sha256" patchBranchMaterial;
  qemuNixHash = builtins.hashFile "sha256" ./qemu.nix;
  shmemLib = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  shmemGeneratedHeader = ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  shmemHeaderInstallPath = "include/aos/crucible/crucible_shmem_abi.h";
  shmemHeaderHash = builtins.hashFile "sha256" shmemGeneratedHeader;
  qemuSimCapability =
    if applyCruciblePatch
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
  sambaSmbdExecutable = "sbin/smbd";
  sambaSmbdConfigureFlag = "--smbd=${samba-smbd}/${sambaSmbdExecutable}";
  normalizeSambaSmbdConfigureFlag = executable: flag: let
    expectedFlag = "--smbd=${samba-smbd}/${executable}";
  in
    if flag == expectedFlag
    then "--smbd=@aos-samba-smbd@/${executable}"
    else if lib.hasPrefix "--smbd=" flag
    then throw "unexpected QEMU smbd configure flag: ${flag}"
    else flag;
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
      "--disable-download"
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
      "--disable-usb-redir"
      "--disable-vde"
      "--disable-libnfs"
      "--disable-libssh"
      "--disable-smartcard"
      "--enable-fdt=system"
      "--audio-drv-list="
    ]
    ++ lib.optionals (!isDarwinCross) [
      "--enable-cap-ng"
      "--enable-libusb"
      "--disable-nettle"
      "--enable-gcrypt"
      "--enable-gnutls"
      "--enable-vhost-net"
      "--enable-fuse"
      "--enable-slirp-smbd"
      sambaSmbdConfigureFlag
    ]
    ++ lib.optionals isDarwinCross [
      "--disable-cap-ng"
      "--disable-libusb"
      "--disable-nettle"
      "--disable-gcrypt"
      "--disable-gnutls"
      "--disable-vhost-net"
      "--disable-fuse"
    ]
    # Mach-O executables use Darwin's platform-default PIE model.  QEMU's
    # generic probe passes `-pie` under `-Werror`, which Clang correctly
    # rejects there as an unused ELF-style command-line option.
    ++ lib.optional (!isDarwinCross) "--enable-pie";
  qemuConfigureIdentityFlags =
    map (normalizeSambaSmbdConfigureFlag sambaSmbdExecutable) qemuConfigureFlags;
  qemuConfigureFlagsMaterial = builtins.concatStringsSep "\n" qemuConfigureFlags;
  sambaSmbdRecipeHash = builtins.hashString "sha256" ''
    samba.nix=${builtins.hashFile "sha256" ../networking/samba.nix}
    samba-smbd.nix=${builtins.hashFile "sha256" ../networking/samba-smbd.nix}
  '';
  sambaSmbdVersion = lib.optionalString (!isDarwinCross) samba-smbd.version;
  sambaSmbdSourceHash = lib.optionalString (!isDarwinCross) samba-smbd.src.outputHash;
  sambaSmbdSourceHashAlgo =
    lib.optionalString (!isDarwinCross) samba-smbd.src.outputHashAlgo;
  qemuConfigureIdentityMaterial = ''
    ${builtins.concatStringsSep "\n" qemuConfigureIdentityFlags}
    ${lib.optionalString (!isDarwinCross) ''
      samba_smbd_version=${sambaSmbdVersion}
      samba_smbd_source_hash_algo=${sambaSmbdSourceHashAlgo}
      samba_smbd_source_hash=${sambaSmbdSourceHash}
      samba_smbd_recipe_hash=${sambaSmbdRecipeHash}
      samba_smbd_executable=${sambaSmbdExecutable}
    ''}
  '';
  qemuConfigureFlagsHash = builtins.hashString "sha256" qemuConfigureIdentityMaterial;
  qemuConfigureFlagsScript = builtins.concatStringsSep " \\\n            " qemuConfigureFlags;
  fullUpstreamTestHarnessMutationMaterial = ''
    mutation_version=1
    mutation_scope=post-build-test-harness-only
    temp_root=$TMPDIR
    qemu_machine_temp_policy=explicit-environment
    migration_stress_temp_policy=explicit-environment
    vfio_guest_temp_policy=/tmp
    guest_shebang_allowlist=tests/functional/aarch64/test_device_passthrough.py:20,60:/bin/bash;tests/lcitool/libvirt-ci/lcitool/ansible/playbooks/update/templates/gitlab-runner.j2:1:/bin/sh
    remaining_var_tmp_allowlist=tests/docker/Makefile.include:container-mount-only
    test_shebang_scope=all-files-under-tests-python-scripts
    test_python=${buildPython}/bin/python3
    test_perl=${buildPerl}/bin/perl
    test_shell=${buildBash}/bin/bash
  '';
  fullUpstreamTestHarnessMutationHash =
    builtins.hashString "sha256" fullUpstreamTestHarnessMutationMaterial;
  qemuBuildIdentityMaterial = ''
    qemu_package=${pname}
    qemu_version=${version}
    qemu_source_hash=${atomicPatch.qemuSourceHash}
    qemu_nix_hash=${qemuNixHash}
    qemu_configure_flags_hash=${qemuConfigureFlagsHash}
    qemu_configure_target_list=x86_64-softmmu,aarch64-softmmu
    qemu_atomic_patch_hash=${atomicPatchHash}
    qemu_patch_branch_ref=${atomicPatch.branchRef}
    qemu_patch_branch_model=${atomicPatch.branchModel}
    qemu_patch_branch_bundle_hash=${patchBranchBundleHash}
    qemu_patch_branch_base_commit=${atomicPatch.baseCommit}
    qemu_patch_branch_base_tree=${atomicPatch.baseTree}
    qemu_patch_branch_head_commit=${atomicPatch.commit}
    qemu_patch_branch_material_hash=${patchBranchMaterialHash}
    qemu_plugins_enabled=${
      if enablePlugins
      then "true"
      else "false"
    }
    qemu_crucible_atomic_patch_applied=${
      if applyCruciblePatch
      then "true"
      else "false"
    }
    qemu_sim_capability=${qemuSimCapability}
    qemu_shmem_abi_version=${shmemAbiVersion}
    qemu_shmem_abi=${shmemAbi}
    qemu_shmem_header=${shmemHeaderInstallPath}
    qemu_shmem_header_hash=${shmemHeaderHash}
  '';
  qemuBuildIdentity = builtins.hashString "sha256" qemuBuildIdentityMaterial;
  patchPhase =
    if applyCruciblePatch
    then "      patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < ${atomicPatchPath}\n"
    else "";
in
  assert _testArtifactPolicy == null;
  assert _fullTestSuitePolicy == null;
    mkDerivation {
      inherit pname;
      inherit version;

      src = fetchurl {
        urls = [
          "https://download.qemu.org/qemu-${version}.tar.xz"
        ];
        hash = atomicPatch.qemuSourceHash;
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
          ++ lib.optionals fullUpstreamTestSuiteOnly [
            buildPygdbmi
            buildBash
            buildPerl
          ]
          ++ lib.optional isDarwinCross darwinSigner
        else
          [
            gnumake
            pkg-config
            meson
            ninja
            python3
            setuptools
            distlib
            glib.dev
            glib.tools
          ]
          ++ lib.optionals fullUpstreamTestSuiteOnly [
            buildPygdbmi
            buildBash
            buildPerl
          ];
      runtimeDeps =
        [
          glib
          pixman
          zlib
          libslirp
          dtc
        ]
        ++ lib.optionals (!isDarwinCross) [
          libcap-ng
          libusb1
          libgcrypt
          gnutls
          fuse3
          samba-smbd
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
            # Rewriting the generator's shebang makes it newer than the
            # release tarball's matching generated option table. Make would
            # otherwise rerun Meson introspection without configure's feature
            # selections, which probes optional compilers such as rustc.
            touch scripts/meson-buildoptions.sh
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
            # QEMU 11 validates pip and wheel before installing its vendored
            # qemu.qmp wheel. AOS Python retains its source-tree ensurepip
            # wheel, while setuptools retains wheel as vendored source.
            # Expose both as system packages to the isolated QEMU venv so its
            # offline install never attempts a PyPI fallback.
            pip_wheel=${buildPython}/lib/python3.14/ensurepip/_bundled/pip-25.3-py3-none-any.whl
            test -f "$pip_wheel"
            export PYTHONPATH="${lib.optionalString fullUpstreamTestSuiteOnly "${buildPygdbmi}/lib/python3.14/site-packages:"}$pip_wheel:${buildSetuptools}/lib/python3.14/site-packages/setuptools/_vendor:${buildMeson}/lib/python3/site-packages:${buildDistlib}/lib/python3.14/site-packages:${buildSetuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
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
              --extra-cflags='-DQEMU_CRUCIBLE_BUILD_ID="${qemuBuildIdentity}" -DQEMU_CRUCIBLE_ATOMIC_PATCH_HASH="${atomicPatchHash}" -DQEMU_CRUCIBLE_SHMEM_HEADER_HASH="${shmemHeaderHash}"' \
              ${qemuConfigureFlagsScript}

            ${lib.optionalString (!isDarwinCross) ''
              test -x ${samba-smbd}/sbin/smbd
              grep -F '#define CONFIG_SMBD_COMMAND "${samba-smbd}/sbin/smbd"' \
                build/config-host.h
            ''}
          '';
        }
        {
          name = "build";
          script = ''
            # decodetree.py iterates field-name sets while generating the ARM
            # translators. Pin Python's hash order so those C inputs and the
            # resulting emulator binaries are byte-reproducible.
            export PYTHONHASHSEED=0
            make -j$NIX_BUILD_CORES
          '';
        }
        {
          name = "full-upstream-test-suite";
          script =
            if fullUpstreamTestSuiteOnly
            then ''
              set -eu

              # Configure and compile from the same patched source as the
              # shipped binary. Only after that build is complete, make the
              # upstream test harness hermetic and record every changed test
              # input independently from qemuBuildIdentity.
              suite_tmp_root="$TMPDIR/qemu-full-upstream-test-suite"
              mkdir -p "$suite_tmp_root"
              export TMPDIR="$suite_tmp_root"

              mutation_manifest=full-upstream-test-suite.mutations.tsv
              printf 'kind\tpath\tbefore_sha256\tafter_sha256\tbefore\tafter\n' \
                > "$mutation_manifest"

              for temp_helper in \
                python/qemu/machine/machine.py \
                python/qemu/machine/qtest.py \
                tests/functional/x86_64/test_acpi_bits.py; do
                test "$(grep -Fc 'base_temp_dir: str = "/var/tmp",' "$temp_helper")" -eq 1
                before_hash=$(sha256sum "$temp_helper" | cut -d ' ' -f 1)
                sed -i \
                  's|base_temp_dir: str = "/var/tmp",|base_temp_dir: str = os.environ["TMPDIR"],|' \
                  "$temp_helper"
                after_hash=$(sha256sum "$temp_helper" | cut -d ' ' -f 1)
                printf 'temp-default\t%s\t%s\t%s\t%s\t%s\n' \
                  "$temp_helper" "$before_hash" "$after_hash" \
                  'base_temp_dir: str = "/var/tmp",' \
                  'base_temp_dir: str = os.environ["TMPDIR"],' \
                  >> "$mutation_manifest"
              done

              constructor_file=tests/functional/qemu_test/testcase.py
              constructor_before='tmp_vm = QEMUMachine(self.qemu_bin)'
              constructor_after='tmp_vm = QEMUMachine(self.qemu_bin, base_temp_dir=os.environ["TMPDIR"])'
              test "$(grep -Fc "$constructor_before" "$constructor_file")" -eq 1
              before_hash=$(sha256sum "$constructor_file" | cut -d ' ' -f 1)
              sed -i "s|$constructor_before|$constructor_after|" "$constructor_file"
              after_hash=$(sha256sum "$constructor_file" | cut -d ' ' -f 1)
              printf 'temp-constructor\t%s\t%s\t%s\t%s\t%s\n' \
                "$constructor_file" "$before_hash" "$after_hash" \
                "$constructor_before" "$constructor_after" \
                >> "$mutation_manifest"

              migration_helper=tests/migration-stress/guestperf/engine.py
              test "$(grep -Fc '/var/tmp/' "$migration_helper")" -eq 3
              before_hash=$(sha256sum "$migration_helper" | cut -d ' ' -f 1)
              sed -i \
                -e 's|uri = "unix:/var/tmp/qemu-migrate-%d.migrate" % os.getpid()|uri = "unix:" + os.path.join(os.environ["TMPDIR"], "qemu-migrate-%d.migrate" % os.getpid())|' \
                -e 's|dstmonaddr = "/var/tmp/qemu-dst-%d-monitor.sock" % os.getpid()|dstmonaddr = os.path.join(os.environ["TMPDIR"], "qemu-dst-%d-monitor.sock" % os.getpid())|' \
                -e 's|srcmonaddr = "/var/tmp/qemu-src-%d-monitor.sock" % os.getpid()|srcmonaddr = os.path.join(os.environ["TMPDIR"], "qemu-src-%d-monitor.sock" % os.getpid())|' \
                "$migration_helper"
              after_hash=$(sha256sum "$migration_helper" | cut -d ' ' -f 1)
              printf 'temp-helper\t%s\t%s\t%s\t%s\t%s\n' \
                "$migration_helper" "$before_hash" "$after_hash" \
                'three host socket paths under /var/tmp' \
                'three host socket paths under os.environ["TMPDIR"]' \
                >> "$mutation_manifest"

              # This functional test names a guest temporary file. Keep that
              # guest path independent of the forbidden host /var/tmp fallback
              # so the executable test inventory contains no ambiguous use.
              vfio_test=tests/functional/x86_64/test_vfio_user_client.py
              test "$(grep -Fc '/var/tmp/gpio.out' "$vfio_test")" -eq 3
              before_hash=$(sha256sum "$vfio_test" | cut -d ' ' -f 1)
              sed -i 's|/var/tmp/gpio.out|/tmp/gpio.out|g' "$vfio_test"
              after_hash=$(sha256sum "$vfio_test" | cut -d ' ' -f 1)
              printf 'guest-temp-path\t%s\t%s\t%s\t%s\t%s\n' \
                "$vfio_test" "$before_hash" "$after_hash" \
                '/var/tmp/gpio.out' '/tmp/gpio.out' \
                >> "$mutation_manifest"

              test -x ${buildPython}/bin/python3
              test -x ${buildPerl}/bin/perl
              test -x ${buildBash}/bin/bash
              # First-line scripts in these trees run on the build host or are
              # sourced by its test runner. The one guest configuration
              # template is excluded here and asserted below with guest paths.
              find tests python scripts -type f \
                -exec grep -IlE '^#![[:space:]]*(/usr/bin/env|/usr/bin/python3|/bin/bash|/bin/sh)' {} + \
                | LC_ALL=C sort \
                | while IFS= read -r test_script; do
                  if test "$test_script" = \
                    tests/lcitool/libvirt-ci/lcitool/ansible/playbooks/update/templates/gitlab-runner.j2; then
                    continue
                  fi
                  first_line=$(head -n 1 "$test_script")
                  case "$first_line" in
                    '#!/usr/bin/env python3'|'#! /usr/bin/env python3'|'#!/usr/bin/python3')
                      replacement='#!${buildPython}/bin/python3'
                      ;;
                    '#!/usr/bin/env python')
                      replacement='#!${buildPython}/bin/python3'
                      ;;
                    '#!/usr/bin/env perl')
                      replacement='#!${buildPerl}/bin/perl'
                      ;;
                    '#!/usr/bin/env bash'|'#!/usr/bin/env sh'|'#!/bin/bash'|'#! /bin/bash'|'#!/bin/sh'|'#! /bin/sh')
                      replacement='#!${buildBash}/bin/bash'
                      ;;
                    '#!/bin/bash -e'|'#!/bin/sh -e')
                      replacement='#!${buildBash}/bin/bash -e'
                      ;;
                    *)
                      continue
                      ;;
                  esac

                  before_hash=$(sha256sum "$test_script" | cut -d ' ' -f 1)
                  sed -i "1c$replacement" "$test_script"
                  after_hash=$(sha256sum "$test_script" | cut -d ' ' -f 1)
                  printf 'shebang\t%s\t%s\t%s\t%s\t%s\n' \
                    "$test_script" "$before_hash" "$after_hash" \
                    "$first_line" "$replacement" \
                    >> "$mutation_manifest"
                done

              # The device-passthrough test writes these two scripts into its
              # guest filesystems. They explicitly use Bash features and the
              # guest launch command already requires Bash, so retain a
              # guest-valid /bin/bash instead of an unavailable store path.
              guest_fixture=tests/functional/aarch64/test_device_passthrough.py
              test "$(grep -xc '#!/usr/bin/env bash' "$guest_fixture")" -eq 2
              before_hash=$(sha256sum "$guest_fixture" | cut -d ' ' -f 1)
              sed -i 's|^#!/usr/bin/env bash$|#!/bin/bash|' "$guest_fixture"
              after_hash=$(sha256sum "$guest_fixture" | cut -d ' ' -f 1)
              printf 'guest-payload-shebang\t%s\t%s\t%s\t%s\t%s\n' \
                "$guest_fixture" "$before_hash" "$after_hash" \
                'two embedded #!/usr/bin/env bash guest payloads' \
                'two embedded #!/bin/bash guest payloads' \
                >> "$mutation_manifest"
              guest_template=tests/lcitool/libvirt-ci/lcitool/ansible/playbooks/update/templates/gitlab-runner.j2
              test "$(head -n 1 "$guest_template")" = '#!/bin/sh'
              guest_template_hash=$(sha256sum "$guest_template" | cut -d ' ' -f 1)
              printf 'guest-payload-allowlist\t%s\t%s\t%s\t%s\t%s\n' \
                "$guest_template" "$guest_template_hash" "$guest_template_hash" \
                '#!/bin/sh' '#!/bin/sh; unchanged guest configuration template' \
                >> "$mutation_manifest"

              forbidden_shebangs=$TMPDIR/forbidden-test-shebangs
              find tests python scripts -type f \
                -exec grep -IlE '^#![[:space:]]*(/usr/bin/env|/usr/bin/python3)' {} + \
                | LC_ALL=C sort > "$forbidden_shebangs"
              if test -s "$forbidden_shebangs"; then
                echo 'executable test inputs retain forbidden host interpreter paths:' >&2
                cat "$forbidden_shebangs" >&2
                exit 1
              fi
              guest_shebangs=$TMPDIR/guest-test-shebangs
              expected_guest_shebangs=$TMPDIR/expected-guest-test-shebangs
              find tests python scripts -type f \
                -exec grep -InHE '^#![[:space:]]*/bin/(ba)?sh([[:space:]].*)?$' {} + \
                | LC_ALL=C sort > "$guest_shebangs"
              printf '%s\n' \
                'tests/functional/aarch64/test_device_passthrough.py:20:#!/bin/bash' \
                'tests/functional/aarch64/test_device_passthrough.py:60:#!/bin/bash' \
                'tests/lcitool/libvirt-ci/lcitool/ansible/playbooks/update/templates/gitlab-runner.j2:1:#!/bin/sh' \
                > "$expected_guest_shebangs"
              if ! diff -u "$expected_guest_shebangs" "$guest_shebangs"; then
                echo 'guest-valid test shebang inventory drifted' >&2
                exit 1
              fi
              ! grep -F '/var/tmp' \
                python/qemu/machine/machine.py \
                python/qemu/machine/qtest.py \
                tests/functional/x86_64/test_acpi_bits.py \
                tests/functional/qemu_test/testcase.py \
                tests/migration-stress/guestperf/engine.py
              remaining_var_tmp=$TMPDIR/remaining-test-var-tmp
              expected_var_tmp=$TMPDIR/expected-test-var-tmp
              find tests python scripts -type f -exec grep -Il '/var/tmp' {} + \
                | LC_ALL=C sort > "$remaining_var_tmp"
              printf '%s\n' tests/docker/Makefile.include > "$expected_var_tmp"
              if ! diff -u "$expected_var_tmp" "$remaining_var_tmp"; then
                echo 'test inputs retain an unclassified /var/tmp path' >&2
                exit 1
              fi
              docker_makefile_hash=$(sha256sum tests/docker/Makefile.include | cut -d ' ' -f 1)
              printf 'allowlist\t%s\t%s\t%s\t%s\t%s\n' \
                tests/docker/Makefile.include \
                "$docker_makefile_hash" "$docker_makefile_hash" \
                '/var/tmp/qemu' 'container mount path; unchanged and not host-executed' \
                >> "$mutation_manifest"

              mutation_manifest_hash=$(sha256sum "$mutation_manifest" | cut -d ' ' -f 1)
              test -n "$mutation_manifest_hash"

              # QEMU 11's check target is generated from Meson's complete
              # configured test inventory. Thorough mode includes the slow,
              # thorough, and optional suites that quick mode filters out.
              # Functional tests must use only assets already present in the
              # source or build tree; absent upstream assets remain explicit
              # skips in the JUnit evidence.
              export QEMU_TEST_NO_DOWNLOAD=1
              if make -j$NIX_BUILD_CORES V=1 SPEED=thorough \
                check-report.junit.xml > full-upstream-test-suite.log 2>&1; then
                suite_status=0
              else
                suite_status=$?
              fi
              cat full-upstream-test-suite.log
              if [ "$suite_status" -ne 0 ]; then
                echo "QEMU's complete configured test target failed with status $suite_status" >&2
                exit "$suite_status"
              fi

              junit=build/check-report.junit.xml
              test -s "$junit"
              ${buildPython}/bin/python3 - "$junit" \
                full-upstream-test-suite.summary \
                full-upstream-test-suite.skipped <<'PYTHON'
              import sys
              import xml.etree.ElementTree as ET

              junit_path, summary_path, skipped_path = sys.argv[1:]
              root = ET.parse(junit_path).getroot()
              cases = list(root.iter("testcase"))

              failed = []
              errored = []
              skipped = []
              for case in cases:
                  name = case.get("name", "<unnamed>")
                  suite = case.get("classname", "<unknown-suite>")
                  qualified_name = f"{suite}::{name}"
                  if case.find("failure") is not None:
                      failed.append(qualified_name)
                  if case.find("error") is not None:
                      errored.append(qualified_name)
                  skip = case.find("skipped")
                  if skip is not None:
                      reason = skip.get("message") or (skip.text or "").strip()
                      reason = " ".join(reason.split()) or "<no-reason>"
                      skipped.append((qualified_name, reason))

              if not cases:
                  raise SystemExit("QEMU test report contains no test cases")
              if failed or errored:
                  raise SystemExit(
                      "QEMU test report is not green: "
                      f"{len(failed)} failed, {len(errored)} errored"
                  )

              passed = len(cases) - len(skipped)
              with open(summary_path, "w", encoding="utf-8") as summary:
                  print(f"tests={len(cases)}", file=summary)
                  print(f"passed={passed}", file=summary)
                  print(f"failed={len(failed)}", file=summary)
                  print(f"errors={len(errored)}", file=summary)
                  print(f"skipped={len(skipped)}", file=summary)

              with open(skipped_path, "w", encoding="utf-8") as skipped_file:
                  for qualified_name, reason in sorted(skipped):
                      print(f"{qualified_name}\t{reason}", file=skipped_file)
              PYTHON
              cat full-upstream-test-suite.summary

              mkdir -p "$out/nix-support" "$out/share/aos/crucible"
              cp full-upstream-test-suite.log \
                "$out/share/aos/crucible/full-upstream-test-suite.log"
              cp full-upstream-test-suite.summary \
                "$out/share/aos/crucible/full-upstream-test-suite.summary"
              cp full-upstream-test-suite.skipped \
                "$out/share/aos/crucible/full-upstream-test-suite.skipped"
              cp build/check-report.junit.xml \
                "$out/share/aos/crucible/full-upstream-test-suite.junit.xml"
              cp build/meson-logs/check-report.txt \
                "$out/share/aos/crucible/full-upstream-test-suite.meson-log.txt"
              cp build/meson-info/intro-tests.json \
                "$out/share/aos/crucible/configured-tests.json"
              cp build/Makefile.mtest \
                "$out/share/aos/crucible/configured-test-targets.mk"
              cp "$mutation_manifest" \
                "$out/share/aos/crucible/full-upstream-test-suite.mutations.tsv"
              cat > "$out/share/aos/crucible/qemu-test-harness-mutation.env" <<'MUTATION'
              ${fullUpstreamTestHarnessMutationMaterial}
              qemu_test_harness_mutation_hash=${fullUpstreamTestHarnessMutationHash}
              MUTATION
              printf 'mutation_manifest_sha256=%s\n' "$mutation_manifest_hash" \
                >> "$out/share/aos/crucible/qemu-test-harness-mutation.env"

              cat > "$out/share/aos/crucible/qemu-build-identity.env" <<'IDENTITY'
              ${qemuBuildIdentityMaterial}
              qemu_build_id=${qemuBuildIdentity}
              qemu_test_harness_mutation_hash=${fullUpstreamTestHarnessMutationHash}
              IDENTITY
              printf 'qemu_test_harness_manifest_hash=%s\n' "$mutation_manifest_hash" \
                >> "$out/share/aos/crucible/qemu-build-identity.env"
              cat > "$out/result" <<'RESULT'
              PASS
              gate=gate:qemu-full-upstream-test-suite
              attr_path=checks.crucible.phase7.qemuFullUpstreamTestSuite
              upstream_runner=make
              upstream_target=check-report.junit.xml
              meson_test_setup=thorough
              selection=all-configured-tests
              functional_asset_policy=no-download
              qemu_test_harness_mutation_hash=${fullUpstreamTestHarnessMutationHash}
              qemu_build_id=${qemuBuildIdentity}
              qemu_version=${version}
              qemu_atomic_patch_hash=${atomicPatchHash}
              RESULT
              printf 'qemu_test_harness_manifest_hash=%s\n' "$mutation_manifest_hash" \
                >> "$out/result"
              cat full-upstream-test-suite.summary >> "$out/result"

              cat > "$out/nix-support/aos-release-policy" <<'RELEASE_POLICY'
              policy_version=1
              artifact_role=test-evidence
              standalone_release=false
              release_via=none-test-only
              corresponding_source_required=false
              publishable=false
              RELEASE_POLICY
            ''
            else ''
              true
            '';
        }
        {
          name = "check";
          script =
            if applyCruciblePatch && !fullUpstreamTestSuiteOnly
            then ''
              build/tests/unit/test-rcu-list --tap -p /rcu/hot-fork/barrier
              build/tests/unit/test-aio --tap -p /aio/hot-fork/async-worker-barrier
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
              build/tests/unit/test-crucible-x86-fingerprint --tap \
                -p /crucible/x86/mmx-empty-tag
              build/tests/unit/test-crucible-acpi-piix-fingerprint --tap \
                --seed=R02S00000000000000000000000000000000 \
                > acpi-fingerprint-tests.tap
              cat acpi-fingerprint-tests.tap
              build/tests/unit/test-crucible-vga-fingerprint --tap \
                --seed=R02S00000000000000000000000000000000 \
                > vga-fingerprint-tests.tap
              cat vga-fingerprint-tests.tap
              build/tests/unit/test-crucible-parallel-fingerprint --tap \
                --seed=R02S00000000000000000000000000000000 \
                > parallel-fingerprint-tests.tap
              cat parallel-fingerprint-tests.tap
              build/tests/unit/test-crucible-fdc-fingerprint --tap \
                --seed=R02S00000000000000000000000000000000 \
                > fdc-fingerprint-tests.tap
              cat fdc-fingerprint-tests.tap
              build/tests/unit/test-crucible-e1000-fingerprint --tap \
                --seed=R02S00000000000000000000000000000000 \
                > e1000-fingerprint-tests.tap
              cat e1000-fingerprint-tests.tap
              test "$(grep -F -x -c \
                '    .crucible_fingerprint_projection = &pci_vga_fingerprint,' \
                hw/display/vga-pci.c)" -eq 1
              test "$(grep -F -x -c \
                '    dc->vmsd = &vmstate_vga_pci;' \
                hw/display/vga-pci.c)" -eq 1
              test "$(grep -F -x -c \
                '    .crucible_fingerprint_projection = &parallel_isa_fingerprint,' \
                hw/char/parallel.c)" -eq 1
              test "$(grep -F -x -c \
                '    dc->vmsd = &vmstate_parallel_isa;' \
                hw/char/parallel.c)" -eq 1
              test "$(grep -F -x -c \
                '    .crucible_fingerprint_projection = &isa_fdc_fingerprint,' \
                hw/block/fdc-isa.c)" -eq 1
              test "$(grep -F -x -c \
                '    dc->vmsd = &vmstate_isa_fdc;' \
                hw/block/fdc-isa.c)" -eq 1
              test "$(grep -F -x -c \
                '    .crucible_fingerprint_projection = &sysbus_fdc_fingerprint,' \
                hw/block/fdc-sysbus.c)" -eq 1
              test "$(grep -F -x -c \
                '    dc->vmsd = &vmstate_sysbus_fdc;' \
                hw/block/fdc-sysbus.c)" -eq 1
              test "$(grep -F -x -c \
                '    .crucible_fingerprint_projection = &e1000_fingerprint,' \
                hw/net/e1000.c)" -eq 1
              test "$(grep -F -x -c \
                '    dc->vmsd = &vmstate_e1000;' \
                hw/net/e1000.c)" -eq 1
              test "$(grep -F -x -c \
                '        if (strcmp(current_accel_name(), "sim") == 0) {' \
                hw/i386/multiboot.c)" -eq 1
              test "$(grep -F -x -c \
                '            mbs.mb_buf = g_malloc0(mb_kernel_size);' \
                hw/i386/multiboot.c)" -eq 1
              test "$(grep -F -x -c \
                '            mbs.mb_buf = g_malloc(mb_kernel_size);' \
                hw/i386/multiboot.c)" -eq 1
              test "$(grep -F -x -c \
                'static TranslationBlock *tb_generate_on_miss(CPUState *cpu,' \
                accel/tcg/cpu-exec.c)" -eq 1
              test "$(grep -F -x -c \
                '                tb = tb_generate_on_miss(cpu, s);' \
                accel/tcg/cpu-exec.c)" -eq 2
              test -f tests/qtest/crucible-translation-prefetch.py
              test "$(grep -F -x -c \
                '        !qemu_plugin_request_time_control() ||' \
                tests/tcg/plugins/crucible-fingerprint-observer.c)" -eq 1
              test "$(grep -F -x -c \
                '    qemu_plugin_register_sim_shmem_dispatch_cb(' \
                tests/tcg/plugins/crucible-fingerprint-observer.c)" -eq 1
              python3 - <<'PYTHON'
              import re
              from pathlib import Path

              rr = Path("accel/tcg/tcg-accel-ops-rr.c").read_text()
              rr_header = Path("accel/tcg/tcg-accel-ops-rr.h").read_text()
              rr_trace = Path("accel/tcg/trace-events").read_text()
              icount = Path("accel/tcg/tcg-accel-ops-icount.c").read_text()
              timer = Path("util/qemu-timer.c").read_text()
              timer_header = Path("include/qemu/timer.h").read_text()
              timer_trace = Path("util/trace-events").read_text()
              aio_test = Path("tests/unit/test-aio.c").read_text()
              ceiling_wait = rr[
                  rr.index("static void rr_crucible_sim_wait_at_dispatch_ceiling"):
                  rr.index("static void rr_crucible_sim_acknowledge_control_boundary")
              ]
              notify = rr[
                  rr.index("void rr_crucible_sim_notify_dispatch_ceiling"):
                  rr.index("void rr_kick_vcpu_thread")
              ]
              kick = rr[
                  rr.index("void rr_kick_vcpu_thread"):
                  rr.index("/*\n * TCG vCPU kick timer")
              ]
              hot_fork_start = rr.index(
                  "int rr_hot_fork_restart_vcpu_thread"
              )
              hot_fork = rr[hot_fork_start:rr.index(
                  "static G_NORETURN void rr_cpu_thread_loop", hot_fork_start
              )]
              start_thread = rr[rr.index("void rr_start_vcpu_thread"):]
              shmem = Path("accel/tcg/tcg-accel-ops-sim-shmem.c").read_text()
              shmem_header = Path(
                  "accel/tcg/tcg-accel-ops-sim-shmem.h"
              ).read_text()
              plugin = Path("plugins/api-system.c").read_text()
              monitor = Path("monitor/qmp-cmds.c").read_text()
              idle_test = Path(
                  "tests/qtest/crucible-idle-wait-liveness.py"
              ).read_text()
              idle_plugin = Path(
                  "tests/tcg/plugins/crucible-idle-wait-liveness.c"
              ).read_text()
              hermetic_qtests = "\n".join(
                  Path(path).read_text()
                  for path in (
                      "tests/qtest/crucible-idle-wait-liveness.py",
                      "tests/qtest/crucible-multiboot-gap.py",
                      "tests/qtest/crucible-translation-prefetch.py",
                  )
              )
              control_complete = plugin[
                  plugin.rindex("static void qemu_plugin_control_boundary_complete_bh"):
                  plugin.rindex("static void qemu_plugin_control_boundary_barrier_bh")
              ]
              request_boundary = plugin[
                  plugin.index("static void qemu_plugin_request_rr_control_boundary"):
                  plugin.index("int qemu_plugin_request_control_boundary")
              ]
              acknowledge_boundary = plugin[
                  plugin.index("void qemu_plugin_crucible_rr_control_boundary_acknowledge"):
                  plugin.index("void qemu_plugin_crucible_rr_control_boundary_cancel")
              ]
              cancel_boundary = plugin[
                  plugin.index("void qemu_plugin_crucible_rr_control_boundary_cancel"):
                  plugin.index("static void qemu_plugin_request_rr_control_boundary")
              ]
              wake_handler = plugin[
                  plugin.index("static void qemu_plugin_wake_fd_read"):
                  plugin.index("int qemu_plugin_register_wake_fd")
              ]
              wake_handler_code = re.sub(
                  r"/\*.*?\*/", "", wake_handler, flags=re.DOTALL
              )
              time_advance_complete = plugin[
                  plugin.index("static void qemu_plugin_time_advance_complete_bh(void *opaque)\n{"):
                  plugin.index("static bool qemu_plugin_release_control_boundary_schedule")
              ]
              time_advance_complete_code = re.sub(
                  r"/\*.*?\*/", "", time_advance_complete, flags=re.DOTALL
              )
              late_test = idle_test[
                  idle_test.index("def run_late_ceiling_test"):
                  idle_test.index("def main")
              ]
              vmstop_test = idle_test[
                  idle_test.index("def run_vmstop_at_ceiling_test"):
                  idle_test.index("def run_late_ceiling_test")
              ]
              time_advance_test = idle_test[
                  idle_test.index("def run_time_advance_reentry_test"):
                  idle_test.index("def run_hlt_at_ceiling_test")
              ]
              time_advance_idle_callback = idle_plugin[
                  idle_plugin.index("static void idle_callback"):
                  idle_plugin.index("static void time_advance_callback")
              ]
              time_advance_plugin_callback = idle_plugin[
                  idle_plugin.index("static void time_advance_callback"):
                  idle_plugin.index("static void resume_callback")
              ]
              time_advance_plugin_install = idle_plugin[
                  idle_plugin.index("QEMU_PLUGIN_EXPORT int qemu_plugin_install"):
              ]
              idle_trace = rr[
                  rr.index("void rr_crucible_sim_trace_idle_advance"):
                  rr.index("void rr_kick_vcpu_thread")
              ]
              timer_callback = timer[
                  timer.index("bool timerlist_run_timers"):
                  timer.index("bool qemu_clock_run_timers")
              ]
              timer_service_complete = timer[
                  timer.index("static void timerlist_crucible_complete_service"):
                  timer.index("static const char *crucible_determinism_timer_scope")
              ]
              timer_service_request = timer[
                  timer.index("bool qemu_clock_crucible_request_due_timer_service"):
                  timer.index("bool qemu_clock_crucible_timer_service_quiescent")
              ]
              timer_service_quiescent = timer[
                  timer.index("bool qemu_clock_crucible_timer_service_quiescent"):
                  timer.index("void timerlist_notify")
              ]
              timer_service_wait = rr[
                  rr.index("static bool rr_crucible_sim_service_due_aio_timers"):
                  rr.index("static void rr_crucible_sim_service_force_shutdown")
              ]

              checks = [
                  ("clamp declaration", shmem_header,
                   r"clamp_cpu_budget\([^;]+max_advance_icount\);", 1),
                  ("clamp implementation", shmem,
                   r"int64_t crucible_sim_shmem_clamp_cpu_budget\("
                   r"[^)]*max_advance_icount\)\s*\{", 1),
                  ("captured clamp calls", rr,
                   r"clamp_cpu_budget\(\s*current_icount,\s*\*?cpu_budget,"
                   r"\s*dispatch_ceiling\)", 2),
                  ("captured dispatch ceiling reads", rr,
                   r"dispatch_ceiling\s*=\s*"
                   r"crucible_sim_shmem_max_advance_icount\(\);", 2),
                  ("exact boundary references", rr,
                   r"rr_crucible_sim_complete_dispatch_boundary\(", 5),
                  ("intermediate-only progress", rr,
                   r"service_after > service_before\s*&&\s*"
                   r"service_after < dispatch_ceiling", 1),
                  ("already-due vmstop fallthrough", rr,
                   r"vmstop_pending\(\)\s*&&\s*!\("
                   r"crucible_sim_shmem_dispatch_registered\(\)\s*&&\s*"
                   r"dispatch_due\)", 2),
                  ("level-triggered dispatch wake", ceiling_wait,
                   r"qemu_event_reset\(&rr_dispatch_ceiling_event\);\s*"
                   r"rr_crucible_sim_complete_wake_boundary\(\);\s*"
                   r"if \(qemu_plugin_crucible_rr_control_boundary_"
                   r"pending\(\)\s*\|\|\s*qemu_force_shutdown_requested\(\)"
                   r"\s*\|\|\s*!runstate_is_running\(\)\s*\|\|\s*"
                   r"rr_crucible_sim_stop_or_unplug_pending\(\)\s*\|\|\s*"
                   r"qemu_plugin_crucible_vmstop_pending\(\)\s*\|\|\s*"
                   r"qemu_plugin_time_advance_is_pending\(\)\) \{\s*"
                   r"return;\s*\}\s*"
                   r"if \(rr_crucible_sim_vcpu_work_pending\(\)\) \{\s*"
                   r"rr_crucible_sim_drain_vcpu_work\(\);\s*continue;\s*\}"
                   r"\s*if \(!wait_traced\) \{\s*"
                   r"trace_crucible_sim_rr_dispatch_ceiling_wait\(\s*"
                   r"qemu_get_thread_id\(\),\s*"
                   r"&rr_dispatch_ceiling_event.value,\s*"
                   r"sizeof\(rr_dispatch_ceiling_event.value\)\);\s*"
                   r"wait_traced = true;\s*\}\s*.*?"
                   r"bql_unlock\(\);\s*"
                   r"qemu_event_wait\(&rr_dispatch_ceiling_event\);\s*"
                   r"bql_lock\(\);",
                   1),
                  ("stale condition dispatch wait", ceiling_wait,
                   r"qemu_cond_(?:timed)?wait_bql", 0),
                  ("owner-published dispatch event", rr,
                   r"if \(wake_state_published\) \{\s*.*?"
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);\s*\}", 1),
                  ("dispatch event notifier", notify,
                   r"qatomic_load_acquire\(&rr_dispatch_ceiling_event_"
                   r"initialized\).*?qemu_event_set\(&rr_dispatch_ceiling_event\)",
                   1),
                  ("dispatch event owners", kick,
                   r"wake_state_published = true;", 1),
                  ("kick producer does not consume wake state", kick,
                   r"rr_crucible_sim_complete_wake_boundary\(\)", 0),
                  ("stateful kick retains idle wake predicate", kick,
                   r"if \(stateful_exit \|\| idle_wake\) \{.*?"
                   r"CPU_FOREACH\(cpu\) \{\s*"
                   r"tcg_kick_vcpu_thread\(cpu\);\s*\}.*?"
                   r"if \(starting_wake\) \{.*?"
                   r"RR_TCG_EXEC_STARTING_WAKE_ARMING,\s*"
                   r"RR_TCG_EXEC_STARTING\);\s*"
                   r"\} else if \(idle_wake\) \{\s*"
                   r"qatomic_cmpxchg\(&rr_tcg_exec_state,\s*"
                   r"RR_TCG_EXEC_IDLE_WAKE_ARMING,\s*"
                   r"RR_TCG_EXEC_IDLE_WAKE_PENDING\);\s*\}", 1),
                  ("dispatch event owner notification", kick,
                   r"if \(wake_state_published\) \{.*?"
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);\s*\}", 1),
                  ("zero-quantum dispatch event notification", kick,
                   r"CPU_FOREACH\(cpu\) \{\s*"
                   r"tcg_kick_vcpu_thread\(cpu\);\s*\};\s*"
                   r"if \(rr_crucible_sim_mode\(\)\) \{\s*.*?"
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);\s*\}", 1),
                  ("dispatch event initialization", start_thread,
                   r"qemu_event_init\(&rr_dispatch_ceiling_event, false\);\s*"
                   r"qatomic_store_release\(&rr_dispatch_ceiling_event_"
                   r"initialized, true\);\s*single_tcg_halt_cond", 1),
                  ("hot-fork dispatch event reinit", hot_fork,
                   r"qemu_event_destroy\(&rr_dispatch_ceiling_event\);\s*"
                   r"qemu_event_init\(&rr_dispatch_ceiling_event, false\);",
                   1),
                  ("lifecycle dispatch event notification", control_complete,
                   r"if \(rr_lifecycle_cancel\) \{\s*"
                   r"qemu_plugin_crucible_rr_control_boundary_cancel\(\);\s*"
                   r"if \(first_cpu\) \{\s*"
                   r"qemu_cond_broadcast\(first_cpu->halt_cond\);\s*"
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);", 1),
                  ("request dispatch event notification", request_boundary,
                   r"qatomic_store_release\("
                   r"&qemu_plugin_rr_control_request_generation,\s*"
                   r"request_generation \+ 1\);\s*"
                   r"/\*\s*\*\s*The durable request must wake a ceiling waiter "
                   r"even if the CPU kick\s*"
                   r"\* coalesces with an already-pending RR wake-state "
                   r"transition\.\s*\*/\s*"
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);\s*"
                   r"rr_crucible_sim_trace_control_boundary\(\s*"
                   r'"request",\s*request_generation \+ 1,\s*'
                   r"acknowledged_generation,\s*"
                   r"qatomic_load_acquire\("
                   r"&qemu_plugin_rr_control_complete_generation\),\s*"
                   r"qatomic_load_acquire\("
                   r"&qemu_plugin_rr_control_schedule_token\)\);\s*"
                   r"qemu_cpu_kick\(first_cpu\);", 1),
                  ("request dispatch event notification count",
                   request_boundary,
                   r"rr_crucible_sim_notify_dispatch_ceiling\(\);", 1),
                  ("paused RR transfer after device notifier fanout",
                   wake_handler_code,
                   r"bool single_threaded_rr = drained && first_cpu &&\s*"
                   r"qemu_plugin_crucible_single_threaded_rr\(\);\s*"
                   r"if \(drained\) \{\s*"
                   r"notifier_list_notify\(&qemu_plugin_wake_notifiers,\s*"
                   r"\(void \*\)\(intptr_t\)"
                   r"QEMU_PLUGIN_WAKE_EVENT_DRAINED\);\s*\}\s*"
                   r"if \(single_threaded_rr &&\s*"
                   r"qemu_plugin_crucible_vmstop_quiesced\(\)\) \{\s*"
                   r"if \(qemu_plugin_crucible_rr_control_boundary_"
                   r"pending\(\)\) \{\s*"
                   r"qemu_plugin_crucible_rr_control_boundary_cancel\(\);\s*"
                   r"\}\s*qemu_plugin_schedule_control_boundary\(\);\s*"
                   r"\} else if \(single_threaded_rr\) \{\s*"
                   r"qemu_plugin_request_rr_control_boundary\(\);\s*"
                   r"\} else if \(drained && first_cpu\) \{\s*"
                   r"qemu_plugin_schedule_control_boundary\(\);", 1),
                  ("stale pre-notifier RR request", wake_handler_code,
                   r"qemu_plugin_request_rr_control_boundary\(\);\s*\}\s*"
                   r"if \(drained\) \{\s*notifier_list_notify", 0),
                  ("single RR request owner in wake handler", wake_handler,
                   r"qemu_plugin_request_rr_control_boundary\(\);", 1),
                  ("time advance direct idle reentry",
                   time_advance_complete_code,
                   r"qatomic_store_release\("
                   r"&qemu_plugin_time_advance_pending, 0\);\s*"
                   r"rr_crucible_sim_trace_idle_advance\("
                   r'"complete", target\);\s*'
                   r"notifier_list_notify\(&qemu_plugin_wake_notifiers,\s*"
                   r"\(void \*\)\(intptr_t\)"
                   r"QEMU_PLUGIN_WAKE_EVENT_DRAINED\);\s*"
                   r"if \(first_cpu\) \{\s*"
                   r"qemu_cpu_kick\(first_cpu\);\s*\}", 1),
                  ("stale time advance generic boundary",
                   time_advance_complete,
                   r"qemu_plugin_schedule_control_boundary\(\);", 0),
                  ("time advance direct reentry oracle", time_advance_test,
                   r"events = \[live.marker\(\), live.marker\(\), "
                   r"live.marker\(\)\].*?"
                   r"events\[:2\] != \[\(\"work\", 0\), "
                   r"\(\"advance\", \(0, target\)\)\].*?"
                   r"events\[2\]\[0\] != \"park\"", 1),
                  ("time advance idle request", time_advance_idle_callback,
                   r"if \(time_advance_target != UINT64_MAX\) \{\s*"
                   r"if \(!atomic_exchange_explicit\("
                   r"&time_advance_requested, true,\s*"
                   r"memory_order_acq_rel\)\) \{\s*"
                   r"if \(qemu_plugin_advance_time_ns\("
                   r"\(int64_t\)time_advance_target\) != 0\) \{\s*"
                   r"_exit\(92\);\s*\}\s*return;\s*\}\s*"
                   r"if \(!atomic_load_explicit\("
                   r"&time_advance_completed,\s*memory_order_acquire\)\) "
                   r"\{\s*return;", 1),
                  ("time advance callback registration",
                   time_advance_plugin_install,
                   r"time-advance-target=.*?"
                   r"qemu_plugin_register_time_advance_cb\("
                   r"time_advance_callback, NULL\) != 0", 1),
                  ("time advance completion marker",
                   time_advance_plugin_callback,
                   r"atomic_store_explicit\(&time_advance_completed, true, "
                   r"memory_order_release\);\s*"
                   r"memcpy\(&marker\[1\], &status, sizeof\(status\)\);\s*"
                   r"memcpy\(&marker\[9\], &target, sizeof\(target\)\);\s*"
                   r"write_marker\(marker, sizeof\(marker\)\);", 1),
                  ("control generation trace bridge", notify,
                   r"void rr_crucible_sim_trace_control_boundary\("
                   r"const char \*phase,\s*uint64_t request_generation,\s*"
                   r"uint64_t ack_generation,\s*"
                   r"uint64_t complete_generation,\s*"
                   r"uintptr_t schedule_token\)\s*\{\s*"
                   r"trace_crucible_sim_rr_control_boundary\(\s*"
                   r"phase,\s*request_generation,\s*ack_generation,\s*"
                   r"complete_generation,\s*schedule_token,\s*"
                   r"qatomic_read\(&rr_tcg_exec_state\)\);\s*\}", 1),
                  ("control generation trace schema", rr_trace,
                   r"crucible_sim_rr_control_boundary\(const char \*phase, "
                   r"uint64_t request, uint64_t ack, uint64_t complete, "
                   r"uintptr_t token, unsigned int state\)", 1),
                  ("determinism idle trace declaration", rr_header,
                   r"void rr_crucible_sim_trace_idle_advance\("
                   r"const char \*phase,\s*int64_t target_ns\);", 1),
                  ("determinism idle trace schema", rr_trace,
                   r"crucible_sim_determinism_idle\(const char \*phase, "
                   r"uint64_t sequence, uint64_t raw, int64_t virtual_ns, "
                   r"int64_t target_ns, int64_t deadline_ns, "
                   r"uint64_t rr_owner, uint64_t rr_cursor, "
                   r"const char \*cpu_facts\).*?"
                   r'rr_owner=%" PRIu64 " rr_cursor=%" PRIu64 " %s"', 1),
                  ("determinism timer trace schema", timer_trace,
                   r"crucible_sim_determinism_timer\(uint64_t sequence, "
                   r"uint64_t timer, uint64_t list, const char \*scope, "
                   r"const char \*owner, int64_t expire_ns, "
                   r"int64_t current_ns, uint64_t raw\).*?"
                   r'owner=%s expire_ns=%" PRId64 " current_ns=%" PRId64 " '
                   r'raw=%" PRIu64', 1),
                  ("determinism timer service trace schema", timer_trace,
                   r"crucible_sim_determinism_timer_service\("
                   r"uint64_t sequence, const char \*phase, uint64_t list, "
                   r"uint64_t request, uint64_t complete, "
                   r"int64_t expire_ns, int64_t current_ns, uint64_t raw, "
                   r"const char \*owner\).*?"
                   r'phase=%s list=%" PRIu64 " request=%" PRIu64 '
                   r'" complete=%" PRIu64 " expire_ns=%" PRId64 '
                   r'" current_ns=%" PRId64 " raw=%" PRIu64 " owner=%s"', 1),
                  ("timer service generation state", timer,
                   r"uint64_t crucible_service_request_generation;\s*"
                   r"uint64_t crucible_service_complete_generation;", 1),
                  ("timer service declarations", timer_header,
                   r"typedef void QemuCrucibleTimerServiceNotify\(void\);.*?"
                   r"void qemu_timer_register_crucible_timer_service_notify\(\s*"
                   r"QemuCrucibleTimerServiceNotify \*notify\);\s*"
                   r"bool qemu_clock_crucible_request_due_timer_service\("
                   r"QEMUClockType type\);\s*"
                   r"bool qemu_clock_crucible_timer_service_quiescent"
                   r"\(void\);", 1),
                  ("timer service notifier registration", timer,
                   r"void qemu_timer_register_crucible_timer_service_notify\(\s*"
                   r"QemuCrucibleTimerServiceNotify \*notify\)\s*\{\s*"
                   r"assert\(notify\);\s*assert\(!crucible_timer_service_notify\);"
                   r"\s*qatomic_store_release\(&crucible_timer_service_notify, "
                   r"notify\);\s*\}", 1),
                  ("timer service request publication", timer_service_request,
                   r"qatomic_store_release\(\s*"
                   r"&timer_list->crucible_service_request_generation,\s*"
                   r"request_generation\);\s*new_request = true;.*?"
                   r"trace_crucible_sim_determinism_timer_service\(\s*"
                   r"sequence, \"request\", timer_list->crucible_hot_fork_id,\s*"
                   r"request_generation, complete_generation, expire_ns,\s*"
                   r"current_ns, raw, rr_owner \? \"rr\" : \"host\"\);.*?"
                   r"timerlist_notify\(timer_list\);", 1),
                  ("timer service request coalescing", timer_service_request,
                   r"if \(request_generation == complete_generation\) \{.*?"
                   r"request_generation\+\+;.*?new_request = true;\s*\}", 1),
                  ("timer service completion publication", timer_service_complete,
                   r"if \(timer_expired_ns\(timer_list->active_timers, "
                   r"current_ns\)\) \{.*?return;\s*\}.*?"
                   r"trace_crucible_sim_determinism_timer_service\(\s*"
                   r"sequence, \"complete\", timer_list->crucible_hot_fork_id,\s*"
                   r"request_generation, request_generation, expire_ns, "
                   r"current_ns,\s*raw, rr_owner \? \"rr\" : \"host\"\);\s*\}"
                   r"\s*qatomic_store_release\("
                   r"&timer_list->crucible_service_complete_generation,\s*"
                   r"request_generation\);.*?notify\(\);", 1),
                  ("timer service quiescence proof", timer_service_quiescent,
                   r"qatomic_read\(\s*"
                   r"&timer_list->crucible_service_request_generation\) !=\s*"
                   r"qatomic_load_acquire\(\s*"
                   r"&timer_list->crucible_service_complete_generation\)\) "
                   r"\{\s*return false;\s*\}.*?return true;", 1),
                  ("level-triggered AIO timer service wait", timer_service_wait,
                   r"while \(qemu_clock_deadline_ns_all\(QEMU_CLOCK_VIRTUAL,\s*"
                   r"QEMU_TIMER_ATTR_ALL\) == 0\) \{.*?"
                   r"qemu_event_reset\(&rr_dispatch_ceiling_event\);.*?"
                   r"rr_crucible_sim_complete_wake_boundary\(\);.*?"
                   r"qemu_clock_crucible_request_due_timer_service\(\s*"
                   r"QEMU_CLOCK_VIRTUAL\).*?continue;\s*\}.*?"
                   r"replay_mutex_unlock\(\);\s*bql_unlock\(\);\s*"
                   r"qemu_event_wait\(&rr_dispatch_ceiling_event\);\s*"
                   r"replay_mutex_lock\(\);\s*bql_lock\(\);", 1),
                  ("sim precise unresolved deadline budget", icount,
                   r"if \(limit <= 0\) \{\s*"
                   r"if \(strcmp\(current_accel_name\(\), \"sim\"\) == 0 &&\s*"
                   r"icount_enabled\(\) == ICOUNT_PRECISE\) \{\s*return 0;\s*\}"
                   r"\s*return \(int64_t\)remaining;\s*\}", 1),
                  ("generic RR unresolved deadline fallback", icount,
                   r"if \(rr_switch_quantum != 0 && limit <= 0 &&\s*"
                   r"\(strcmp\(current_accel_name\(\), \"sim\"\) != 0 \|\|\s*"
                   r"icount_enabled\(\) != ICOUNT_PRECISE\)\) \{\s*"
                   r"cpu->icount_budget = cpu_budget;", 1),
                  ("sim timer service notifier owner", start_thread,
                   r"qemu_timer_register_crucible_determinism_sampler\(\s*"
                   r"rr_crucible_sim_sample_determinism_timer\);\s*"
                   r"qemu_timer_register_crucible_timer_service_notify\(\s*"
                   r"rr_crucible_sim_notify_dispatch_ceiling\);", 1),
                  ("sole timer service notifier registration", rr,
                   r"qemu_timer_register_crucible_timer_service_notify\(", 1),
                  ("RR hot-fork timer service assertion", hot_fork,
                   r"qemu_event_init\(&rr_dispatch_ceiling_event, false\);\s*"
                   r"g_assert\(qemu_clock_crucible_timer_service_quiescent\(\)\);",
                   1),
                  ("pre-barrier timer service drain", monitor,
                   r"if \(!qemu_clock_crucible_timer_service_quiescent\(\)\) "
                   r"\{\s*outcome = "
                   r"CRUCIBLE_HOT_FORK_TEMPLATE_OUTCOME_DRAINING;\s*break;\s*\}"
                   r".*?QEMU_RCU_HOT_FORK_BARRIER_HOLD.*?"
                   r"QEMU_ASYNC_WORKER_HOT_FORK_BARRIER_HOLD", 1),
                  ("retained timer service quiescence proof", monitor,
                   r"if \(!qemu_clock_crucible_timer_service_quiescent\(\)\) "
                   r"\{\s*operation->blocker = "
                   r'"timer service generation is not quiescent";\s*'
                   r"return -EBUSY;\s*\}.*?"
                   r"qemu_crucible_hot_fork_begin_retained_runtime_transaction",
                   1),
                  ("AIO timer service immediate rearm fixture", aio_test,
                   r"static void crucible_timer_service_rearm\(void \*opaque\)"
                   r"\s*\{.*?timer_mod_ns\(&data->timer, 0\);.*?"
                   r"\.max = 2,.*?"
                   r"qemu_clock_crucible_request_due_timer_service\(.*?"
                   r"qemu_clock_crucible_request_due_timer_service\(.*?"
                   r"g_assert_cmpint\(data.n, ==, 2\);\s*"
                   r"g_assert_cmpuint\(crucible_timer_service_completions, ==, 1\);"
                   r".*?timer_del\(&data.timer\);.*?"
                   r"g_assert_cmpuint\(crucible_timer_service_completions, ==, 2\);",
                   1),
                  ("determinism trace serialization declarations",
                   timer_header,
                   r"typedef void QemuCrucibleDeterminismTimerSample\(\s*"
                   r"uint64_t \*raw, bool \*rr_owner\);.*?"
                   r"void qemu_timer_register_crucible_determinism_sampler\(\s*"
                   r"QemuCrucibleDeterminismTimerSample \*sample\);.*?"
                   r"uint64_t qemu_crucible_determinism_trace_begin\("
                   r"void\);\s*"
                   r"void qemu_crucible_determinism_trace_end\(void\);", 1),
                  ("determinism trace serialization", timer,
                   r"static QemuMutex crucible_determinism_trace_lock;\s*"
                   r"static uint64_t crucible_determinism_trace_sequence;\s*"
                   r"uint64_t qemu_crucible_determinism_trace_begin\(void\)"
                   r"\s*\{\s*qemu_mutex_lock\("
                   r"&crucible_determinism_trace_lock\);\s*"
                   r"if \(crucible_determinism_trace_sequence == "
                   r"UINT64_MAX\) \{\s*"
                   r'error_report\("Crucible determinism trace sequence '
                   r'overflow"\);\s*abort\(\);\s*\}\s*'
                   r"return \+\+crucible_determinism_trace_sequence;\s*\}\s*"
                   r"void qemu_crucible_determinism_trace_end\(void\)\s*"
                   r"\{\s*qemu_mutex_unlock\("
                   r"&crucible_determinism_trace_lock\);\s*\}", 1),
                  ("determinism trace lock initialization", timer,
                   r"void qemu_init_clocks\([^)]*\)\s*\{\s*"
                   r"QEMUClockType type;\s*qemu_mutex_init\("
                   r"&crucible_determinism_trace_lock\);\s*for ", 1),
                  ("determinism trace begin consumers", rr + timer,
                   r"qemu_crucible_determinism_trace_begin\(\)", 2),
                  ("determinism trace end consumers", rr + timer,
                   r"qemu_crucible_determinism_trace_end\(\);", 2),
                  ("determinism timer sampler registration", timer,
                   r"static QemuCrucibleDeterminismTimerSample\s*"
                   r"\*crucible_determinism_timer_sample;.*?"
                   r"void qemu_timer_register_crucible_determinism_sampler\(\s*"
                   r"QemuCrucibleDeterminismTimerSample \*sample\)\s*\{\s*"
                   r"assert\(sample\);\s*"
                   r"assert\(!crucible_determinism_timer_sample\);\s*"
                   r"qatomic_store_release\("
                   r"&crucible_determinism_timer_sample, sample\);\s*\}", 1),
                  ("determinism timer stable classification", timer,
                   r"if \(timer_list == main_loop_tlg\.tl\[type\]\) \{\s*"
                   r"return \"global\";\s*\}\s*return \"aio\";", 1),
                  ("common timer has no system-only sampler input", timer,
                   r"\bcurrent_cpu\b|\bicount_get_raw_observed\b", 0),
                  ("sim determinism timer sampler", idle_trace,
                   r"static void rr_crucible_sim_sample_determinism_timer\("
                   r"uint64_t \*raw,\s*bool \*rr_owner\)\s*\{\s*"
                   r"\*raw = \(uint64_t\)MAX\("
                   r"icount_get_raw_observed\(\), 0\);\s*"
                   r"\*rr_owner = current_cpu != NULL;\s*\}", 1),
                  ("sim-only determinism timer sampler registration",
                   start_thread,
                   r"if \(!single_tcg_cpu_thread\) \{\s*"
                   r"if \(rr_crucible_sim_mode\(\)\) \{\s*"
                   r"qemu_timer_register_crucible_determinism_sampler\(\s*"
                   r"rr_crucible_sim_sample_determinism_timer\);\s*"
                   r"qemu_timer_register_crucible_timer_service_notify\(\s*"
                   r"rr_crucible_sim_notify_dispatch_ceiling\);\s*\}\s*"
                   r"qemu_event_init\(&rr_dispatch_ceiling_event, false\);",
                   1),
                  ("sole determinism timer sampler registration", rr,
                   r"qemu_timer_register_crucible_determinism_sampler\(", 1),
                  ("determinism virtual timer callback trace", timer_callback,
                   r"if \(timer_list->clock->type == QEMU_CLOCK_VIRTUAL &&\s*"
                   r"trace_event_get_state_backends\(\s*"
                   r"TRACE_CRUCIBLE_SIM_DETERMINISM_TIMER\)\) \{\s*"
                   r"QemuCrucibleDeterminismTimerSample \*sample =\s*"
                   r"qatomic_load_acquire\("
                   r"&crucible_determinism_timer_sample\);\s*"
                   r"if \(sample\) \{\s*"
                   r"uint64_t sequence = "
                   r"qemu_crucible_determinism_trace_begin\(\);\s*"
                   r"int64_t virtual_ns = qemu_clock_get_ns\("
                   r"QEMU_CLOCK_VIRTUAL\);\s*uint64_t raw;\s*"
                   r"bool rr_owner;\s*sample\(&raw, &rr_owner\);\s*"
                   r"trace_crucible_sim_determinism_timer\(\s*sequence,\s*"
                   r"#ifdef CONFIG_POSIX\s*ts->crucible_hot_fork_id,\s*"
                   r"timer_list->crucible_hot_fork_id,\s*#else\s*0, 0,\s*"
                   r"#endif\s*crucible_determinism_timer_scope\(timer_list\),"
                   r"\s*rr_owner \? \"rr\" : \"host\", expire_ns,\s*"
                   r"virtual_ns, raw\);\s*"
                   r"qemu_crucible_determinism_trace_end\(\);\s*\}\s*\}\s*"
                   r"cb\(opaque\);", 1),
                  ("determinism idle canonical facts", idle_trace,
                   r"if \(!rr_crucible_sim_mode\(\) \|\|\s*"
                   r"!trace_event_get_state_backends\("
                   r"TRACE_CRUCIBLE_SIM_DETERMINISM_IDLE\)\) \{\s*return;"
                   r"\s*\}\s*sequence = "
                   r"qemu_crucible_determinism_trace_begin\(\);\s*"
                   r"CPU_FOREACH\(cpu\).*?"
                   r'"cpu_count=%u halted=0x%" PRIx64 " work=0x%" PRIx64\s*'
                   r'" exit=0x%" PRIx64 " interrupt=0x%" PRIx64\s*'
                   r'" stop=0x%" PRIx64 " state=%u".*?'
                   r"g_assert\(cpu_facts_length >= 0 &&\s*"
                   r"\(size_t\)cpu_facts_length < sizeof\(cpu_facts\)\);.*?"
                   r"trace_crucible_sim_determinism_idle\(.*?"
                   r"target_ns, deadline_ns, "
                   r"icount_crucible_rr_current_vcpu\(\),\s*"
                   r"icount_crucible_rr_cursor_position\(\), cpu_facts\);\s*"
                   r"qemu_crucible_determinism_trace_end\(\);", 1),
                  ("determinism idle CPU mask bound", idle_trace,
                   r"if \(cpu_count > 64\) \{\s*"
                   r'error_report\("Crucible determinism trace supports at '
                   r'most 64 CPUs"\);\s*abort\(\);\s*\}', 1),
                  ("determinism idle request phase", plugin,
                   r"qatomic_set\(&qemu_plugin_time_advance_target, "
                   r"new_time\);\s*rr_crucible_sim_trace_idle_advance\("
                   r'"request", new_time\);\s*run_on_cpu', 1),
                  ("stale determinism idle run phase", plugin,
                   r'rr_crucible_sim_trace_idle_advance\("run"', 0),
                  ("determinism idle complete phase", plugin,
                   r"qatomic_store_release\(&qemu_plugin_time_advance_pending,"
                   r" 0\);\s*rr_crucible_sim_trace_idle_advance\("
                   r'"complete", target\);', 1),
                  ("determinism idle trace phase cardinality", plugin,
                   r"rr_crucible_sim_trace_idle_advance\(", 2),
                  ("ack generation trace", acknowledge_boundary,
                   r"schedule_token = qemu_plugin_schedule_control_boundary\(\);"
                   r"\s*qatomic_store_release\("
                   r"&qemu_plugin_rr_control_ack_generation,\s*"
                   r"request_generation\);\s*qatomic_store_release\("
                   r"&qemu_plugin_rr_control_schedule_token,\s*"
                   r"schedule_token\);\s*"
                   r'rr_crucible_sim_trace_control_boundary\(\s*"ack",\s*'
                   r"request_generation,\s*request_generation,\s*"
                   r"complete_generation,\s*schedule_token\);", 1),
                  ("complete generation trace", control_complete,
                   r"qatomic_store_release\("
                   r"&qemu_plugin_rr_control_complete_generation,\s*"
                   r"rr_ack_generation\);\s*"
                   r'rr_crucible_sim_trace_control_boundary\(\s*"complete",\s*'
                   r"rr_request_generation,\s*rr_ack_generation,\s*"
                   r"rr_ack_generation,\s*schedule_token\);", 1),
                  ("canceled generation trace", cancel_boundary,
                   r"uintptr_t rr_schedule_token = qatomic_load_acquire\(\s*"
                   r"&qemu_plugin_rr_control_schedule_token\);.*?"
                   r"uint64_t complete_generation = qatomic_load_acquire\(\s*"
                   r"&qemu_plugin_rr_control_complete_generation\);.*?"
                   r"qatomic_store_release\("
                   r"&qemu_plugin_rr_control_ack_generation,\s*"
                   r"request_generation\);\s*qatomic_store_release\("
                   r"&qemu_plugin_rr_control_complete_generation,\s*"
                   r"request_generation\);\s*"
                   r"if \(request_generation != complete_generation\) \{\s*"
                   r'rr_crucible_sim_trace_control_boundary\(\s*"cancel",\s*'
                   r"request_generation,\s*request_generation,\s*"
                   r"request_generation,\s*rr_schedule_token\);\s*\}", 1),
                  ("stale QemuCond ceiling trace", idle_test,
                   r"RR_HALT_TRACE|wait_for_rr_halt_cond|FUTEX_WAIT_BITSET|"
                   r"cond=", 0),
                  ("host-interpreter QEMU qtest shebang", hermetic_qtests,
                   r"(?m)^#!.*(?:/usr/bin/env|/usr/bin/python|/bin/)", 0),
                  ("exact dispatch event futex", idle_test,
                   r"futex_address == event_address\s*and\s*"
                   r"futex_command == FUTEX_WAIT", 1),
                  ("exact dispatch event task", idle_test,
                   r"expected exactly one ALL CPUs/TCG task", 1),
                  ("exact dispatch event mapping", idle_test,
                   r"futex_mappings != event_mappings", 1),
                  ("exact dispatch event waits", idle_test,
                   r"wait_for_rr_dispatch_event\(park_deadline\)", 2),
                  ("parked main-loop eventfd progress", late_test,
                   r"live.qmp\(\"query-status\"\).*?"
                   r"os.eventfd_write\(live.wake_fd, 1\)", 1),
                  ("paused VM control eventfd", vmstop_test,
                   r"live.qmp\(\"query-status\"\).*?"
                   r"\{\"status\": \"paused\", \"running\": False\}.*?"
                   r"live.control_state.flush\(\)\s*"
                   r"os.eventfd_write\(live.wake_fd, 1\)\s*"
                   r"event = live.marker\(\).*?"
                   r"expected_control = \(\"control\", "
                   r"\(dispatch_ceiling, 1\)\)", 1),
                  ("stale dispatch wake bypass", rr,
                   r"crucible_sim_preemption_apply_due\(cpu_ptr\)\) \{\s*"
                   r"return true;\s*\}\s*if \("
                   r"rr_crucible_sim_complete_wake_boundary\(\)\)", 0),
                  ("stale alternate HLT park", idle_test,
                   r"allow_idle_park|return \"idle-futex\"", 0),
                  ("settled request escape", rr,
                   r"rr_control_boundary_pending\(\)\s*&&\s*"
                   r"qatomic_read\(&rr_tcg_exec_state\) == RR_TCG_EXEC_IDLE",
                   2),
                  ("terminal lifecycle service", rr,
                   r"static void rr_crucible_sim_service_force_shutdown"
                   r"\(void\)\s*\{[^}]*"
                   r"rr_crucible_sim_complete_wake_boundary\(\);[^}]*"
                   r"qemu_plugin_crucible_rr_control_boundary_cancel\(\);"
                   r"[^}]*rr_crucible_sim_drain_vcpu_work\(\);[^}]*"
                   r"if \(!work_pending\) \{[^}]*"
                   r"qemu_cond_wait_bql\(first_cpu->halt_cond\);", 1),
                  ("terminal outer-loop cutover", rr,
                   r"if \(rr_crucible_sim_mode\(\) &&\s*"
                   r"qemu_force_shutdown_requested\(\)\) \{\s*"
                   r"replay_mutex_unlock\(\);\s*"
                   r"rr_crucible_sim_service_force_shutdown\(\);\s*"
                   r"continue;\s*\}", 1),
                  ("terminal wait cutovers", rr,
                   r"qemu_cond_wait_bql\(first_cpu->halt_cond\);\s*"
                   r"if \(rr_crucible_sim_mode\(\) &&\s*"
                   r"qemu_force_shutdown_requested\(\)\) \{\s*"
                   r"return;\s*\}", 2),
                  ("serialized atomic invariant", rr,
                   r"g_assert\(r != EXCP_ATOMIC\);", 1),
                  ("active epoch adoption", plugin,
                   r"if \(active_token != 0\) \{\s*return active_token;", 1),
                  ("unclaimed request deferral", plugin,
                   r"if \(rr_request_unacknowledged\) \{[^}]+"
                   r"release_control_boundary_schedule\(schedule_token\);"
                   r"\s*return;", 1),
                  ("fixed request target", plugin,
                   r"if \(!\*rr_target_bound[^}]+\*rr_target_generation = "
                   r"rr_request_generation;[^}]+\*rr_target_bound = true;", 1),
                  ("stale two-argument clamp", rr,
                   r"crucible_sim_shmem_clamp_cpu_budget\(\s*current_icount,"
                   r"\s*\*?cpu_budget\)", 0),
                  ("stale collision failure", plugin,
                   r"if \(active_token != 0\) \{\s*return 0;", 0),
                  ("stale RR atomic execution", rr,
                   r"cpu_exec_step_atomic\(cpu\)|last_exit == EXCP_ATOMIC|"
                   r"r\s*==\s*EXCP_ATOMIC", 0),
              ]
              for label, source, pattern, expected in checks:
                  count = len(re.findall(pattern, source, re.DOTALL))
                  if count != expected:
                      raise SystemExit(
                          f"QEMU {label} count drifted: {count} != {expected}"
                      )

              service = rr.index("qemu_crucible_fault_vcpu_service_account")
              first_stop = rr.index(
                  "qemu_plugin_crucible_vmstop_pending", service
              )
              first_owner = rr.index(
                  "service_after == dispatch_ceiling", first_stop
              )
              fault = rr.index("qemu_crucible_fault_dispatch_boundary", service)
              observer = rr.index(
                  "crucible_sim_observer_notify_current_icount", fault
              )
              final_owner = rr.index(
                  "service_after == dispatch_ceiling", observer
              )
              final_stop = rr.index(
                  "qemu_plugin_crucible_vmstop_pending", final_owner
              )
              order = (service, first_stop, first_owner, fault, observer,
                       final_owner, final_stop)
              if list(order) != sorted(order):
                  raise SystemExit("QEMU exact-ceiling ordering drifted")
              PYTHON
              python3 tests/qtest/crucible-multiboot-gap.py \
                --qemu build/qemu-system-x86_64 \
                > multiboot-gap.txt
              cat multiboot-gap.txt
              grep -F -x -q 'multiboot_sim_intersegment_gap_zero=true' \
                multiboot-gap.txt
              build/tests/unit/test-crucible-idle-wait --tap \
                --seed=R02S00000000000000000000000000000000 \
                > idle-wake-tests.tap
              cat idle-wake-tests.tap
              timer_witness_tap_line='# timer_witness generation=1 deadline_ns=500 deadline_icount=900 armed_raw_icount=100 fired_expire_ns=500 fired_virtual_ns=504 fired_raw_icount=100 completed=1 reserved=0'
              test "$(grep -F -x -c "$timer_witness_tap_line" \
                idle-wake-tests.tap)" -eq 1
              grep -F -x "$timer_witness_tap_line" idle-wake-tests.tap \
                > virtual-timer-witness.txt
              {
                printf '%s\n' \
                  'qemu_atomic_patch_hash=${atomicPatchHash}' \
                  'qemu_shmem_header_hash=${shmemHeaderHash}' \
                  'qemu_build_id=${qemuBuildIdentity}'
              } >> virtual-timer-witness.txt
              cat virtual-timer-witness.txt
              make test-plugins
              python3 tests/qtest/crucible-translation-prefetch.py \
                --qemu build/qemu-system-x86_64 \
                --plugin build/tests/tcg/plugins/libcrucible-fingerprint-observer.so \
                > translation-prefetch.txt
              cat translation-prefetch.txt
              test "$(grep -E -c \
                '^translation_prefetch_ordinary_demand_requests=[1-9][0-9]*$' \
                translation-prefetch.txt)" -eq 1
              test "$(grep -E -c \
                '^translation_prefetch_ordinary_demand_completions=[1-9][0-9]*$' \
                translation-prefetch.txt)" -eq 1
              for fact in \
                translation_prefetch_off_requests=0 \
                translation_prefetch_off_completions=0 \
                translation_prefetch_on_off_fingerprint_identical=true \
                translation_prefetch_repeated_material_runs=16 \
                translation_prefetch_non_sim_rejected=true; do
                test "$(grep -F -x -c "$fact" translation-prefetch.txt)" -eq 1
              done
              python3 - <<'PYTHON'
              bios = bytearray(65536)
              bios[-16:-12] = bytes((0xfa, 0xf4, 0xeb, 0xfd))
              with open("idle-wake-bios.bin", "wb") as output:
                  output.write(bios)
              PYTHON
              python3 tests/qtest/crucible-idle-wait-liveness.py \
                --qemu build/qemu-system-x86_64 \
                --plugin build/tests/tcg/plugins/libcrucible-idle-wait-liveness.so \
                --bios idle-wake-bios.bin \
                > idle-wake-liveness.txt
              cat idle-wake-liveness.txt
              for fact in \
                post_unplug_shutdown_runs=64 \
                control_boundary_runs=8 \
                time_advance_direct_reentry_runs=16 \
                time_advance_reentry_order=work,advance,park \
                hlt_at_ceiling_runs=16 \
                hlt_at_ceiling_dispatches=1 \
                vmstop_at_ceiling_runs=16 \
                vmstop_at_ceiling_dispatches=1 \
                vmstop_at_ceiling_paused_control_runs=16 \
                already_due_vmstop_at_ceiling_runs=16 \
                already_due_vmstop_at_ceiling_dispatches=1 \
                already_due_vmstop_at_ceiling_paused_control_runs=16 \
                late_ceiling_wake_runs=64 \
                late_ceiling_park_attestations=64 \
                late_ceiling_main_loop_progress_runs=64 \
                late_ceiling_initial_icount=1000 \
                late_ceiling_resumed_icount=2000 \
                late_ceiling_resume_event_order=control,dispatch; do
                test "$(grep -F -x -c "$fact" \
                  idle-wake-liveness.txt)" -eq 1
              done
              python3 tests/qtest/crucible-exact-tb-exit.py \
                --qemu build/qemu-system-x86_64 \
                --plugin build/tests/tcg/plugins/libcrucible-exact-tb-exit.so \
                > exact-tb-exit.txt
              cat exact-tb-exit.txt
              grep -F -x -q 'PASS trap_icount=3 boundary_icount=4' \
                exact-tb-exit.txt
              python3 tests/qtest/crucible-fingerprint-projection.py \
                --qemu build/qemu-system-x86_64 \
                --plugin build/tests/tcg/plugins/libcrucible-fingerprint-observer.so \
                --architecture x86_64 \
                --plugin-quiesced-capture-only \
                > plugin-quiesced-fingerprint.txt
              cat plugin-quiesced-fingerprint.txt
              grep -F -x -q 'plugin_quiesced_capture=true' \
                plugin-quiesced-fingerprint.txt
              python3 tests/qtest/crucible-fingerprint-projection.py \
                --qemu build/qemu-system-aarch64 \
                --plugin build/tests/tcg/plugins/libcrucible-fingerprint-observer.so \
                --architecture aarch64 \
                > aarch64-fingerprint-projection.txt
              cat aarch64-fingerprint-projection.txt
              test "$(grep -F -x -c \
                'aarch64_virtio_net_bh_projection=true' \
                aarch64-fingerprint-projection.txt)" -eq 1
              test "$(grep -F -x -c \
                'virtio_net_scheduler_kind_sensitivity=true' \
                aarch64-fingerprint-projection.txt)" -eq 1
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
            ${lib.optionalString fullUpstreamTestSuiteOnly "exit 0"}
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

            plugin_header=include/plugins/qemu-plugin.h
            test -f "$plugin_header"
            mkdir -p "$out/include/qemu"
            install -m 644 "$plugin_header" "$out/include/qemu/qemu-plugin.h"
            mkdir -p "$out/include/aos/crucible"
            install -m 644 include/aos/crucible/crucible_shmem_abi.h \
              "$out/${shmemHeaderInstallPath}"

            mkdir -p "$out/share/aos/crucible"
            ${lib.optionalString applyCruciblePatch ''
              install -m 644 block-backend-tests.tap \
                "$out/share/aos/crucible/block-backend-tests.tap"
              install -m 644 acpi-fingerprint-tests.tap \
                "$out/share/aos/crucible/acpi-fingerprint-tests.tap"
              install -m 644 vga-fingerprint-tests.tap \
                "$out/share/aos/crucible/vga-fingerprint-tests.tap"
              install -m 644 parallel-fingerprint-tests.tap \
                "$out/share/aos/crucible/parallel-fingerprint-tests.tap"
              install -m 644 fdc-fingerprint-tests.tap \
                "$out/share/aos/crucible/fdc-fingerprint-tests.tap"
              install -m 644 e1000-fingerprint-tests.tap \
                "$out/share/aos/crucible/e1000-fingerprint-tests.tap"
              install -m 644 idle-wake-tests.tap \
                "$out/share/aos/crucible/idle-wake-tests.tap"
              install -m 644 virtual-timer-witness.txt \
                "$out/share/aos/crucible/virtual-timer-witness.txt"
              install -m 644 idle-wake-liveness.txt \
                "$out/share/aos/crucible/idle-wake-liveness.txt"
              install -m 644 exact-tb-exit.txt \
                "$out/share/aos/crucible/exact-tb-exit.txt"
              install -m 644 plugin-quiesced-fingerprint.txt \
                "$out/share/aos/crucible/plugin-quiesced-fingerprint.txt"
              install -m 644 aarch64-fingerprint-projection.txt \
                "$out/share/aos/crucible/aarch64-fingerprint-projection.txt"
              install -m 644 multiboot-gap.txt \
                "$out/share/aos/crucible/multiboot-gap.txt"
              install -m 644 translation-prefetch.txt \
                "$out/share/aos/crucible/translation-prefetch.txt"
            ''}
            cat > "$out/share/aos/crucible/qemu-build-identity.env" <<'QEMU_BUILD_IDENTITY'
            qemu_package=${pname}
            qemu_version=${version}
            qemu_source_hash=${atomicPatch.qemuSourceHash}
            qemu_nix_hash=${qemuNixHash}
            qemu_configure_flags_hash=${qemuConfigureFlagsHash}
            qemu_configure_target_list=x86_64-softmmu,aarch64-softmmu
            qemu_atomic_patch_hash=${atomicPatchHash}
            qemu_patch_branch_ref=${atomicPatch.branchRef}
            qemu_patch_branch_model=${atomicPatch.branchModel}
            qemu_patch_branch_bundle_hash=${patchBranchBundleHash}
            qemu_patch_branch_base_commit=${atomicPatch.baseCommit}
            qemu_patch_branch_base_tree=${atomicPatch.baseTree}
            qemu_patch_branch_head_commit=${atomicPatch.commit}
            qemu_patch_branch_material_hash=${patchBranchMaterialHash}
            qemu_plugins_enabled=${
              if enablePlugins
              then "true"
              else "false"
            }
            qemu_crucible_atomic_patch_applied=${
              if applyCruciblePatch
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
            ${lib.optionalString applyCruciblePatch ''
              install -m 644 ${./qemu-patches/LICENSES.md} \
                "$out/share/licenses/${pname}/AOS-PATCH-LICENSES.md"
            ''}
            cat > "$out/share/licenses/${pname}/AOS-MODIFICATIONS" <<'MODIFICATIONS'
            AOS package: ${pname}
            Upstream version: ${version}
            Modified QEMU: ${
              if applyCruciblePatch
              then "yes"
              else "no"
            }
            Atomic patch artifact: ${atomicPatch.file}
            Atomic patch identity: ${atomicPatchHash}
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
            ${lib.optionalString applyCruciblePatch ''
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
        standaloneRelease = !applyCruciblePatch && !testOnlyNonDistributable;
        inherit testOnlyNonDistributable;
        releaseVia =
          if applyCruciblePatch && !testOnlyNonDistributable
          then "crucible"
          else null;
        inherit
          qemuBuildIdentity
          qemuBuildIdentityMaterial
          qemuSimCapability
          qemuConfigureFlags
          qemuConfigureFlagsHash
          qemuConfigureIdentityFlags
          qemuConfigureIdentityMaterial
          qemuConfigureFlagsMaterial
          normalizeSambaSmbdConfigureFlag
          sambaSmbdConfigureFlag
          sambaSmbdExecutable
          sambaSmbdRecipeHash
          sambaSmbdSourceHash
          sambaSmbdSourceHashAlgo
          sambaSmbdVersion
          fullUpstreamTestHarnessMutationHash
          fullUpstreamTestHarnessMutationMaterial
          qemuNixHash
          shmemAbi
          shmemAbiVersion
          shmemGeneratedHeader
          shmemHeaderHash
          shmemHeaderInstallPath
          patchBranchBundleHash
          atomicPatchCommit
          patchBranchMaterial
          patchBranchMaterialHash
          atomicPatch
          atomicPatchHash
          ;
      };

      checks = {
        testing,
        self,
        pkgs,
      }:
        if pname == "qemu-crucible" && !fullUpstreamTestSuiteOnly
        then let
          patchMicrotests = import ../../tests/crucible/phase2-patch-microtests.nix {
            inherit pkgs lib;
            qemuPackage = self;
            attrPath = "checks.integration.qemu-crucible-patch-microtests";
            taskIds = ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"];
            openTaskIds = [];
          };
        in {
          full-upstream-test-suite = pkgs.qemu-crucible-full-test-suite;
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
