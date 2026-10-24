##! systemd — System and service manager
{
  lib,
  service-management,
  init-system,
  dbus,
  aos-configuration-provider,
  aos-host-policy,
  mkDerivation,
  stdenv,
  buildPackages,
  fetchurl,
  gnumake,
  pkg-config,
  gawk,
  linux-headers,
  linux,
  kernelCloneLayout ? linux.dev,
  bpftool,
  libbpf,
  util-linux,
  kmod,
  zlib,
  xz,
  lz4,
  zstd,
  zfs,
  openssl,
  perl,
  meson,
  ninja,
  python3,
  gperf,
  getent,
  libcap,
  libxcrypt,
  gcc-libs,
  libidn2,
  pcre2,
  audit,
  libselinux,
  libsepol,
  libseccomp,
  acl,
  cryptsetup,
  elfutils,
  linux-pam,
  tpm2-tss,
  coreutils,
  cpio,
  binutils,
  dosfstools,
  e2fsprogs,
  erofs-utils,
  fakeroot,
  findutils,
  gptfdisk,
  grep,
  iproute2,
  jq,
  less,
  mtools,
  sbsigntools,
  sed,
  tar,
  bash,
  bzip2,
  python3-pefile,
  python3-pyelftools,
  aos-recovery,
  aos-systemd-provider,
  nix,
  pe-tools,
}: let
  buildShell =
    if stdenv.isCross
    then buildPackages.bash
    else bash;
  # Current Ninja launches commands through /bin/sh. Use the source-built
  # shell for this builder without changing the compiler toolchain graph.
  buildNinja =
    (
      if stdenv.isCross
      then buildPackages.ninja
      else ninja
    ).passthru.withCommandShell
    buildShell;
  identityShells = import ./_systemd-abilities/identity-shells.nix {inherit bash util-linux;};

  version = "261.2";

  # PYTHONPATH that makes `import pefile` / `import elftools` succeed
  # when ukify runs (both also needed during meson configure — see
  # the configure phase's PYTHONPATH export). python3.nix pins 3.14.
  ukifyPythonPath = "${python3-pefile}/lib/python3.14/site-packages:${python3-pyelftools}/lib/python3.14/site-packages";

  # Late RPATH entries retain dlopen libraries even without DT_NEEDED entries.
  # Helper executables retain their own tools; adding those tool roots here
  # would pull image assembly and Python into every PID 1 runtime closure.
  systemdRuntimeLibraries = [
    bzip2
    util-linux
    kmod
    zlib
    xz
    lz4
    zstd
    openssl
    libcap
    libxcrypt
    # glibc loads these by SONAME for unwinding and IDN name-service paths.
    # Keep the providers in PID 1's authenticated runtime closure explicitly.
    gcc-libs
    libidn2
    audit
    libselinux
    libsepol
    pcre2
    libseccomp
    acl
    cryptsetup
    elfutils
    libbpf
    linux-pam
    tpm2-tss
  ];

  systemdRuntimeDeps =
    systemdRuntimeLibraries
    ++ [
      bash
      python3
      coreutils
      cpio
      dosfstools
      e2fsprogs
      erofs-utils
      fakeroot
      findutils
      gcc-libs
      gawk
      gptfdisk
      grep
      iproute2
      jq
      less
      mtools
      sbsigntools
      sed
      tar
      zfs
      aos-recovery
      pe-tools
      nix
    ];
  systemdRuntimeLibraryPath = builtins.concatStringsSep ":" (
    map (dependency: "${dependency}/lib") systemdRuntimeLibraries
  );
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "systemd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "systemd-escape emits the canonical escaped path.";
        "files" = {};
        "input" = "An absolute filesystem path.";
        "operation" = "Escape the path as a systemd unit-name component.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/systemd-escape"
              "--path"
              "/var/lib/aos"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "var-lib-aos\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "systemd-escape rejects the relative path.";
        "files" = {};
        "input" = "A relative path, which is outside --path's accepted input domain.";
        "operation" = "Attempt to escape the relative value as an absolute path.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/systemd-escape"
              "--path"
              "relative/path"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    module = ./_systemd-abilities;
    # Native resource handlers pin the real system-bus manager identity. The
    # broker's package module is required even when systemd is installed alone.
    moduleDeps = [service-management init-system aos-configuration-provider aos-host-policy linux-pam dbus];

    # Keep UKI construction and kernel installation in `tools`, including
    # kernel-install's Python hook. PID 1 and boot-time generators do not need
    # that interpreter. Image builders select systemd.tools explicitly.
    # Native effect entry points have their own small authenticated NAR.
    # Only handlers reference out; out must not link back to these wrappers.
    outputs = ["out" "tools" "handlers"];

    # The package performs ELF path cleanup below, then retains its declared
    # runtime directories for libraries loaded on demand. A second DT_NEEDED-
    # only shrink would remove libmount and prevent PID 1 from booting.
    dontPatchELF = true;

    src = fetchurl {
      urls = [
        "https://github.com/systemd/systemd/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-7RBZ/5ZPXfNbYFZDTMF8yD+G3JE/EEiZSKCxm2CBxew=";
    };

    # Patches applied after unpack (via mkDerivation's built-in patch phase):
    #   0001 — Remove /usr/lib, /usr/local/lib, /lib fallback paths from
    #          path-lookup.c so systemd only searches SYSTEM_DATA_UNIT_DIR
    #          (= $out/lib/systemd/system with --prefix=$out) and /etc.
    #   0002 — Add PREFIX "/lib/" to CONF_PATHS macro in constants.h so
    #          systemd finds tmpfiles.d, sysctl.d, modules-load.d etc. in
    #          the Nix store.
    #   0004 — Skip creating /run/systemd for test-run managers so offline
    #          analysis tools can run inside the Nix sandbox.
    #   0005 — Fail closed when RootHashSignature= is present but the kernel
    #          rejects the dm-verity signed-key activation.
    #   0006 — Keep an embedded signed UKI command line authoritative over
    #          addon and SMBIOS fragments that run before initrd validation.
    #   0007 — Add the closed AOS payload seccomp profile to nspawn and install
    #          it after container setup, immediately before payload execution.
    #   0008 — Consume a named supervisor-only root descriptor without
    #          reopening its pathname or forwarding it to the payload.
    #   0009 — Test fail-closed shutdown-intent state for retained-supervisor
    #          reboot support. Runtime integration is a separate step.
    #   0010 — Authenticate per-boot shutdown intent and reset the empty payload
    #          cgroup while retaining the AOS supervisor and unit invocation.
    #   0011 — Install a broker-owned attachment anchor from an exact named
    #          descriptor with the target idmap and hard read-only attributes.
    #   0012 — Reserve unit-reference lifetime control to root so an
    #          unprivileged client cannot prevent exact terminal collection.
    #   0013 — Route authenticated switch-root and daemon-reexec operations
    #          through the immutable AOS SELinux guard without init fallback.
    #   0014 — Deliver only an exact named, sealed guest-agent descriptor set
    #          to the fixed PID 1 bootstrap, never generic activation FDs.
    #   0015 — Require the AOS kernel no-set-ID task guard before seccomp for
    #          RestrictSUIDSGID=, allowing safe descriptor-relative openat2.
    #   0016 — Reject truncated sd-bus ancillary data even when the message
    #          body does not reference the discarded descriptor.
    #   0017 — Pin protected Network service fragments to the measured image
    #          before every PID 1 spawn, including privileged prestart tasks.
    #   0017-nspawn — Retain the payload cgroup and sealed original
    #          credential/inode join for the fixed Guest owner bootstrap.
    #   0020 — Bound the fixed Controller plaintext publisher-policy handoff
    #          and deliver its credential mount with strict ownership and labels.
    #   0021 — Loan PID1's current image only to the two sealed own-unit
    #          Mount/Source principals; no generic executable or unit selector.
    #   0022 — Pin every fixed online Nix command to the same physical EROFS
    #          fragment, excluding mutable aliases, environment and overrides.
    #   0024 — Opt-in original PID1/component CPU, memory and PID enclosures
    #          before generators; preserve finite contexts and checked originals.
    #   0025 — Retain fixed Source/Controller launch originals through exec and
    #          charge bounded preparation to the original parent subdivisions.
    #   0026 — Deliver Cache's distinct original through the same retained sender.
    #   0027 — Select canonical Parent04 and distinct Mount/Network F/M slices,
    #          preserving the enrolled Controller normal/recovery sender paths.
    #   0039 — Keep namespace retirement notifications under Secure Boot
    #          lockdown through typed fentry instead of a kprobe perf event.
    patches = [
      ./patches/0001-remove-usr-lib-unit-lookup-paths.patch
      ./patches/0002-add-prefix-to-conf-paths.patch
      ./patches/0004-skip-runtime-dir-for-test-run-manager.patch
      ./patches/0005-fail-closed-on-roothash-signature-rejection.patch
      ./patches/0006-ignore-external-cmdline-for-embedded-uki.patch
      ./patches/0007-nspawn-aos-payload-seccomp-profile.patch
      ./patches/0008-nspawn-owned-root-descriptor.patch
      ./patches/0009-nspawn-shutdown-intent-state.patch
      ./patches/0010-nspawn-retained-supervisor-reboot.patch
      ./patches/0011-nspawn-attachment-anchor-descriptor.patch
      ./patches/0012-restrict-unit-reference-methods.patch
      ./patches/0013-aos-selinux-root-handoff.patch
      ./patches/0014-nspawn-guest-agent-descriptors.patch
      ./patches/0015-restrict-suid-sgid-kernel-guard.patch
      ./patches/0016-reject-truncated-bus-ancillary-data.patch
      ./patches/0017-pin-network-unit-fragments-before-spawn.patch
      ./patches/0018-launch-image-fuse-worker-role.patch
      ./patches/0017-nspawn-guest-cgroup-custody.patch
      ./patches/0019-fixed-fuse-worker-private-transport.patch
      ./patches/0020-bounded-controller-publisher-policy-credential.patch
      ./patches/0021-fixed-source-launcher-image-loan.patch
      ./patches/0021-nspawn-host-readiness-report.patch
      ./patches/0022-pin-online-nix-unit-fragment-before-spawn.patch
      ./patches/0023-controller-resource-enrollment.patch
      ./patches/0024-component-parent-enclosure.patch
      ./patches/0025-source-signer-origin.patch
      ./patches/0026-cache-signer-origin.patch
      ./patches/0027-fixed-service-parent04.patch
      ./patches/0028-network-worker-source-custody.patch
      ./patches/0029-host-component-readiness-report.patch
      ./patches/0030-boot-preparation-source-origin.patch
      ./patches/0031-source-clone-dominant-permits.patch
      ./patches/0032-network-worker-reaped-status.patch
      ./patches/0033-controller-prepaid-recipient-range.patch
      ./patches/0034-resource-enrollment-startup-diagnostics.patch
      ./patches/0035-merged-usr-immutable-image-paths.patch
      ./patches/0036-select-sandbox-resource-unit-families.patch
      ./patches/0037-account-view-root-preparation.patch
      ./patches/0038-confine-offline-public-output.patch
      ./patches/0039-nsresourced-retirement-fentry.patch
    ];

    buildDeps = [
      bpftool
      buildPackages.binutils
      buildPackages.llvm
      binutils
      gnumake
      pkg-config
      gawk
      perl
      meson
      buildNinja
      python3
      gperf
      getent
      grep
      # Kernel UAPI headers are compile-time only. Keeping them out of
      # runtimeDeps avoids a dead RPATH/RUNPATH entry (linux-headers ships no
      # shared library) and keeps the 7 MiB header tree out of the closure.
      linux-headers
      # Preserve this exact target DATA output. Tool dependency splicing selects
      # native packages by name and would substitute the default kernel variant.
      # String coercion keeps its store dependency without treating it as a tool.
      (toString kernelCloneLayout)
    ];
    # Installed helpers and the cryptsetup/ukify wrappers execute the target
    # interpreters. TPM2 supplies libtss2-esys/rc/mu and the device TCTI for
    # systemd-cryptsetup's TPM2 token, systemd-pcrextend, and systemd-measure.
    # Image assembly pins its build-platform tools independently. The ukify
    # wrapper retains binutils only in `tools`, while these native providers
    # are executed by wrappers installed in the runtime output.
    runtimeDeps = systemdRuntimeDeps ++ [aos-systemd-provider aos-configuration-provider];
    propagatedDeps = [];

    # systemd's many [0]/[1] trailing-array structs get narrowed to a fixed
    # size by -fstrict-flex-arrays=3, so _FORTIFY_SOURCE aborts tools like
    # systemd-tmpfiles at runtime ("buffer overflow detected"). Step down to
    # level 1 (nixpkgs' default level); fortify3 and the rest stay on.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    # The ukify wrapper installed into $tools/bin references python3 +
    # the pefile / pyelftools site-packages. Listed in nukeRefsKeep so
    # scrubPhase preserves the hashes only inside the tools output.
    nukeRefsKeep = [binutils python3 python3-pefile python3-pyelftools];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd systemd-${version}
        '';
      }
      {
        name = "patch-source";
        script = ''
          cp ${./aos-resource-unit-name.h} src/core/aos-resource-unit-name.h
          nativePython=$(command -v python3)

          # kernel-install and its complete plugin set live with ukify in the
          # tools output. Preserve administrator overrides in /etc/kernel.
          test "$(grep -Fc '"/usr/lib/kernel/install.d"' src/kernel-install/kernel-install.c)" -eq 1
          sed -i \
            "s|\"/usr/lib/kernel/install.d\"|\"$tools/lib/kernel/install.d\"|" \
            src/kernel-install/kernel-install.c

          # libseccomp is loaded on demand, so DT_NEEDED-based RPATH shrinking
          # cannot retain its search directory. Bind the loader to the AOS
          # library's real inode: immutable stage 0 rejects an absolute dlopen
          # path that still traverses even an in-store SONAME symlink.
          test "$(grep -Fc '"libseccomp.so.2"' src/shared/seccomp-util.c)" -eq 1
          libseccomp_real=$(${coreutils}/bin/readlink -f \
            ${libseccomp}/lib/libseccomp.so.2)
          test -f "$libseccomp_real"
          sed -i \
            "s|\"libseccomp.so.2\"|\"$libseccomp_real\"|" \
            src/shared/seccomp-util.c

          # Configure executes helpers such as git-setup.sh directly. Bind
          # their interpreters through the standard build-environment helper.
          patchShebangs .

          # Preserve Python shebang pinning for non-executable sources too.
          for f in $(find . -type f -name '*.py'); do
            if head -1 "$f" | grep -q '^#!'; then
              sed -i "1s|#!/usr/bin/env python3|#!$nativePython|" "$f"
              sed -i "1s|#!/usr/bin/python3|#!$nativePython|" "$f"
            fi
          done

          # linux/vm_sockets.h needs struct sockaddr/sa_family_t from sys/socket.h.
          # glibc 2.39's linux/vm_sockets.h doesn't include it automatically.
          sed -i 's|#include <linux/vm_sockets.h>|#include <sys/socket.h>\n#include <linux/vm_sockets.h>|' \
            src/basic/socket-util.h

          # Rewrite hardcoded binary paths that don't have a meson
          # `-D<tool>-path=` equivalent.
          sed -i 's|/sbin/modprobe|${kmod}/sbin/modprobe|g' units/modprobe@.service
          sed -i "s|/usr/lib/systemd/catalog/|$out/lib/systemd/catalog/|g" \
            src/libsystemd/sd-journal/catalog.c

          # Replace DEFAULT_PATH macros with the Nix store bin path.
          # systemd uses these to resolve bare names in ExecStart= (e.g.
          # systemd-tmpfiles, udevadm, journalctl).  Upstream defaults to
          # /usr/{,local/}{s,}bin which don't exist on AOS.
          # (Same approach as NixOS: single $out/bin, no FHS paths.)
          sed -i \
            -e 's|#define DEFAULT_PATH_WITH_FULL_SBIN .*|#define DEFAULT_PATH_WITH_FULL_SBIN "'"$out"'/bin:'"$out"'/lib/systemd"|' \
            -e 's|#define DEFAULT_PATH_WITH_LOCAL_SBIN .*|#define DEFAULT_PATH_WITH_LOCAL_SBIN DEFAULT_PATH_WITH_FULL_SBIN|' \
            -e 's|#define DEFAULT_PATH_WITHOUT_SBIN .*|#define DEFAULT_PATH_WITHOUT_SBIN DEFAULT_PATH_WITH_FULL_SBIN|' \
            -e 's|#define DEFAULT_PATH_COMPAT .*|#define DEFAULT_PATH_COMPAT DEFAULT_PATH_WITH_FULL_SBIN|' \
            src/basic/path-util.h
        '';
      }
      {
        name = "configure";
        script = ''
                  cp ${./aos-offline-public-output.h} src/core/aos-offline-public-output.h
                  # Ensure meson's Python module, pefile, and pyelftools
                  # are findable both at meson-configure time and when
                  # ninja later invokes patched python3 scripts (e.g.
                  # src/boot/generate-hwids-section.py which imports
                  # ukify → pefile).
                  nativeMesonRoot=$(dirname "$(dirname "$(command -v meson)")")
                  export PYTHONPATH="$nativeMesonRoot/lib/python3/site-packages:${ukifyPythonPath}''${PYTHONPATH:+:$PYTHONPATH}"

                  # systemd's meson.build uses `pymod.find_installation(
                  # 'python3', modules: ['elftools'])` — meson's python
                  # module runs the probe through `subprocess.run` with
                  # an env-sanitized child, so the parent's PYTHONPATH
                  # export above does NOT reach that check. Wrap python3
                  # with a shell script that re-exports PYTHONPATH and
                  # exec's the real interpreter; put the wrapper first
                  # in PATH so meson's `find_program('python3')` lands
                  # on it. (The exported PYTHONPATH at phase level
                  # still handles the ninja build path, which invokes
                  # scripts by their pinned store-path shebangs.)
                  mkdir -p .python-wrapper/bin
                  cat > .python-wrapper/bin/python3 << PYW
          #!$CONFIG_SHELL
          export PYTHONPATH="${ukifyPythonPath}\''${PYTHONPATH:+:\$PYTHONPATH}"
          exec $(command -v python3) "\$@"
          PYW
                  chmod +x .python-wrapper/bin/python3
                  export PATH="$(pwd)/.python-wrapper/bin:$PATH"

                  # Keep the numeric layout and its image association together.
                  # Only these generated headers enter the source tree; none
                  # embeds a development-output path in the running manager.
                  clone_layout="${kernelCloneLayout}/share/aos-kernel-clone-layout-v1"
                  for clone_header in \
                    aos-kernel-clone-layout-v1.h \
                    aos-kernel-clone-association-v1.h
                  do
                    test -s "$clone_layout/$clone_header"
                    cp "$clone_layout/$clone_header" "src/core/$clone_header"
                  done

                  # Managed user namespaces require the BPF LSM skeleton. Bind
                  # its CO-RE types to the selected AOS kernel, never host /sys.
                  kernel_build="$(${findutils}/bin/find ${kernelCloneLayout}/lib/modules \
                    -mindepth 2 -maxdepth 2 -name build -type d)"
                  test -n "$kernel_build"
                  test -s "$kernel_build/vmlinux"
                  # Compiling a skeleton does not prove that its retirement
                  # target exists or that this kernel supports BPF trampolines.
                  # Inspect target metadata with native tools in cross builds.
                  cp ${./_systemd-abilities/userns_bpf_kernel.py} userns_bpf_kernel.py
                  cp ${./_systemd-abilities/userns_bpf_kernel_test.py} userns_bpf_kernel_test.py
                  python3 -B userns_bpf_kernel_test.py
                  bpftool btf dump file "$kernel_build/vmlinux" format raw > userns-kernel.btf
                  python3 -B userns_bpf_kernel.py "$clone_layout/kernel.config" userns-kernel.btf
                  bpftool btf dump file "$kernel_build/vmlinux" format c > vmlinux.h
                  test -s vmlinux.h
                  aos_vmlinux_header="$PWD/vmlinux.h"

                  # Clang's BPF target has no libc search path. Supply only the
                  # target's AOS UAPI/libc headers; leave ordinary C builds on
                  # the existing compiler wrapper and its header ordering.
                  mkdir -p .bpf-tools
                  cat > .bpf-tools/clang <<'BPF_CLANG'
          #!${buildPackages.bash}/bin/bash
          exec ${buildPackages.llvm}/bin/clang \
            -idirafter ${linux-headers}/include \
            -idirafter ${lib.getDev stdenv.glibc}/include "$@"
          BPF_CLANG
                  chmod +x .bpf-tools/clang
                  export PATH="$PWD/.bpf-tools:$PATH"

                  # Explicit RPATH keeps systemd's own shared libs resolvable.
                  export LDFLAGS="''${LDFLAGS:-} -Wl,-rpath,$out/lib -Wl,-rpath,$out/lib/systemd"

                  # Override compiled-in binary paths so systemd references its
                  # own store path at runtime (not /lib/systemd/systemd).
                  export CFLAGS="''${CFLAGS:-} \
                    -Wno-error=missing-prototypes -Wno-error=return-type \
                    -DSYSTEMD_BINARY_PATH=\"\\\"$out/lib/systemd/systemd\\\"\" \
                    -DSYSTEMD_CGROUP_AGENTS_PATH=\"\\\"$out/lib/systemd/systemd-cgroups-agent\\\"\""

                  # Strip linux-headers from C_INCLUDE_PATH so we can add it as
                  # -I in build.ninja with controlled ordering (GCC ignores -I for
                  # dirs already in C_INCLUDE_PATH, which is treated as -isystem).
                  export C_INCLUDE_PATH="$(echo "$C_INCLUDE_PATH" | tr ':' '\n' | grep -v linux-headers | tr '\n' ':' | sed 's/:$//')"

                  mkdir -p build && cd build
                  # The stage-2 launcher must carry a GNU build ID; Meson did
                  # not retain it when it was supplied through LDFLAGS alone.
                  meson setup .. \
                    $mesonFlags \
                    --prefix=$out \
                    --sysconfdir=/etc \
                    -Dwerror=false \
                    --buildtype=release \
                    '-Dc_link_args=["-Wl,--build-id=sha1"]' \
                    -Dmode=release \
                    -Dbpf-framework=enabled \
                    -Dvmlinux-h=provided \
                    -Dvmlinux-h-path="$aos_vmlinux_header" \
                    -Dsysvinit-path="" \
                    -Dsysvrcnd-path="" \
                    -Dutmp=true \
                    -Dhibernate=false \
                    -Dldconfig=false \
                    -Dresolve=true \
                    -Defi=true \
                    -Dbootloader=enabled \
                    -Dukify=enabled \
                    -Dsbat-distro=aos \
                    -Dsbat-distro-generation=1 \
                    '-Dsbat-distro-summary=ANDYL OS' \
                    -Dsbat-distro-pkgname=systemd \
                    -Dsbat-distro-version=${version} \
                    -Dsbat-distro-url=https://andyl.com \
                    -Dtpm=true \
                    -Denvironment-d=false \
                    -Dbinfmt=false \
                    -Drepart=enabled \
                    -Dcoredump=true \
                    -Dpstore=false \
                    -Doomd=true \
                    -Dlogind=true \
                    -Dhostnamed=true \
                    -Dlocaled=false \
                    -Dmachined=false \
                    -Dportabled=false \
                    -Dsysext=false \
                    -Duserdb=false \
                    -Dhomed=disabled \
                    -Dnetworkd=true \
                    -Dtimedated=true \
                    -Dtimesyncd=true \
                    -Dremote=disabled \
                    -Dnss-myhostname=true \
                    -Dnss-mymachines=disabled \
                    -Dnss-resolve=enabled \
                    -Dnss-systemd=true \
                    -Dfirstboot=false \
                    -Drandomseed=true \
                    -Dbacklight=false \
                    -Dvconsole=false \
                    -Dquotacheck=false \
                    -Dsysusers=true \
                    -Dtmpfiles=true \
                    -Dimportd=disabled \
                    -Dhwdb=true \
                    -Drfkill=false \
                    -Dxdg-autostart=false \
                    -Dman=disabled \
                    -Dhtml=disabled \
                    -Dtranslations=false \
                    -Dinstall-sysconfdir=false \
                    -Dcreate-log-dirs=false \
                    -Dsshconfdir=no \
                    -Dsshdconfdir=no \
                    -Dacl=enabled \
                    -Dpam=enabled \
                    -Dlibcryptsetup=enabled \
                    -Dlibcryptsetup-plugins=enabled \
                    -Dseccomp=enabled \
                    -Dselinux=enabled \
                    -Dapparmor=disabled \
                    -Daudit=enabled \
                    -Dkmod=enabled \
                    -Dblkid=enabled \
                    -Dfdisk=enabled \
                    -Dgnutls=disabled \
                    -Dopenssl=enabled \
                    -Dp11kit=disabled \
                    -Dlibfido2=disabled \
                    -Dtpm2=enabled \
                    -Dlibcurl=disabled \
                    -Dlibidn2=disabled \
                    -Dlibidn=disabled \
                    -Dlibiptc=disabled \
                    -Dqrencode=disabled \
                    -Dgcrypt=disabled \
                    -Delfutils=enabled \
                    -Dzlib=enabled \
                    -Dlz4=enabled \
                    -Dxz=enabled \
                    -Dzstd=enabled \
                    -Ddefault-dnssec=no \
                    -Ddefault-mdns=no \
                    -Ddefault-llmnr=no \
                    -Dmount-path=${util-linux}/bin/mount \
                    -Dumount-path=${util-linux}/bin/umount \
                    -Dagetty-path=${util-linux}/sbin/agetty \
                    -Dswapon-path=${util-linux}/sbin/swapon \
                    -Dswapoff-path=${util-linux}/sbin/swapoff \
                    -Dsulogin-path=${util-linux}/sbin/sulogin \
                    -Dnologin-path=${util-linux}/sbin/nologin \
                    -Dkmod-path=${kmod}/bin/kmod \
                    -Ddbuspolicydir=$out/share/dbus-1/system.d \
                    -Ddbussessionservicedir=$out/share/dbus-1/services \
                    -Ddbussystemservicedir=$out/share/dbus-1/system-services \
                    -Ddbus-interfaces-dir=$out/share/dbus-1/interfaces

                  grep -Fxq '#define BPF_FRAMEWORK 1' config.h
                  grep -Fxq '#define HAVE_LIBBPF 1' config.h
                  grep -Fxq '#define HAVE_VMLINUX_H 1' config.h

                  # systemd's src/include/override/ has replacement headers (sys/syscall.h,
                  # sys/socket.h, sys/mount.h, linux/keyctl.h, etc.) that use
                  # #include_next to chain to glibc while adding missing defines
                  # (SCM_MAX_FD, KEY_POS_VIEW, __NR_setxattrat, struct xattr_args...).
                  #
                  # Problem: cc-wrapper injects -isystem /glibc/include BEFORE meson's
                  # -isystem for the override dir, so glibc headers always win.
                  #
                  # Fix: AFTER meson generates build.ninja (so configure checks are
                  # unaffected), promote overrides from -isystem to -I and append
                  # linux-headers -I so the search order is:
                  #   1. override/ (-I, has fallback defines + #include_next)
                  #   2. linux-headers (-I, newer kernel UAPI than glibc's bundled copy)
                  #   3. glibc (-isystem from cc-wrapper)
                  sed -i 's|-isystem\.\./src/include/override|-I../src/include/override|g' build.ninja
                  sed -i 's|-isystemsrc/include/override|-Isrc/include/override|g' build.ninja
                  sed -i 's|-isystem\.\./src/include/uapi|-I../src/include/uapi -I${linux-headers}/include|g' build.ninja

                  # Rename conflicting defines in config.h so our CFLAGS
                  # -DSYSTEMD_BINARY_PATH etc. take effect without warnings.
                  sed -i \
                    -e 's/SYSTEMD_BINARY_PATH/_SYSTEMD_BINARY_PATH_MESON/' \
                    -e 's/SYSTEMD_CGROUP_AGENTS_PATH/_SYSTEMD_CGROUP_AGENTS_PATH_MESON/' \
                    config.h
        '';
      }
      {
        name = "build";
        script = ''
          ninja -j$NIX_BUILD_CORES

          # Inspect the generated BPF object, including in cross builds. A
          # successful C build alone does not establish its attachment kind.
          ${buildPackages.binutils}/bin/readelf -SW src/bpf/userns-restrict.bpf.o \
            > userns-restrict-sections.txt
          grep -Fq ' fentry/retire_userns_sysctls ' userns-restrict-sections.txt
          if grep -Eq '[[:space:]]k(ret)?probe/' userns-restrict-sections.txt; then
            echo 'namespace retirement unexpectedly retains a kprobe section' >&2
            exit 1
          fi
        '';
      }
      {
        name = "check-aos-payload-seccomp";
        script =
          if stdenv.isCross
          then ''
            # Target execution belongs to the architecture-specific VM gate.
            true
          ''
          else ''
            ./test-nspawn-seccomp
          '';
      }
      {
        name = "check-aos-offline-public-output";
        script = ''
          for selinux_enabled in 0 1; do
            $CC -std=c17 -Wall -Wextra -Werror \
              -DHAVE_SELINUX=$selinux_enabled -I../src/core \
              ${./tests/offline-public-output.c} -o test-aos-offline-public-output
            ${lib.optionalString (!stdenv.isCross) "./test-aos-offline-public-output"}
          done
        '';
      }
      {
        name = "install";
        # DESTDIR=/ satisfies systemd's "test -n $DESTDIR" guard that skips
        # live-system mutations during packaging.  With --prefix=$out, all
        # install paths are already absolute Nix store paths, so DESTDIR=/
        # is effectively a no-op for prefix-relative targets.
        script = ''
          DESTDIR=/ ninja install
          ${elfutils}/bin/eu-readelf --notes "$out/lib/systemd/systemd" \
            | grep -Fq 'Build ID:'
          # A patch log is insufficient evidence that PID 1 contains the
          # authenticated switch-root guard; enforce it on the installed ELF.
          ${grep}/bin/grep -aFq 'Cannot open authenticated AOS root-handoff guard' \
            "$out/lib/systemd/systemd"

          # The fixed public-output label must be in the installed executor,
          # not only in an unapplied patch or its isolated state-machine test.
          ${grep}/bin/grep -aFq 'aos_nix_offline_public_output_t' \
            "$out/lib/systemd/systemd-executor"

          # This target realizes the provider-neutral boot-integrity-failure
          # milestone for the selected systemd boot platform.
          cp ${./aos-boot-integrity-failure.target} \
            "$out/lib/systemd/system/aos-boot-integrity-failure.target"

          # Source generators must run with native Python during the cross
          # build. Retarget installed scripts to the AArch64 interpreter.
          nativePythonRoot=$(dirname "$(dirname "$(command -v python3)")")
          nativePythonRefs=$(mktemp)
          if grep -IrlZ -F "$nativePythonRoot" "$out" > "$nativePythonRefs" 2>/dev/null; then
            xargs -0 -r sed -i "s|$nativePythonRoot|${python3}|g" < "$nativePythonRefs"
          else
            grepStatus=$?
            # No references is expected when upstream installed scripts
            # already use the target interpreter. Preserve real grep errors.
            [ "$grepStatus" -eq 1 ] || exit "$grepStatus"
          fi
          rm -f "$nativePythonRefs"

          # Upstream leaves several installed helpers on host-global
          # interpreters, which do not exist on AOS. Keep the explicit list in
          # sync with the installed systemd and kernel-install entry points.
          for script in \
            "$out/lib/kernel/install.d/50-depmod.install" \
            "$out/lib/kernel/install.d/90-loaderentry.install" \
            "$out/lib/kernel/install.d/90-uki-copy.install" \
            "$out/lib/systemd/systemd-update-helper"; do
            sed -i "1c #!${bash}/bin/bash" "$script"
          done
          sed -i "1c #!${python3}/bin/python3" \
            "$out/lib/kernel/install.d/60-ukify.install"

          mkdir -p "$out/libexec"
          sed \
            -e 's|@bash@|${bash}|g' \
            -e 's|@libselinux@|${libselinux}|g' \
            ${./aos-systemd-verity-root-setup.sh.in} \
            > "$out/libexec/aos-systemd-verity-root-setup"
          chmod 0555 "$out/libexec/aos-systemd-verity-root-setup"

          sed \
            -e 's|@bash@|${bash}|g' \
            -e "s|@systemd_creds@|$out/bin/systemd-creds|g" \
            ${./aos-systemd-boot-credential-seal.sh.in} \
            > "$out/libexec/aos-boot-credential-seal"
          chmod 0555 "$out/libexec/aos-boot-credential-seal"
        '';
      }
      {
        name = "wrap-runtime-tools";
        # systemd's LUKS2 token plugins (libcryptsetup-token-*.so) are loaded
        # via dlopen from $out/lib/cryptsetup/. DT_RPATH on the binary does not
        # propagate to libraries loaded via dlopen, so
        # systemd-cryptsetup and systemd-cryptenroll need LD_LIBRARY_PATH
        # extended at runtime to find them. nixpkgs handles this with
        # wrapProgram (makeWrapper); AOS has no wrapProgram, so we inline
        # the equivalent shell wrapper.
        #
        # Note on escapes: the heredoc body must contain the literal text
        # `${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}` so the fallback is
        # evaluated at wrapper RUNTIME, not at cat time. Both $ signs are
        # escaped with \ so the unquoted heredoc doesn't expand them at
        # cat time. (stdenv/setup.sh:47 sets LD_LIBRARY_PATH during the
        # build from buildInputs, so an unescaped ${LD_LIBRARY_PATH:+...}
        # would fire at cat time and produce a trailing-colon path — a
        # classic ld.so CWD-search bug.)
        script = ''
          # Meson does not preserve the cc-wrapper RPATH on every target.
          # First resolve direct dependencies and discard unused build paths,
          # then retain existing declared library directories for systemd's
          # dlopen calls. Some runtime tools, notably bash, have no lib/; a
          # nonexistent RPATH fails the immutable stage-0 closure audit.
          runtime_library_path="$out/lib:$out/lib/systemd"
          for dependency in ${builtins.concatStringsSep " " (map builtins.toString systemdRuntimeLibraries)}; do
            if [ -d "$dependency/lib" ]; then
              runtime_library_path="$runtime_library_path:$dependency/lib"
            fi
          done
          find "$out" -type f | while read -r executable; do
            patchelf --print-needed "$executable" >/dev/null 2>&1 || continue
            patchelf --force-rpath --add-rpath \
              "$runtime_library_path" \
              "$executable"
            patchelf --shrink-rpath "$executable"
            # glibc's libgcc_s unwind load is an indirect dlopen. DT_RPATH
            # carries the sealed directory set to linked descendants;
            # DT_RUNPATH does not.
            patchelf --force-rpath --add-rpath \
              "$runtime_library_path" \
              "$executable"
          done

          for f in bin/systemd-cryptsetup bin/systemd-cryptenroll; do
            if [ -x "$out/$f" ]; then
              wrapped="$out/$f"
              mv "$wrapped" "$wrapped.unwrapped"
              cat > "$wrapped" << EOF
          #!${bash}/bin/bash
          export LD_LIBRARY_PATH="$out/lib/cryptsetup\''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
          exec "$wrapped.unwrapped" "\$@"
          EOF
              chmod +x "$wrapped"
            fi
          done

          # ukify: pefile must be importable when the wrapped shebang
          # runs. systemd's meson install lays the script down with a
          # plain python3 shebang — we relocate it into the `tools`
          # output (so the python3 / pefile / pyelftools refs don't
          # land in PID-1 systemd's closure) and emit a bash wrapper
          # that exports PYTHONPATH pointing at python3-pefile's
          # site-packages before invoking python3 on the original
          # script.
          if [ -x "$out/bin/ukify" ]; then
            mkdir -p "$tools/bin" "$tools/lib/systemd"
            mv "$out/bin/ukify" "$tools/bin/.ukify-unwrapped"
            sed -i "1c #!${python3}/bin/python3" \
              "$tools/bin/.ukify-unwrapped"
            cat > "$tools/bin/ukify" << EOF
          #!${bash}/bin/bash
          export PATH="${binutils}/bin:\$PATH"
          export PYTHONPATH="${ukifyPythonPath}\''${PYTHONPATH:+:\$PYTHONPATH}"
          exec "${python3}/bin/python3" "$tools/bin/.ukify-unwrapped" "\$@"
          EOF
            chmod +x "$tools/bin/ukify"

            # Meson also installs a relative compatibility alias. Keep it
            # beside the relocated tool; leaving it in $out points at the
            # now-absent $out/bin/ukify and breaks the immutable stage-0
            # runtime-closure audit.
            mv "$out/lib/systemd/ukify" "$tools/lib/systemd/ukify"
            test -x "$tools/lib/systemd/ukify"
          fi

          mkdir -p "$tools/lib/kernel"
          mv "$out/bin/kernel-install" "$tools/bin/kernel-install"
          mv "$out/lib/kernel/install.d" "$tools/lib/kernel/install.d"

          # The Python plugin imports ukify as a module, so point it at the
          # unwrapped source instead of the public shell launcher. Both tools
          # receive the same pefile and pyelftools module search path.
          ukify_hook="$tools/lib/kernel/install.d/60-ukify.install"
          mv "$ukify_hook" "$ukify_hook.unwrapped"
          cat > "$ukify_hook" << EOF
          #!${bash}/bin/bash
          export PYTHONPATH="${ukifyPythonPath}\''${PYTHONPATH:+:\$PYTHONPATH}"
          export KERNEL_INSTALL_UKIFY="\''${KERNEL_INSTALL_UKIFY:-$tools/bin/.ukify-unwrapped}"
          exec "${python3}/bin/python3" "$ukify_hook.unwrapped" "\$@"
          EOF
          chmod +x "$ukify_hook"
        '';
      }
      {
        name = "install-aos-payload-policy";
        script = ''
          test -x "$out/lib/systemd/systemd"
          test -x "$out/bin/systemd-nspawn"
          mkdir -p "$out/share/aos"
          cp ${./payload-root-policy-v1} "$out/share/aos/payload-root-policy-v1"
          # Meson leaves the phase in build/, one level below patched source.
          cp ../src/nspawn/nspawn-seccomp.c "$out/share/aos/nspawn-seccomp-source-v1"
          ${
            if stdenv.isCross
            then ''
              # No target execution or substitute host artifact is implied. The
              # selected canary's expected-program producer remains unavailable
              # for cross builds; ordinary package features are unchanged.
            ''
            else ''
              ./test-nspawn-seccomp --aos-export-payload-programs-v1 \
                > "$out/share/aos/payload-filter-programs-v1"
              program_bytes=$(${coreutils}/bin/stat -c %s \
                "$out/share/aos/payload-filter-programs-v1")
              test "$program_bytes" -gt 176
              test "$program_bytes" -le 98504
            ''
          }
        '';
      }
      {
        name = "install-native-platform-tools";
        script = ''
          mkdir -p "$handlers/bin"
          cat > "$handlers/bin/aos-systemd-credential-encrypt" << EOF
          #!${bash}/bin/bash
          exec "${aos-systemd-provider}/bin/aos-systemd-credential-encrypt" \\
            --systemd-creds "$out/bin/systemd-creds" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-credential-encrypt"

          cat > "$handlers/bin/aos-systemd-boot-platform" << EOF
          #!${bash}/bin/bash
          exec "${aos-systemd-provider}/bin/aos-systemd-boot-platform" \\
            --bootctl "$out/bin/bootctl" \\
            --bless-boot "$out/lib/systemd/systemd-bless-boot" \\
            --mount "${util-linux}/bin/mount" \\
            --systemctl "$out/bin/systemctl" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-boot-platform"

          cat > "$handlers/bin/aos-systemd-image-evidence" << EOF
          #!${bash}/bin/bash
          exec "${aos-systemd-provider}/bin/aos-systemd-image-evidence" \\
            --openssl "${openssl}/bin/openssl" \\
            --objcopy "${pe-tools}/bin/objcopy" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-image-evidence"

        '';
      }
      {
        name = "install-native-image-stage";
        script = ''
          mkdir -p "$handlers/bin"
          cat > "$handlers/bin/aos-systemd-image-stage" << EOF
          #!${bash}/bin/bash
          exec "${aos-systemd-provider}/bin/aos-systemd-image-stage" \\
            --mount "${util-linux}/bin/mount" \\
            --umount "${util-linux}/bin/umount" \\
            --blkid "${util-linux}/sbin/blkid" \\
            --veritysetup "${cryptsetup}/sbin/veritysetup" \\
            --nix-store "${nix}/bin/nix-store" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-image-stage"
        '';
      }
      {
        name = "install-native-network-handler";
        script = ''
          mkdir -p "$handlers/libexec" "$handlers/bin"
          cp ${./_systemd-abilities/network-handler.py} "$handlers/libexec/aos-network-handler.py"
          cat > "$handlers/bin/aos-network-handler" << EOF
          #!${bash}/bin/bash
          exec "${python3}/bin/python3" "$handlers/libexec/aos-network-handler.py" \\
            --systemctl "$out/bin/systemctl" \\
            --wait-online "$out/lib/systemd/systemd-networkd-wait-online" \\
            --unit-directory "$out/lib/systemd/system" \\
            --matchpathcon "${libselinux}/sbin/matchpathcon" \\
            --setfilecon "${libselinux}/sbin/setfilecon" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-network-handler"
        '';
      }
      {
        name = "install-native-service-handler";
        script = ''
          mkdir -p "$handlers/libexec" "$handlers/bin"
          cp ${./_systemd-abilities/service-handler.py} "$handlers/libexec/aos-service-handler.py"
          cp ${./_systemd-abilities/aos_service_resources.py} "$handlers/libexec/aos_service_resources.py"
          cp ${./_systemd-abilities/aos_service_storage.py} "$handlers/libexec/aos_service_storage.py"
          cat > "$handlers/bin/aos-service-handler" << EOF
          #!${bash}/bin/bash
          export PYTHONPATH="$handlers/libexec"
          exec "${python3}/bin/python3" -B "$handlers/libexec/aos-service-handler.py" \\
            --systemctl "$out/bin/systemctl" \\
            --true-executable "${coreutils}/bin/true" \\
            --flock-executable "${util-linux}/bin/flock" \\
            --mac-condition-executable "$handlers/bin/aos-service-handler" \\
            --matchpathcon "${libselinux}/sbin/matchpathcon" \\
            --setfilecon "${libselinux}/sbin/setfilecon" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-service-handler"

          cp ${./_systemd-abilities/bootstrap-provider.py} "$handlers/libexec/aos-systemd-bootstrap.py"
          cat > "$handlers/bin/aos-systemd-bootstrap" << EOF
          #!${bash}/bin/bash
          export PYTHONPATH="$handlers/libexec"
          exec "${python3}/bin/python3" -B "$handlers/libexec/aos-systemd-bootstrap.py" \\
            --nix-store "${nix}/bin/nix-store" \\
            --nix-hash "${nix}/bin/nix-hash" \\
            --group-renderer "$handlers/bin/aos-systemd-native-resources" \\
            --true-executable "${coreutils}/bin/true" \\
            --flock-executable "${util-linux}/bin/flock" \\
            --mac-condition-executable "$handlers/bin/aos-service-handler" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-bootstrap"
        '';
      }
      {
        name = "install-native-resource-handler";
        script = ''
          mkdir -p "$handlers/bin"
          cat > "$handlers/bin/aos-systemd-native-resources" << EOF
          #!${bash}/bin/bash
          exec "${aos-systemd-provider}/bin/aos-systemd-native-resource-provider" \\
            --systemd-creds "$out/bin/systemd-creds" \\
            --login-shell "${identityShells.login}" \\
            --nologin-shell "${identityShells.nologin}" \\
            --matchpathcon "${libselinux}/sbin/matchpathcon" \\
            --setfilecon "${libselinux}/sbin/setfilecon" \\
            "\$@"
          EOF
          chmod +x "$handlers/bin/aos-systemd-native-resources"
        '';
      }
      {
        name = "verify-runtime-configuration-paths";
        script = ''
          # PID 1 must retain dlopen libraries without inheriting the tools
          # used by separate assembly and native-handler executables.
          pid1_rpath=$(patchelf --print-rpath "$out/lib/systemd/systemd")
          case ":$pid1_rpath:" in
            *":${cryptsetup}/lib:"*) ;;
            *) echo "systemd PID 1 is missing its cryptsetup library path" >&2; exit 1 ;;
          esac
          for tool in ${lib.concatStringsSep " " (map toString [python3 cpio dosfstools erofs-utils fakeroot mtools aos-recovery pe-tools])}; do
            case ":$pid1_rpath:" in
              *":$tool/lib:"*)
                echo "systemd PID 1 retains an unrelated tool library path: $tool" >&2
                exit 1
                ;;
            esac
          done

          for executable in aos-systemd-credential-encrypt aos-systemd-boot-platform aos-systemd-image-evidence aos-systemd-image-stage; do
            test -x "$handlers/bin/$executable"
            test ! -e "$out/bin/$executable"
            test ! -L "$out/bin/$executable"
          done
          grep -F -- '--nix-store "${nix}/bin/nix-store"' \
            "$handlers/bin/aos-systemd-image-stage" >/dev/null

          # Administrator state belongs to the live /etc overlay. Compiling
          # the output path into systemd would let runtime tools mutate the
          # package through the writable /nix overlay.
          grep -F '/etc/profile.d/70-systemd-shell-extra.sh' \
            "$out/lib/tmpfiles.d/20-systemd-shell-extra.conf" >/dev/null
          grep -F '/etc/profile.d/80-systemd-osc-context.sh' \
            "$out/lib/tmpfiles.d/20-systemd-osc-context.conf" >/dev/null
          if grep -F "$out/etc/profile.d" \
            "$out/lib/tmpfiles.d/20-systemd-shell-extra.conf" \
            "$out/lib/tmpfiles.d/20-systemd-osc-context.conf" >/dev/null; then
            echo "systemd tmpfiles targets its immutable output" >&2
            exit 1
          fi

          test ! -e "$out/etc"

          ${
            if stdenv.isCross
            then ''
              echo "skipping target systemd path execution while cross-compiling"
            ''
            else ''
              # Reaching request parsing proves every pinned staging tool
              # exists and resolves inside its retained package output.
              if printf '%s' '{}' | "$handlers/bin/aos-systemd-image-stage" \
                > stage-probe.out 2> stage-probe.err; then
                echo "image staging accepted an incomplete request" >&2
                exit 1
              fi
              test ! -s stage-probe.out
              grep -F 'missing field `schema`' stage-probe.err >/dev/null

              test "$($out/bin/systemd-path system-configuration)" = /etc

              unitPaths="$($out/bin/systemd-analyze unit-paths)"
              printf '%s\n' "$unitPaths" \
                | grep -Fx /etc/systemd/system >/dev/null
              if printf '%s\n' "$unitPaths" \
                | grep -Fx "$out/etc/systemd/system" >/dev/null; then
                echo "systemd runtime unit lookup includes its immutable output" >&2
                exit 1
              fi
            ''
          }
        '';
      }
    ];

    # Fixup strips nspawn and adjusts RPATHs; reference scrubbing can change
    # either executable afterward. Bind the public artifact only once their
    # installed bytes are final. Host independently verifies the live manager
    # and executable; this metadata cannot grant backend readiness.
    postFinalize = ''
      pid1_digest=$(sha256sum "$out/lib/systemd/systemd")
      nspawn_digest=$(sha256sum "$out/bin/systemd-nspawn")
      payload_filter_digest=$(sha256sum "$out/share/aos/nspawn-seccomp-source-v1")
      pid1_digest=''${pid1_digest%% *}
      nspawn_digest=''${nspawn_digest%% *}
      payload_filter_digest=''${payload_filter_digest%% *}
      {
        printf 'AOSBPA02\n'
        printf '%s\n' "$pid1_digest"
        printf '%s\n' "$nspawn_digest"
        cat "$out/share/aos/payload-root-policy-v1"
        printf '%s\n' "$payload_filter_digest"
      } > "$out/share/aos/backend-policy-artifact-v2"
    '';

    meta = {
      description = "systemd — system and service manager for Linux";
      homepage = "https://systemd.io";
      license = "LGPL-2.1-or-later";
    };
  }
