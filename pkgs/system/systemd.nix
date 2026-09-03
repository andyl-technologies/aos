##! systemd — System and service manager
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gawk,
  linux-headers,
  util-linux,
  kmod,
  zlib,
  xz,
  lz4,
  zstd,
  openssl,
  perl,
  meson,
  ninja,
  python3,
  gperf,
  getent,
  libcap,
  libxcrypt,
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
  bash,
  python3-pefile,
  python3-pyelftools,
}: let
  version = "259.8";

  # PYTHONPATH that makes `import pefile` / `import elftools` succeed
  # when ukify runs (both also needed during meson configure — see
  # the configure phase's PYTHONPATH export). python3.nix pins 3.14.
  ukifyPythonPath = "${python3-pefile}/lib/python3.14/site-packages:${python3-pyelftools}/lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "systemd";
    inherit version;

    # Split ukify into a `tools` output so the python3-pefile and
    # python3-pyelftools site-packages stay out of PID-1 systemd's
    # runtime closure. aos-uki (the only consumer of ukify) pulls
    # systemd.tools explicitly.
    outputs = ["out" "tools"];

    src = fetchurl {
      urls = [
        "https://github.com/systemd/systemd/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-eECOyN7Dwn6XphbzUNXFLZYBbUuflXbpv1ghHw2ZZLc=";
    };

    # Patches applied after unpack (via mkDerivation's built-in patch phase):
    #   0001 — Remove /usr/lib, /usr/local/lib, /lib fallback paths from
    #          path-lookup.c so systemd only searches SYSTEM_DATA_UNIT_DIR
    #          (= $out/lib/systemd/system with --prefix=$out) and /etc.
    #   0002 — Add PREFIX "/lib/" to CONF_PATHS macro in constants.h so
    #          systemd finds tmpfiles.d, sysctl.d, modules-load.d etc. in
    #          the Nix store.
    #   0003 — Remove install_emptydir(systemdstatedir) from meson.build
    #          (resolves to /var/lib/systemd which can't be created in the
    #          sandbox; created at system activation time instead).
    #   0004 — Skip creating /run/systemd for test-run managers so offline
    #          analysis tools can run inside the Nix sandbox.
    #   0005 — Fail closed when RootHashSignature= is present but the kernel
    #          rejects the dm-verity signed-key activation.
    #   0006 — Keep an embedded signed UKI command line authoritative over
    #          addon and SMBIOS fragments that run before initrd validation.
    #   0007 — Add the closed AOS payload seccomp profile to nspawn and install
    #          it after container setup, immediately before payload execution.
    patches = [
      ./patches/0001-remove-usr-lib-unit-lookup-paths.patch
      ./patches/0002-add-prefix-to-conf-paths.patch
      ./patches/0003-remove-install-emptydir-systemdstatedir.patch
      ./patches/0004-skip-runtime-dir-for-test-run-manager.patch
      ./patches/0005-fail-closed-on-roothash-signature-rejection.patch
      ./patches/0006-ignore-external-cmdline-for-embedded-uki.patch
      ./patches/0007-nspawn-aos-payload-seccomp-profile.patch
    ];

    buildDeps = [
      gnumake
      pkg-config
      gawk
      perl
      meson
      ninja
      python3
      gperf
      getent
      # Kernel UAPI headers are compile-time only. Keeping them out of
      # runtimeDeps avoids a dead RPATH/RUNPATH entry (linux-headers ships no
      # shared library) and keeps the 7 MiB header tree out of the closure.
      linux-headers
    ];
    runtimeDeps = [
      util-linux
      kmod
      zlib
      xz
      lz4
      zstd
      openssl
      libcap
      libxcrypt
      audit
      libselinux
      libsepol
      pcre2
      libseccomp
      acl
      cryptsetup
      elfutils
      linux-pam
      # TPM2 (RFC-0006 phase 3): libtss2-esys/rc/mu + the device TCTI for
      # systemd-cryptsetup's TPM2 token, systemd-pcrextend, systemd-measure.
      tpm2-tss
    ];
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
    nukeRefsKeep = [python3 python3-pefile python3-pyelftools];

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
          # Fix shebangs: /usr/bin/env and /bin/bash don't exist in the sandbox
          for f in $(find . -type f \( -name '*.sh' -o -name '*.py' \)); do
            if head -1 "$f" | grep -q '^#!'; then
              sed -i "1s|#!/usr/bin/env bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/bash|#!$CONFIG_SHELL|" "$f"
              sed -i "1s|#!/usr/bin/env python3|#!${python3}/bin/python3|" "$f"
              sed -i "1s|#!/usr/bin/python3|#!${python3}/bin/python3|" "$f"
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
                  # Ensure meson's Python module, pefile, and pyelftools
                  # are findable both at meson-configure time and when
                  # ninja later invokes patched python3 scripts (e.g.
                  # src/boot/generate-hwids-section.py which imports
                  # ukify → pefile).
                  export PYTHONPATH="${meson}/lib/python3/site-packages:${ukifyPythonPath}''${PYTHONPATH:+:$PYTHONPATH}"

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
          exec ${python3}/bin/python3 "\$@"
          PYW
                  chmod +x .python-wrapper/bin/python3
                  export PATH="$(pwd)/.python-wrapper/bin:$PATH"

                  # Explicit RPATH so systemd binaries find their own shared libs
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
                  meson setup .. \
                    --prefix=$out \
                    --sysconfdir=$out/etc \
                    -Dwerror=false \
                    --buildtype=release \
                    -Dmode=release \
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
        '';
      }
      {
        name = "check";
        script = ''
          version_output="$($out/lib/systemd/systemd --version)"
          version_line="$(echo "$version_output" | head -n 1)"
          if [ "$version_line" != "systemd 259 (${version})" ]; then
            echo "ERROR: unexpected systemd version: $version_line" >&2
            exit 1
          fi

          for required_feature in +PAM +AUDIT +SELINUX +SECCOMP +OPENSSL \
            +ACL +BLKID +KMOD +LIBCRYPTSETUP +TPM2; do
            if ! echo "$version_output" | grep -F -q -- "$required_feature"; then
              echo "ERROR: systemd lacks required feature $required_feature" >&2
              exit 1
            fi
          done

          for executable in systemctl systemd-analyze systemd-nspawn; do
            if [ ! -x "$out/bin/$executable" ]; then
              echo "ERROR: systemd did not install $executable" >&2
              exit 1
            fi
            "$out/bin/$executable" --version > /dev/null
          done

          if ! "$out/bin/systemd-nspawn" --help | grep -F -q -- \
            '--aos-payload-seccomp-profile=PROFILE'; then
            echo "ERROR: systemd-nspawn lacks the AOS payload seccomp option" >&2
            exit 1
          fi

          if "$out/bin/systemd-nspawn" \
            --aos-payload-seccomp-profile=not-a-profile \
            --directory=/nonexistent > /dev/null 2>&1; then
            echo "ERROR: systemd-nspawn accepted an unknown AOS payload profile" >&2
            exit 1
          fi

          ./test-nspawn-seccomp
        '';
      }
      {
        name = "fixup";
        # LUKS2 token plugins (libcryptsetup-token-*.so) are loaded via
        # dlopen from $cryptsetup/lib/cryptsetup/. DT_RPATH on the binary
        # does NOT propagate to libraries loaded via dlopen, so
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
            mkdir -p "$tools/bin"
            mv "$out/bin/ukify" "$tools/bin/.ukify-unwrapped"
            cat > "$tools/bin/ukify" << EOF
          #!${bash}/bin/bash
          export PYTHONPATH="${ukifyPythonPath}\''${PYTHONPATH:+:\$PYTHONPATH}"
          exec "${python3}/bin/python3" "$tools/bin/.ukify-unwrapped" "\$@"
          EOF
            chmod +x "$tools/bin/ukify"
          fi
        '';
      }
    ];

    meta = {
      description = "systemd — system and service manager for Linux";
      homepage = "https://systemd.io";
      license = "LGPL-2.1-or-later";
    };
  }
