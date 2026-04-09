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
  dbus,
  zlib,
  xz,
  lz4,
  openssl,
  perl,
  meson,
  ninja,
  python3,
  gperf,
  libcap,
  libxcrypt,
  pcre2,
  audit,
  libselinux,
  libsepol,
  libseccomp,
  coreutils,
  bash,
}:
let
  version = "259.1";
in
mkDerivation {
  pname = "systemd";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/systemd/systemd/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-evTzbbUSrS8PdJoPmIY3Dt6yu1EoAU/EfN9zcCx+GRE=";
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
  patches = [
    ./patches/0001-remove-usr-lib-unit-lookup-paths.patch
    ./patches/0002-add-prefix-to-conf-paths.patch
    ./patches/0003-remove-install-emptydir-systemdstatedir.patch
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
  ];
  runtimeDeps = [
    util-linux
    kmod
    dbus
    linux-headers
    zlib
    xz
    lz4
    openssl
    libcap
    libxcrypt
    audit
    libselinux
    libsepol
    pcre2
    libseccomp
  ];
  propagatedDeps = [ ];

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

        # Rewrite hardcoded binary paths to Nix store paths.
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
                # Create getent shim — systemd's meson.build uses getent to look up
                # system users/groups (nobody, systemd-journal, etc.) during configure.
                # In the Nix sandbox there's no NSS, so we provide a shim that returns
                # the expected entries for standard system accounts.
                mkdir -p .shim-bin
                cat > .shim-bin/getent << 'GETENT'
        #!/bin/sh
        db="$1"; key="$2"
        case "$db" in
          passwd)
            case "$key" in
              root)              echo "root:x:0:0:root:/root:/bin/sh" ;;
              nobody)            echo "nobody:x:65534:65534:Nobody:/:/sbin/nologin" ;;
              systemd-journal)   echo "systemd-journal:x:101:101:systemd Journal:/:/sbin/nologin" ;;
              systemd-network)   echo "systemd-network:x:102:102:systemd Network:/:/sbin/nologin" ;;
              systemd-resolve)   echo "systemd-resolve:x:103:103:systemd Resolver:/:/sbin/nologin" ;;
              systemd-timesync)  echo "systemd-timesync:x:104:104:systemd Time Sync:/:/sbin/nologin" ;;
              *)                 exit 2 ;;
            esac ;;
          group)
            case "$key" in
              root)              echo "root:x:0:" ;;
              nobody)            echo "nobody:x:65534:" ;;
              utmp)              echo "utmp:x:22:" ;;
              systemd-journal)   echo "systemd-journal:x:101:" ;;
              systemd-network)   echo "systemd-network:x:102:" ;;
              *)                 exit 2 ;;
            esac ;;
          *)                     exit 2 ;;
        esac
        GETENT
                chmod +x .shim-bin/getent
                export PATH="$(pwd)/.shim-bin:$PATH"

                # Ensure meson's Python module is findable during build
                # (ninja invokes python3 -m mesonbuild.mesonmain directly)
                export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"

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
                  -Dutmp=false \
                  -Dhibernate=false \
                  -Dldconfig=false \
                  -Dresolve=false \
                  -Defi=false \
                  -Dtpm=false \
                  -Denvironment-d=false \
                  -Dbinfmt=false \
                  -Drepart=disabled \
                  -Dcoredump=false \
                  -Dpstore=false \
                  -Doomd=false \
                  -Dlogind=true \
                  -Dhostnamed=true \
                  -Dlocaled=false \
                  -Dmachined=false \
                  -Dportabled=false \
                  -Dsysext=false \
                  -Duserdb=false \
                  -Dhomed=disabled \
                  -Dnetworkd=true \
                  -Dtimedated=false \
                  -Dtimesyncd=false \
                  -Dremote=disabled \
                  -Dnss-myhostname=true \
                  -Dnss-mymachines=disabled \
                  -Dnss-resolve=disabled \
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
                  -Dseccomp=enabled \
                  -Dselinux=enabled \
                  -Dapparmor=disabled \
                  -Daudit=enabled \
                  -Dkmod=enabled \
                  -Dblkid=enabled \
                  -Dfdisk=disabled \
                  -Dgnutls=disabled \
                  -Dopenssl=enabled \
                  -Dp11kit=disabled \
                  -Dlibfido2=disabled \
                  -Dtpm2=disabled \
                  -Dlibcurl=disabled \
                  -Dlibidn2=disabled \
                  -Dlibidn=disabled \
                  -Dlibiptc=disabled \
                  -Dqrencode=disabled \
                  -Dgcrypt=disabled \
                  -Dzlib=enabled \
                  -Dlz4=enabled \
                  -Dxz=enabled \
                  -Dzstd=disabled \
                  -Ddefault-dnssec=no \
                  -Ddefault-mdns=no \
                  -Ddefault-llmnr=no \
                  -Dmount-path=${util-linux}/bin/mount \
                  -Dumount-path=${util-linux}/bin/umount \
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
  ];

  meta = {
    description = "systemd — system and service manager for Linux";
    homepage = "https://systemd.io";
    license = "LGPL-2.1-or-later";
  };
}
