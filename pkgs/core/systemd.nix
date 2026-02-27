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
      name = "patch-shebangs";
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

        # key_serial_t is provided by libkeyutils headers which we don't have.
        # Add the typedef to systemd's override header so keyctl support compiles.
        sed -i '1i #include <stdint.h>\ntypedef int32_t key_serial_t;' \
          src/include/override/sys/keyctl.h
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

                # Set RPATH so systemd binaries can find their own shared libs
                # (meson uses --prefix=/ with DESTDIR=$out, so RPATH would point
                # to /lib instead of $out/lib without this)
                export LDFLAGS="''${LDFLAGS:-} -Wl,-rpath,$out/lib -Wl,-rpath,$out/lib/systemd"

                mkdir -p build && cd build
                meson setup .. \
                  --prefix=/ \
                  --sysconfdir=/etc \
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
                  -Ddbuspolicydir=$out/share/dbus-1/system.d \
                  -Ddbussessionservicedir=$out/share/dbus-1/services \
                  -Ddbussystemservicedir=$out/share/dbus-1/system-services \
                  -Ddbus-interfaces-dir=$out/share/dbus-1/interfaces
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
      script = ''
        DESTDIR=$out ninja install
      '';
    }
  ];

  meta = {
    description = "systemd — system and service manager for Linux";
    homepage = "https://systemd.io";
    license = "LGPL-2.1-or-later";
  };
}
