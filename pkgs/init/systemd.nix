# systemd — System and service manager
{ mkDerivation, fetchurl, make, pkg-config, gawk,
  linux-headers, util-linux, kmod, dbus, zlib, xz, lz4, openssl, audit,
  libselinux, perl }:

let version = "256.9"; in
mkDerivation {
  pname = "systemd";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/systemd/systemd-stable/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-1VWM1BnI1GvclYBky5f5Y9HqeThmQUwCWQbsFQM1Eu0=";
  };

  buildDeps = [ make pkg-config gawk perl ];
  runtimeDeps = [ util-linux kmod dbus linux-headers zlib xz lz4 openssl
                  audit libselinux ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd systemd-stable-${version}
      '';
    }
    { name = "configure";
      script = ''
        mkdir -p build && cd build
        meson setup .. \
          --prefix=$out \
          --sysconfdir=/etc \
          --buildtype=release \
          -Dmode=release \
          -Drootprefix=$out \
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
          -Drepart=false \
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
          -Dhomed=false \
          -Dnetworkd=true \
          -Dtimedated=false \
          -Dtimesyncd=false \
          -Dremote=false \
          -Dnss-myhostname=true \
          -Dnss-mymachines=false \
          -Dnss-resolve=false \
          -Dnss-systemd=true \
          -Dfirstboot=false \
          -Drandomseed=true \
          -Dbacklight=false \
          -Dvconsole=false \
          -Dquotacheck=false \
          -Dsysusers=true \
          -Dtmpfiles=true \
          -Dimportd=false \
          -Dhwdb=true \
          -Drfkill=false \
          -Dxdg-autostart=false \
          -Dman=false \
          -Dhtml=false \
          -Dtranslations=false \
          -Dinstall-sysconfdir=false \
          -Dseccomp=disabled \
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
          -Dcurl=disabled \
          -Didn=disabled \
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
          -Ddefault-llmnr=no
      '';
    }
    { name = "build";
      script = ''
        cd build
        ninja -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        cd build
        DESTDIR="" ninja install
      '';
    }
  ];

  meta = {
    description = "systemd — system and service manager for Linux";
    homepage = "https://systemd.io";
    license = "LGPL-2.1-or-later";
  };
}
