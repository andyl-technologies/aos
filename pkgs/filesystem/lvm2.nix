##! lvm2 — Logical Volume Manager 2 tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libaio,
  util-linux,
  device-mapper,
}:
let
  version = "2.03.28";
in
mkDerivation {
  pname = "lvm2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceware.org/ftp/lvm2/LVM2.${version}.tgz"
      "https://mirrors.kernel.org/sourceware/lvm2/LVM2.${version}.tgz"
    ];
    hash = "sha256-uCK6/2ti3zY4LHF866mKJojrsxvyt2jz/6K21eJVckI=";
  };

  buildDeps = [
    gnumake
    pkg-config
  ];
  runtimeDeps = [
    libaio
    util-linux
    device-mapper
  ];
  propagatedDeps = [
    device-mapper
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd LVM2.${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=/ \
          --enable-pkgconfig \
          --enable-cmdlib \
          --enable-dmeventd=none \
          --with-thin=none \
          --with-cache=none \
          --disable-selinux \
          --disable-readline \
          --disable-editline
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install DESTDIR=$out
      '';
    }
  ];

  meta = {
    description = "Logical Volume Manager 2 tools";
    homepage = "https://sourceware.org/lvm2/";
    license = "GPL-2.0-only";
  };
}
