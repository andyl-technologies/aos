##! ZFS — OpenZFS filesystem and volume manager
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  util-linux,
  openssl,
  zlib,
  linux-headers,
}:

let
  version = "2.3.0";
in
mkDerivation {
  pname = "zfs";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/openzfs/zfs/releases/download/zfs-${version}/zfs-${version}.tar.gz"
    ];
    hash = "sha256-boeH6rVfJMa5wxfz/psNqaZl6zTDHfiP82jZqS6TVqY=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [
    util-linux
    openssl
    zlib
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd zfs-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
          --with-linux-headers=${linux-headers}/include \
          --with-mounthelperdir=$out/sbin \
          --with-udevdir=$out/lib/udev \
          --with-systemdunitdir=$out/lib/systemd/system \
          --with-systemdpresetdir=$out/lib/systemd/system-preset \
          --enable-linux-builtin=no \
          --enable-sysvinit=no \
          --disable-static
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
        make install
      '';
    }
  ];

  meta = {
    description = "OpenZFS — advanced filesystem and volume manager";
    homepage = "https://openzfs.org";
    license = "CDDL-1.0";
  };
}
