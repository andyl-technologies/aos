# ZFS — OpenZFS filesystem and volume manager
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  util-linux, openssl, zlib, linux-headers }:

mkDerivation {
  name = "zfs-${versions.storage.zfs}";
  version = versions.storage.zfs;

  src = fetchurl {
    inherit (sources.zfs) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ util-linux openssl zlib ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd zfs-${versions.storage.zfs}
      '';
    }
    { name = "configure";
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
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
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
