##! ZFS — OpenZFS filesystem and volume manager
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  util-linux,
  openssl,
  zlib,
  libtirpc,
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
    libtirpc
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
          --with-config=user \
          --with-mounthelperdir=$out/sbin \
          --with-udevdir=$out/lib/udev \
          --with-systemdunitdir=$out/lib/systemd/system \
          --with-systemdpresetdir=$out/lib/systemd/system-preset \
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
        # Override hardcoded paths that would install outside the store
        make install \
          i_tdir=$out/share/initramfs-tools \
          initconfdir=$out/etc/default \
          dracutdir=$out/lib/dracut \
          bashcompletiondir=$out/share/bash-completion/completions
      '';
    }
  ];

  meta = {
    description = "OpenZFS — advanced filesystem and volume manager";
    homepage = "https://openzfs.org";
    license = "CDDL-1.0";
  };
}
