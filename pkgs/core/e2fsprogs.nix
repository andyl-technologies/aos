# e2fsprogs — Utilities for ext2/ext3/ext4 filesystems
{ mkDerivation, fetchurl, make, pkg-config, util-linux }:

let version = "1.47.1"; in
mkDerivation {
  pname = "e2fsprogs";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/e2fsprogs/e2fsprogs-${version}.tar.gz"
    ];
    hash = "sha256-mvzSAfOUKdLbJJKusT26XnXWzFBoK3MtyjVkO9XwkuM=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ util-linux ];
  propagatedDeps = [ util-linux ];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd e2fsprogs-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-elf-shlibs \
          --disable-libblkid \
          --disable-libuuid \
          --disable-uuidd \
          --disable-fsck
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
        make install-libs
      '';
    }
  ];

  meta = {
    description = "Utilities for ext2/ext3/ext4 filesystems";
    homepage = "http://e2fsprogs.sourceforge.net/";
    license = "GPL-2.0-only";
  };
}
