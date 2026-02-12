# kmod — Linux kernel module handling
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, zlib, xz }:

mkDerivation {
  name = "kmod-${versions.init.kmod}";
  version = versions.init.kmod;

  src = fetchurl {
    inherit (sources.kmod) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ zlib xz ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd kmod-${versions.init.kmod}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=/etc \
          --with-xz \
          --with-zlib \
          --with-zstd=no \
          --disable-manpages \
          --disable-test-modules
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
        # Create compatibility symlinks
        mkdir -p $out/sbin
        for tool in depmod insmod lsmod modinfo modprobe rmmod; do
          ln -sf ../bin/kmod $out/sbin/$tool
        done
      '';
    }
  ];

  meta = {
    description = "kmod — Linux kernel module handling tools";
    homepage = "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git";
    license = "LGPL-2.1-or-later";
  };
}
