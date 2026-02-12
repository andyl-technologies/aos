# GCC — GNU Compiler Collection
{ mkDerivation, fetchurl, sources, versions, make, gawk, linux-headers, zlib }:

mkDerivation {
  name = "gcc-${versions.toolchain.gcc}";
  version = versions.toolchain.gcc;

  src = fetchurl {
    inherit (sources.gcc) url hash;
  };

  buildDeps = [ make gawk ];
  runtimeDeps = [ linux-headers ];
  propagatedDeps = [ zlib ];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd gcc-${versions.toolchain.gcc}
      '';
    }
    { name = "configure";
      script = ''
        mkdir -p build && cd build
        ../configure \
          --prefix=$out \
          --enable-languages=c,c++ \
          --with-system-zlib \
          --disable-multilib \
          --disable-bootstrap \
          --disable-nls \
          --with-sysroot=/ \
          --with-native-system-header-dir=/include \
          --enable-default-pie \
          --enable-default-ssp
      '';
    }
    { name = "build";
      script = ''
        cd build
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        cd build
        make install
        # Create cc symlink
        ln -sf gcc $out/bin/cc
      '';
    }
  ];

  meta = {
    description = "GNU Compiler Collection — C and C++ compilers";
    homepage = "https://gcc.gnu.org";
    license = "GPL-3.0-or-later";
  };
}
