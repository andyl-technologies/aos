# Binutils — GNU Binary Utilities
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "binutils-${versions.toolchain.binutils}";
  version = versions.toolchain.binutils;

  src = fetchurl {
    inherit (sources.binutils) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd binutils-${versions.toolchain.binutils}
      '';
    }
    { name = "configure";
      script = ''
        mkdir -p build && cd build
        ../configure \
          --prefix=$out \
          --enable-deterministic-archives \
          --disable-nls \
          --enable-64-bit-bfd \
          --enable-gold \
          --enable-plugins \
          --enable-relro \
          --enable-default-hash-style=gnu
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
      '';
    }
  ];

  meta = {
    description = "GNU Binary Utilities — assembler, linker, and related tools";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
  };
}
