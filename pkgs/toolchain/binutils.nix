# Binutils — GNU Binary Utilities
{ mkDerivation, fetchurl, make }:

let version = "2.42"; in
mkDerivation {
  pname = "binutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/binutils/binutils-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/binutils/binutils-${version}.tar.xz"
    ];
    hash = "sha256-9uTUH9X8d4sGt4kUV7NiDaXs6hAGxqSkGumYEJ+FqAA=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd binutils-${version}
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
        make -j$NIX_BUILD_CORES MAKEINFO=true
      '';
    }
    { name = "install";
      script = ''
        make install MAKEINFO=true
      '';
    }
  ];

  meta = {
    description = "GNU Binary Utilities — assembler, linker, and related tools";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
  };
}
