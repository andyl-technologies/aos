# GCC — GNU Compiler Collection
{ mkDerivation, fetchurl, make, gawk, linux-headers, zlib }:

let version = "13.3.0"; in
mkDerivation {
  pname = "gcc";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/gcc/gcc-${version}/gcc-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/gcc/gcc-${version}/gcc-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/gcc/gcc-${version}/gcc-${version}.tar.xz"
    ];
    hash = "sha256-CEXpYhyVQ6E/SE6UWEpJ/8ASmXDpkUYkI1/B0GGgwIM=";
  };

  buildDeps = [ make gawk ];
  runtimeDeps = [ linux-headers ];
  propagatedDeps = [ zlib ];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd gcc-${version}
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
