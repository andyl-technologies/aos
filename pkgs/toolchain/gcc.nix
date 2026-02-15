##! GCC — GNU Compiler Collection
{
  mkDerivation,
  fetchurl,
  make,
  gawk,
  bootstrapTools,
  linux-headers,
  zlib,
  gmp,
  mpfr,
  libmpc,
}:

let
  version = "13.3.0";
in
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

  buildDeps = [
    make
    gawk
    gmp
    mpfr
    libmpc
  ];
  runtimeDeps = [ linux-headers ];
  propagatedDeps = [ zlib ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd gcc-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        # Skip fixincludes — AOS uses the ccWrapper for include paths,
        # and /include doesn't exist in the sandbox (headers come from
        # linux-headers via -isystem flags).
        sed -i 's|STMP_FIXINC = @STMP_FIXINC@|STMP_FIXINC =|' gcc/Makefile.in

        mkdir -p objdir && cd objdir

        # Target library configure scripts try to run compiled programs;
        # they need the dynamic linker and library paths from bootstrap tools.
        export LDFLAGS_FOR_TARGET="$LDFLAGS"

        # xgcc (the just-built compiler) doesn't use C_INCLUDE_PATH or the
        # ccWrapper, so it can't find system headers.  Explicitly pass
        # glibc and kernel header paths so target libraries (libgcc,
        # libstdc++) can find stdio.h, stdint.h, linux/futex.h, etc.
        export CFLAGS_FOR_TARGET="-O2 -isystem ${bootstrapTools}/include-glibc -isystem ${linux-headers}/include"
        export CXXFLAGS_FOR_TARGET="-O2 -isystem ${bootstrapTools}/include-glibc -isystem ${linux-headers}/include"

        ../configure \
          --prefix=$out \
          --enable-languages=c,c++ \
          --with-system-zlib \
          --with-gmp=${gmp} \
          --with-mpfr=${mpfr} \
          --with-mpc=${libmpc} \
          --disable-multilib \
          --disable-bootstrap \
          --disable-nls \
          --disable-libsanitizer \
          --with-sysroot=/ \
          --with-native-system-header-dir=${linux-headers}/include \
          --enable-default-pie \
          --enable-default-ssp
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
