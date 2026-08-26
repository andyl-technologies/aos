##! libmpc — GNU library for multiprecision complex arithmetic
{
  mkDerivation,
  fetchurl,
  gnumake,
  gmp,
  mpfr,
}: let
  version = "1.3.1";
in
  mkDerivation {
    pname = "libmpc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/mpc/mpc-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/mpc/mpc-${version}.tar.gz"
      ];
      hash = "sha256-q2QkkvXPiCt0qgy3MM1BCoHtzb7IlRg86TDnBsHHWbg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [
      gmp
      mpfr
    ];
    propagatedDeps = [
      gmp
      mpfr
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mpc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-gmp=${gmp} \
            --with-mpfr=${mpfr} \
            --enable-shared \
            --disable-static \
            --with-pic
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
      description = "libmpc — GNU library for multiprecision complex arithmetic with exact rounding";
      homepage = "https://www.multiprecision.org/mpc/";
      license = "LGPL-2.1-or-later";
    };
  }
