##! MPFR — GNU multiple-precision floating-point library
{
  mkDerivation,
  fetchurl,
  gnumake,
  gmp,
}: let
  version = "4.2.2";
in
  mkDerivation {
    pname = "mpfr";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.mpfr.org/mpfr-${version}/mpfr-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/mpfr/mpfr-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/mpfr/mpfr-${version}.tar.xz"
      ];
      hash = "sha256-tnugOD736KhWNzTi6InvXsPDuJigHQD6CmhprYHGzgE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [gmp];
    propagatedDeps = [gmp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mpfr-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-gmp=${gmp} \
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
      description = "MPFR — GNU multiple-precision floating-point library";
      homepage = "https://www.mpfr.org/";
      license = "LGPL-3.0-or-later";
    };
  }
