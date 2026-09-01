##! MPFR — GNU multiple-precision floating-point library
{
  mkDerivation,
  fetchurl,
  gnumake,
  gmp,
  stdenv,
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
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Mach-O debug symbols retain compilation and object paths even
              # after stripping. Remap the sandbox prefix at compile time so
              # cached libraries contain no ephemeral /build references.
              export CFLAGS="''${CFLAGS:-} -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."
            ''
            else ""
          }

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
