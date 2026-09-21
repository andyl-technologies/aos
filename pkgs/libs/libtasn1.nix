{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "4.21.0";
in
  mkDerivation {
    pname = "libtasn1";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/libtasn1/libtasn1-${version}.tar.gz"
        "https://mirrors.dotsrc.org/gnu/libtasn1/libtasn1-${version}.tar.gz"
      ];
      hash = "sha256-HYpESiI8xUZCQHdzRuEl3lHY5qvwuLrHQqyEYJFn3Ic=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtasn1-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --disable-doc \
            --disable-nls
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
      description = "ASN.1 and DER structure parsing/encoding library";
      homepage = "https://www.gnu.org/software/libtasn1/";
      license = "LGPL-2.1-or-later";
    };
  }
