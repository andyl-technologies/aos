##! Fontconfig — font configuration and customization library
{
  mkDerivation,
  fetchurl,
  gnumake,
  gperf,
  pkg-config,
  python3,
  freetype,
  expat,
  zlib,
}: let
  version = "2.15.0";
in
  mkDerivation {
    pname = "fontconfig";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.freedesktop.org/software/fontconfig/release/fontconfig-${version}.tar.xz"
      ];
      hash = "sha256-Y6BljQ4G4PqIYQZFK1jvBPIfWCAuoCqUw53g0zNdfA4=";
    };

    buildDeps = [
      gnumake
      gperf
      pkg-config
      python3
    ];
    runtimeDeps = [
      freetype
      expat
      zlib
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fontconfig-${version}
        '';
      }
      {
        name = "build";
        script = ''
          FREETYPE_CFLAGS="-I${freetype}/include/freetype2" \
          FREETYPE_LIBS="-L${freetype}/lib -lfreetype" \
          $CONFIG_SHELL ./configure \
            $configureFlags \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --localstatedir=$out/var \
            --disable-docs
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
      description = "Fontconfig — font configuration and customization library";
      homepage = "https://www.freedesktop.org/wiki/Software/fontconfig/";
      license = "MIT";
    };
  }
