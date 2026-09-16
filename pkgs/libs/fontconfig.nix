##! Fontconfig — font configuration and customization library
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  gettext,
  gperf,
  pkg-config,
  python3,
  freetype,
  expat,
  zlib,
}: let
  version = "2.18.3";
in
  mkDerivation {
    pname = "fontconfig";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gitlab.freedesktop.org/fontconfig/fontconfig/-/archive/${version}/fontconfig-${version}.tar.gz"
      ];
      hash = "sha256-muAeHVOs3vVgEMVFHNNKpB0yWy+szYYGRI2PoBsklrM=";
    };

    buildDeps = [
      gnumake
      autoconf
      automake
      libtool
      gettext
      gperf
      pkg-config
      python3
    ];
    runtimeDeps = [
      freetype
      expat
      zlib
    ];
    # Consumers need these to resolve fontconfig.pc's Requires fields.
    propagatedDeps = [freetype expat];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fontconfig-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal"
          NOCONFIGURE=1 $CONFIG_SHELL ./autogen.sh
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
