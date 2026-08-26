##! FreeType — font rendering library
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  bash,
  stdenv,
}: let
  version = "2.13.3";
in
  mkDerivation {
    pname = "freetype";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/freetype/freetype-${version}.tar.xz"
      ];
      hash = "sha256-BVA1BmbUJ8dNrrhdWse7NTrLpfdpVjlZlTEanG8GMok=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd freetype-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-freetype-config \
            --with-zlib=yes \
            --without-bzip2 \
            --without-png \
            --without-harfbuzz \
            --without-brotli
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/freetype-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "FreeType — font rendering library";
      homepage = "https://freetype.org";
      license = "FTL OR GPL-2.0-or-later";
    };
  }
