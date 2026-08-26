##! libxml2 — XML parsing library (GNOME)
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  bash,
  stdenv,
}: let
  version = "2.12.9";
in
  mkDerivation {
    pname = "libxml2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/libxml2/${builtins.concatStringsSep "." (builtins.genList (i: builtins.elemAt (builtins.splitVersion version) i) 2)}/libxml2-${version}.tar.xz"
      ];
      hash = "sha256-WZEttTarVqOZZInqApl2jHvP/lcWnwI15/liqR9INZA=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libxml2-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --enable-shared \
            --with-zlib=${zlib} \
            --without-python \
            --without-icu \
            --without-lzma \
            --without-readline \
            --without-history
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/xml2-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "libxml2 — XML C parser and toolkit";
      homepage = "https://gitlab.gnome.org/GNOME/libxml2";
      license = "MIT";
    };
  }
