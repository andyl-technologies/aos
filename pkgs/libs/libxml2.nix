##! libxml2 — XML parsing library (GNOME)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  bash,
  stdenv,
}: let
  version = "2.15.4";
in
  mkDerivation {
    pname = "libxml2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/libxml2/${builtins.concatStringsSep "." (builtins.genList (i: builtins.elemAt (builtins.splitVersion version) i) 2)}/libxml2-${version}.tar.xz"
      ];
      hash = "sha256-mAh/0YHZBwck8/vGXHN32wMDjrkr2II3Ta/0SUATiCE=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libxml2-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
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
