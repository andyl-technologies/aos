##! libxslt — XSLT processing library (includes xsltproc)
{
  mkDerivation,
  fetchurl,
  gnumake,
  libxml2,
  bash,
  stdenv,
}: let
  version = "1.1.42";
in
  mkDerivation {
    pname = "libxslt";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/libxslt/${builtins.concatStringsSep "." (builtins.genList (i: builtins.elemAt (builtins.splitVersion version) i) 2)}/libxslt-${version}.tar.xz"
      ];
      hash = "sha256-hcpiysDUH8d9P2Az2p32/XPSDqL8GLCjYJ/7QRDhuus=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [libxml2]
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
            cd libxslt-${version}
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
          script =
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # xml2-config is installed for the target. Its prefix data is
              # correct, but configure must interpret it with a native shell.
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/xml2-config <<EOF
              #!$CONFIG_SHELL
              exec "$CONFIG_SHELL" ${libxml2}/bin/xml2-config "\$@"
              EOF
              chmod +x .aos-build-tools/xml2-config

              XML_CONFIG="$PWD/.aos-build-tools/xml2-config" \
                ./configure \
                  $configureFlags \
                  --prefix=$out \
                  --disable-static \
                  --enable-shared \
                  --with-libxml-prefix=${libxml2} \
                  --without-python \
                  --without-crypto
            ''
            else ''
              ./configure \
                $configureFlags \
                --prefix=$out \
                --disable-static \
                --enable-shared \
                --with-libxml-prefix=${libxml2} \
                --without-python \
                --without-crypto
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
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/xslt-config"
            ''
            else ''
              make install
            '';
        }
      ];

    meta = {
      description = "libxslt — XSLT C library (includes xsltproc)";
      homepage = "https://gitlab.gnome.org/GNOME/libxslt";
      license = "MIT";
    };
  }
