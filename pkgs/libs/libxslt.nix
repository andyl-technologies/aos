##! libxslt — XSLT processing library (includes xsltproc)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libxml2,
  bash,
  stdenv,
}: let
  version = "1.1.45";
in
  mkDerivation {
    pname = "libxslt";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "answer.txt";
            "text" = "42\n";
          }
        ];
        "expected" = "The output artifact contains the exact selected value 42.";
        "files" = {
          "input.xml" = "<root><answer>42</answer></root>\n";
          "transform.xsl" = "<xsl:stylesheet version=\"1.0\"\n  xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n  <xsl:output method=\"text\"/>\n  <xsl:template match=\"/\"><xsl:value-of select=\"root/answer\"/><xsl:text>&#10;</xsl:text></xsl:template>\n</xsl:stylesheet>\n";
        };
        "input" = "An XML answer element and an XSLT stylesheet selecting its text.";
        "operation" = "Transform the document into plain text through xsltproc.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xsltproc"
              "-o"
              "answer.txt"
              "transform.xsl"
              "input.xml"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "xsltproc exits with its stylesheet parse-error status.";
        "files" = {
          "input.xml" = "<root/>\n";
          "invalid.xsl" = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n  <xsl:template match=\"/\">\n</xsl:stylesheet>\n";
        };
        "input" = "An XSLT stylesheet with an unclosed template element.";
        "operation" = "Parse and apply the malformed stylesheet through xsltproc.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xsltproc"
              "invalid.xsl"
              "input.xml"
            ];
            "exit_code" = 4;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/libxslt/${builtins.concatStringsSep "." (builtins.genList (i: builtins.elemAt (builtins.splitVersion version) i) 2)}/libxslt-${version}.tar.xz"
      ];
      hash = "sha256-ms/mhBnE0GpFxVAyGzISdi2S9BRlBiyk6hnmMu5dIW4=";
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
