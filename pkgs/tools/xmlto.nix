##! DocBook transformation frontend and conditional XML filter.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bash,
  coreutils,
  findutils,
  grep,
  sed,
  util-linux,
  libxml2,
  libxslt,
  docbook-xml,
  docbook-xml-4-2,
  docbook-xsl,
  zip,
}: let
  version = "0.0.29";
  catalogs = "${docbook-xml-4-2}/share/xml/docbook/schema/dtd/4.2/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml";
  runtimeTools = [coreutils findutils grep sed util-linux libxml2 libxslt zip];
  runtimePath = builtins.concatStringsSep ":" (map (package: "${package}/bin") runtimeTools);
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "xmlto";
    inherit version;
    src = fetchurl {
      urls = ["https://releases.pagure.org/xmlto/xmlto-${version}.tar.bz2"];
      hash = "08ag445xn2hisk28bxdfmva8ig49czc7lpgqqhk0817ry3ldh030";
    };
    buildDeps = [buildPackages.autoconf buildPackages.automake buildPackages.gnumake buildPackages.flex buildPackages.bash buildPackages.util-linux buildPackages.libxslt buildPackages.libxml2];
    runtimeDeps = [bash docbook-xml docbook-xml-4-2 docbook-xsl] ++ runtimeTools;

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd xmlto-${version}
            sed -i '1s|^#!.*|#!${buildPackages.bash}/bin/bash|' xmlif/test/run-test
          '';
        }
        {
          name = "configure";
          script = ''
            export XML_CATALOG_FILES="${catalogs}"
            autoreconf -fi
            # Configure-time utilities execute on the builder. Rebind the
            # installed frontend to target tools after documentation generation.
            XMLTO_BASH_PATH=${buildPackages.bash}/bin/bash \
              GETOPT=${buildPackages.util-linux}/bin/getopt \
              XMLLINT=${buildPackages.libxml2}/bin/xmllint \
              XSLTPROC=${buildPackages.libxslt}/bin/xsltproc \
              $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/libexec" "$out/share/licenses/xmlto"
            mv "$out/bin/xmlto" "$out/libexec/xmlto"
            sed -i \
              -e 's|${buildPackages.bash}/bin/bash|${bash}/bin/bash|g' \
              -e 's|${buildPackages.util-linux}/bin/getopt|${util-linux}/bin/getopt|g' \
              -e 's|${buildPackages.libxml2}/bin/xmllint|${libxml2}/bin/xmllint|g' \
              -e 's|${buildPackages.libxslt}/bin/xsltproc|${libxslt}/bin/xsltproc|g' \
              "$out/libexec/xmlto"
            cat > "$out/bin/xmlto" <<EOF_WRAPPER
            #!${bash}/bin/bash
            export PATH="${runtimePath}:\$PATH"
            export XML_CATALOG_FILES="${catalogs}\''${XML_CATALOG_FILES:+ \$XML_CATALOG_FILES}"
            exec "$out/libexec/xmlto" "\$@"
            EOF_WRAPPER
            chmod +x "$out/bin/xmlto"
            cp COPYING "$out/share/licenses/xmlto/"
          '';
        }
      ];
    meta = {
      description = "Convert XML documents using DocBook stylesheets and format processors";
      homepage = "https://pagure.io/xmlto";
      license = "GPL-2.0-or-later";
      mainProgram = "xmlto";
    };
  }
