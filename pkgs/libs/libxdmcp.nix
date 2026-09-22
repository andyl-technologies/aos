##! X Display Manager Control Protocol library and specification.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
  docbook-xml-4-3,
  docbook-xsl,
}: let
  version = "1.1.5";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libxdmcp";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXdmcp-${version}.tar.xz"];
      hash = "1312l8x3asib77wgf123w3nbabnky61mb6pnmmqapbf350l259fq";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.xmlto buildPackages.libxslt buildPackages.xorg-sgml-doctools];
    runtimeDeps = [xorgproto];
    propagatedDeps = [xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXdmcp-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            export XML_CATALOG_FILES="${docbook-xml-4-3}/share/xml/docbook/schema/dtd/4.3/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static --enable-docs --with-xmlto --with-xsltproc
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
            mkdir -p "$out/share/licenses/libxdmcp"
            cp COPYING "$out/share/licenses/libxdmcp/"
          '';
        }
      ];
    meta = {
      description = "X Display Manager Control Protocol library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
