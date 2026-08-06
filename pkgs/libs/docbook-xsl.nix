##! docbook-xsl — XSL stylesheets for DocBook XML
{
  mkDerivation,
  fetchurl,
}: let
  version = "1.79.2";
in
  mkDerivation {
    pname = "docbook-xsl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/docbook/xslt10-stylesheets/releases/download/release%2F${version}/docbook-xsl-nons-${version}.tar.bz2"
      ];
      hash = "sha256-7oueygt6j4kHWDKi2nU0vOjFR4/I/CZ29RLV2H2DIQI=";
    };

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd docbook-xsl-nons-${version}
        '';
      }
      {
        name = "install";
        script = ''
          target=$out/share/xml/docbook/stylesheet/docbook-xsl
          mkdir -p "$target"
          cp -R . "$target"
          cat > "$out/share/xml/docbook/stylesheet/catalog.xml" <<EOF
          <?xml version="1.0" encoding="utf-8"?>
          <catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
            <rewriteURI uriStartString="http://docbook.sourceforge.net/release/xsl/current/" rewritePrefix="file://$target/"/>
            <rewriteSystem systemIdStartString="http://docbook.sourceforge.net/release/xsl/current/" rewritePrefix="file://$target/"/>
            <rewriteURI uriStartString="https://cdn.docbook.org/release/xsl-nons/current/" rewritePrefix="file://$target/"/>
            <rewriteSystem systemIdStartString="https://cdn.docbook.org/release/xsl-nons/current/" rewritePrefix="file://$target/"/>
          </catalog>
          EOF
          test -f "$target/xhtml/chunk.xsl"
          test -f "$out/share/xml/docbook/stylesheet/catalog.xml"
        '';
      }
    ];

    meta = {
      description = "XSL stylesheets for DocBook XML";
      homepage = "https://github.com/docbook/xslt10-stylesheets";
      license = "MIT";
    };
  }
