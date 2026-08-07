##! docbook-xml — DocBook XML 4.5 document type definition
{
  mkDerivation,
  fetchurl,
  unzip,
}: let
  version = "4.5";
in
  mkDerivation {
    pname = "docbook-xml";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.oasis-open.org/docbook/xml/${version}/docbook-xml-${version}.zip"
      ];
      hash = "sha256-Tk4DeiuDyYxslIGDkNS90/bhD27GLdeRiFlOJhkNx7Q=";
    };

    buildDeps = [unzip];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          unzip -q $src -d source
          cd source
        '';
      }
      {
        name = "install";
        script = ''
          target=$out/share/xml/docbook/schema/dtd/${version}
          mkdir -p "$target"
          cp -R . "$target"
          test -f "$target/docbookx.dtd"
          test -f "$target/catalog.xml"
        '';
      }
    ];

    meta = {
      description = "DocBook XML 4.5 document type definition";
      homepage = "https://docbook.org/xml/4.5/";
      license = "DocBook";
    };
  }
