##! docbook-xml-4_2 — DocBook XML 4.2 document type definition
{
  mkDerivation,
  fetchurl,
  unzip,
}: let
  version = "4.2";
in
  mkDerivation {
    pname = "docbook-xml-4_2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.oasis-open.org/docbook/xml/${version}/docbook-xml-${version}.zip"
      ];
      hash = "sha256-rMRgHk+XoZYHa35ks2jZJIsHx6vyazSgLMpA7uvmD6I=";
    };

    buildDeps = [unzip];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          unzip -q "$src" -d source
          cd source
        '';
      }
      {
        name = "install";
        script = ''
          target="$out/share/xml/docbook/schema/dtd/${version}"
          mkdir -p "$target"
          cp -R . "$target"
          test -f "$target/docbookx.dtd"
          test -f "$target/catalog.xml"
        '';
      }
    ];

    meta = {
      description = "DocBook XML 4.2 document type definition";
      homepage = "https://docbook.org/xml/4.2/";
      license = "DocBook";
    };
  }
