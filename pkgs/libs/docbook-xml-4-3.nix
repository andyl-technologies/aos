##! docbook-xml — DocBook XML 4.3 document type definition
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "4.3";
in
  mkDerivation {
    pname = "docbook-xml";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.oasis-open.org/docbook/xml/${version}/docbook-xml-${version}.zip"
      ];
      hash = "0r1l2if1z4wm2v664sqdizm4gak6db1kx9y50jq89m3gxaa8l1i3";
    };

    buildDeps = [buildPackages.unzip];
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
      description = "DocBook XML 4.3 document type definition";
      homepage = "https://docbook.org/xml/4.3/";
      license = "DocBook";
    };
  }
