##! docbook-xml — DocBook XML 4.2 document type definition
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "4.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "docbook-xml";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.oasis-open.org/docbook/xml/${version}/docbook-xml-${version}.zip"
      ];
      hash = "18hgwvmywh6a5jh38szjmg3hg2r4v5lb6r3ydc3rd8cp9wg61i5c";
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
      description = "DocBook XML 4.2 document type definition";
      homepage = "https://docbook.org/xml/4.2/";
      license = "DocBook";
    };
  }
