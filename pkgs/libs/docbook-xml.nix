##! docbook-xml — DocBook XML 4.5 document type definition
{
  lib,
  mkDerivation,
  fetchurl,
  unzip,
}: let
  version = "4.5";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "docbook-xml";
    qualification.packageProbe = import ./_docbook-xml-probe.nix {inherit lib version;};

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
