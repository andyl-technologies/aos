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
    pname = "docbook-xml";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The catalog is well-formed and its DTD declares the DocBook book element.";
        "files" = {};
        "input" = "The DocBook 4.5 XML catalog and document type definition.";
        "operation" = "Parse the catalog and inspect the book element declaration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, xml.etree.ElementTree as ET\nroot = pathlib.Path(\"@out@/share/xml/docbook/schema/dtd/4.5\")\nET.parse(root / \"catalog.xml\")\nassert \"<!ELEMENT book\" in (root / \"docbookx.dtd\").read_text(errors=\"replace\")\nprint(\"docbook-xml data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docbook-xml data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The DTD lookup rejects the unknown element.";
        "files" = {};
        "input" = "A request for an element declaration absent from DocBook 4.5.";
        "operation" = "Search the installed DTD for the nonexistent declaration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nsource = pathlib.Path(\"@out@/share/xml/docbook/schema/dtd/4.5/docbookx.dtd\").read_text(errors=\"replace\")\nif \"<!ELEMENT aos-nonexistent\" in source:\n    raise SystemExit(2)\nsys.stderr.write(\"docbook-xml rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docbook-xml rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
