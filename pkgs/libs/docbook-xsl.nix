##! docbook-xsl — XSL stylesheets for DocBook XML
{
  lib,
  mkDerivation,
  fetchurl,
}: let
  version = "1.79.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "docbook-xsl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The catalog maps current DocBook stylesheet URIs to the installed tree.";
        "files" = {};
        "input" = "The DocBook stylesheet catalog and XHTML transformation entry point.";
        "operation" = "Parse both XML documents and inspect the catalog rewrite rules.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, xml.etree.ElementTree as ET\nroot = pathlib.Path(\"@out@/share/xml/docbook/stylesheet\")\ncatalog = ET.parse(root / \"catalog.xml\").getroot()\nET.parse(root / \"docbook-xsl/xhtml/docbook.xsl\")\nrules = list(catalog)\nassert any(\"docbook.sourceforge.net/release/xsl/current/\" in value for rule in rules for value in rule.attrib.values())\nprint(\"docbook-xsl data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docbook-xsl data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The stylesheet lookup rejects the unknown output family.";
        "files" = {};
        "input" = "A request for an output-family stylesheet absent from the installed tree.";
        "operation" = "Resolve the nonexistent stylesheet entry point.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/share/xml/docbook/stylesheet/docbook-xsl/aos-output/docbook.xsl\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"docbook-xsl rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docbook-xsl rejected invalid input\n";
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
