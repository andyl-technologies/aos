##! Shared qualification probe for the DocBook XML DTD releases.
{
  lib,
  version,
}: let
  dtdRoot = "@out@/share/xml/docbook/schema/dtd/${version}";
in
  lib.qualification.commandProbe {
    primary = {
      artifacts = [];
      expected = "The catalog is well-formed and the DTD declares the DocBook book element.";
      files = {};
      input = "The DocBook ${version} XML catalog and document type definition.";
      operation = "Parse the catalog and inspect the book element declaration.";
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import pathlib
              import xml.etree.ElementTree as ET

              root = pathlib.Path("${dtdRoot}")
              ET.parse(root / "catalog.xml")
              assert "<!ELEMENT book" in (root / "dbhierx.mod").read_text(errors="replace")
              print("docbook-xml data passed")
            ''
          ];
          exit_code = 0;
          stderr.exact = "";
          stdout.exact = "docbook-xml data passed\n";
        }
      ];
    };

    badInput = {
      artifacts = [];
      expected = "The DTD lookup rejects the unknown element.";
      files = {};
      input = "A request for an element declaration absent from DocBook ${version}.";
      operation = "Search the installed DTD for the nonexistent declaration.";
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import pathlib
              import sys

              source = pathlib.Path("${dtdRoot}/dbhierx.mod").read_text(errors="replace")
              if "<!ELEMENT aos-nonexistent" in source:
                  raise SystemExit(2)
              sys.stderr.write("docbook-xml rejected invalid input\n")
              raise SystemExit(7)
            ''
          ];
          exit_code = 7;
          observes_rejection = true;
          stderr.exact = "docbook-xml rejected invalid input\n";
          stdout.exact = "";
        }
      ];
    };
  }
