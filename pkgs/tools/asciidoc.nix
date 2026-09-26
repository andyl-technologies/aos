##! AsciiDoc text processor and DocBook conversion tools.
{
  mkDerivation,
  fetchurl,
  python3,
  bash,
  libxml2,
  libxslt,
  docbook-xml,
  docbook-xsl,
  lib,
}: let
  version = "10.2.1";
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
    pname = "asciidoc";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A small AsciiDoc document with a heading and paragraph.";
        operation = "Render the document with the installed asciidoc command.";
        expected = "The generated HTML contains the document heading and paragraph.";
        files."sample.adoc" = "= AOS sample\n\nA qualified paragraph.\n";
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''                import pathlib, subprocess, sys
                source = pathlib.Path(sys.argv[2])
                output = source.with_suffix(".html")
                subprocess.run([sys.argv[1], "-o", str(output), str(source)], check=True, capture_output=True)
                html = output.read_text()
                assert "AOS sample" in html and "A qualified paragraph." in html
                print("asciidoc rendering passed")
              ''
              "@out@/bin/asciidoc"
              "@work@/sample.adoc"
            ];
            exit_code = 0;
            stdout.exact = "asciidoc rendering passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An AsciiDoc source path that does not exist.";
        operation = "Ask the installed command to render the missing source.";
        expected = "The command rejects the missing input file.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''                import subprocess, sys
                result = subprocess.run([sys.argv[1], sys.argv[2]], capture_output=True)
                if result.returncode == 0:
                    raise SystemExit("asciidoc accepted a missing source")
                print("asciidoc rejected missing source")
              ''
              "@out@/bin/asciidoc"
              "@work@/missing.adoc"
            ];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "asciidoc rejected missing source\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/1d/e7/315a82f2d256e9270977aa3c15e8fe281fd7c40b8e2a0b97e0cb61ca8fa0/asciidoc-${version}.tar.gz"];
      hash = "10yvvmh5wi20pf0xw1c1sj41x63r4w5cl0hdcvmwgcw1b4l3rwfr";
    };

    buildDeps = [];
    runtimeDeps = [python3 bash libxml2 libxslt docbook-xml docbook-xsl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd asciidoc-${version}
          sed -i \
            -e 's|shell=True, env=ENV|shell=True, executable="${bash}/bin/bash", env=ENV|' \
            -e "s|ASCIIDOC = 'asciidoc'|ASCIIDOC = '$out/bin/asciidoc'|" \
            -e "s|XSLTPROC = 'xsltproc'|XSLTPROC = '${libxslt}/bin/xsltproc'|" \
            -e "s|XMLLINT = 'xmllint'|XMLLINT = '${libxml2}/bin/xmllint'|" \
            asciidoc/a2x.py
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/python3.14/site-packages" "$out/bin" "$out/share/licenses/asciidoc"
          cp -r asciidoc "$out/lib/python3.14/site-packages/"
          for command in asciidoc a2x; do
            cat > "$out/bin/$command" <<PYTHON
          #!${python3}/bin/python3
          import os
          import sys
          sys.path.insert(0, "$out/lib/python3.14/site-packages")
          os.environ["XML_CATALOG_FILES"] = "${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          from asciidoc.$command import cli
          cli()
          PYTHON
            chmod +x "$out/bin/$command"
          done
          cp LICENSE "$out/share/licenses/asciidoc/"
        '';
      }
    ];

    meta = {
      description = "AsciiDoc text processor with DocBook and manual-page conversion";
      homepage = "https://asciidoc.org/";
      license = "GPL-2.0-or-later";
    };
  }
