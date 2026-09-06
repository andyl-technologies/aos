##! docutils — reStructuredText processing tools
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "0.22.4";
  sitePackages = "lib/python3.14/site-packages";
  entryPoints = {
    docutils = "docutils.__main__:main";
    rst2html = "docutils.core:rst2html";
    rst2html4 = "docutils.core:rst2html4";
    rst2html5 = "docutils.core:rst2html5";
    rst2latex = "docutils.core:rst2latex";
    rst2man = "docutils.core:rst2man";
    rst2odt = "docutils.core:rst2odt";
    rst2pseudoxml = "docutils.core:rst2pseudoxml";
    rst2s5 = "docutils.core:rst2s5";
    rst2xetex = "docutils.core:rst2xetex";
    rst2xml = "docutils.core:rst2xml";
  };
in
  mkDerivation {
    pname = "docutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/docutils/files/docutils/${version}/docutils-${version}.tar.gz/download"
      ];
      hash = "sha256-TbU7H96avsu3TZEjDTKrYm2U9rrfxXXW25GUpJ3ymWg=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [python3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd docutils-${version}
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH="$PWD" ${python3}/bin/python3 - <<'PY'
          from docutils.core import publish_string
          output = publish_string("Heading\n=======\n", writer_name="html5")
          assert b"<h1" in output
          PY
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/${sitePackages}" "$out/bin" "$out/share/doc/docutils"
          cp -R docutils "$out/${sitePackages}/"
          cp COPYING.rst README.rst "$out/share/doc/docutils/"

          ${builtins.concatStringsSep "\n" (
            builtins.attrValues (
              builtins.mapAttrs (name: target: let
                parts = builtins.match "(.+):(.+)" target;
                moduleName = builtins.elemAt parts 0;
                functionName = builtins.elemAt parts 1;
              in ''
                cat > "$out/bin/${name}" <<'PY'
                #!${python3}/bin/python3
                import sys
                sys.path.insert(0, "${builtins.placeholder "out"}/${sitePackages}")
                from ${moduleName} import ${functionName}
                ${functionName}()
                PY
                chmod 0755 "$out/bin/${name}"
              '')
              entryPoints
            )
          )}

          printf 'Title\n=====\n' | "$out/bin/rst2man" > test.1
          grep -Fq '.TH "Title"' test.1
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docutils";
        tool = self;
        command = "printf 'Title\\n=====\\n' | rst2man | grep -Fq '.TH \\\"Title\\\"'";
      };
    };

    meta = {
      description = "Documentation utilities for reStructuredText";
      homepage = "https://docutils.sourceforge.io/";
      license = "Public-Domain AND BSD-2-Clause AND PSF-2.0 AND GPL-3.0-or-later";
      mainProgram = "docutils";
    };
  }
