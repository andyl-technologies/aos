##! GObject introspection documentation generator and its bundled templates.
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  python3-markdown,
  python3-markupsafe,
  python3-pygments,
  python3-jinja2,
  python3-typogrify,
  python3-smartypants,
  packaging,
  graphviz,
  buildPackages,
  stdenv,
}: let
  version = "2026.1";
  sitePackages = "lib/python3.14/site-packages";
  pythonDependencies = [
    python3-markdown
    python3-markupsafe
    python3-pygments
    python3-jinja2
    python3-typogrify
    python3-smartypants
    packaging
  ];
  pythonPath = builtins.concatStringsSep ":" (map (dependency: "${dependency}/${sitePackages}") pythonDependencies);
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
    pname = "gi-docgen";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A minimal introspection repository with one documented function.";
        operation = "Generate its HTML reference.";
        expected = "The function page contains its C symbol and description.";
        files."sample.gir" = ''
          <?xml version="1.0"?>
          <repository version="1.2"
            xmlns="http://www.gtk.org/introspection/core/1.0"
            xmlns:c="http://www.gtk.org/introspection/c/1.0">
            <namespace name="AosSample" version="1.0"
              c:identifier-prefixes="Aos" c:symbol-prefixes="aos">
              <function name="answer" c:identifier="aos_answer">
                <doc filename="sample.c" line="1">Returns the answer.</doc>
                <return-value transfer-ownership="none">
                  <type name="gint" c:type="gint"/>
                </return-value>
              </function>
            </namespace>
          </repository>
        '';
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/gi-docgen" "generate" "-q" "--output-dir" "rendered" "sample.gir"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                page = Path("rendered/AosSample-1.0/func.answer.html").read_text()
                assert "aos_answer" in page
                assert "Returns the" in page and "answer." in page
                print("GI-DocGen reference rendering passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "GI-DocGen reference rendering passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An incomplete GIR XML document.";
        operation = "Attempt to generate its reference.";
        expected = "The generator rejects the malformed document.";
        files."broken.gir" = "<repository>\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/gi-docgen" "generate" "-q" "--output-dir" "rendered" "broken.gir"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version;

    src = fetchurl {
      urls = ["https://download.gnome.org/sources/gi-docgen/2026/gi-docgen-${version}.tar.xz"];
      hash = "0yglmj0vhvmmizl2nhivanigz8x6n8gswali4dl6p5wr8v0dc5n3";
    };

    buildDeps = [buildPackages.python3 buildPackages.xz];
    runtimeDeps = [python3 graphviz] ++ pythonDependencies;

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd gi-docgen-${version}
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/${sitePackages}" "$out/bin" "$out/share/pkgconfig" \
              "$out/share/man/man1" "$out/share/licenses/gi-docgen"
            # Templates, fonts and scripts are runtime data located beside the module.
            cp -R gidocgen "$out/${sitePackages}/"
            cp -R LICENSES/. "$out/share/licenses/gi-docgen/"
            cp docs/gi-docgen.1 "$out/share/man/man1/"
            sed 's/@VERSION@/${version}/g' gi-docgen.pc.in > "$out/share/pkgconfig/gi-docgen.pc"

            cat > "$out/bin/gi-docgen" <<'PY'
            #!${python3}/bin/python3
            import os
            import sys
            os.environ["PATH"] = "${graphviz}/bin:" + os.environ.get("PATH", "")
            sys.path[:0] = ["${builtins.placeholder "out"}/${sitePackages}"] + "${pythonPath}".split(":")
            from gidocgen.gidocmain import main
            sys.exit(main())
            PY
            chmod 0755 "$out/bin/gi-docgen"
          '';
        }
      ]
      ++ (
        if stdenv.isCross or false
        then []
        else [
          {
            name = "check";
            script = ''
              PATH="${graphviz}/bin:$PATH" PYTHONPATH="$out/${sitePackages}:${pythonPath}" ${python3}/bin/python3 -m unittest discover -v
              "$out/bin/gi-docgen" --version
            '';
          }
        ]
      );

    meta = {
      description = "Documentation generator for GObject introspection libraries";
      homepage = "https://gitlab.gnome.org/GNOME/gi-docgen";
      license = "GPL-3.0-or-later AND Apache-2.0 AND CC0-1.0";
      mainProgram = "gi-docgen";
    };
  }
