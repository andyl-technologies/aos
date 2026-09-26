##! gtk-doc — Documentation generator for GObject-based libraries
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  gettext,
  python3,
  bash,
  python3-lxml,
  python3-pygments,
  libxslt,
  docbook-xml,
  docbook-xsl,
  buildPackages,
}: let
  version = "1.36.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "gtk-doc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Gtk-doc records the public function in the generated declaration list.";
        "files" = {
          "probe.h" = "/**\n * probe_answer:\n *\n * Returns: the answer\n */\nint probe_answer(void);\n";
        };
        "input" = "A public C header containing one documented function declaration.";
        "operation" = "Scan the header and inspect gtk-doc's declaration inventory.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/gtkdoc-scan\", \"--module=probe\", \"--source-dir=.\"], capture_output=True)\nassert result.returncode == 0, result.stderr\ndeclarations = pathlib.Path(\"probe-decl-list.txt\").read_text()\nassert \"probe_answer\" in declarations\nprint(\"gtk-doc operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "gtk-doc operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Gtk-doc rejects the unknown option before scanning sources.";
        "files" = {};
        "input" = "A gtkdoc-scan option that is not defined.";
        "operation" = "Invoke the scanner with the unknown option.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/gtkdoc-scan\", \"--aos-invalid-option\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"gtk-doc rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "gtk-doc rejected invalid input\n";
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
        "https://gitlab.gnome.org/GNOME/gtk-doc/-/archive/${version}/gtk-doc-${version}.tar.gz"
      ];
      hash = "sha256-nl9t0hLKLDG9DugEupZy8A0wytEsA/mrqdFen3QTTcQ=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      gettext
      python3
      python3-lxml
      python3-pygments
      libxslt
      docbook-xml
      docbook-xsl
    ];
    runtimeDeps = [
      python3
      bash
      python3-lxml
      python3-pygments
      libxslt
      docbook-xml
      docbook-xsl
    ];
    propagatedDeps = [python3-lxml python3-pygments docbook-xml docbook-xsl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gtk-doc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          pythonPath=${python3-lxml}/${sitePackages}:${python3-pygments}/${sitePackages}
          mkdir -p .aos-build-tools
          cat > .aos-build-tools/python3 <<EOF
          #!$CONFIG_SHELL
          export PYTHONPATH="$pythonPath"
          exec ${python3}/bin/python3 "\$@"
          EOF
          chmod 0755 .aos-build-tools/python3
          export PATH="$PWD/.aos-build-tools:$PATH"
          export XML_CATALOG_FILES="${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Dtests=false \
            -Dyelp_manual=false
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:${python3-lxml}/${sitePackages}:${python3-pygments}/${sitePackages}
          ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:${python3-lxml}/${sitePackages}:${python3-pygments}/${sitePackages}
          ninja -C build install

          mkdir -p "$out/libexec/gtk-doc"
          cat > "$out/libexec/gtk-doc/python3" <<'EOF'
          #!${bash}/bin/bash
          export PYTHONPATH=${python3-lxml}/${sitePackages}:${python3-pygments}/${sitePackages}
          export XML_CATALOG_FILES="${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          exec ${python3}/bin/python3 "$@"
          EOF
          chmod 0755 "$out/libexec/gtk-doc/python3"
          find "$out/bin" -type f | while read file; do
            if head -1 "$file" | grep -q 'python3$'; then
              sed -i '1s|.*|#!${builtins.placeholder "out"}/libexec/gtk-doc/python3|' "$file"
            fi
          done
          sed -i '1s|.*|#!${bash}/bin/bash|' "$out/bin/gtkdocize"
          "$out/bin/gtkdoc-scan" --version
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-gtk-doc";
        tool = self;
        command = "gtkdoc-scan --version && gtkdoc-mkhtml --version";
      };
    };

    meta = {
      description = "Tools for extracting documentation from GObject-based C libraries";
      homepage = "https://gitlab.gnome.org/GNOME/gtk-doc";
      license = "GPL-2.0-or-later";
      mainProgram = "gtkdoc-scan";
    };
  }
