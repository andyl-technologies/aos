##! gtk-doc — Documentation generator for GObject-based libraries
{
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
  version = "1.35.1";
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "gtk-doc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gitlab.gnome.org/GNOME/gtk-doc/-/archive/${version}/gtk-doc-${version}.tar.gz"
      ];
      hash = "sha256-9A9uedVVwAvAqp9cyOe+5VRXWJZbwvbyOBKkQtbNCZY=";
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
