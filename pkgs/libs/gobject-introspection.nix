##! gobject-introspection — Metadata compiler for GObject libraries
{
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  flex,
  bison,
  python3,
  bash,
  coreutils,
  setuptools,
  python3-mako,
  python3-markdown,
  gtk-doc,
  cairo,
  glib,
  libffi,
  util-linux,
  buildPackages,
}: let
  version = "1.86.0";
  sitePackages = "lib/python3.14/site-packages";
  pythonPath = "${setuptools}/${sitePackages}:${python3-mako}/${sitePackages}:${python3-markdown}/${sitePackages}";
in
  mkDerivation {
    pname = "gobject-introspection";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/gobject-introspection/1.86/gobject-introspection-${version}.tar.xz"
      ];
      hash = "sha256-kg0aP87ercMqz/lcLiA7MZA53UtKCN0aLf0oPRnAua4=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      flex
      bison
      python3
      setuptools
      python3-mako
      python3-markdown
      gtk-doc
      glib.dev
      glib.tools
      util-linux
    ];
    runtimeDeps = [bash coreutils python3 setuptools python3-mako python3-markdown cairo glib libffi];
    propagatedDeps = [cairo glib.dev libffi python3-mako];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gobject-introspection-${version}

          find . -type f -name '*.py' | while read file; do
            if head -1 "$file" | grep -Eq '^#!/usr/bin/(env )?python3'; then
              sed -i '1s|.*|#!${python3}/bin/python3|' "$file"
            fi
          done

          # Upstream reconstructs glibconfig.h from GLib's library directory.
          # AOS keeps generated headers in GLib's development output, as its
          # pkg-config Cflags already advertise, so use that split location.
          sed -i \
            "s|glib_libincdir = join_paths(glib_libdir, 'glib-2.0', 'include')|glib_libincdir = '${glib.dev}/lib/glib-2.0/include'|" \
            gir/meson.build

          # Generated tools must invoke the hermetic Python launcher directly;
          # the upstream `/usr/bin/env <absolute-path>` shebang is both
          # unnecessary and unavailable in AOS builders.
          sed -i \
            "s|python_cmd = '/usr/bin/env ' + python.full_path()|python_cmd = python.full_path()|" \
            tools/meson.build

          # Python only evaluates .pth files from its configured site roots,
          # not from PYTHONPATH. Import setuptools explicitly so its distutils
          # compatibility hook is active before the scanner imports it.
          sed -i '/^import distutils\.cygwinccompiler$/i import setuptools' \
            giscanner/utils.py
          sed -i '/^import distutils$/i import setuptools' \
            tests/scanner/test_ccompiler.py

          # The glibc ldd script rejects AOS PIE executables before asking the
          # loader to trace them. Run the executable with the loader's trace
          # environment directly, which produces the same dependency listing.
          sed -i \
            "s|args.extend(\['ldd', binary.args\[0\]\])|args.extend(['${coreutils}/bin/env', 'LD_TRACE_LOADED_OBJECTS=1', binary.args[0]])|" \
            giscanner/shlibs.py
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir -p .aos-build-tools
          cat > .aos-build-tools/python3 <<'EOF'
          #!${bash}/bin/bash
          export PYTHONPATH=${pythonPath}''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python3}/bin/python3 "$@"
          EOF
          chmod 0755 .aos-build-tools/python3
          export PATH="$PWD/.aos-build-tools:$PATH"
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --buildtype=release \
            -Dcairo=enabled \
            -Dgtk_doc=true
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:${pythonPath}
          ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:${pythonPath}
          meson test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages:${pythonPath}
          ninja -C build install

          mkdir -p "$out/libexec/gobject-introspection"
          cat > "$out/libexec/gobject-introspection/python3" <<'EOF'
          #!${bash}/bin/bash
          export PYTHONPATH=${pythonPath}''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python3}/bin/python3 "$@"
          EOF
          chmod 0755 "$out/libexec/gobject-introspection/python3"
          find "$out/bin" -type f | while read file; do
            if head -1 "$file" | grep -q 'python3$'; then
              sed -i '1s|.*|#!${builtins.placeholder "out"}/libexec/gobject-introspection/python3|' "$file"
            fi
          done
          "$out/bin/g-ir-scanner" --version
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-gobject-introspection";
        tool = self;
        command = "g-ir-scanner --version && g-ir-compiler --version";
      };
    };

    meta = {
      description = "Middleware for generating and consuming GObject API metadata";
      homepage = "https://gi.readthedocs.io/";
      license = "GPL-2.0-or-later AND LGPL-2.0-or-later";
      mainProgram = "g-ir-scanner";
    };
  }
