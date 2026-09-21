{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  callPackage,
  util-linux,
  zlib,
  stdenv,
  buildPackages,
  gobject-introspection,
}: let
  version = "1.10.8";
  majorMinor = "1.10";
  isCross = stdenv.isCross;
  glib = callPackage ./_image-glib.nix {};
in
  mkDerivation {
    pname = "json-glib";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.gnome.org/sources/json-glib/${majorMinor}/json-glib-${version}.tar.xz"
      ];
      hash = "sha256-VcXBQaVkJFuPj752mGY8h6RaczPCosVvBvgRq3OyEt0=";
    };

    buildDeps = [
      buildPackages.meson
      buildPackages.ninja
      buildPackages.python3
      buildPackages.pkg-config
      buildPackages.glib.tools
      buildPackages.gobject-introspection
      buildPackages.gi-docgen
      buildPackages.docutils
      buildPackages.gettext
    ];
    # glib's gio-2.0.pc has `Requires.private: zlib, mount` (libmount, from
    # util-linux); pkg-config 0.29 resolves private deps too, so those must
    # be reachable or `dependency('gio-2.0')` fails. glib lists util-linux
    # only in runtimeDeps (not propagated), so name them here directly.
    runtimeDeps =
      [glib zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );
    propagatedDeps =
      [glib zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd json-glib-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
          export XDG_DATA_DIRS="${glib}/share:${buildPackages.gobject-introspection}/share"
          export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
          export PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages"
          ${
            if stdenv.isCross
            then ''
              # Use native scanner programs while describing target GI libraries.
              mkdir -p .aos-introspection
              cat > .aos-introspection/ldd-target <<'EOF'
              #!${buildPackages.bash}/bin/bash
              exec ${stdenv.glibc}/lib/${stdenv.hostPlatform.dynamicLinker} --list "$@"
              EOF
              cat > .aos-introspection/g-ir-scanner <<EOF
              #!${buildPackages.bash}/bin/bash
              exec ${buildPackages.gobject-introspection}/bin/g-ir-scanner --use-ldd-wrapper="$PWD/.aos-introspection/ldd-target" "\$@"
              EOF
              chmod +x .aos-introspection/ldd-target .aos-introspection/g-ir-scanner
              cp ${gobject-introspection}/lib/pkgconfig/gobject-introspection-1.0.pc .aos-introspection/
              sed -i \
                -e "s|^g_ir_scanner=.*|g_ir_scanner=$PWD/.aos-introspection/g-ir-scanner|" \
                -e 's|^g_ir_compiler=.*|g_ir_compiler=${buildPackages.gobject-introspection}/bin/g-ir-compiler|' \
                .aos-introspection/gobject-introspection-1.0.pc
              export PKG_CONFIG_PATH="$PWD/.aos-introspection:$PKG_CONFIG_PATH"
            ''
            else ""
          }
          meson setup build $mesonFlags --prefix="$out" --libdir=lib \
            --buildtype=release --wrap-mode=nofallback \
            -Dintrospection=enabled -Ddocumentation=enabled -Dman=true \
            -Dtests=true -Dconformance=true -Dnls=enabled
        '';
      }
      {
        name = "build";
        script = ''
          # Meson records its Python module invocation in build.ninja, not the
          # environment-setting launcher used during setup.
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script =
          if isCross
          then ""
          else ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              meson test -C build --print-errorlogs
          '';
      }
      {
        name = "install";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
        '';
      }
    ];

    meta = {
      description = "GLib-based JSON parsing and generation library";
      homepage = "https://gitlab.gnome.org/GNOME/json-glib";
      license = "LGPL-2.1-or-later";
    };
  }
