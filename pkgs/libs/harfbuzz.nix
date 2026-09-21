##! harfbuzz — Text shaping and glyph rendering for image processing.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  callPackage,
  gobject-introspection,
  freetype,
  cairo,
  icu,
  libpng,
  zlib,
}: let
  glib = callPackage ./_image-glib.nix {};
  version = "14.3.1";
in
  mkDerivation {
    pname = "harfbuzz";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/harfbuzz/harfbuzz/archive/${version}.tar.gz"];
      hash = "1jb9sqg2l6l10g7894ic7q7jgjijx9k7g022v2bp8vc4y3d05rh5";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.gobject-introspection buildPackages.gtk-doc];
    runtimeDeps = [glib freetype cairo icu libpng zlib];
    propagatedDeps = [glib freetype];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd harfbuzz-${version}
            # Meson executes source generators directly during configuration.
            find . -type f -name '*.py' -exec \
              sed -i '1s|^#!.*python.*$|#!${buildPackages.python3}/bin/python3|' {} +
          '';
        }
        {
          name = "configure";
          script = ''
            # Native scanner dependencies also expose bootstrap GLib metadata.
            # Resolve the target image stack's GLib first.
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export XDG_DATA_DIRS="${glib}/share:${buildPackages.gobject-introspection}/share"
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
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dintrospection=enabled
          '';
        }
        {
          name = "build";
          script = ''
            # Ninja invokes Meson's Python helpers without its CLI wrapper.
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/harfbuzz"
            cp COPYING "$out/share/licenses/harfbuzz/"
          '';
        }
      ];

    meta = {
      description = "Text shaping library with glyph rendering, subsetting, and font utilities";
      homepage = "https://github.com/harfbuzz/harfbuzz";
      license = "MIT";
    };
  }
