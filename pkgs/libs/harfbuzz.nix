##! harfbuzz — Text shaping and glyph rendering for image processing.
{
  mkDerivation,
  lib,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "harfbuzz";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The UTF-8 text ffi and an empty shaping font.";
        operation = "Shape the text through the public HarfBuzz buffer and font APIs.";
        expected = "Shaping retains three glyphs and the first input cluster.";
        artifacts = [];
        files."probe.c" = ''
          #include <hb.h>
          #include <stdio.h>

          int main(void) {
              hb_buffer_t *buffer = hb_buffer_create();
              hb_buffer_add_utf8(buffer, "ffi", -1, 0, -1);
              hb_buffer_guess_segment_properties(buffer);
              hb_shape(hb_font_get_empty(), buffer, NULL, 0);

              unsigned int count = 0;
              const hb_glyph_info_t *glyphs = hb_buffer_get_glyph_infos(buffer, &count);
              if (count != 3 || glyphs == NULL || glyphs[0].cluster != 0) {
                  hb_buffer_destroy(buffer);
                  return 1;
              }

              hb_buffer_destroy(buffer);
              puts("shaped three glyphs");
              return 0;
          }
        '';
        steps = [
          {
            argv = [
              "@cc@"
              "-I@out@/include/harfbuzz"
              "probe.c"
              "@out@/lib/libharfbuzz.so"
              "-Wl,-rpath,@out@/lib"
              "-o"
              "@work@/primary/probe"
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/probe"];
            exit_code = 0;
            stdout.exact = "shaped three glyphs\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A file containing text instead of font data.";
        operation = "Ask hb-shape to load the malformed font and shape text.";
        expected = "The font loader rejects the malformed file.";
        artifacts = [];
        files."bad.ttf" = "not a font\n";
        steps = [
          {
            argv = ["@out@/bin/hb-shape" "bad.ttf" "ffi"];
            exit_code = 2;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "hb-shape: bad.ttf: Failed loading font face\nTry `hb-shape --help' for more information.\n";
          }
        ];
      };
    };
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
