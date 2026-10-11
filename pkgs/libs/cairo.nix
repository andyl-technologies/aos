##! cairo — Two-dimensional graphics library
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  meson,
  ninja,
  pkg-config,
  gtk-doc,
  pixman,
  fontconfig,
  freetype,
  expat,
  libpng,
  glib,
  libffi,
  pcre2,
  zlib,
  lzo,
  buildPackages,
}: let
  version = "1.18.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "cairo";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <cairo.h>\n\nint main(void) {\n    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 2, 2);\n    cairo_t *context = cairo_create(surface);\n    cairo_set_source_rgb(context, 1.0, 0.0, 0.0);\n    cairo_paint(context);\n    cairo_surface_flush(surface);\n    int failed = cairo_status(context) != CAIRO_STATUS_SUCCESS\n        || cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS;\n    cairo_destroy(context);\n    cairo_surface_destroy(surface);\n    if (failed) {\n        return 2;\n    }\n    return puts(\"cairo api passed\") == EOF;\n}\n";
        };
        "input" = "A two-by-two in-memory ARGB image surface.";
        "operation" = "Create the surface, paint it red, and validate the surface status.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include/cairo"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcairo"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cairo api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <cairo.h>\n\nint main(void) {\n    cairo_surface_t *surface = cairo_image_surface_create((cairo_format_t)999, 2, 2);\n    cairo_status_t status = cairo_surface_status(surface);\n    cairo_surface_destroy(surface);\n    if (status != CAIRO_STATUS_INVALID_FORMAT) {\n        return 2;\n    }\n    fputs(\"cairo rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An image surface request with an invalid pixel format.";
        "operation" = "Create the surface and inspect Cairo's error-object status.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include/cairo"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcairo"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cairo rejected invalid input\n";
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
      urls = ["https://cairographics.org/releases/cairo-${version}.tar.xz"];
      hash = "sha256-RF7YIIpuSCPeEianTKMZ02AOg/Y2n5mxQmUAZZnDLMs=";
    };

    buildDeps = [meson ninja pkg-config buildPackages.python3 gtk-doc glib.dev];
    runtimeDeps = [pixman fontconfig freetype expat libpng glib libffi pcre2 zlib lzo];
    propagatedDeps = [pixman fontconfig freetype libpng glib libffi pcre2 zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cairo-${version}

          # Meson executes this source helper while configuring. Point it at
          # the AOS Python rather than the unavailable host interpreter.
          sed -i '1s|.*|#!${buildPackages.python3}/bin/python3|' version.py
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # GLib's unversioned linker names live in its target dev output;
            # build dependencies otherwise provide the native headers/tools.
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
          ''
          + ''
            export PKG_CONFIG_PATH=${fontconfig}/lib/pkgconfig:${freetype}/lib/pkgconfig:${expat}/lib/pkgconfig:${libpng}/lib/pkgconfig:${zlib}/lib/pkgconfig:${glib.dev}/lib/pkgconfig:${libffi}/lib/pkgconfig:${pcre2}/lib/pkgconfig:${pixman}/lib/pkgconfig:$PKG_CONFIG_PATH
            meson setup build \
              $mesonFlags \
              --prefix="$out" \
              --buildtype=release \
              -Dfontconfig=enabled \
              -Dfreetype=enabled \
              -Dpng=enabled \
              -Dtee=enabled \
              -Dzlib=enabled \
              -Dlzo=enabled \
              -Dglib=enabled \
              -Dxcb=disabled \
              -Dxlib=disabled \
              -Dxlib-xcb=disabled \
              -Dquartz=disabled \
              -Ddwrite=disabled \
              -Dgtk2-utils=disabled \
              -Dspectre=disabled \
              -Dsymbol-lookup=disabled \
              -Dtests=disabled \
              -Dgtk_doc=true
          '';
      }
      {
        name = "build";
        script = ''
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
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

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-cairo";
        library = self;
        includes = ["${self}/include/cairo"];
        libs = ["-lcairo"];
        testSource = ''
          #include <cairo.h>

          int main(void) {
              cairo_surface_t *surface =
                  cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
              int failed = cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS;
              cairo_surface_destroy(surface);
              return failed;
          }
        '';
      };
    };

    meta = {
      description = "Vector graphics library with multiple output targets";
      homepage = "https://cairographics.org/";
      license = "LGPL-2.1-only OR MPL-1.1";
    };
  }
