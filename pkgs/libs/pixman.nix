##! pixman — Low-level pixel manipulation library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  buildPackages,
}: let
  version = "0.46.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "pixman";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The destination becomes the exact source pixel.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"pixman primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"pixman rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pixman.h>\nint main(void) {\n    uint32_t source_pixel = 0xffff0000, destination_pixel = 0;\n    pixman_image_t *source = pixman_image_create_bits(PIXMAN_a8r8g8b8, 1, 1, &source_pixel, 4);\n    pixman_image_t *destination = pixman_image_create_bits(PIXMAN_a8r8g8b8, 1, 1, &destination_pixel, 4);\n    if (source == NULL || destination == NULL) return 2;\n    pixman_image_composite32(PIXMAN_OP_SRC, source, NULL, destination, 0, 0, 0, 0, 0, 0, 1, 1);\n    int ok = destination_pixel == source_pixel;\n    pixman_image_unref(destination); pixman_image_unref(source);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "One opaque red source pixel composited over a blank destination.";
        "operation" = "Composite the pixel through pixman_image_composite32.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/pixman-1"
              "-lpixman-1"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "pixman primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "pixman rejects the dimensions by returning a null image.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"pixman primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"pixman rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pixman.h>\nint main(void) {\n    pixman_image_t *image = pixman_image_create_bits(PIXMAN_a8r8g8b8, 0x7fffffff, 1, NULL, 4);\n    if (image != NULL) { pixman_image_unref(image); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "An image width above pixman's supported coordinate range.";
        "operation" = "Create the out-of-range image through pixman_image_create_bits.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-I@out@/include/pixman-1"
              "-lpixman-1"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "pixman rejected invalid input\n";
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
        "https://cairographics.org/releases/pixman-${version}.tar.gz"
        "https://www.x.org/releases/individual/lib/pixman-${version}.tar.gz"
      ];
      hash = "sha256-0JxE68O9W+5wIcefki/o+y+1f3Mg9V6X/5kU0jRqWRw=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pixman-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          meson setup build \
            $mesonFlags \
            --prefix=$out \
            --buildtype=release \
            -Dgtk=disabled \
            -Dlibpng=disabled \
            -Dtests=disabled \
            -Ddemos=disabled
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          # Meson records its Python module invocation in build.ninja, not the
          # environment-setting launcher used during setup.
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install
        '';
      }
    ];

    meta = {
      description = "pixman — low-level pixel manipulation library";
      homepage = "https://pixman.org";
      license = "MIT";
    };
  }
