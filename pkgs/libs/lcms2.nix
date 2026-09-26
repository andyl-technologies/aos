##! lcms2 — ICC color management for image processing.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  mozjpeg,
  libtiff,
}: let
  version = "2.19.1";
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
    pname = "lcms2";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A generated sRGB ICC profile and one RGB pixel.";
        operation = "Serialize and reload the profile, then transform the pixel between matching profiles.";
        expected = "The reloaded profile retains its color space and the transform preserves the pixel.";
        files."profile.c" = ''
          #include <lcms2.h>
          #include <stdio.h>
          #include <stdlib.h>

          int main(void) {
            cmsHPROFILE source = cmsCreate_sRGBProfile();
            if (!source) return 1;

            cmsUInt32Number size = 0;
            if (!cmsSaveProfileToMem(source, NULL, &size) || size == 0) return 2;
            void *bytes = malloc(size);
            if (!bytes || !cmsSaveProfileToMem(source, bytes, &size)) return 3;

            cmsHPROFILE loaded = cmsOpenProfileFromMem(bytes, size);
            if (!loaded || cmsGetColorSpace(loaded) != cmsSigRgbData) return 4;
            cmsHTRANSFORM transform = cmsCreateTransform(
              loaded, TYPE_RGB_8, source, TYPE_RGB_8, INTENT_PERCEPTUAL, 0
            );
            if (!transform) return 5;

            unsigned char input[3] = {48, 128, 224};
            unsigned char output[3] = {0};
            cmsDoTransform(transform, input, output, 1);
            for (int channel = 0; channel < 3; channel++) {
              if (input[channel] != output[channel]) return 6;
            }

            cmsDeleteTransform(transform);
            cmsCloseProfile(loaded);
            cmsCloseProfile(source);
            free(bytes);
            puts("lcms2 ICC profile round trip passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "profile.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llcms2"
              "-o"
              "profile"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./profile"];
            exit_code = 0;
            stdout.exact = "lcms2 ICC profile round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not contain an ICC profile.";
        operation = "Attempt to load them as a profile.";
        expected = "The profile parser rejects the bytes.";
        files."bad.c" = ''
          #include <lcms2.h>
          #include <stdio.h>

          int main(void) {
            const char bytes[] = "not an ICC profile";
            cmsHPROFILE profile = cmsOpenProfileFromMem(bytes, sizeof(bytes));
            if (profile) return 1;

            puts("lcms2 rejected malformed ICC profile");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cc@"
              "-std=c11"
              "-I@out@/include"
              "bad.c"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llcms2"
              "-o"
              "bad"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./bad"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "lcms2 rejected malformed ICC profile\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/mm2/Little-CMS/releases/download/lcms${version}/lcms2-${version}.tar.gz"];
      hash = "1j0m505qqsj1frmx8iyv8sylmfjc5q1sh51004hwkysrmdxlzidz";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [mozjpeg libtiff];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd lcms2-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Dutils=true -Djpeg=enabled -Dtiff=enabled
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
            mkdir -p "$out/share/licenses/lcms2"
            cp LICENSE "$out/share/licenses/lcms2/"
          '';
        }
      ];

    meta = {
      description = "ICC color management library for image processing";
      homepage = "https://www.littlecms.com/";
      license = "MIT";
    };
  }
