##! libexif — EXIF metadata reader and writer used by image processing libraries.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "0.6.26";
  probeSource = ''
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <libexif/exif-data.h>

    int main(int argc, char **argv) {
        if (argc > 1 && strcmp(argv[1], "bad") == 0) {
            const unsigned char broken[] = "not exif";
            ExifData *data = exif_data_new_from_data(broken, sizeof broken - 1);
            if (data == NULL) return 3;
            for (int i = 0; i < EXIF_IFD_COUNT; ++i) {
                if (data->ifd[i]->count != 0) return 2;
            }
            exif_data_unref(data);
            puts("libexif ignored malformed metadata");
            return 0;
        }

        ExifData *original = exif_data_new();
        if (original == NULL) return 4;
        ExifEntry *entry = exif_entry_new();
        if (entry == NULL) return 5;
        entry->tag = EXIF_TAG_IMAGE_DESCRIPTION;
        entry->format = EXIF_FORMAT_ASCII;
        entry->components = 4;
        entry->size = 4;
        entry->data = malloc(4);
        if (entry->data == NULL) return 6;
        memcpy(entry->data, "AOS", 4);
        exif_content_add_entry(original->ifd[EXIF_IFD_0], entry);
        exif_entry_unref(entry);

        unsigned char *encoded = NULL;
        unsigned int length = 0;
        exif_data_save_data(original, &encoded, &length);
        exif_data_unref(original);
        if (encoded == NULL || length == 0) return 7;
        ExifData *decoded = exif_data_new_from_data(encoded, length);
        free(encoded);
        if (decoded == NULL) return 8;
        ExifEntry *result = exif_content_get_entry(decoded->ifd[EXIF_IFD_0], EXIF_TAG_IMAGE_DESCRIPTION);
        int valid = result != NULL && result->size == 4 && memcmp(result->data, "AOS", 4) == 0;
        exif_data_unref(decoded);
        if (!valid) return 9;
        puts("libexif metadata round trip passed");
        return 0;
    }
  '';
  compileProbe = {
    argv = [
      "@cc@"
      "-I@out@/include"
      "probe.c"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "-lexif"
      "-o"
      "probe"
    ];
    exit_code = 0;
  };
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
    pname = "libexif";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An EXIF image-description tag containing AOS.";
        operation = "Serialize and parse the tag with libexif.";
        expected = "The parsed tag retains its exact text value.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe"];
            exit_code = 0;
            stdout.exact = "libexif metadata round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not contain EXIF metadata.";
        operation = "Parse them through libexif.";
        expected = "The parser returns no metadata tags.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe" "bad"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libexif ignored malformed metadata\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/libexif/libexif/releases/download/v${version}/libexif-${version}.tar.xz"];
      hash = "sha256-SgVe1ldeYcpGwxcr48dTzBbJvs0Pmexx1Y3Q5HFHbAw=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.gettext buildPackages.pkg-config];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libexif-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
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
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libexif"
            cp COPYING "$out/share/licenses/libexif/"
          '';
        }
      ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libexif";
        library = self;
        libs = ["-lexif"];
        testSource = ''
          #include <stddef.h>
          #include <libexif/exif-data.h>

          int main(void) {
              ExifData *data = exif_data_new();
              if (data == NULL) return 1;
              exif_data_unref(data);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Library for parsing and writing EXIF image metadata";
      homepage = "https://libexif.github.io/";
      license = "LGPL-2.1-or-later";
    };
  }
