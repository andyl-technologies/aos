##! libmd — BSD message-digest functions
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.2.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "libmd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The hexadecimal digest matches the standard SHA-256 vector.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmd primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmd rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <sha256.h>\nint main(void) {\n    char digest[SHA256_DIGEST_STRING_LENGTH];\n    const char *result = SHA256Data((const unsigned char *)\"abc\", 3, digest);\n    return result != NULL && strcmp(digest, \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\") == 0 ? pass() : 2;\n}\n\n";
        };
        "input" = "The ASCII string abc for SHA-256 hashing.";
        "operation" = "Hash the bytes through libmd's SHA256Data interface.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmd"
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
              "exact" = "libmd primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libmd returns a null result instead of a digest.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmd primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmd rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <sha256.h>\nint main(void) {\n    char digest[SHA256_DIGEST_STRING_LENGTH];\n    if (SHA256File(\"missing-qualification-file\", digest) != NULL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A pathname that does not exist.";
        "operation" = "Hash the missing file through SHA256File.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmd"
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
              "exact" = "libmd rejected invalid input\n";
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
        "https://libbsd.freedesktop.org/releases/libmd-${version}.tar.xz"
      ];
      hash = "sha256-rBX/uEMFAvuszexmxagu4OqwsPNiIN9WcQ/q3+sT0KA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libmd-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install

          mkdir -p "$out/share/licenses/libmd"
          cp COPYING "$out/share/licenses/libmd/COPYING"
        '';
      }
    ];

    meta = {
      description = "BSD message-digest functions";
      homepage = "https://www.hadrons.org/software/libmd/";
      platforms = ["x86_64-linux" "aarch64-linux"];
      license = [
        "BSD-2-Clause"
        "BSD-3-Clause"
        "ISC"
        "Beerware"
        "LicenseRef-Public-Domain"
      ];
    };
  }
