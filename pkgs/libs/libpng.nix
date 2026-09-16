##! libpng — PNG reference library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "1.6.58";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libpng";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API reports the same nonzero version encoded by the header.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpng primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpng rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <png.h>\nint main(void) {\n    return png_access_version_number() == PNG_LIBPNG_VER && PNG_LIBPNG_VER > 10000 ? pass() : 2;\n}\n\n";
        };
        "input" = "A request for libpng's compiled library version.";
        "operation" = "Read and validate the version through png_access_version_number.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpng"
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
              "exact" = "libpng primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libpng reports that the bytes are not a PNG signature.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpng primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpng rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <png.h>\nint main(void) {\n    const png_byte signature[8] = {'G','I','F','8','9','a',0,0};\n    if (png_sig_cmp(signature, 0, sizeof(signature)) == 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "The eight-byte signature of a GIF file.";
        "operation" = "Ask png_sig_cmp to validate the foreign image signature.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpng"
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
              "exact" = "libpng rejected invalid input\n";
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
        "https://download.sourceforge.net/libpng/libpng-${version}.tar.xz"
      ];
      hash = "sha256-KOtAP1Hw90BSSRMs7P6C6lwO+X8bMsWmWCiBSuDTR3U=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpng-${version}
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
      {
        name = "check";
        script = ''
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpng";
        library = self;
        libs = ["-lpng"];
        testSource = ''
          #include <png.h>

          int main(void) {
              return png_access_version_number() == 0;
          }
        '';
      };
    };

    meta = {
      description = "Reference library for reading and writing PNG images";
      homepage = "http://www.libpng.org/pub/png/libpng.html";
      license = "libpng-2.0";
    };
  }
