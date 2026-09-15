##! lzo — Low-latency lossless compression library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.10";
in
  mkDerivation {
    pname = "lzo";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The recovered bytes equal the original string.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lzo primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lzo rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <lzo/lzo1x.h>\nint main(void) {\n    const unsigned char input[] = \"AOS qualification\"; unsigned char compressed[128], output[128];\n    lzo_uint compressed_size = sizeof(compressed), output_size = sizeof(output);\n    unsigned char work[LZO1X_1_MEM_COMPRESS];\n    if (lzo_init() != LZO_E_OK || lzo1x_1_compress(input, sizeof(input), compressed, &compressed_size, work) != LZO_E_OK) return 2;\n    if (lzo1x_decompress_safe(compressed, compressed_size, output, &output_size, NULL) != LZO_E_OK) return 3;\n    return output_size == sizeof(input) && memcmp(output, input, sizeof(input)) == 0 ? pass() : 4;\n}\n\n";
        };
        "input" = "A fixed byte string compressed into a bounded LZO1X block.";
        "operation" = "Compress and safely decompress the bytes through LZO.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llzo2"
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
              "exact" = "lzo primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "LZO returns a non-success corruption status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lzo primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lzo rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <lzo/lzo1x.h>\nint main(void) {\n    const unsigned char invalid[] = {0xff}; unsigned char output[32]; lzo_uint output_size = sizeof(output);\n    if (lzo_init() != LZO_E_OK) return 2;\n    if (lzo1x_decompress_safe(invalid, sizeof(invalid), output, &output_size, NULL) == LZO_E_OK) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A truncated LZO block with no complete token sequence.";
        "operation" = "Decode the malformed block through lzo1x_decompress_safe.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llzo2"
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
              "exact" = "lzo rejected invalid input\n";
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
      urls = ["https://www.oberhumer.com/opensource/lzo/download/lzo-${version}.tar.gz"];
      hash = "sha256-wPiSlDIIJm+bZUOzrjCPq2KExckOYnkxRG+0m0IhoHI=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    configureFlags = "--enable-shared --enable-static";
    doCheck = true;

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-lzo";
        library = self;
        libs = ["-llzo2"];
        testSource = ''
          #include <lzo/lzo1x.h>
          int main(void) {
            return lzo_init() == LZO_E_OK ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Low-latency lossless data compression library";
      homepage = "https://www.oberhumer.com/opensource/lzo/";
      license = "GPL-2.0-or-later";
    };
  }
