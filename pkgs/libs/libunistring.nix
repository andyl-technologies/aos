##! libunistring — Unicode string processing library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "1.4.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libunistring";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libunistring returns a null error pointer for valid UTF-8.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libunistring primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libunistring rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <unistr.h>\nint main(void) {\n    const uint8_t input[] = {'b', 0xc3, 0xbc, 'c', 'h', 'e', 'r'};\n    return u8_check(input, sizeof(input)) == NULL ? pass() : 2;\n}\n\n";
        };
        "input" = "A valid UTF-8 sequence containing a two-byte umlaut.";
        "operation" = "Validate the complete byte sequence through u8_check.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lunistring"
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
              "exact" = "libunistring primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libunistring returns a pointer to the invalid byte.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libunistring primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libunistring rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <unistr.h>\nint main(void) {\n    const uint8_t input[] = {'a', 0xc3};\n    if (u8_check(input, sizeof(input)) == NULL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A truncated two-byte UTF-8 sequence.";
        "operation" = "Validate the malformed sequence through u8_check.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lunistring"
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
              "exact" = "libunistring rejected invalid input\n";
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
        "https://ftp.gnu.org/gnu/libunistring/libunistring-${version}.tar.gz"
      ];
      hash = "sha256-6CZksXAGTmIzGWISayWdRS1Tsie7SpOrIAQNhG/sAdg=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libunistring-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libunistring";
        library = self;
        libs = ["-lunistring"];
        testSource = ''
          #include <unistr.h>
          #include <stdio.h>

          int main(void) {
              const uint8_t input[] = "AOS";
              printf("%zu\n", u8_strlen(input));
              return u8_strlen(input) == 3 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Unicode string processing library";
      homepage = "https://www.gnu.org/software/libunistring/";
      license = "LGPL-3.0-or-later";
    };
  }
