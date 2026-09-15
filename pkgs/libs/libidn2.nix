##! libidn2 — IDNA2008 and Unicode TR46 implementation
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  libunistring,
}: let
  version = "2.3.8";
in
  mkDerivation {
    pname = "libidn2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libidn2 returns xn--bcher-kva.example.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libidn2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libidn2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <idn2.h>\nint main(void) {\n    char *ascii = NULL;\n    int status = idn2_to_ascii_8z(\"b\\xc3\\xbc\" \"cher.example\", &ascii, 0);\n    int ok = status == IDN2_OK && ascii != NULL && strcmp(ascii, \"xn--bcher-kva.example\") == 0;\n    idn2_free(ascii);\n    return ok ? pass() : 2;\n}\n\n";
        };
        "input" = "The Unicode domain name bucher.example with an umlaut.";
        "operation" = "Convert the domain to its IDNA ASCII representation.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lidn2"
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
              "exact" = "libidn2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libidn2 returns a non-success status and no accepted domain.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libidn2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libidn2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <idn2.h>\nint main(void) {\n    char *ascii = NULL;\n    int status = idn2_to_ascii_8z(\"bad\\xff.example\", &ascii, 0); idn2_free(ascii);\n    if (status == IDN2_OK) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A domain containing an invalid UTF-8 byte sequence.";
        "operation" = "Pass the malformed name to the IDNA converter.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lidn2"
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
              "exact" = "libidn2 rejected invalid input\n";
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
        "https://ftp.gnu.org/gnu/libidn/libidn2-${version}.tar.gz"
      ];
      hash = "sha256-9VeRG/YXFiHh9y/zX1sYJbs1tS7UUyXc3ukx5dPAeHo=";
    };

    buildDeps = [gnumake pkg-config gettext];
    runtimeDeps = [libunistring];
    propagatedDeps = [libunistring];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libidn2-${version}
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
        pname = "lib-libidn2";
        library = self;
        libs = ["-lidn2"];
        testSource = ''
          #include <idn2.h>
          #include <stdio.h>

          int main(void) {
              char *ascii = NULL;
              int result = idn2_lookup_u8(
                  (const uint8_t *)"example.com",
                  (uint8_t **)&ascii,
                  0);
              if (result != IDN2_OK) return 1;
              printf("%s\n", ascii);
              idn2_free(ascii);
              return 0;
          }
        '';
      };

      tool = testing.mkToolCheck {
        pname = "tool-idn2";
        tool = self;
        command = "idn2 --version";
      };
    };

    meta = {
      description = "IDNA2008 and Unicode TR46 implementation";
      homepage = "https://www.gnu.org/software/libidn/#libidn2";
      license = "LGPL-3.0-or-later AND GPL-2.0-or-later AND GPL-3.0-or-later";
      mainProgram = "idn2";
    };
  }
