##! gperf — GNU perfect hash function generator
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.3";
in
  mkDerivation {
    pname = "gperf";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The generated perfect hash maps each keyword to its declared value.";
        "files" = {
          "consumer.c" = "#include <stdio.h>\n#include <string.h>\n#include \"keywords.c\"\n\nint main(void) {\n    const struct keyword *alpha = lookup(\"alpha\", 5);\n    const struct keyword *beta = lookup(\"beta\", 4);\n    if (alpha == NULL || beta == NULL || alpha->value + beta->value != 42) {\n        return 2;\n    }\n    return puts(\"gperf lookup passed\") == EOF;\n}\n";
          "keywords.gperf" = "%{\n#include <string.h>\n%}\nstruct keyword { const char *name; int value; };\n%%\nalpha, 19\nbeta, 23\n%%\n";
        };
        "input" = "Two distinct keywords with associated integer values.";
        "operation" = "Generate a C lookup table, compile a consumer, and query both keywords.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gperf"
              "--language=C"
              "--struct-type"
              "--lookup-function-name=lookup"
              "--output-file=keywords.c"
              "keywords.gperf"
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
              "@cc@"
              "consumer.c"
              "-o"
              "consumer"
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
              "@work@/primary/consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "gperf lookup passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Gperf rejects the duplicate keyword with status 1.";
        "files" = {
          "duplicates.gperf" = "%%\nalpha\nalpha\n%%\n";
        };
        "input" = "Two records declaring the same keyword.";
        "operation" = "Generate a perfect hash without duplicate-key support.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/gperf"
              "--output-file=duplicates.c"
              "duplicates.gperf"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
        "https://mirrors.kernel.org/gnu/gperf/gperf-${version}.tar.gz"
      ];
      hash = "sha256-/Yfgq6fkOuBUg3r9bNTbA6PyaT3rNhkIXm7Z2NlgStg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gperf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
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
        '';
      }
    ];

    meta = {
      description = "gperf — GNU perfect hash function generator";
      homepage = "https://www.gnu.org/software/gperf/";
      license = "GPL-3.0-or-later";
    };
  }
