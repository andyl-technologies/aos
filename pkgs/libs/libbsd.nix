##! libbsd — BSD compatibility interfaces for Linux
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  libmd,
}: let
  version = "0.12.2";
in
  mkDerivation {
    pname = "libbsd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "strtonum returns 42 with no diagnostic.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libbsd primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libbsd rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <bsd/stdlib.h>\nint main(void) {\n    const char *error = NULL;\n    long long value = strtonum(\"42\", 0, 100, &error);\n    return value == 42 && error == NULL ? pass() : 2;\n}\n\n";
        };
        "input" = "The decimal text 42 constrained to the range 0 through 100.";
        "operation" = "Parse and range-check the value through strtonum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-l:libbsd.so.0"
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
              "exact" = "libbsd primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "strtonum rejects the value with the too-large diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libbsd primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libbsd rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <bsd/stdlib.h>\nint main(void) {\n    const char *error = NULL;\n    (void)strtonum(\"101\", 0, 100, &error);\n    if (error == NULL || strcmp(error, \"too large\") != 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A decimal value above the permitted maximum.";
        "operation" = "Parse and range-check the value through strtonum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-l:libbsd.so.0"
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
              "exact" = "libbsd rejected invalid input\n";
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
        "https://libbsd.freedesktop.org/releases/libbsd-${version}.tar.xz"
      ];
      hash = "sha256-uIzJFj0MZSqvOamZkdl03bocOpcR248bWDivKhRzEBQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [libmd];
    # libbsd.so is an ld script whose GROUP contains AS_NEEDED(-lmd), so every
    # downstream link against -lbsd must also be able to resolve libmd.
    propagatedDeps = [libmd];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libbsd-${version}
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

          mkdir -p "$out/share/licenses/libbsd"
          cp COPYING "$out/share/licenses/libbsd/COPYING"
        '';
      }
    ];

    meta = {
      description = "BSD compatibility interfaces for Linux";
      homepage = "https://libbsd.freedesktop.org/";
      platforms = ["x86_64-linux" "aarch64-linux"];
      license = [
        "BSD-2-Clause"
        "BSD-3-Clause"
        "LicenseRef-BSD-5-Clause-Peter-Wemm"
        "ISC"
        "MIT"
        "Beerware"
        "LicenseRef-Public-Domain"
      ];
    };
  }
