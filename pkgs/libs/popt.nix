##! popt — command-line option parsing library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.19";
in
  mkDerivation {
    pname = "popt";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser stores integer value 42 and reaches end of options.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"popt primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"popt rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <popt.h>\nint main(void) {\n    int count = 0; const char *arguments[] = {\"probe\", \"--count=42\", NULL};\n    struct poptOption options[] = {{\"count\", 'c', POPT_ARG_INT, &count, 0, \"count\", \"N\"}, POPT_TABLEEND};\n    poptContext context = poptGetContext(NULL, 2, arguments, options, 0);\n    int status = poptGetNextOpt(context); poptFreeContext(context);\n    return status == -1 && count == 42 ? pass() : 2;\n}\n\n";
        };
        "input" = "A --count=42 command-line option.";
        "operation" = "Parse the option through poptGetNextOpt.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpopt"
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
              "exact" = "popt primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The parser returns POPT_ERROR_BADNUMBER.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"popt primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"popt rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <popt.h>\nint main(void) {\n    int count = 0; const char *arguments[] = {\"probe\", \"--count=not-a-number\", NULL};\n    struct poptOption options[] = {{\"count\", 'c', POPT_ARG_INT, &count, 0, \"count\", \"N\"}, POPT_TABLEEND};\n    poptContext context = poptGetContext(NULL, 2, arguments, options, 0);\n    int status = poptGetNextOpt(context); poptFreeContext(context);\n    if (status != POPT_ERROR_BADNUMBER) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A --count value that is not an integer.";
        "operation" = "Parse the malformed integer option through popt.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpopt"
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
              "exact" = "popt rejected invalid input\n";
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
        "https://ftp.osuosl.org/pub/rpm/popt/releases/popt-1.x/popt-${version}.tar.gz"
      ];
      hash = "sha256-wlpIOPyOTByKrLi9Yg7bMISj1jv4mH/a08onWMYyQPk=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd popt-${version}
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
        '';
      }
    ];

    meta = {
      description = "popt — command-line option parsing library";
      homepage = "https://github.com/rpm-software-management/popt";
      license = "MIT";
    };
  }
