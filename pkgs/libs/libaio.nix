##! libaio — Linux-native asynchronous I/O facility
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.3.113";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "libaio";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The kernel-backed context is created and released successfully.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libaio primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libaio rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libaio.h>\nint main(void) {\n    io_context_t context = 0;\n    if (io_setup(1, &context) != 0 || context == 0) return 2;\n    return io_destroy(context) == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "A request for one empty Linux asynchronous-I/O context.";
        "operation" = "Create and destroy the context through io_setup and io_destroy.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-laio"
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
              "exact" = "libaio primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libaio returns EINVAL without creating a context.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libaio primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libaio rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <errno.h>\n#include <libaio.h>\nint main(void) {\n    io_context_t context = 0;\n    int status = io_setup(0, &context);\n    if (status != -EINVAL || context != 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A request for an asynchronous-I/O context with zero events.";
        "operation" = "Submit the invalid capacity through io_setup.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-laio"
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
              "exact" = "libaio rejected invalid input\n";
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
        "https://pagure.io/libaio/archive/libaio-${version}/libaio-libaio-${version}.tar.gz"
      ];
      hash = "sha256-cWxwWXAyRzROsGa1TsvDyiE08BAzBxkubCt9q1+VKKs=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libaio-libaio-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES prefix=$out libdir=$out/lib
        '';
      }
      {
        name = "install";
        script = ''
          make install prefix=$out libdir=$out/lib
        '';
      }
    ];

    meta = {
      description = "Linux-native asynchronous I/O facility";
      homepage = "https://pagure.io/libaio";
      license = "LGPL-2.1-or-later";
    };
  }
