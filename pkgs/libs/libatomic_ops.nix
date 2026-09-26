##! libatomic_ops — portable atomic memory operations library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "7.8.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libatomic_ops";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The operation returns the prior value 41 and stores 42.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libatomic_ops primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libatomic_ops rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <atomic_ops.h>\nint main(void) {\n    volatile AO_t value;\n    AO_store(&value, 41);\n    AO_t previous = AO_fetch_and_add1(&value);\n    return previous == 41 && AO_load(&value) == 42 ? pass() : 2;\n}\n\n";
        };
        "input" = "An atomic word initialized to 41.";
        "operation" = "Increment the word through AO_fetch_and_add1 and load it atomically.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-latomic_ops"
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
              "exact" = "libatomic_ops primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The operation reports failure and leaves the word unchanged.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libatomic_ops primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libatomic_ops rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <atomic_ops.h>\nint main(void) {\n    volatile AO_t value;\n    AO_store(&value, 42);\n    if (AO_compare_and_swap(&value, 41, 99) || AO_load(&value) != 42) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A compare-and-swap whose expected old value differs from the atomic word.";
        "operation" = "Attempt the conditional update through AO_compare_and_swap.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-latomic_ops"
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
              "exact" = "libatomic_ops rejected invalid input\n";
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
        "https://github.com/ivmai/libatomic_ops/releases/download/v${version}/libatomic_ops-${version}.tar.gz"
      ];
      hash = "sha256-0wUgf+IH8rP7XLTAGdoStEzj/LxZPf1QgNhnsaJBm1E=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libatomic_ops-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --build=${stdenv.buildPlatform.config} \
            --host=${stdenv.hostPlatform.config} \
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
      description = "Portable atomic memory operations library";
      homepage = "https://github.com/ivmai/libatomic_ops";
      # The core library is MIT; the separately installed gpl extension is
      # GPL-2.0-only. The package output contains both components.
      license = ["MIT" "GPL-2.0-only"];
    };
  }
