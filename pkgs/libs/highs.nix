##! HiGHS — Linear, mixed integer, and quadratic optimization.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  zlib,
}: let
  version = "1.13.1";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "highs";
    qualification.packageProbe = lib.qualification.commandProbe (let
      source = ''
        #include <highs/interfaces/highs_c_api.h>
        #include <string.h>

        int main(int argc, char **argv) {
            if (argc != 2) return 2;
            void *solver = Highs_create();
            if (solver == NULL) return 2;
            Highs_setBoolOptionValue(solver, "output_flag", 0);
            if (strcmp(argv[1], "invalid") == 0) {
                HighsInt status = Highs_setIntOptionValue(solver, "threads", -1);
                Highs_destroy(solver);
                return status == kHighsStatusError ? 7 : 2;
            }
            HighsInt added = Highs_addCol(solver, 1.0, 2.0, 10.0, 0, NULL, NULL);
            HighsInt solved = Highs_run(solver);
            int failed = added != kHighsStatusOk || solved != kHighsStatusOk
                || Highs_getModelStatus(solver) != kHighsModelStatusOptimal
                || Highs_getObjectiveValue(solver) != 2.0;
            Highs_destroy(solver);
            return failed;
        }
      '';
      compile = {
        argv = ["@cc@" "probe.c" "-I@out@/include" "-I@out@/include/highs" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lhighs" "-o" "probe"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      };
    in {
      primary = {
        input = "A bounded one-variable linear minimization problem.";
        operation = "Build and optimize the model through the C API.";
        expected = "The solver reports optimality with objective value 2.";
        files."probe.c" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/primary/probe" "solve"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A negative thread count.";
        operation = "Set an invalid execution option through the C API.";
        expected = "The solver rejects the option and the consumer records rejection.";
        files."probe.c" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/bad-input/probe" "invalid"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
    });
    version = "=${version}";

    src = fetchurl {
      urls = [
        "https://github.com/ERGO-Code/HiGHS/archive/refs/tags/v${version}.tar.gz"
        "https://codeload.github.com/ERGO-Code/HiGHS/tar.gz/refs/tags/v${version}"
      ];
      hash = "sha256-1JFEjlhdvwjNiUXKXcu+O3hNc7nGjupOdFYnRhnVYWQ=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd HiGHS-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_PREFIX_PATH="${zlib}" \
            -DZLIB_ROOT="${zlib}" \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_TESTING=ON \
            -DBUILD_EXAMPLES=ON \
            -DZLIB=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/licenses/highs"
          cp LICENSE.txt THIRD_PARTY_NOTICES.md "$out/share/licenses/highs/"
          for notice in extern/amd/License.txt extern/metis/LICENSE.txt \
            extern/pdqsort/license.txt extern/rcm/LICENSE extern/zstr/LICENSE \
            highs/io/filereaderlp/LICENSE; do
            mkdir -p "$out/share/licenses/highs/$(dirname "$notice")"
            cp "$notice" "$out/share/licenses/highs/$notice"
          done
          sed -n '1,/^#pragma once/p' extern/CLI11.hpp \
            > "$out/share/licenses/highs/CLI11-NOTICE"
        '';
      }
    ];

    meta = {
      description = "High performance linear and mixed integer optimization";
      homepage = "https://highs.dev";
      license = "MIT AND BSD-3-Clause AND Zlib";
    };
  }
