##! z3 — Z3 SMT solver with C/C++ API and Python bindings
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "5.3.2";
  src = fetchurl {
    urls = [
      "https://github.com/Z3Prover/z3/archive/refs/tags/z3-${version}.tar.gz"
      "https://codeload.github.com/Z3Prover/z3/tar.gz/refs/tags/z3-${version}"
    ];
    hash = "sha256-35G4eCL1+LZxCvHyQZuph1jNZH3uOo8NBw8Si0cCTb4=";
  };

  # Upstream names the shared object by major.minor and the Python loader
  # searches for that soname first.
  soVersion = builtins.head (builtins.match "([0-9]+[.][0-9]+)[.].*" version);
  sitePackages = "lib/python3.14/site-packages";
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
    pname = "z3";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Z3 reports sat with the unique model, then unsat.";
        "files" = {
          "problem.smt2" = "(set-option :produce-models true)\n(declare-const x Int)\n(declare-const b (_ BitVec 8))\n(push 1)\n(assert (= (* 3 x) 42))\n(assert (= (bvadd b #x01) #x00))\n(check-sat)\n(get-value (x b))\n(pop 1)\n(assert (and (> x 1) (< x 2)))\n(check-sat)\n";
        };
        "input" = "An SMT-LIB script with one satisfiable and one unsatisfiable scope.";
        "operation" = "Solve the script with the packaged z3 executable.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/z3"
              "problem.smt2"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "sat\n((x 14)\n (b #xff))\nunsat\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Z3 reports an SMT-LIB parse error and returns failure.";
        "files" = {
          "broken.smt2" = "(declare-const x Int)\n(assert (= x\n";
        };
        "input" = "An SMT-LIB script with an unterminated assertion.";
        "operation" = "Solve the malformed script with the packaged z3 executable.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nimport sys\nresult = subprocess.run([\"@out@/bin/z3\", \"broken.smt2\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"(error \" in result.stdout\n\nsys.stderr.write(\"z3 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "z3 rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # Z3 does not document a semantic-versioning policy for its C API.
    version = "=${version}";
    inherit src;

    # CMake runs Python to generate API sources and the Python bindings.
    buildDeps = [
      buildPackages.cmake
      buildPackages.ninja
      buildPackages.python3
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd z3-z3-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # The release archive has no Git metadata; disable the version
          # probes so configure cannot consult a host git.
          cmake -S . -B build -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_INSTALL_INCLUDEDIR=include \
            -DCMAKE_BUILD_TYPE=Release \
            -DPython3_EXECUTABLE=${buildPackages.python3}/bin/python3 \
            -DZ3_INCLUDE_GIT_HASH=OFF \
            -DZ3_INCLUDE_GIT_DESCRIBE=OFF \
            -DZ3_BUILD_PYTHON_BINDINGS=ON \
            -DZ3_INSTALL_PYTHON_BINDINGS=ON \
            -DCMAKE_INSTALL_PYTHON_PKG_DIR=${sitePackages} \
            -DZ3_BUILD_TEST_EXECUTABLES=OFF

          # Fail if an upstream default change drops a published component.
          for setting in \
            BUILD_SHARED_LIBS:BOOL=ON \
            Z3_BUILD_EXECUTABLE:BOOL=ON \
            Z3_BUILD_PYTHON_BINDINGS:BOOL=ON \
            Z3_INSTALL_PYTHON_BINDINGS:BOOL=ON; do
            grep -Fxq "$setting" build/CMakeCache.txt || {
              echo "unexpected Z3 configuration: missing $setting" >&2
              exit 1
            }
          done
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build

          # Upstream installs the build tree's libz3 symlink beside the Python
          # modules. Point it at the installed library so the bindings load
          # this package's libz3 rather than a dangling build path.
          site="$out/${sitePackages}"
          for link in "$site"/z3/libz3.so*; do
            test -L "$link" || continue
            ln -sfn "../../../$(basename "$link")" "$link"
          done
          test -e "$site/z3/libz3.so.${soVersion}"
          test -e "$out/lib/libz3.so.${soVersion}"
          test -f "$out/lib/cmake/z3/Z3Config.cmake"

          mkdir -p "$out/share/licenses/z3"
          cp LICENSE.txt "$out/share/licenses/z3/"
        '';
      }
    ];

    checks = {
      self,
      pkgs,
      ...
    }: {
      smt-lib = pkgs.mkDerivation {
        pname = "z3-smt-lib";
        version = "1";
        src = null;
        buildDeps = [self pkgs.python3];
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p "$out"

              # The SMT-LIB fixture checks a unique model and an unsat scope.
              ${self}/bin/z3 ${./_z3-tests/solve.smt2} > "$out/solve.out"
              if ! cmp -s ${./_z3-tests/solve.expected} "$out/solve.out"; then
                echo "z3 output differs from the expected transcript:" >&2
                diff ${./_z3-tests/solve.expected} "$out/solve.out" >&2 || true
                exit 1
              fi

              # Run the bindings in isolated mode so only this package's
              # site-packages directory supplies the z3 module.
              ${pkgs.python3}/bin/python3 -I -c '
              import runpy, sys
              sys.path.insert(0, sys.argv[1])
              runpy.run_path(sys.argv[2], run_name="__main__")
              ' "${self}/${sitePackages}" ${./_z3-tests/bindings.py} \
                > "$out/bindings.out"
              grep -Fq "z3 bindings passed: x=13 y=52 version=${version}" \
                "$out/bindings.out"
            '';
          }
        ];
      };
    };

    meta = {
      description = "Z3 SMT solver with C, C++, and Python APIs";
      homepage = "https://github.com/Z3Prover/z3";
      license = "MIT";
      mainProgram = "z3";
    };
  }
