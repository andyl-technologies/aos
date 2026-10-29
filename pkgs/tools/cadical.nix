##! cadical — Conflict-driven clause-learning SAT solver
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
}: let
  # Lean 4 pins this release for `bv_decide`; its LRAT proof output is part
  # of the contract Lean's checker consumes, so move both together.
  version = "2.1.2";
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
    pname = "cadical";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "CaDiCaL reports the formula satisfiable with SAT competition exit status 10.";
        "files" = {
          "satisfiable.cnf" = "p cnf 2 2\n1 2 0\n-1 0\n";
        };
        "input" = "A two-variable DIMACS formula whose only model sets variable 2.";
        "operation" = "Solve the formula and print the model.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/cadical\", \"-q\", \"satisfiable.cnf\"], capture_output=True, text=True)\nassert result.returncode == 10, result\nassert \"s SATISFIABLE\" in result.stdout and \"v -1 2 0\" in result.stdout, result.stdout\nprint(\"cadical operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cadical operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "CaDiCaL rejects the malformed header and returns failure.";
        "files" = {
          "invalid.cnf" = "p dnf 1 1\n1 0\n";
        };
        "input" = "A DIMACS file with an invalid problem line.";
        "operation" = "Parse the malformed formula.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/cadical\", \"-q\", \"invalid.cnf\"], capture_output=True, text=True)\nassert result.returncode not in (0, 10, 20), result\n\nsys.stderr.write(\"cadical rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cadical rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    # CaDiCaL does not publish a library compatibility policy.
    version = "=${version}";
    src = fetchurl {
      urls = ["https://codeload.github.com/arminbiere/cadical/tar.gz/refs/tags/rel-${version}"];
      hash = "sha256-KSwruNcS1tBfzj099juSK4+kXgOXSnn3uuW/aMKE8TE=";
    };

    buildDeps = [gnumake bash];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cadical-rel-${version}
          sed -i '1s|^#!/bin/sh$|#!${bash}/bin/bash|' configure scripts/*.sh

          # The generated build header otherwise records the build time and
          # the builder's kernel and hostname. Keep the release identity only.
          sed -i \
            -e 's|^DATE=.*|DATE="release ${version}"|' \
            -e 's|^OS=.*|OS="linux"|' \
            scripts/make-build-header.sh
        '';
      }
      {
        name = "configure";
        script = ''
          CXX="$CXX" ${bash}/bin/bash ./configure
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL=${bash}/bin/bash
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib" "$out/include" "$out/share/licenses/cadical"
          install -m755 build/cadical build/mobical "$out/bin/"
          install -m644 build/libcadical.a "$out/lib/"
          install -m644 src/cadical.hpp src/ccadical.h src/ipasir.h src/tracer.hpp "$out/include/"
          install -m644 LICENSE "$out/share/licenses/cadical/"
        '';
      }
      {
        name = "check";
        script = ''
          printf 'p cnf 1 2\n1 0\n-1 0\n' > unsat.cnf
          status=0
          "$out/bin/cadical" -q unsat.cnf > unsat.out || status=$?
          test "$status" -eq 20
          grep -qx 's UNSATISFIABLE' unsat.out
        '';
      }
    ];

    meta = {
      description = "CaDiCaL conflict-driven clause-learning SAT solver";
      homepage = "https://github.com/arminbiere/cadical";
      license = "MIT";
      mainProgram = "cadical";
    };
  }
