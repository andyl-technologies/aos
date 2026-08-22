# tests/build/critical-pkgs.nix — Build checks for critical packages
#
# Verifies key packages build successfully and closure sizes stay within
# reasonable bounds. Failing on oversized closures catches accidental
# dependency bloat before images ship.
#
# Usage:
#   nix-build -A checks.build.critical-pkgs
{
  pkgs,
  lib,
}: let
  # Key packages that must build successfully for any AOS image.
  criticalPackages = [
    pkgs.linux
    pkgs.systemd
    pkgs.containerd
    pkgs.kubelet
    pkgs.coreutils
    pkgs.bash
    pkgs.openssl
    pkgs.aos
  ];

  # Check that a package's closure does not exceed a size limit.
  # Nix supplies a deterministic closure graph to the sandbox. Summing that
  # graph measures the transitive NAR payload rather than only the root path.
  checkClosureSize = pkg: maxMB: let
    nameStr = pkg.pname or pkg.name or "unknown";
  in
    pkgs.mkDerivation {
      pname = "closure-check-${nameStr}";
      version = "0";
      src = null;

      outputChecks = {};
      exportReferencesGraph.runtime = [pkg];
      buildDeps = [pkgs.jq];
      dontStrip = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "check";
          script = ''
            set -euo pipefail

            size=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
            maxBytes=$((${builtins.toString maxMB} * 1024 * 1024))

            if [ "$size" -gt "$maxBytes" ]; then
              echo "FAIL: ${nameStr} closure is $size bytes (max: $maxBytes)"
              exit 1
            fi

            echo "PASS: ${nameStr} closure is $size bytes (limit: ${builtins.toString maxMB} MB)"
            mkdir -p $out
            echo "PASS" > $out/result
          '';
        }
      ];
    };

  # Check that a critical executable can be loaded with only its declared
  # runtime closure. Closure-size checks alone cannot detect a scrubbed RPATH.
  checkProgramRuns = {
    name,
    program,
    arguments ? [],
  }:
    pkgs.mkDerivation {
      pname = "runtime-check-${name}";
      version = "0";
      src = null;

      outputChecks = {};
      dontStrip = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "check";
          script = ''
            set -euo pipefail
            ${program} ${builtins.concatStringsSep " " arguments}
            mkdir -p "$out"
            echo "PASS" > "$out/result"
          '';
        }
      ];
    };
in
  pkgs.mkDerivation {
    pname = "aos-build-checks";
    version = "0";
    src = null;

    # Force all critical packages to build by listing them as dependencies.
    buildDeps =
      criticalPackages
      ++ [
        (checkClosureSize pkgs.linux 500)
        (checkClosureSize pkgs.systemd 200)
        (checkClosureSize pkgs.containerd 300)
        (checkClosureSize pkgs.coreutils 100)
        (checkClosureSize pkgs.aos 400)
        (checkProgramRuns {
          name = "qemu-img";
          program = "${pkgs.qemu-img}/bin/qemu-img";
          arguments = ["--version"];
        })
      ];

    phases = [
      {
        name = "check";
        script = ''
          echo "==> AOS Build Checks"
          echo ""
          echo "All critical packages built successfully."
          echo "All closure size checks passed."
          echo ""
          echo "==> All build checks passed."
          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }
    ];
  }
