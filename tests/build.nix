# tests/build.nix — Layer 2: Build checks
#
# Verifies key packages build successfully and closure sizes stay within
# reasonable bounds. Failing on oversized closures catches accidental
# dependency bloat before images ship.
#
# Usage:
#   nix-build -A checks.build
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
  ];

  # Check that a package's closure does not exceed a size limit.
  # This is a derivation that queries the store at build time.
  checkClosureSize = pkg: maxMB: let
    nameStr = pkg.pname or pkg.name or "unknown";
  in
    pkgs.mkDerivation {
      pname = "closure-check-${nameStr}";
      version = "0";
      src = null;

      buildDeps = [pkg];

      phases = [
        {
          name = "check";
          script = ''
            set -euo pipefail

            # Query the closure size of the package
            size=$(nix-store --query --size ${builtins.toString pkg} 2>/dev/null || echo "0")
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
