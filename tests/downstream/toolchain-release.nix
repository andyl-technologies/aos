##! Release coverage of the downstream toolchain set.
##!
##! Release planning derives the package matrix from each recipe's
##! `platformSupport` and the deferred-platform list, then publishes the
##! complete runtime closure of every planned output to the binary cache.
##! This check fails when a toolchain member would drop out of that matrix on
##! either Linux platform: an unknown or non-public package, a host constraint
##! that excludes the platform, or a deferred platform. Deferring a Linux
##! platform therefore requires a reviewed decision about downstream
##! toolchains as well.
{
  pkgs,
  lib,
  toolchainNames ? import ../../lib/downstream-toolchains.nix,
  releaseSystems ? ["x86_64-linux" "aarch64-linux"],
}: let
  decisions =
    builtins.concatMap (
      system:
        map (name: {
          inherit name system;
          decision =
            if builtins.elem name pkgs.allPackageNames
            then pkgs.platformSupport.releaseDecision system name
            else {
              state = "missing";
              reason = "not in the release package inventory";
            };
        })
        toolchainNames
    )
    releaseSystems;

  excluded = builtins.filter (entry: entry.decision.state != "eligible") decisions;

  report =
    lib.concatMapStrings (
      entry: "  ${entry.name} on ${entry.system}: ${entry.decision.state} (${entry.decision.reason or entry.decision.rule or "no reason"})\n"
    )
    excluded;
in
  pkgs.mkDerivation {
    pname = "aos-downstream-toolchain-release-check";
    version = "0";
    src = null;
    inherit report;
    passAsFile = ["report"];
    phases = [
      {
        name = "check";
        script = ''
          if [ -s "$reportPath" ]; then
            echo "Downstream toolchains missing from the release package matrix:" >&2
            cat "$reportPath" >&2
            exit 1
          fi
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
