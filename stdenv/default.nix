# stdenv/default.nix — AOS standard build environment (self-initializing)
#
# Imports the full bootstrap chain and toolchain ladder internally, then
# wraps the latest tier into a complete stdenv.
#
# The latest toolchain (currently GCC 14.3.0) uses GCC's stock bootstrap for
# the final compiler while the rest of the tier is built once.
#
# Usage:
#   stdenv.mkDerivation { ... }       # build with the latest GCC
#   stdenv.bootstrap.gcc              # GCC 2.95.3 from hex0 chain
#
# Attributes:
#   mkDerivation, mkShell, fetchurl, fetchgit    — builders
#   cc, shell, stdenv, initialPath               — environment
#   gcc, glibc, binutils, bash, coreutils, ...   — raw toolchain components
#   bootstrap                                    — hex0 → GCC 2.95.3 chain
#
{
  buildPlatform,
  hostPlatform ? buildPlatform,
  targetPlatform ? hostPlatform,
  storeDir ? "/nix/store",
}: let
  system = buildPlatform.system;
  lib = import ../lib {
    inherit system;
    bash = tier.bash;
  };

  # ── Bootstrap: hex0 → GCC 2.95.3 + glibc 2.2.5 (i686) ─────────────
  bootstrap = import ./bootstrap {inherit buildPlatform;};

  # ── Toolchain ladder: GCC 3.4 → 4.1 → 4.4 → 4.8 → 8 → 11 → 14 ───
  # Returns the latest tier, whose final GCC is bootstrapped internally.
  tier = import ./toolchains {
    inherit
      bootstrap
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };

  mkTierStdenv = import ./tier-stdenv.nix {
    inherit lib buildPlatform hostPlatform targetPlatform storeDir;
  };

  # ── Wrap a raw toolchain tier into a full stdenv ────────────────────
  mkStdenvFromTier = tc:
    (mkTierStdenv {inherit tc;})
    // {
      # Bootstrap chain (hex0 → GCC 2.95.3) accessible from any stdenv.
      inherit bootstrap;
    };
in
  mkStdenvFromTier tier
