# stdenv/toolchain/default.nix — Production toolchain composition
#
# Takes the bootstrap exports (gcc346, glibc225, binutils220, busybox136,
# make44, linuxHeaders414) and builds the GCC version ladder up to the
# production toolchain (GCC 14.3.0, glibc 2.39, binutils 2.41).
#
# Uses a callPackage DAG — no numbered stages. Dependencies are resolved
# naturally through the recursive attrset.
#
# Usage:
#   let
#     bootstrap = import ./stdenv/bootstrap {};
#     toolchain = import ./stdenv/toolchain { inherit bootstrap; };
#   in toolchain.gcc  # → GCC 14.3.0
#
{
  bootstrap,
}:
let
  system = "x86_64-linux";

  # callPackage: import a file and auto-fill its args from `self`
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) self;
  in
    fn (auto // overrides);

  self = {
    inherit system;

    # ── From bootstrap (versioned names) ──────────────────────────────
    inherit (bootstrap) busybox136 make44 gcc346 glibc225 binutils220
      linuxHeaders414;

    # ── GCC version ladder ────────────────────────────────────────────
    # Each depends on the previous GCC, same binutils220 + glibc225
    gcc412 = callPackage ./gcc412.nix {}; # C only (RHEL 5)
    gcc447 = callPackage ./gcc447.nix {}; # first C++ (RHEL 6)
    gcc485 = callPackage ./gcc485.nix {}; # needs C++ to build (RHEL 7)
    gcc85 = callPackage ./gcc85.nix {}; # RHEL 8
    gcc115 = callPackage ./gcc115.nix {}; # RHEL 9

    # ── Modern toolchain rebuild ──────────────────────────────────────
    # Rebuilt with GCC 11.5.0 for the final production compiler
    binutils241 = callPackage ./binutils241.nix {};
    glibc239 = callPackage ./glibc239.nix {};
    gcc143 = callPackage ./gcc143.nix {}; # production GCC

    # ── Production POSIX tools ────────────────────────────────────────
    # Built with gcc143 + glibc239 + binutils241
    bash52 = callPackage ./bash52.nix {};
    coreutils95 = callPackage ./coreutils95.nix {};
    gnumake44 = callPackage ./gnumake44.nix {};
    sed49 = callPackage ./sed49.nix {};
    grep311 = callPackage ./grep311.nix {};
    findutils410 = callPackage ./findutils410.nix {};
    gawk53 = callPackage ./gawk53.nix {};
    diffutils310 = callPackage ./diffutils310.nix {};
    tar135 = callPackage ./tar135.nix {};
    gzip113 = callPackage ./gzip113.nix {};
    patch27 = callPackage ./patch27.nix {};

    # ── Versionless aliases (point to production versions) ────────────
    gcc = self.gcc143;
    glibc = self.glibc239;
    binutils = self.binutils241;
    bash = self.bash52;
    coreutils = self.coreutils95;
    gnumake = self.gnumake44;
    sed = self.sed49;
    grep = self.grep311;
    findutils = self.findutils410;
    gawk = self.gawk53;
    diffutils = self.diffutils310;
    tar = self.tar135;
    gzip = self.gzip113;
    patch = self.patch27;
  };
in
  self
