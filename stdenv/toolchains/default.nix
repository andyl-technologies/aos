# stdenv/toolchains/default.nix — GCC version ladder
#
# Chains toolchain tiers from GCC 3.4.6 (RHEL 4) through GCC 14.3.0 (RHEL 10).
# Each tier builds a complete set of tools (compiler + binutils + glibc + POSIX utils).
#
# The bootstrap chain produces i686 binaries (mescc only works on i686).
# Standalone cross tiers handle architecture transitions:
#   gcc3_4_cross — always: i686 → x86_64
#   gcc4_8_cross — aarch64 targets: x86_64 → aarch64 (GCC 4.8+ has backend)
#   gcc8_cross   — riscv64 targets: x86_64 → riscv64 (GCC 7+ has backend)
#
# Chain:
#   gcc3_4 (i686) → gcc3_4_cross (i686→x86_64)
#     → gcc4_1..gcc4_8 (x86_64)
#     → [aarch64: gcc4_8_cross] → gcc8 (x86_64 or aarch64)
#     → [riscv64: gcc8_cross]   → gcc11 (x86_64 or target)
#     → gcc14 (final target)
#
# The latest tier's final GCC uses stock GCC bootstrap internally. To update,
# add the new tier, point `latest` at it, and keep the final compiler
# bootstrapped while the rest of the tier builds once.
#
# Post-cross tiers run via QEMU binfmt_misc on the x86_64 builder.
# The `system` attribute is always buildPlatform.system (x86_64-linux)
# for Nix scheduling.
#
{
  bootstrap,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  lib = import ../../lib/platform.nix;

  # Override system for Nix scheduling while preserving platform identity.
  # Foreign-arch binaries run via QEMU binfmt_misc on the x86_64 builder.
  mkBuildable = platform: platform // {system = buildPlatform.system;};

  bootstrapPlatform = mkBuildable (lib.mkPlatform "i686-linux");

  # ── Cross transition logic ────────────────────────────────────────
  cross0Platform = lib.mkPlatform "x86_64-linux";

  cross1Targets = ["aarch64"]; # GCC 3.4
  needsCross1 = builtins.elem hostPlatform.constraints.cpu cross1Targets;
  cross1Platform =
    if needsCross1
    then mkBuildable hostPlatform
    else cross0Platform;

  cross2Targets = ["riscv64"]; # GCC 8
  needsCross2 = builtins.elem hostPlatform.constraints.cpu cross2Targets;
  cross2Platform =
    if needsCross2
    then mkBuildable hostPlatform
    else cross1Platform;

  # ── gcc3_4: i686 native ───────────────────────────────────────────
  gcc3_4 = import ./gcc3_4 {
    inherit bootstrap;
    buildPlatform = bootstrapPlatform;
    hostPlatform = bootstrapPlatform;
    targetPlatform = bootstrapPlatform;
  };

  # ── gcc3_4_cross: always i686→x86_64 ──────────────────────────────
  gcc3_4_cross = import ./gcc3_4_cross {
    prev = gcc3_4;
    prevPlatform = bootstrapPlatform;
    buildPlatform = bootstrapPlatform;
    hostPlatform = cross0Platform;
    targetPlatform = cross0Platform;
  };

  # ── gcc4_1 through gcc4_8: x86_64 native ──────────────────────────
  gcc4_1 = import ./gcc4_1 {
    prev = gcc3_4_cross;
    buildPlatform = cross0Platform;
    hostPlatform = cross0Platform;
    targetPlatform = cross0Platform;
  };
  gcc4_4 = import ./gcc4_4 {
    prev = gcc4_1;
    buildPlatform = cross0Platform;
    hostPlatform = cross0Platform;
    targetPlatform = cross0Platform;
  };
  gcc4_8 = import ./gcc4_8 {
    prev = gcc4_4;
    buildPlatform = cross0Platform;
    hostPlatform = cross0Platform;
    targetPlatform = cross0Platform;
  };

  # ── gcc4_8_cross: x86_64→aarch64 (when needed) ────────────────────
  gcc4_8_cross = import ./gcc4_8_cross {
    prev = gcc4_8;
    prevPlatform = cross0Platform;
    buildPlatform = cross0Platform;
    inherit hostPlatform targetPlatform;
  };

  # ── gcc8: native on x86_64 or aarch64 ─────────────────────────────
  gcc8 = import ./gcc8 {
    prev =
      if needsCross1
      then gcc4_8_cross
      else gcc4_8;
    buildPlatform = cross1Platform;
    hostPlatform = cross1Platform;
    targetPlatform = cross1Platform;
  };

  # ── gcc8_cross: x86_64→riscv64 (when needed) ──────────────────────
  gcc8_cross = import ./gcc8_cross {
    prev = gcc8;
    prevPlatform = cross1Platform;
    buildPlatform = cross1Platform;
    inherit hostPlatform targetPlatform;
  };

  # ── gcc11: native on final target ─────────────────────────────────
  gcc11 = import ./gcc11 {
    prev =
      if needsCross2
      then gcc8_cross
      else gcc8;
    buildPlatform = cross2Platform;
    hostPlatform = cross2Platform;
    targetPlatform = cross2Platform;
  };

  # ── gcc14: native on final target ─────────────────────────────────
  gcc14 = import ./gcc14 {
    prev = gcc11;
    buildPlatform = mkBuildable hostPlatform;
    hostPlatform = mkBuildable hostPlatform;
    targetPlatform = mkBuildable targetPlatform;
  };
  toolchainTiers = {
    inherit
      gcc3_4
      gcc3_4_cross
      gcc4_1
      gcc4_4
      gcc4_8
      gcc4_8_cross
      gcc8
      gcc8_cross
      gcc11
      gcc14
      ;
  };
  # ── latest: change this when adding a new GCC tier ──────────────
  # Points to the newest tier directory. The final compiler bootstrap happens
  # inside the tier; the rest of the tier is not rebuilt with itself.
in
  gcc14 // {inherit toolchainTiers;}
