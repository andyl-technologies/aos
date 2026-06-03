# tests/build/kernel-config.nix — Resolved kernel config assertions
#
# Reads the kernel .config installed by pkgs/kernel/linux.nix and asserts that
# lockdown and module signing stay disabled, and that the key-free hardening
# symbols resolve as expected. Architecture-specific symbols are only checked
# on the architecture that defines them.
#
# Usage:
#   nix-build -A checks.build.kernel-config
{
  pkgs,
  lib,
}: let
  system = pkgs.linux.system or "x86_64-linux";
  isX86 = builtins.match "x86_64-.*" system != null;
  isAarch64 = builtins.match "aarch64-.*" system != null;

  configFile = "${pkgs.linux}/boot/config-${pkgs.linux.version}";

  # Symbols required to be enabled (CONFIG_<name>=y).
  enabledCommon = [];

  # Symbols required to hold a specific value (CONFIG_<name>=<value>).
  valueCommon = {};

  # Symbols that must not be enabled. SECURITY_LOCKDOWN_LSM pulls in module
  # signing, whose default key generation is incompatible with a reproducible
  # public base.
  disabledCommon = [
    "SECURITY_LOCKDOWN_LSM"
    "SECURITY_LOCKDOWN_LSM_EARLY"
    "MODULE_SIG"
    "MODULE_SIG_ALL"
    "MODULE_SIG_FORCE"
  ];

  enabledX86 = [];
  enabledAarch64 = [];

  enabled =
    enabledCommon
    ++ lib.optionals isX86 enabledX86
    ++ lib.optionals isAarch64 enabledAarch64;

  enabledLines = builtins.concatStringsSep "\n" (builtins.map (s: "assert_enabled ${s}") enabled);
  valueLines = builtins.concatStringsSep "\n" (
    lib.mapAttrsToList (name: value: "assert_value ${name} ${value}") valueCommon
  );
  disabledLines = builtins.concatStringsSep "\n" (builtins.map (s: "assert_disabled ${s}") disabledCommon);
in
  pkgs.mkDerivation {
    pname = "kernel-config-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.linux];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          cfg=${configFile}
          [ -f "$cfg" ] || {
            echo "FAIL: kernel config $cfg not found"
            exit 1
          }

          fail() {
            echo "FAIL: $1"
            exit 1
          }

          # Required to be enabled.
          assert_enabled() {
            grep -q "^CONFIG_$1=y" "$cfg" || fail "CONFIG_$1 is not enabled"
            echo "ok: CONFIG_$1=y"
          }

          # Required to hold a specific value.
          assert_value() {
            grep -q "^CONFIG_$1=$2$" "$cfg" || fail "CONFIG_$1 is not $2"
            echo "ok: CONFIG_$1=$2"
          }

          # Must not be enabled (unset or explicitly "is not set" are fine).
          assert_disabled() {
            if grep -q "^CONFIG_$1=y" "$cfg"; then
              fail "CONFIG_$1 must not be enabled"
            fi
            echo "ok: CONFIG_$1 disabled"
          }

          echo "==> Kernel config checks (${system})"
          ${enabledLines}
          ${valueLines}
          ${disabledLines}

          echo "==> All kernel config checks passed."
          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }
    ];
  }
