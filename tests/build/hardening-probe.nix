# tests/build/hardening-probe.nix — cc-wrapper hardening policy probes
#
# Each probe compiles a purpose-built source with the AOS stdenv and inspects
# the result with AOS binutils (readelf/objdump via the cc-wrapper). The
# probes prove that default hardening is applied, that opt-outs do what they
# claim, and that unknown tokens are rejected at evaluation time.
#
# Usage:
#   nix-build -A checks.build.hardening-probe
{
  pkgs,
  lib,
}: let
  system = pkgs.stdenv.system or pkgs.bash.system or "x86_64-linux";

  # Source with a stack object (forces stack-protector coverage) and a call
  # to a fortifiable libc function (so __*_chk is observable when Fortify is
  # active).
  probeSrc = builtins.toFile "hardening-probe.c" ''
    #include <string.h>
    #include <stdio.h>

    __attribute__((noinline)) void copy(char *dst, const char *src) {
      char buf[64];
      strcpy(buf, src);
      strcpy(dst, buf);
    }

    int main(int argc, char **argv) {
      char out[128];
      copy(out, argc > 1 ? argv[1] : "hello");
      printf("%s\n", out);
      return 0;
    }
  '';

  # Shared assertion helpers used by the compile-and-inspect probes.
  assertHelpers = ''
    fail() {
      echo "FAIL: $1"
      exit 1
    }

    assert_pie() {
      readelf -h ./probe | grep -q 'Type:.*DYN' || fail "expected PIE (ET_DYN)"
      echo "ok: PIE"
    }
    assert_not_pie() {
      readelf -h ./probe | grep -q 'Type:.*EXEC' || fail "expected non-PIE (ET_EXEC)"
      echo "ok: non-PIE"
    }
    assert_relro() {
      readelf -l ./probe | grep -q 'GNU_RELRO' || fail "expected GNU_RELRO segment"
      echo "ok: RELRO"
    }
    assert_bindnow() {
      readelf -d ./probe | grep -Eq 'BIND_NOW|Flags:.*NOW' || fail "expected BIND_NOW"
      echo "ok: BIND_NOW"
    }
    assert_noexecstack() {
      line=$(readelf -l ./probe | grep 'GNU_STACK' || true)
      [ -n "$line" ] || fail "no GNU_STACK segment"
      if echo "$line" | grep -q 'RWE'; then fail "executable stack"; fi
      echo "ok: noexecstack"
    }
    assert_ssp() {
      objdump -d ./probe | grep -q '__stack_chk_fail' || fail "expected stack protector"
      echo "ok: SSP"
    }
    assert_no_ssp() {
      if objdump -d ./probe | grep -q '__stack_chk_fail'; then
        fail "unexpected stack protector"
      fi
      echo "ok: no SSP"
    }
  '';

  # Build a probe: compile probe.c under the given hardening attrs, then run
  # `checkScript` (with the assert_* helpers and ./probe in place).
  mkProbe = {
    name,
    hardeningEnable ? [],
    hardeningDisable ? [],
    extraCflags ? "",
    checkScript,
  }:
    pkgs.mkDerivation {
      pname = "hardening-probe-${name}";
      version = "0";
      src = null;
      inherit hardeningEnable hardeningDisable;
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            cp ${probeSrc} probe.c
            echo "AOS_HARDENING_ENABLE=[$AOS_HARDENING_ENABLE]"
            gcc ${extraCflags} -o probe probe.c

            ${assertHelpers}
            ${checkScript}

            mkdir -p $out
            echo "PASS" > $out/result
          '';
        }
      ];
    };

  # Unknown tokens must be rejected during evaluation, not at build time.
  badTokenThrows =
    !(
      builtins.tryEval (
        pkgs.mkDerivation {
          pname = "hardening-probe-bad-token";
          version = "0";
          src = null;
          hardeningEnable = ["totallybogus"];
          phases = [
            {
              name = "noop";
              script = "true";
            }
          ];
        }
      )
      .drvPath
    )
    .success;
in {
  # Default hardening: dynamic PIE with RELRO, BIND_NOW, non-executable
  # stack, and stack-protector coverage where the source forces it.
  default-c = mkProbe {
    name = "default-c";
    checkScript = ''
      assert_pie
      assert_relro
      assert_bindnow
      assert_noexecstack
      assert_ssp
    '';
  };

  # hardeningDisable = [ "all" ] clears wrapper hardening: the wrapper must
  # actively negate GCC's default PIE and stack protector.
  disable-all = mkProbe {
    name = "disable-all";
    hardeningDisable = ["all"];
    checkScript = ''
      assert_not_pie
      assert_no_ssp
    '';
  };

  # Disabling only pie produces a non-PIE executable; stack protector stays.
  pie-disabled = mkProbe {
    name = "pie-disabled";
    hardeningDisable = ["pie"];
    checkScript = ''
      assert_not_pie
      assert_ssp
    '';
  };

  # Unknown tokens are an evaluation error.
  unknown-token = pkgs.mkDerivation {
    pname = "hardening-probe-unknown-token";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          ${
            if badTokenThrows
            then ''echo "ok: unknown hardening token rejected at eval time"''
            else ''echo "FAIL: unknown hardening token was accepted"; exit 1''
          }
          mkdir -p $out
          echo "PASS" > $out/result
        '';
      }
    ];
  };
}
