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

  # Compile-only sources that assert the active Fortify level via the
  # preprocessor. The wrapper defines _FORTIFY_SOURCE on the command line, so
  # the #if is evaluated against the effective level.
  fortify2Src = builtins.toFile "fortify2.c" ''
    #include <string.h>
    #if !defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE != 2
    #error "expected _FORTIFY_SOURCE=2"
    #endif
    int main(void) { return 0; }
  '';

  fortifyOffSrc = builtins.toFile "fortify-off.c" ''
    #include <string.h>
    #ifdef _FORTIFY_SOURCE
    #error "expected no _FORTIFY_SOURCE"
    #endif
    int main(void) { return 0; }
  '';

  # Non-literal format string: rejected under -Werror=format-security, accepted
  # when the format token is disabled.
  formatSrc = builtins.toFile "format.c" ''
    #include <stdio.h>
    void emit(const char *s) { printf(s); }
    int main(int argc, char **argv) {
      emit(argv[0]);
      return argc;
    }
  '';

  cxxAssertSrc = builtins.toFile "cxx-assert.cc" ''
    #ifndef _GLIBCXX_ASSERTIONS
    #error "expected _GLIBCXX_ASSERTIONS"
    #endif
    int main() { return 0; }
  '';

  flexSrc = builtins.toFile "flex.c" ''
    struct s {
      int n;
      int data[3];
    };
    int main(void) { return sizeof(struct s) > 0 ? 0 : 1; }
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
    assert_fortify() {
      objdump -d ./probe | grep -q '_chk' || fail "expected a fortified (__*_chk) call"
      echo "ok: Fortify"
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

  # Compile-only probe: compile `src` with the given hardening attrs and
  # assert the compile succeeds (or, when expectSuccess is false, fails).
  mkCompileProbe = {
    name,
    src,
    hardeningEnable ? [],
    hardeningDisable ? [],
    isCxx ? false,
    expectSuccess ? true,
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
            cp ${src} src.${
              if isCxx
              then "cc"
              else "c"
            }
            echo "AOS_HARDENING_ENABLE=[$AOS_HARDENING_ENABLE]"
            if ${
              if isCxx
              then "g++"
              else "gcc"
            } -c src.${
              if isCxx
              then "cc"
              else "c"
            } -o out.o 2>compile.log; then
              status=0
            else
              status=1
            fi
            cat compile.log || true
            ${
              if expectSuccess
              then ''
                [ "$status" -eq 0 ] || { echo "FAIL: expected compile to succeed"; exit 1; }
                echo "ok: compiled"
              ''
              else ''
                [ "$status" -ne 0 ] || { echo "FAIL: expected compile to fail"; exit 1; }
                echo "ok: rejected as expected"
              ''
            }
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
      assert_fortify
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

  # Disabling fortify3 downgrades Fortify to level 2.
  fortify2-fallback = mkCompileProbe {
    name = "fortify2-fallback";
    src = fortify2Src;
    hardeningDisable = ["fortify3"];
  };

  # Disabling fortify removes _FORTIFY_SOURCE entirely.
  fortify-off = mkCompileProbe {
    name = "fortify-off";
    src = fortifyOffSrc;
    hardeningDisable = ["fortify"];
  };

  # A non-literal format string is rejected under default hardening.
  format-negative = mkCompileProbe {
    name = "format-negative";
    src = formatSrc;
    expectSuccess = false;
  };

  # The same source compiles when the format token is disabled.
  format-disabled = mkCompileProbe {
    name = "format-disabled";
    src = formatSrc;
    hardeningDisable = ["format"];
  };

  # C++ sees _GLIBCXX_ASSERTIONS under default hardening.
  cxx-assertions = mkCompileProbe {
    name = "cxx-assertions";
    src = cxxAssertSrc;
    isCxx = true;
  };

  # The compiler accepts -fstrict-flex-arrays=3 under default hardening.
  strict-flex-arrays = mkCompileProbe {
    name = "strict-flex-arrays";
    src = flexSrc;
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
