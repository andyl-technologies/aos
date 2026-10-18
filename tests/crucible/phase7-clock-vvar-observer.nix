{pkgs}:
assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
assert pkgs.linux.version == "7.2.3";
  pkgs.mkDerivation {
    pname = "crucible-guest-clock-vvar-observer";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.linux.dev pkgs.patchelf];
    runtimeDeps = [];
    phases = [
      {
        name = "build-observer";
        script = ''
          set -eu
          kernel=${pkgs.linux.dev}/lib/modules/7.2.3/build
          grep -Fxq 'CONFIG_X86_64=y' "$kernel/.config"
          grep -Fxq 'CONFIG_GENERIC_GETTIMEOFDAY=y' "$kernel/.config"
          grep -Fxq 'CONFIG_GENERIC_VDSO_OVERFLOW_PROTECT=y' "$kernel/.config"
          grep -Eq '^#define[[:space:]]+__VDSO_PAGES[[:space:]]+6$' "$kernel/arch/x86/include/asm/vdso/vsyscall.h"
          cp ${./phase7-clock-vvar-layout.h} phase7-clock-vvar-layout.h

          # This object is a build-only layout check, never linked into the guest.
          cc -std=gnu11 -fcf-protection=branch -D__KERNEL__ -include "$kernel/include/linux/kconfig.h" \
            -I "$kernel/include" -I "$kernel/include/generated" \
            -I "$kernel/arch/x86/include" -I "$kernel/arch/x86/include/generated" \
            -I "$kernel/include/uapi" -I "$kernel/include/generated/uapi" \
            -I "$kernel/arch/x86/include/uapi" -I "$kernel/arch/x86/include/generated/uapi" \
            -I . -c ${./phase7-clock-vvar-layout-check.c} -o layout-check.o
          cc -static -O2 -Wall -Wextra -Werror -I . \
            ${./phase7-clock-vvar-observer.c} -o observer
          if patchelf --print-interpreter observer > interpreter 2>/dev/null; then
            echo 'clock VVAR observer unexpectedly has an ELF interpreter' >&2
            exit 1
          fi
          mkdir -p "$out/bin"
          cp observer "$out/bin/clock-vvar-observer"
        '';
      }
    ];
  }
