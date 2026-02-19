# stdenv/bootstrap/default.nix — Full source bootstrap chain (stages 0-9)
#
# Composes all bootstrap stages into a single evaluation:
#    hex0 (229 byte seed, the ONLY opaque binary)
#     → kaem (compiled from hex0 source)
#       → mescc-tools (hex0 → M2-Planet → kaem)
#       → GNU Mes (MesCC C compiler)
#         → TinyCC 0.9.27 (5-pass from MesCC)
#           → make 3.82, sed 4.0.9, grep 2.4, patch 2.5.9
#             → binutils 2.20.1a (from TCC, Mes libc)
#               → GCC 2.95.3 (from TCC, Mes libc, freestanding)
#                 → Linux 4.14 headers
#                   → glibc 2.2.5
#                     → GCC 3.4.6 (first GCC with real glibc)
#                       → BusyBox 1.36 + GNU Make 4.4
#
# Exports only well-built tools for use by the toolchain.
# All internal bootstrap stages (hex0, kaem, mes, tcc, gcc295, etc.)
# are NOT exported.
#
# Usage:
#   nix-build -E '(import ./stdenv/bootstrap {}).gcc346'
#   nix-build -E '(import ./stdenv/bootstrap {}).busybox136'
#
{
  system ? "x86_64-linux",
}:
let
  # ── Stage 0: Bootstrap seeds ──────────────────────────────────────────
  # hex0 (229 bytes) — the ONLY opaque binary. kaem compiled from source.
  seeds = import ./stage0-seeds.nix {inherit system;};

  # ── Stage 0→1: mescc-tools ────────────────────────────────────────────
  # hex0 → hex1 → hex2 → M0 → M1 → M2-Planet → kaem + mescc-tools-extra
  mescc-tools = import ./stage1-mescc-tools.nix {inherit seeds system;};

  # ── Stage 1: GNU Mes ──────────────────────────────────────────────────
  # MesCC C compiler (Scheme-based), Mes libc
  mes = import ./stage2-mes.nix {inherit mescc-tools system;};

  # ── Stage 2: TinyCC ───────────────────────────────────────────────────
  # MesCC → TCC 0.9.26 → TCC 0.9.27 (with Mes libc)
  tinycc = import ./stage3-tinycc.nix {inherit mes mescc-tools system;};

  # ── Stage 3: POSIX tools from TCC ─────────────────────────────────────
  # Individual tools compiled directly with TCC + Mes libc
  make382 = import ./stage3-make382.nix {inherit tinycc mescc-tools system;};
  sed409 = import ./stage3-sed409.nix {inherit tinycc make382 mescc-tools system;};
  grep24 = import ./stage3-grep24.nix {inherit tinycc mescc-tools system;};
  patch259 = import ./stage3-patch259.nix {inherit tinycc mescc-tools system;};

  # ── Stage 4: binutils 2.20.1a ─────────────────────────────────────────
  # GNU assembler/linker (from TCC, Mes libc)
  binutils220 = import ./stage4-binutils220.nix {
    inherit tinycc mescc-tools make382 sed409 grep24 patch259 system;
  };

  # ── Stage 5: GCC 2.95.3 ───────────────────────────────────────────────
  # First GCC (C only, from TCC, Mes libc, freestanding)
  gcc295 = import ./stage5-gcc295.nix {
    binutils = binutils220;
    inherit tinycc mescc-tools make382 sed409 grep24 patch259 system;
  };

  # ── Stage 6: Linux 4.14 headers ───────────────────────────────────────
  # Sanitized UAPI headers (uses gcc295 to compile unifdef)
  linuxHeaders414 = import ./stage6-linux-headers.nix {
    binutils = binutils220;
    inherit gcc295 mescc-tools make382 sed409 grep24 patch259 system;
  };

  # ── Stage 7: glibc 2.2.5 ──────────────────────────────────────────────
  # First real C library (replaces Mes libc for all subsequent stages)
  glibc225 = import ./stage7-glibc225.nix {
    binutils = binutils220;
    linuxHeaders = linuxHeaders414;
    inherit gcc295 mescc-tools make382 sed409 grep24 patch259 system;
  };

  # ── Stage 8: GCC 3.4.6 ────────────────────────────────────────────────
  # C only, first GCC linked against real glibc
  gcc346 = import ./stage8-gcc346.nix {
    glibc = glibc225;
    binutils = binutils220;
    inherit gcc295 mescc-tools make382 sed409 grep24 patch259 system;
  };

  # ── Stage 9: BusyBox 1.36 + GNU Make 4.4 ──────────────────────────────
  # BusyBox provides sh + coreutils + everything for toolchain builds
  # Make 4.4 provides full-featured make for ./configure && make
  busybox136 = import ./stage9-busybox136.nix {
    inherit gcc346 glibc225 binutils220 mescc-tools make382 sed409 grep24 patch259 system;
  };

  make44 = import ./stage9-make44.nix {
    inherit gcc346 glibc225 binutils220 mescc-tools make382 sed409 grep24 patch259 system;
  };
in
  # ════════════════════ BOOTSTRAP BOUNDARY ════════════════════
  # Only export well-built tools. Everything above this line
  # (hex0, kaem, mes, tcc, gcc295, make382, sed409, grep24, patch259)
  # stays INTERNAL — never leaked to the toolchain.
  {
    inherit busybox136; # shell + coreutils + everything
    inherit make44; # GNU Make 4.4
    inherit gcc346; # GCC 3.4.6 (C only, glibc-linked)
    inherit glibc225; # glibc 2.2.5
    inherit binutils220; # binutils 2.20.1a
    inherit linuxHeaders414; # Linux 4.14 headers
  }
