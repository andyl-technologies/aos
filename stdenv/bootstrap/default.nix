# stdenv/bootstrap/default.nix — Complete bootstrap chain
#
# Wires all bootstrap stages together and exports GCC 2.95.3-compiled tools.
# No TCC-compiled binaries leave bootstrap — stage 8 recompiles everything.
#
# Stage 0: hex0 → kaem, mkdir, ln
# Stage 1: hex0 + kaem → posix-tools (M2-Planet, blood-elf, M1, hex2, kaem, etc.)
# Stage 2: posix-tools → GNU Mes 0.27.1 (Scheme + MesCC C compiler)
# Stage 3: MesCC + kaem → TinyCC 0.9.27 (via boot0 → boot1 → boot2 → 0.9.27)
# Stage 4: TCC + kaem → bash 2.05b (last kaem-based build)
# Stage 5: TCC + bash → make, sed, grep, patch, linux-headers (Mes libc, bash as builder)
# Stage 6: TCC + bash → binutils, GCC 2.95.3 (Mes libc, bash as builder)
# Stage 7: GCC + bash → glibc 2.2.5, self-hosted GCC 2.95.3, binutils (linked against glibc)
# Stage 8: GCC + bash + glibc → full POSIX tool set (all linked against glibc)
#
# All stages target i686-linux (32-bit). Cross-compilation happens in toolchains.
#
{
  buildPlatform,
  ...
}:
let
  # ══════════════════════════════════════════════════════════════════════
  # Stage 0: Seeds (hex0-seed + hex0-compiled tools)
  # ══════════════════════════════════════════════════════════════════════
  seeds = import ./stage0-seeds.nix { inherit buildPlatform; };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 1: Posix-tools (M2-Planet, M1, hex2, blood-elf, full kaem, etc.)
  # ══════════════════════════════════════════════════════════════════════
  posix-tools = import ./stage1-posix-tools.nix { inherit seeds buildPlatform; };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 2: GNU Mes 0.27.1 (Scheme interpreter + MesCC C compiler)
  # ══════════════════════════════════════════════════════════════════════
  mes = import ./stage2-mes.nix { inherit posix-tools seeds buildPlatform; };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 3: TinyCC 0.9.27 (built via MesCC → boot chain)
  # ══════════════════════════════════════════════════════════════════════
  tinycc = import ./stage3-tinycc.nix {
    inherit
      mes
      posix-tools
      seeds
      buildPlatform
      ;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 4: Bash 2.05b (last kaem-based build)
  # This is the last derivation built with kaem as the builder shell.
  # All subsequent stages use bash as the builder.
  # ══════════════════════════════════════════════════════════════════════
  bash-tcc = import ./stage4-bash-tcc.nix {
    inherit
      tinycc
      posix-tools
      seeds
      buildPlatform
      ;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 5: TCC-compiled tools using bash as builder (internal — not exported)
  # These are compiled by TCC against Mes libc (static) with bash as the
  # builder shell. They exist only to build GCC 2.95.3 and are replaced
  # by GCC-compiled versions in stage 8.
  # ══════════════════════════════════════════════════════════════════════
  gnumake-tcc = import ./stage5-gnumake-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  sed-tcc = import ./stage5-sed-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
  };
  grep-tcc = import ./stage5-grep-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
  };
  patch-tcc = import ./stage5-patch-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };
  linuxHeaders = import ./stage5-linux-headers.nix {
    inherit posix-tools buildPlatform;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 6: TCC-compiled binutils + GCC using bash as builder (internal — not exported)
  # These are compiled by TCC against Mes libc (static) with bash as the
  # builder shell. They exist only to build glibc and self-hosted GCC and
  # are replaced by GCC-compiled versions in stage 7.
  # ══════════════════════════════════════════════════════════════════════
  binutils-tcc = import ./stage6-binutils-tcc.nix {
    inherit
      tinycc
      posix-tools
      buildPlatform
      ;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
  };
  gcc-tcc = import ./stage6-gcc-tcc.nix {
    inherit
      tinycc
      posix-tools
      buildPlatform
      ;
    bash = bash-tcc;
    binutils = binutils-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 7: GCC 2.95.3 self hosted compiler using bash as builder (exported)
  # ══════════════════════════════════════════════════════════════════════

  # glibc 2.2.5 (compiled by gcc-tcc, using configure+make like Guix)
  glibc = import ./stage7-glibc.nix {
    gcc = gcc-tcc;
    binutils = binutils-tcc;
    inherit linuxHeaders;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    inherit posix-tools buildPlatform;
  };

  # GCC 2.95.3 self-hosted (compiled by gcc-tcc, linked against glibc)
  gcc = import ./stage7-gcc.nix {
    gcc = gcc-tcc;
    binutils = binutils-tcc;
    inherit glibc linuxHeaders;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    inherit posix-tools buildPlatform;
  };

  # Binutils recompiled with self-hosted GCC (configure+make)
  binutils = import ./stage7-binutils.nix {
    inherit gcc glibc linuxHeaders;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    inherit posix-tools buildPlatform;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 8: GCC 2.95.3-compiled tools using bash as builder (exported)
  # Everything is recompiled with GCC to eliminate TCC artifacts.
  # ══════════════════════════════════════════════════════════════════════

  # Bash 2.05b recompiled with GCC
  bash = import ./stage8-bash.nix {
    inherit
      gcc
      glibc
      binutils
      linuxHeaders
      ;
    bash = bash-tcc;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    inherit posix-tools buildPlatform;
  };

  # GNU Make recompiled with self-hosted GCC
  gnumake = import ./stage8-gnumake.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU sed recompiled with self-hosted GCC
  sed = import ./stage8-sed.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU grep recompiled with self-hosted GCC
  grep = import ./stage8-grep.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU patch recompiled with self-hosted GCC
  patch = import ./stage8-patch.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU Coreutils 5.0 compiled with self-hosted GCC
  coreutils = import ./stage8-coreutils.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU awk 3.0.6 compiled with self-hosted GCC
  gawk = import ./stage8-gawk.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU findutils 4.1 compiled with self-hosted GCC
  findutils = import ./stage8-findutils.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU diffutils 2.7 compiled with self-hosted GCC
  diffutils = import ./stage8-diffutils.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU tar 1.13 compiled with self-hosted GCC
  tar = import ./stage8-tar.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };

  # GNU gzip 1.2.4 compiled with self-hosted GCC
  gzip = import ./stage8-gzip.nix {
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
    bash = bash-tcc;
    posix-tools = posix-tools;
    gnumake = gnumake-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
  };
in
{
  # ── Public exports (consumed by toolchains/gcc3_4) ──────────────────
  inherit gcc; # GCC 2.95.3 (self-hosted, linked against glibc)
  inherit glibc; # glibc 2.2.5 (GCC-compiled)
  inherit binutils; # binutils 2.20.1a (GCC-compiled)
  inherit bash; # bash 2.05b (GCC-compiled)
  inherit gnumake; # GNU Make 3.79.1 (GCC-compiled)
  inherit sed; # GNU sed 3.02 (GCC-compiled)
  inherit grep; # GNU grep 2.4.2 (GCC-compiled)
  inherit patch; # GNU patch 2.5.4 (GCC-compiled)
  inherit coreutils; # GNU Coreutils 5.0 (GCC-compiled)
  inherit gawk; # GNU awk 3.0.6 (GCC-compiled)
  inherit findutils; # GNU findutils 4.1 (GCC-compiled)
  inherit diffutils; # GNU diffutils 2.7 (GCC-compiled)
  inherit tar; # GNU tar 1.13 (GCC-compiled)
  inherit gzip; # GNU gzip 1.2.4 (GCC-compiled)

  meta = {
    description = "AOS source bootstrap: hex0 → posix-tools → Mes → TCC → GCC 2.95.3";
    platforms = [ "i686-linux" ];
  };
}
