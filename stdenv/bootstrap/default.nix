# stdenv/bootstrap/default.nix — Complete bootstrap chain
#
# Wires all bootstrap stages together and exports GCC 2.95.3-compiled tools.
# No TCC-compiled binaries leave bootstrap — stage 5 recompiles everything.
#
# Stage 0: hex0 → kaem, mkdir, ln
# Stage 1: hex0 + kaem → posix-tools (M2-Planet, blood-elf, M1, hex2, kaem, etc.)
# Stage 2: posix-tools → GNU Mes 0.27.1 (Scheme + MesCC C compiler)
# Stage 3: MesCC + kaem → TinyCC 0.9.27 (via boot0 → boot1 → boot2 → 0.9.27)
# Stage 4: TCC + bash → ALL TCC-compiled packages (Mes libc, i386, internal)
#   4a: bash-tcc       (kaem-built, LAST KAEM BUILD)
#   4b: sed-tcc, patch-tcc, grep-tcc, diffutils-tcc, gzip-tcc, tar-tcc
#   4c: coreutils-tcc  (needs patch-tcc)
#   4d: findutils-tcc
#   4e: gnumake-tcc    (needs coreutils-tcc)
#   4f: binutils-tcc   (configure+make, needs sed/grep/patch/coreutils/make)
#   4g: gcc-tcc        (configure+make, needs everything + binutils-tcc)
# Stage 5: GCC + bash → ALL GCC-compiled packages (glibc, exported)
#   5a: linux-headers, glibc, gcc (self-hosted), binutils
#   5b: bash, gnumake, sed, grep, patch, coreutils, gawk,
#       findutils, diffutils, tar, gzip
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
  # Stage 4: ALL TCC-compiled packages (Mes libc, i386, internal)
  # These are compiled by TCC against Mes libc (static) with bash as the
  # builder shell. They exist only to build GCC 2.95.3 and are replaced
  # by GCC-compiled versions in stage 5.
  # ══════════════════════════════════════════════════════════════════════

  # 4a: bash (LAST KAEM BUILD — first shell in the chain)
  bash-tcc = import ./stage4-bash-tcc.nix {
    inherit
      tinycc
      posix-tools
      seeds
      buildPlatform
      ;
  };

  # 4b: Individual GNU tools (file-by-file TCC builds, no source mods needed)
  sed-tcc = import ./stage4-sed-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  patch-tcc = import ./stage4-patch-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  grep-tcc = import ./stage4-grep-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  diffutils-tcc = import ./stage4-diffutils-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  gzip-tcc = import ./stage4-gzip-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  tar-tcc = import ./stage4-tar-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  # 4c: coreutils (needs patch-tcc to apply Mes libc compatibility patches)
  coreutils-tcc = import ./stage4-coreutils-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
    patch = patch-tcc;
  };

  # 4d: findutils
  findutils-tcc = import ./stage4-findutils-tcc.nix {
    inherit tinycc posix-tools buildPlatform;
    bash = bash-tcc;
  };

  # 4e: GNU Make (file-by-file build, needs coreutils for cp -r)
  gnumake-tcc = import ./stage4-gnumake-tcc.nix {
    inherit tinycc buildPlatform;
    bash = bash-tcc;
    coreutils = coreutils-tcc;
  };

  # 4e2: GNU awk (file-by-file build, needed by binutils/gcc configure)
  gawk-tcc = import ./stage4-gawk-tcc.nix {
    inherit tinycc buildPlatform;
    bash = bash-tcc;
    coreutils = coreutils-tcc;
  };

  # 4f: binutils (configure+make, needs sed/grep/patch/coreutils/make/awk)
  binutils-tcc = import ./stage4-binutils-tcc.nix {
    inherit tinycc buildPlatform;
    bash = bash-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    coreutils = coreutils-tcc;
    diffutils = diffutils-tcc;
    gnumake = gnumake-tcc;
    gawk = gawk-tcc;
  };

  # 4g: GCC 2.95.3 (configure+make, needs everything + binutils-tcc)
  gcc-tcc = import ./stage4-gcc-tcc.nix {
    inherit tinycc buildPlatform;
    bash = bash-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    coreutils = coreutils-tcc;
    diffutils = diffutils-tcc;
    gnumake = gnumake-tcc;
    gawk = gawk-tcc;
    tar = tar-tcc;
    binutils = binutils-tcc;
  };

  # ══════════════════════════════════════════════════════════════════════
  # Stage 5: ALL GCC-compiled packages (glibc, exported)
  # Everything is recompiled with GCC 2.95.3 to eliminate TCC artifacts.
  # ══════════════════════════════════════════════════════════════════════

  # 5a: Core toolchain (linux-headers, glibc, self-hosted GCC, binutils)

  linuxHeaders = import ./stage5-linux-headers.nix {
    inherit buildPlatform;
    bash = bash-tcc;
    coreutils = coreutils-tcc;
    gnumake = gnumake-tcc;
  };

  glibc = import ./stage5-glibc.nix {
    gcc = gcc-tcc;
    binutils = binutils-tcc;
    inherit linuxHeaders buildPlatform;
    bash = bash-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    coreutils = coreutils-tcc;
    gnumake = gnumake-tcc;
    gawk = gawk-tcc;
    diffutils = diffutils-tcc;
  };

  # GCC 2.95.3 self-hosted (compiled by gcc-tcc, linked against glibc)
  gcc = import ./stage5-gcc.nix {
    gcc = gcc-tcc;
    binutils = binutils-tcc;
    inherit glibc linuxHeaders buildPlatform;
    bash = bash-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    coreutils = coreutils-tcc;
    diffutils = diffutils-tcc;
    gnumake = gnumake-tcc;
    gawk = gawk-tcc;
    tar = tar-tcc;
  };

  # Stage 4 tool set — TCC-compiled, used to build the stage 5a toolchain.
  # These may have TCC codegen bugs; we move away from them ASAP.
  stage4-tools = {
    bash = bash-tcc;
    sed = sed-tcc;
    grep = grep-tcc;
    patch = patch-tcc;
    coreutils = coreutils-tcc;
    diffutils = diffutils-tcc;
    gnumake = gnumake-tcc;
    gawk = gawk-tcc;
    tar = tar-tcc;
    binutils = binutils-tcc;
  };

  # 5a continued: Binutils recompiled with self-hosted GCC
  binutils = import ./stage5-binutils.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage4-tools);

  # Stage 5 tools — stage4 shell tools + stage5 GCC-compiled binutils.
  # All stage5b packages use the trusted binutils (ar, as, ld, etc.).
  stage5-tools = stage4-tools // { binutils = binutils; };

  # 5b: All tools recompiled with GCC 2.95.3 + glibc + binutils

  gawk = import ./stage5-gawk.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  sed = import ./stage5-sed.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  bash = import ./stage5-bash.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  patch = import ./stage5-patch.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  coreutils = import ./stage5-coreutils.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  gnumake = import ./stage5-gnumake.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  grep = import ./stage5-grep.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  findutils = import ./stage5-findutils.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  diffutils = import ./stage5-diffutils.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  tar = import ./stage5-tar.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);

  gzip = import ./stage5-gzip.nix ({
    inherit
      gcc
      glibc
      linuxHeaders
      buildPlatform
      ;
  } // stage5-tools);
in
{
  # ── Public exports (consumed by toolchains/gcc3_4) ──────────────────
  inherit gcc; # GCC 2.95.3 (self-hosted, linked against glibc)
  inherit glibc; # glibc 2.2.5 (GCC-compiled)
  inherit binutils; # binutils 2.20.1a (GCC-compiled)
  inherit bash; # bash 2.05b (GCC-compiled)
  inherit gnumake; # GNU Make 3.79.1 (GCC-compiled)
  inherit sed; # GNU sed 4.0.9 (GCC-compiled)
  inherit grep; # GNU grep 2.4 (GCC-compiled)
  inherit patch; # GNU patch 2.5.9 (GCC-compiled)
  inherit coreutils; # GNU Coreutils 5.0 (GCC-compiled)
  inherit gawk; # GNU awk 3.0.6 (GCC-compiled)
  inherit findutils; # GNU findutils 4.1 (GCC-compiled)
  inherit diffutils; # GNU diffutils 2.7 (GCC-compiled)
  inherit tar; # GNU tar 1.12 (GCC-compiled)
  inherit gzip; # GNU gzip 1.2.4 (GCC-compiled)

  meta = {
    description = "AOS source bootstrap: hex0 → posix-tools → Mes → TCC → GCC 2.95.3";
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = "i686";
    };
  };
}
