# stdenv/toolchains/gcc14/default.nix — GCC 14.3.0 toolchain tier (RHEL 10)
#
# Takes the gcc11 toolchain as `prev` and builds the RHEL 10 era toolchain:
#   Phase 1: GCC 14.3.0 (C/C++, in-tree GMP/MPFR/MPC/ISL, PIE+SSP by default)
#   Phase 2: binutils 2.41
#   Phase 3: linux-headers 6.12 + glibc 2.39
#   Phase 4: All POSIX tools
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  callPackage =
    path: overrides:
    let
      fn = import path;
      auto = builtins.intersectAttrs (builtins.functionArgs fn) scope;
    in
    fn (auto // overrides);

  # Phase 1: stage-1 GCC 14.3.0 built with prev.gcc (11.5.0).
  # Has prev.glibc (2.34) crt*.o in its specs dir; pinned to prev because
  # that is the only glibc that exists at this point. Consumed only by the
  # tier-internal builds (binutils, linuxHeaders, glibc, bzip2) and as the
  # host compiler for the stage-2 rebuild — never exposed downstream.
  gccRaw = callPackage ./gcc.nix { };

  # Phase 4: stage-2 GCC 14.3.0 self-recompiled by gccRaw against THIS
  # tier's glibc-2.39 / binutils-2.41 / linux-headers-6.12. This is what
  # the wrapper (and therefore stdenv.gcc) points at, so the production
  # compiler's closure is free of the pre-tier bootstrap chain.
  gccStage2 = callPackage ./gcc-stage2.nix { gccStage1 = gccRaw; };

  scope = {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # GCC wrapper around stage-2: passes -B${glibc}/lib / -idirafter
    # ${glibc}/include for cc-wrapper-symmetry and for callers that probe
    # `gcc -v`. Stage-2's own specs file already has these baked in, so
    # these flags are belt-and-suspenders.
    gcc = builtins.derivation {
      name = "gcc-14.3.0-wrapped";
      system = buildPlatform.system;
      builder = "${prev.bash}/bin/bash";
      args = [
        "-c"
        ''
          set -eu
          export PATH="${prev.coreutils}/bin"
          mkdir -p $out/bin

          echo '#!/bin/sh' > $out/bin/gcc
          echo 'exec ${gccStage2}/bin/gcc -B${scope.glibc}/lib -idirafter ${scope.glibc}/include "$@"' >> $out/bin/gcc
          chmod +x $out/bin/gcc

          if [ -f "${gccStage2}/bin/g++" ]; then
            echo '#!/bin/sh' > $out/bin/g++
            echo 'exec ${gccStage2}/bin/g++ -B${scope.glibc}/lib -idirafter ${scope.glibc}/include "$@"' >> $out/bin/g++
            chmod +x $out/bin/g++
          fi

          [ -f "$out/bin/gcc" ] && [ ! -e "$out/bin/cc" ] && ln -sf gcc $out/bin/cc
          [ -f "$out/bin/g++" ] && [ ! -e "$out/bin/c++" ] && ln -sf g++ $out/bin/c++

          # Symlink all other binaries from stage-2 GCC
          for f in ${gccStage2}/bin/*; do
            bn=$(basename "$f")
            [ ! -e "$out/bin/$bn" ] && ln -s "$f" "$out/bin/$bn"
          done

          # Symlink lib/libexec/include/share and target-specific directories.
          # `|| true` because ${targetPlatform.config} may not exist in stage2
          # (Phase 2b removed the binutils-symlink subdir) and the trailing
          # `[ -e ] && ln -s` would otherwise trip set -e.
          for d in lib lib64 libexec include share ${targetPlatform.config}; do
            [ -e "${gccStage2}/$d" ] && ln -s "${gccStage2}/$d" "$out/$d" || true
          done
        ''
      ];
    };

    # Phase 2: binutils 2.41 built with raw GCC
    binutils = callPackage ./binutils.nix { gcc = gccRaw; };

    # Phase 3: linux-headers + glibc built with raw GCC + binutils
    linuxHeaders = callPackage ./linux-headers.nix { gcc = gccRaw; };
    glibc = callPackage ./glibc.nix { gcc = gccRaw; };

    # Phase 3.5: Autotools rebuilt with wrapped gcc + binutils + glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man)
    perl = callPackage ./perl.nix { };
    texinfo = callPackage ./texinfo.nix { };
    help2man = callPackage ./help2man.nix { };
    m4 = callPackage ./m4.nix { };
    flex = callPackage ./flex.nix { };
    bison = callPackage ./bison.nix { };
    autoconf = callPackage ./autoconf.nix { };
    automake = callPackage ./automake.nix { };
    gperf = callPackage ./gperf.nix { };
    python3 = prev.python3;

    # Compression tools (needed so tar can decompress .tar.xz/.tar.bz2 in the production stdenv)
    xz = callPackage ./xz.nix { };
    bzip2 = callPackage ./bzip2.nix { gcc = gccRaw; };

    # Build tools
    patchelf = callPackage ./patchelf.nix { };

    # Phase 4: POSIX tools built with wrapped gcc + binutils + glibc
    bash = callPackage ./bash.nix { };
    coreutils = callPackage ./coreutils.nix { };
    gnumake = callPackage ./gnumake.nix { };
    sed = callPackage ./sed.nix { };
    grep = callPackage ./grep.nix { };
    gawk = callPackage ./gawk.nix { };
    findutils = callPackage ./findutils.nix { };
    diffutils = callPackage ./diffutils.nix { };
    tar = callPackage ./tar.nix { };
    gzip = callPackage ./gzip.nix { };
    patch = callPackage ./patch.nix { };
  };
in
{
  inherit (scope)
    gcc
    binutils
    glibc
    linuxHeaders
    m4
    flex
    bison
    perl
    autoconf
    automake
    texinfo
    help2man
    gperf
    python3
    xz
    bzip2
    patchelf
    bash
    coreutils
    gnumake
    sed
    grep
    gawk
    findutils
    diffutils
    tar
    gzip
    patch
    ;
}
