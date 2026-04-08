# stdenv/toolchains/gcc11/default.nix — GCC 11.5.0 toolchain tier (RHEL 9)
#
# Takes the gcc8 toolchain as `prev` and builds the RHEL 9 era toolchain:
#   Phase 1: GCC 11.5.0 (C/C++, in-tree GMP/MPFR/MPC/ISL for Graphite)
#   Phase 2: binutils 2.35
#   Phase 3: linux-headers 5.14 + glibc 2.34
#   Phase 4: All POSIX tools
#
# GCC 11 requires a C++14-capable host compiler (provided by GCC 8.5.0).
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
      args = builtins.functionArgs fn;
      auto = builtins.intersectAttrs args scope;
    in
    fn (auto // overrides);

  # Phase 1: Raw GCC 11.5.0 built with prev.gcc (8.5.0)
  # Has prev.glibc (2.28) crt*.o in its specs dir — NOT compatible with
  # glibc 2.34 which removed __libc_csu_init/__libc_csu_fini.
  gccRaw = callPackage ./gcc.nix { };

  scope = {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;

    # GCC wrapper: adds -B${glibc}/lib so gcc finds glibc 2.34's crt*.o
    # instead of the old crt*.o from prev.glibc (2.28) in GCC's specs dir.
    gcc = builtins.derivation {
      name = "gcc-11.5.0-wrapped";
      system = buildPlatform.system;
      builder = "${prev.bash}/bin/bash";
      args = [
        "-c"
        ''
          set -eu
          export PATH="${prev.coreutils}/bin"
          mkdir -p $out/bin

          echo '#!${prev.bash}/bin/bash' > $out/bin/gcc
          echo 'exec ${gccRaw}/bin/gcc -B${scope.glibc}/lib -idirafter ${scope.glibc}/include "$@"' >> $out/bin/gcc
          chmod +x $out/bin/gcc

          if [ -f "${gccRaw}/bin/g++" ]; then
            echo '#!${prev.bash}/bin/bash' > $out/bin/g++
            echo 'exec ${gccRaw}/bin/g++ -B${scope.glibc}/lib -idirafter ${scope.glibc}/include "$@"' >> $out/bin/g++
            chmod +x $out/bin/g++
          fi

          [ -f "$out/bin/gcc" ] && [ ! -e "$out/bin/cc" ] && ln -sf gcc $out/bin/cc
          [ -f "$out/bin/g++" ] && [ ! -e "$out/bin/c++" ] && ln -sf g++ $out/bin/c++

          # Symlink all other binaries from raw GCC
          for f in ${gccRaw}/bin/*; do
            bn=$(basename "$f")
            [ ! -e "$out/bin/$bn" ] && ln -s "$f" "$out/bin/$bn"
          done

          # Symlink lib/libexec/include/share and target-specific directories
          for d in lib lib64 libexec include share ${targetPlatform.config}; do
            [ -e "${gccRaw}/$d" ] && ln -s "${gccRaw}/$d" "$out/$d"
          done
        ''
      ];
    };

    # Phase 2: binutils 2.35 built with raw GCC (no glibc 2.34 needed)
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
