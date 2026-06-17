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
}: let
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = prev.bash;
  };

  phases = import ../../phases.nix;

  mkTierStdenv = import ../../tier-stdenv.nix {
    inherit
      lib
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };

  callPackage = path: overrides: let
    fn = import path;
    args = builtins.functionArgs fn;
    auto = builtins.intersectAttrs args scope;
  in
    fn (auto // overrides);

  # Phase 1: Raw GCC 11.5.0 built with prev.gcc (8.5.0)
  # Has prev.glibc (2.28) crt*.o in its specs dir — NOT compatible with
  # glibc 2.34 which removed __libc_csu_init/__libc_csu_fini.
  gccRaw = callPackage ./gcc.nix {};

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
    binutils = callPackage ./binutils.nix {gcc = gccRaw;};

    # Phase 3: linux-headers + glibc built with raw GCC + binutils
    linuxHeaders = callPackage ./linux-headers.nix {gcc = gccRaw;};
    glibc = callPackage ./glibc.nix {gcc = gccRaw;};

    # Shared mini-stdenv for gcc11's POSIX/autotools tools. Use the
    # wrapped gcc11 so tool builds see this tier's glibc-2.34 crt objects.
    # The shell and baseline POSIX PATH stay on gcc8 while gcc11's POSIX
    # tools are being built.
    tierBuildStdenv = mkTierStdenv {
      tc = {
        inherit (scope) gcc binutils glibc;
        inherit
          (prev)
          coreutils
          findutils
          gnumake
          gawk
          grep
          sed
          tar
          gzip
          diffutils
          patch
          bash
          ;
      };
      staticDefault = true;
    };

    mkAutotoolsTool = import ../lib/mk-autotools-tool.nix {
      inherit
        lib
        phases
        buildPlatform
        hostPlatform
        ;
      tierStdenv = scope.tierBuildStdenv;
    };

    manifest = import ./manifest.nix {
      inherit buildPlatform hostPlatform;
      inherit
        (scope)
        m4
        flex
        bison
        perl
        autoconf
        automake
        texinfo
        help2man
        ;
    };

    # Phase 3.5: Autotools rebuilt with wrapped gcc + binutils + glibc
    # Order: perl/texinfo/help2man first (no m4/flex/bison deps),
    # then m4/flex/bison/autoconf/automake (can use real texinfo/help2man).
    perl = scope.mkAutotoolsTool scope.manifest.perl;
    texinfo = scope.mkAutotoolsTool scope.manifest.texinfo;
    help2man = scope.mkAutotoolsTool scope.manifest.help2man;
    m4 = scope.mkAutotoolsTool scope.manifest.m4;
    flex = scope.mkAutotoolsTool scope.manifest.flex;
    bison = scope.mkAutotoolsTool scope.manifest.bison;
    autoconf = scope.mkAutotoolsTool scope.manifest.autoconf;
    automake = scope.mkAutotoolsTool scope.manifest.automake;
    gperf = scope.mkAutotoolsTool scope.manifest.gperf;
    python3 = scope.mkAutotoolsTool scope.manifest.python3;

    # Phase 4: POSIX tools built with wrapped gcc + binutils + glibc
    bash = scope.mkAutotoolsTool scope.manifest.bash;
    coreutils = scope.mkAutotoolsTool scope.manifest.coreutils;
    gnumake = scope.mkAutotoolsTool scope.manifest.gnumake;
    sed = scope.mkAutotoolsTool scope.manifest.sed;
    grep = scope.mkAutotoolsTool scope.manifest.grep;
    gawk = scope.mkAutotoolsTool scope.manifest.gawk;
    findutils = scope.mkAutotoolsTool scope.manifest.findutils;
    diffutils = scope.mkAutotoolsTool scope.manifest.diffutils;
    tar = scope.mkAutotoolsTool scope.manifest.tar;
    gzip = scope.mkAutotoolsTool scope.manifest.gzip;
    patch = scope.mkAutotoolsTool scope.manifest.patch;
  };
in {
  inherit
    (scope)
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
