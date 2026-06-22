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

  mkManifestTools = import ../lib/mk-manifest-tools.nix;

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

  manifestToolNames = [
    "perl"
    "texinfo"
    "help2man"
    "m4"
    "flex"
    "bison"
    "autoconf"
    "automake"
    "gperf"
    "python3"
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "gawk"
    "findutils"
    "diffutils"
    "tar"
    "gzip"
    "patch"
  ];

  baseScope = {
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
  };

  manifestTools = mkManifestTools {
    manifest = baseScope.manifest;
    mkTool = baseScope.mkAutotoolsTool;
    names = manifestToolNames;
  };

  scope = baseScope // manifestTools;
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
