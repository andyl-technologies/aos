# stdenv/bootstrap/stage1-mescc-tools.nix — mescc-tools bootstrap chain
#
# Runs the stage0-posix build process using the kaem seed from stage0-seeds.nix.
# This builds the entire hex0 -> hex1 -> hex2 -> M0 -> cc_x86 -> M2-Planet
# -> blood-elf -> M1 -> hex2 -> kaem chain, plus mescc-tools-extra utilities.
#
# All tools are built as x86 (32-bit) binaries. Cross-compilation to
# x86_64 and aarch64 happens later after GCC is available.
#
# The build is driven by the stage0-posix kaem scripts (proven by the
# live-bootstrap project). We copy the source tree, symlink our seeds,
# and run the three-phase bootstrap.
#
# Builder: kaem-seed (618 bytes, from stage 0). No /bin/sh.
#
# kaem-seed is a minimal script executor: it reads lines from a file and
# fork/execs each one. No variable expansion, no conditionals, no loops.
# All store paths are pre-interpolated by Nix at eval time.
#
# The build uses a two-phase approach:
#   1. Build phase: kaem-seed runs the stage0-posix kaem scripts using
#      relative paths (Nix sets CWD to $TMPDIR).
#   2. Install phase: the freshly-built full kaem (which supports ${VAR}
#      expansion) copies outputs to ${out}.
#
# Reference: https://github.com/oriansj/stage0-posix
#
{
  seeds, # Output of stage0-seeds.nix (provides hex0 and kaem paths)
  system ? "x86_64-linux",
}: let
  # Fetch stage0-posix with all submodules (mescc-tools, M2-Planet, M2libc, etc.)
  stage0-posix-src = builtins.fetchGit {
    url = "https://github.com/oriansj/stage0-posix.git";
    ref = "refs/tags/Release_1.9.1";
    rev = "45d90f5955b6907dc6cdea9ebafce558359edcd3";
    submodules = true;
  };

  # ── Hex0 sources for bootstrap utilities ──────────────────────────────
  # The kaem-seed builder provides no coreutils (no mkdir, cp, chmod).
  # We compile tiny i386 ELF binaries from hex0 source to provide the
  # minimum tools needed to set up the build directory structure.
  # hex0 creates output files with mode 0750 (executable).

  # mkdir(argv[1], 0755) — 108 bytes
  # i386 ELF: pop argc, pop argv[0], pop argv[1]=path, syscall mkdir, exit
  # NOTE: hex0-seed requires a comment line before hex data (parsing init quirk)
  mkdirHex = builtins.toFile "mkdir.hex0" ''
    # mkdir(argv[1], 0755) — i386 ELF binary
    7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00
    02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00
    00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00
    00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08
    00 80 04 08 6C 00 00 00 6C 00 00 00 07 00 00 00
    00 10 00 00
    59 59 5B B8 27 00 00 00 B9 ED 01 00 00 CD 80
    31 DB B8 01 00 00 00 CD 80
  '';

  # symlink(argv[1]=target, argv[2]=linkpath) — 104 bytes
  # i386 ELF: pop argc, pop argv[0], pop ebx=target, pop ecx=link, syscall 83, exit
  # NOTE: hex0-seed requires a comment line before hex data (parsing init quirk)
  symlinkHex = builtins.toFile "symlink.hex0" ''
    # symlink(argv[1]=target, argv[2]=linkpath) — i386 ELF binary
    7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00
    02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00
    00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00
    00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08
    00 80 04 08 68 00 00 00 68 00 00 00 07 00 00 00
    00 10 00 00
    59 59 5B 59 B8 53 00 00 00 CD 80
    31 DB B8 01 00 00 00 CD 80
  '';

  # ── Install script (run by freshly-built full kaem) ──────────────────
  # This script uses full kaem's ${VAR} expansion to access $out (set by
  # Nix daemon). It copies all built binaries to the output directory.
  #
  # In Nix's '' '' strings: ''${...} escapes Nix interpolation, passing
  # the literal ${...} through to full kaem for build-time expansion.
  installScript = builtins.toFile "install-mescc-tools.kaem" ''
    # Install mescc-tools binaries to ''${out}
    # ''${out} is expanded by full kaem from the Nix-set environment variable
    x86/bin/mkdir ''${out}
    x86/bin/mkdir ''${out}/bin

    # Copy binaries from x86/bin/ (phases 9-11 + mescc-tools-extra)
    x86/bin/cp x86/bin/M1 ''${out}/bin/M1
    x86/bin/cp x86/bin/hex2 ''${out}/bin/hex2
    x86/bin/cp x86/bin/kaem ''${out}/bin/kaem
    x86/bin/cp x86/bin/M2-Planet ''${out}/bin/M2-Planet
    x86/bin/cp x86/bin/M2-Mesoplanet ''${out}/bin/M2-Mesoplanet
    x86/bin/cp x86/bin/blood-elf ''${out}/bin/blood-elf
    x86/bin/cp x86/bin/get_machine ''${out}/bin/get_machine
    x86/bin/cp x86/bin/sha256sum ''${out}/bin/sha256sum
    x86/bin/cp x86/bin/match ''${out}/bin/match
    x86/bin/cp x86/bin/mkdir ''${out}/bin/mkdir
    x86/bin/cp x86/bin/untar ''${out}/bin/untar
    x86/bin/cp x86/bin/ungz ''${out}/bin/ungz
    x86/bin/cp x86/bin/unbz2 ''${out}/bin/unbz2
    x86/bin/cp x86/bin/unxz ''${out}/bin/unxz
    x86/bin/cp x86/bin/catm ''${out}/bin/catm
    x86/bin/cp x86/bin/cp ''${out}/bin/cp
    x86/bin/cp x86/bin/chmod ''${out}/bin/chmod
    x86/bin/cp x86/bin/rm ''${out}/bin/rm
    x86/bin/cp x86/bin/replace ''${out}/bin/replace
    x86/bin/cp x86/bin/wrap ''${out}/bin/wrap

    # Make all binaries executable (mescc-tools chmod sets 0750)
    x86/bin/chmod ''${out}/bin/M1
    x86/bin/chmod ''${out}/bin/hex2
    x86/bin/chmod ''${out}/bin/kaem
    x86/bin/chmod ''${out}/bin/M2-Planet
    x86/bin/chmod ''${out}/bin/M2-Mesoplanet
    x86/bin/chmod ''${out}/bin/blood-elf
    x86/bin/chmod ''${out}/bin/get_machine
    x86/bin/chmod ''${out}/bin/sha256sum
    x86/bin/chmod ''${out}/bin/match
    x86/bin/chmod ''${out}/bin/mkdir
    x86/bin/chmod ''${out}/bin/untar
    x86/bin/chmod ''${out}/bin/ungz
    x86/bin/chmod ''${out}/bin/unbz2
    x86/bin/chmod ''${out}/bin/unxz
    x86/bin/chmod ''${out}/bin/catm
    x86/bin/chmod ''${out}/bin/cp
    x86/bin/chmod ''${out}/bin/chmod
    x86/bin/chmod ''${out}/bin/rm
    x86/bin/chmod ''${out}/bin/replace
    x86/bin/chmod ''${out}/bin/wrap

    # Copy early-chain tools from artifact/ that aren't in bin/
    x86/bin/cp x86/artifact/hex0 ''${out}/bin/hex0
    x86/bin/chmod ''${out}/bin/hex0
    x86/bin/cp x86/artifact/hex1 ''${out}/bin/hex1
    x86/bin/chmod ''${out}/bin/hex1
    x86/bin/cp x86/artifact/kaem-0 ''${out}/bin/kaem-0
    x86/bin/chmod ''${out}/bin/kaem-0
    x86/bin/cp x86/artifact/hex2-0 ''${out}/bin/hex2-0
    x86/bin/chmod ''${out}/bin/hex2-0
    x86/bin/cp x86/artifact/M0 ''${out}/bin/M0
    x86/bin/chmod ''${out}/bin/M0
    x86/bin/cp x86/artifact/cc_x86 ''${out}/bin/cc_x86
    x86/bin/chmod ''${out}/bin/cc_x86
    x86/bin/cp x86/artifact/catm ''${out}/bin/catm-0
    x86/bin/chmod ''${out}/bin/catm-0
  '';

  # The full mescc-tools + mescc-tools-extra build (x86/32-bit)
  #
  # The build script is passed via passAsFile, which writes the string
  # attribute to a Nix-chosen path ($buildScriptPath). /bin/sh resolves
  # this env var and execs kaem-seed with the actual file path.
  #
  # Unlike builtins.toFile, derivation string attributes can reference
  # ANY derivation outputs (builtin:fetchurl FODs, fetchGit, etc.).
  mescc-tools = builtins.derivation {
    name = "mescc-tools";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${seeds.kaem} "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    # ── Build script (run by kaem-seed) ──────────────────────────────
    # kaem-seed has NO variable expansion — every path must be a literal
    # string, pre-interpolated by Nix at eval time. CWD is $TMPDIR (set
    # by Nix daemon). We use relative paths for build outputs.
    #
    # The x86/ source files from stage0-posix-src that are NOT artifact/
    # or bin/ must be symlinked individually (kaem-seed has no loops).
    buildScript = ''
      # ── Bootstrap minimal tools from hex0 ──────────────────────────
      # Compile mkdir and symlink from hex0 assembly so we can set up
      # the build directory structure.
      ${seeds.hex0} ${mkdirHex} mkdir
      ${seeds.hex0} ${symlinkHex} ln

      # ── Set up build directory ──────────────────────────────────────
      # The stage0-posix kaem scripts build in-place, writing to
      # x86/artifact/ and x86/bin/. We create the directory structure
      # and symlink source files from the Nix store.

      # Create writable output directories
      ./mkdir x86
      ./mkdir x86/artifact
      ./mkdir x86/bin

      # Symlink top-level source directories (read-only from store)
      ./ln ${stage0-posix-src}/mescc-tools mescc-tools
      ./ln ${stage0-posix-src}/mescc-tools-extra mescc-tools-extra
      ./ln ${stage0-posix-src}/M2-Planet M2-Planet
      ./ln ${stage0-posix-src}/M2libc M2libc
      ./ln ${stage0-posix-src}/M2-Mesoplanet M2-Mesoplanet

      # Symlink x86 source files (kaem scripts, hex sources) — enumerated
      # explicitly since kaem-seed has no loops or glob expansion
      ./ln ${stage0-posix-src}/x86/hex0_x86.hex0 x86/hex0_x86.hex0
      ./ln ${stage0-posix-src}/x86/hex1_x86.hex0 x86/hex1_x86.hex0
      ./ln ${stage0-posix-src}/x86/hex2_x86.hex1 x86/hex2_x86.hex1
      ./ln ${stage0-posix-src}/x86/catm_x86.hex2 x86/catm_x86.hex2
      ./ln ${stage0-posix-src}/x86/M0_x86.hex2 x86/M0_x86.hex2
      ./ln ${stage0-posix-src}/x86/cc_x86.M1 x86/cc_x86.M1
      ./ln ${stage0-posix-src}/x86/x86_defs.M1 x86/x86_defs.M1
      ./ln ${stage0-posix-src}/x86/libc-core.M1 x86/libc-core.M1
      ./ln ${stage0-posix-src}/x86/ELF-i386.hex2 x86/ELF-i386.hex2
      ./ln ${stage0-posix-src}/x86/ELF-i386-debug.hex2 x86/ELF-i386-debug.hex2
      ./ln ${stage0-posix-src}/x86/kaem-minimal.hex0 x86/kaem-minimal.hex0
      ./ln ${stage0-posix-src}/x86/mescc-tools-seed-kaem.kaem x86/mescc-tools-seed-kaem.kaem
      ./ln ${stage0-posix-src}/x86/mescc-tools-mini-kaem.kaem x86/mescc-tools-mini-kaem.kaem
      ./ln ${stage0-posix-src}/x86/mescc-tools-full-kaem.kaem x86/mescc-tools-full-kaem.kaem
      ./ln ${stage0-posix-src}/x86/kaem.run x86/kaem.run
      ./ln ${stage0-posix-src}/x86/Development x86/Development
      ./ln ${stage0-posix-src}/x86/GAS x86/GAS
      ./ln ${stage0-posix-src}/x86/LICENSE x86/LICENSE
      ./ln ${stage0-posix-src}/x86/makefile x86/makefile
      ./ln ${stage0-posix-src}/x86/README.md x86/README.md

      # Set up bootstrap-seeds location expected by kaem scripts
      ./mkdir bootstrap-seeds
      ./mkdir bootstrap-seeds/POSIX
      ./mkdir bootstrap-seeds/POSIX/x86
      ./ln ${seeds.hex0} bootstrap-seeds/POSIX/x86/hex0-seed
      ./ln ${seeds.kaem} bootstrap-seeds/POSIX/x86/kaem-optional-seed

      # Symlink answers file for sha256sum verification
      ./ln ${stage0-posix-src}/x86.answers x86.answers

      # Symlink after.kaem (called by kaem.run at the end)
      ./ln ${stage0-posix-src}/after.kaem after.kaem

      # ── Phase 0: hex0-seed -> hex0, kaem-minimal ──────────────────
      ${seeds.kaem} x86/mescc-tools-seed-kaem.kaem

      # ── Phases 1-11: hex1->hex2->M0->catm->cc_x86->M2->blood-elf->M1->hex2->kaem
      ./x86/artifact/kaem-0 x86/mescc-tools-mini-kaem.kaem

      # ── Phases 12+: Rebuild tools + mescc-tools-extra utilities ──
      ./x86/bin/kaem --verbose --strict --file x86/kaem.run

      # ── Install phase ──────────────────────────────────────────────
      # Use the freshly-built full kaem to run the install script.
      # Full kaem expands ''${out} from the environment (set by Nix daemon).
      ./x86/bin/kaem --verbose --strict --file ${installScript}
    '';
  };
in
  mescc-tools
  // {
    meta = {
      description = "mescc-tools: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet bootstrap chain";
      homepage = "https://github.com/oriansj/stage0-posix";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux"];
    };
  }
