# stdenv/bootstrap/stage1-posix-tools.nix — posix-tools bootstrap chain
#
# Runs the stage0-posix build process to produce the full posix-tools suite.
# hex0 -> hex1 -> hex2 -> M0 -> cc_x86 -> M2-Planet -> blood-elf -> M1 ->
#   hex2 -> kaem + posix-tools-extra utilities.
#
# All tools are built as x86 (32-bit) binaries. Cross-compilation to
# x86_64 and aarch64 happens later after GCC is available.
#
# The build is driven by the stage0-posix kaem scripts (proven by the
# live-bootstrap project). We create writable directories, symlink source
# files from the Nix store, and run the three-phase bootstrap.
#
# Builder: kaemNix (from stage 0). No /bin/sh.
#
# kaemNix is kaem-minimal patched to read $buildScriptPath from the
# environment when argc < 2. This makes it usable as a Nix builder
# with passAsFile, without needing /bin/sh or -c flags.
#
# The build uses a two-phase approach:
#   1. Build phase: kaemNix runs the build script which invokes the
#      stage0-posix kaem scripts using relative paths (CWD = $TMPDIR).
#   2. Install phase: the freshly-built full kaem (which supports ${VAR}
#      expansion) copies outputs to ${out}.
#
# Reference: https://github.com/oriansj/stage0-posix
#
{
  seeds, # Output of stage0-seeds.nix (provides hex0, kaemNix, mkdir, ln)
  buildPlatform,
  ...
}:
let
  inherit (import ../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;
  system = buildPlatform.system;
  # TODO: The old builtins.fetchGit used submodules = true. GitHub tarballs do
  # not include submodules. This needs a tarball that bundles all submodules
  # (e.g. a release tarball or a custom archive). Compute hash on builder.
  src = fetchTarball {
    url = "https://github.com/oriansj/stage0-posix/archive/45d90f5955b6907dc6cdea9ebafce558359edcd3.tar.gz";
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  # ── Install script (run by freshly-built full kaem) ──────────────────
  # This script uses full kaem's ${VAR} expansion to access $out (set by
  # Nix daemon). It copies all built binaries to the output directory.
  #
  # In Nix's '' '' strings: ''${...} escapes Nix interpolation, passing
  # the literal ${...} through to full kaem for build-time expansion.
  installScript = builtins.toFile "install-posix-tools.kaem" ''
    # Install posix-tools binaries to ''${out}
    # ''${out} is expanded by full kaem from the Nix-set environment variable
    ./x86/bin/mkdir ''${out}
    ./x86/bin/mkdir ''${out}/bin

    # Copy binaries from x86/bin/ (phases 9-11 + posix-tools-extra)
    ./x86/bin/cp x86/bin/M1 ''${out}/bin/M1
    ./x86/bin/cp x86/bin/hex2 ''${out}/bin/hex2
    ./x86/bin/cp x86/bin/kaem ''${out}/bin/kaem
    ./x86/bin/cp x86/bin/M2-Planet ''${out}/bin/M2-Planet
    ./x86/bin/cp x86/bin/M2-Mesoplanet ''${out}/bin/M2-Mesoplanet
    ./x86/bin/cp x86/bin/blood-elf ''${out}/bin/blood-elf
    ./x86/bin/cp x86/bin/get_machine ''${out}/bin/get_machine
    ./x86/bin/cp x86/bin/sha256sum ''${out}/bin/sha256sum
    ./x86/bin/cp x86/bin/match ''${out}/bin/match
    ./x86/bin/cp x86/bin/mkdir ''${out}/bin/mkdir
    ./x86/bin/cp x86/bin/untar ''${out}/bin/untar
    ./x86/bin/cp x86/bin/ungz ''${out}/bin/ungz
    ./x86/bin/cp x86/bin/unbz2 ''${out}/bin/unbz2
    ./x86/bin/cp x86/bin/unxz ''${out}/bin/unxz
    ./x86/bin/cp x86/bin/catm ''${out}/bin/catm
    ./x86/bin/cp x86/bin/cp ''${out}/bin/cp
    ./x86/bin/cp x86/bin/chmod ''${out}/bin/chmod
    ./x86/bin/cp x86/bin/rm ''${out}/bin/rm
    ./x86/bin/cp x86/bin/replace ''${out}/bin/replace
    ./x86/bin/cp x86/bin/wrap ''${out}/bin/wrap

    # Make all binaries executable (posix-tools chmod sets 0750)
    ./x86/bin/chmod 750 ''${out}/bin/M1
    ./x86/bin/chmod 750 ''${out}/bin/hex2
    ./x86/bin/chmod 750 ''${out}/bin/kaem
    ./x86/bin/chmod 750 ''${out}/bin/M2-Planet
    ./x86/bin/chmod 750 ''${out}/bin/M2-Mesoplanet
    ./x86/bin/chmod 750 ''${out}/bin/blood-elf
    ./x86/bin/chmod 750 ''${out}/bin/get_machine
    ./x86/bin/chmod 750 ''${out}/bin/sha256sum
    ./x86/bin/chmod 750 ''${out}/bin/match
    ./x86/bin/chmod 750 ''${out}/bin/mkdir
    ./x86/bin/chmod 750 ''${out}/bin/untar
    ./x86/bin/chmod 750 ''${out}/bin/ungz
    ./x86/bin/chmod 750 ''${out}/bin/unbz2
    ./x86/bin/chmod 750 ''${out}/bin/unxz
    ./x86/bin/chmod 750 ''${out}/bin/catm
    ./x86/bin/chmod 750 ''${out}/bin/cp
    ./x86/bin/chmod 750 ''${out}/bin/chmod
    ./x86/bin/chmod 750 ''${out}/bin/rm
    ./x86/bin/chmod 750 ''${out}/bin/replace
    ./x86/bin/chmod 750 ''${out}/bin/wrap

    # Copy early-chain tools from artifact/ that aren't in bin/
    ./x86/bin/cp x86/artifact/hex0 ''${out}/bin/hex0
    ./x86/bin/chmod 750 ''${out}/bin/hex0
    ./x86/bin/cp x86/artifact/hex1 ''${out}/bin/hex1
    ./x86/bin/chmod 750 ''${out}/bin/hex1
    ./x86/bin/cp x86/artifact/kaem-0 ''${out}/bin/kaem-0
    ./x86/bin/chmod 750 ''${out}/bin/kaem-0
    ./x86/bin/cp x86/artifact/hex2-0 ''${out}/bin/hex2-0
    ./x86/bin/chmod 750 ''${out}/bin/hex2-0
    ./x86/bin/cp x86/artifact/M0 ''${out}/bin/M0
    ./x86/bin/chmod 750 ''${out}/bin/M0
    ./x86/bin/cp x86/artifact/cc_x86 ''${out}/bin/cc_x86
    ./x86/bin/chmod 750 ''${out}/bin/cc_x86
    ./x86/bin/cp x86/artifact/catm ''${out}/bin/catm-0
    ./x86/bin/chmod 750 ''${out}/bin/catm-0
  '';

  # The full posix-tools + posix-tools-extra build (x86/32-bit)
  #
  # kaemNix reads $buildScriptPath from the environment (set by Nix's
  # passAsFile mechanism). No /bin/sh, no -c flag hack.
  #
  # Unlike builtins.toFile, derivation string attributes can reference
  # ANY derivation outputs (builtin:fetchurl FODs, fetchGit, etc.).
  posix-tools = builtins.derivation {
    name = "posix-tools";
    inherit system;
    builder = "${seeds.kaemNix}";
    passAsFile = [ "buildScript" ];
    # ── Build script (run by kaemNix) ──────────────────────────────────
    # kaemNix (kaem-minimal) has NO variable expansion — every path must
    # be a literal string, pre-interpolated by Nix at eval time. CWD is
    # $TMPDIR (set by Nix daemon). We use relative paths for build outputs.
    #
    # seeds.mkdir and seeds.ln are hex0-compiled tools from stage 0.
    buildScript = ''
      # ── Set up build directory ──────────────────────────────────────
      # The stage0-posix kaem scripts build in-place, writing to
      # x86/artifact/ and x86/bin/. We create the directory structure
      # and symlink source files from the Nix store.

      # Create writable output directories
      ${seeds.mkdir} x86
      ${seeds.mkdir} x86/artifact
      ${seeds.mkdir} x86/bin

      # Symlink top-level source directories (read-only from store)
      # NOTE: mescc-tools-extra must be a REAL directory (not a symlink)
      # because kaem.run does "cd mescc-tools-extra" and then uses ../x86/bin/
      # relative paths. If it's a symlink, cd follows it into the Nix store
      # and ../ resolves to the wrong parent.
      ${seeds.ln} ${src}/mescc-tools mescc-tools
      ${seeds.ln} ${src}/M2-Planet M2-Planet
      ${seeds.ln} ${src}/M2libc M2libc
      ${seeds.ln} ${src}/M2-Mesoplanet M2-Mesoplanet

      # Create real mescc-tools-extra directory with file symlinks
      ${seeds.mkdir} mescc-tools-extra
      ${seeds.ln} ${src}/mescc-tools-extra/mescc-tools-extra.kaem mescc-tools-extra/mescc-tools-extra.kaem
      ${seeds.ln} ${src}/mescc-tools-extra/sha256sum.c mescc-tools-extra/sha256sum.c
      ${seeds.ln} ${src}/mescc-tools-extra/match.c mescc-tools-extra/match.c
      ${seeds.ln} ${src}/mescc-tools-extra/mkdir.c mescc-tools-extra/mkdir.c
      ${seeds.ln} ${src}/mescc-tools-extra/untar.c mescc-tools-extra/untar.c
      ${seeds.ln} ${src}/mescc-tools-extra/ungz.c mescc-tools-extra/ungz.c
      ${seeds.ln} ${src}/mescc-tools-extra/unbz2.c mescc-tools-extra/unbz2.c
      ${seeds.ln} ${src}/mescc-tools-extra/unxz.c mescc-tools-extra/unxz.c
      ${seeds.ln} ${src}/mescc-tools-extra/catm.c mescc-tools-extra/catm.c
      ${seeds.ln} ${src}/mescc-tools-extra/cp.c mescc-tools-extra/cp.c
      ${seeds.ln} ${src}/mescc-tools-extra/chmod.c mescc-tools-extra/chmod.c
      ${seeds.ln} ${src}/mescc-tools-extra/rm.c mescc-tools-extra/rm.c
      ${seeds.ln} ${src}/mescc-tools-extra/replace.c mescc-tools-extra/replace.c
      ${seeds.ln} ${src}/mescc-tools-extra/wrap.c mescc-tools-extra/wrap.c

      # Symlink x86 source files (kaem scripts, hex sources) — enumerated
      # explicitly since kaemNix (kaem-minimal) has no loops or glob expansion
      ${seeds.ln} ${src}/x86/hex0_x86.hex0 x86/hex0_x86.hex0
      ${seeds.ln} ${src}/x86/hex1_x86.hex0 x86/hex1_x86.hex0
      ${seeds.ln} ${src}/x86/hex2_x86.hex1 x86/hex2_x86.hex1
      ${seeds.ln} ${src}/x86/catm_x86.hex2 x86/catm_x86.hex2
      ${seeds.ln} ${src}/x86/M0_x86.hex2 x86/M0_x86.hex2
      ${seeds.ln} ${src}/x86/cc_x86.M1 x86/cc_x86.M1
      ${seeds.ln} ${src}/x86/x86_defs.M1 x86/x86_defs.M1
      ${seeds.ln} ${src}/x86/libc-core.M1 x86/libc-core.M1
      ${seeds.ln} ${src}/x86/ELF-i386.hex2 x86/ELF-i386.hex2
      ${seeds.ln} ${src}/x86/ELF-i386-debug.hex2 x86/ELF-i386-debug.hex2
      ${seeds.ln} ${src}/x86/kaem-minimal.hex0 x86/kaem-minimal.hex0
      ${seeds.ln} ${src}/x86/mescc-tools-seed-kaem.kaem x86/mescc-tools-seed-kaem.kaem
      ${seeds.ln} ${src}/x86/mescc-tools-mini-kaem.kaem x86/mescc-tools-mini-kaem.kaem
      ${seeds.ln} ${src}/x86/mescc-tools-full-kaem.kaem x86/mescc-tools-full-kaem.kaem
      ${seeds.ln} ${src}/x86/kaem.run x86/kaem.run
      ${seeds.ln} ${src}/x86/Development x86/Development
      ${seeds.ln} ${src}/x86/GAS x86/GAS
      ${seeds.ln} ${src}/x86/LICENSE x86/LICENSE
      ${seeds.ln} ${src}/x86/makefile x86/makefile
      ${seeds.ln} ${src}/x86/README.md x86/README.md

      # Set up bootstrap-seeds location expected by kaem scripts
      ${seeds.mkdir} bootstrap-seeds
      ${seeds.mkdir} bootstrap-seeds/POSIX
      ${seeds.mkdir} bootstrap-seeds/POSIX/x86
      ${seeds.ln} ${seeds.hex0} bootstrap-seeds/POSIX/x86/hex0-seed
      ${seeds.ln} ${seeds.kaemNix} bootstrap-seeds/POSIX/x86/kaem-optional-seed

      # Symlink answers file for sha256sum verification
      ${seeds.ln} ${src}/x86.answers x86.answers

      # Symlink after.kaem (called by kaem.run at the end)
      ${seeds.ln} ${src}/after.kaem after.kaem

      # ── Phase 0: hex0-seed -> hex0, kaem-minimal ──────────────────
      ${seeds.kaemNix} x86/mescc-tools-seed-kaem.kaem

      # ── Phases 1-11: hex1->hex2->M0->catm->cc_x86->M2->blood-elf->M1->hex2->kaem
      ./x86/artifact/kaem-0 x86/mescc-tools-mini-kaem.kaem

      # ── Phases 12+: Rebuild tools + posix-tools-extra utilities ──
      ./x86/bin/kaem --verbose --strict --file x86/kaem.run

      # ── Install phase ──────────────────────────────────────────────
      # Use the freshly-built full kaem to run the install script.
      # Full kaem expands ''${out} from the environment (set by Nix daemon).
      ./x86/bin/kaem --verbose --strict --file ${installScript}
    '';
  };
in
posix-tools
// {
  meta = {
    description = "posix-tools: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet bootstrap chain";
    homepage = "https://github.com/oriansj/stage0-posix";
    license = "GPL-3.0-or-later";
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
