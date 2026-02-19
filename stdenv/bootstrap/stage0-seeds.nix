# stdenv/bootstrap/stage0-seeds.nix — Bootstrap seeds (hex0 only)
#
# The root of trust for the entire AOS bootstrap chain.
#
# hex0 (229 bytes) is the ONLY opaque pre-compiled binary. It reads hex pairs
# from an input file and writes raw bytes to an output file — the simplest
# possible "compiler", hand-auditable machine code.
#
# kaem is COMPILED FROM SOURCE by hex0. The source is kaem-minimal.hex0 from
# the stage0-posix project — a hex-encoded i386 ELF binary that hex0 converts
# to a real executable. This means everything except the 229-byte hex0 seed
# is built from auditable source code.
#
# kaem is a minimal script executor: reads a file line-by-line and executes
# each line as a command. No variables, no control flow. Together hex0 and
# kaem drive the stage0-posix 3-phase build (stage 1).
#
# The bootstrap targets x86 (32-bit) because MesCC's x86_64 code generator
# is broken (GNU Mes issue #470). This matches Guix's approach: build the
# full early bootstrap as i686, then cross-compile to x86_64/aarch64 after
# a working GCC is available.
#
# Sources:
#   hex0 seed: https://github.com/oriansj/bootstrap-seeds (Release_1.3.0)
#   kaem source: https://github.com/oriansj/stage0-posix-x86 (via stage0-posix Release_1.9.1)
#
{
  system ? "x86_64-linux",
}: let
  version = "Release_1.3.0";

  # The ONLY opaque binary: hex0-seed (229 bytes)
  # Fetched via builtin:fetchurl (runs on the Nix daemon, no builder needed)
  hex0 = builtins.derivation {
    name = "hex0-seed";
    system = "builtin";
    builder = "builtin:fetchurl";
    url = "https://github.com/oriansj/bootstrap-seeds/raw/${version}/POSIX/x86/hex0-seed";
    executable = true;
    outputHash = "sha256-QU3RPGy51W7M2xnfFY1IqruKzusrSLU+L190ztN6JW8=";
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # Fetch kaem-minimal.hex0 source — auditable hex-encoded i386 ELF
  # From the stage0-posix-x86 submodule at stage0-posix Release_1.9.1
  # (commit 3b9c2bb6d4155e4f2e5f642b5e0f59255dfc5934)
  kaemHex0Src = builtins.derivation {
    name = "kaem-minimal-hex0-source";
    system = "builtin";
    builder = "builtin:fetchurl";
    url = "https://raw.githubusercontent.com/oriansj/stage0-posix-x86/3b9c2bb6d4155e4f2e5f642b5e0f59255dfc5934/kaem-minimal.hex0";
    outputHash = "sha256-otQDaxf0KiCB+JIDiz/RL36IZzLI2nV7291fsj4Awa4=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # Compile kaem from source using hex0
  # hex0 reads hex pairs from kaemHex0Src and writes a raw i386 ELF binary to $out.
  # Note: this derivation's output CANNOT be referenced from builtins.toFile
  # (only builtin:fetchurl FODs and other toFile outputs are allowed in toFile content).
  # Stage 1 compiles kaem from source internally using hex0 instead.
  kaem = builtins.derivation {
    name = "kaem";
    inherit system;
    builder = "${hex0}";
    args = ["${kaemHex0Src}" (builtins.placeholder "out")];
  };

  # Fetch the bootstrap-seeds release tarball (needed by stage 1 for
  # hex0 source files used during the mescc-tools build)
  seedsArchive = builtins.derivation {
    name = "bootstrap-seeds-source-${version}";
    system = "builtin";
    builder = "builtin:fetchurl";
    url = "https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/${version}.tar.gz";

    # Fixed-output derivation: content is verified by hash
    outputHash = "sha256-JNRNnC9VT7hwvD4YXRtqYG2cG5TEsgffJe2HxGzLjQM=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";

    preferLocalBuild = true;
  };
in {
  inherit version hex0 kaem;

  # The source archive is still needed for hex0 source files used by stage 1
  src = seedsArchive;

  meta = {
    description = "Bootstrap seeds: hex0 (229B opaque binary) + kaem (compiled from source by hex0)";
    homepage = "https://github.com/oriansj/bootstrap-seeds";
    license = "GPL-3.0-or-later";
    platforms = ["i686-linux"];
  };
}
