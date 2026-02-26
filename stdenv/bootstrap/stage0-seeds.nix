# stdenv/bootstrap/stage0-seeds.nix — Bootstrap seeds
#
# The root of trust for the entire AOS bootstrap chain.
#
# hex0-seed (256 bytes) is the ONLY opaque pre-compiled binary. It reads
# hex pairs from an input file and writes raw bytes to an output file —
# the simplest possible "compiler", hand-auditable machine code.
#
# All other seed tools are COMPILED FROM SOURCE by hex0:
#   kaem       — upstream kaem-minimal, script executor (line-by-line fork/exec)
#   kaemNix    — patched kaem with $buildScriptPath env var support (Nix builder)
#   mkdir      — minimal directory creation (SYS_mkdir)
#   ln         — minimal symlink creation (SYS_symlink)
#
# hex0-seed and all .hex0 source files are checked into the repository
# under seeds/. No network fetch for the seed binary.
#
# The bootstrap targets x86 (32-bit) because MesCC's x86_64 code generator
# is broken (GNU Mes issue #470). Cross-compilation happens after GCC.
#
{
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  # The ONLY opaque binary: hex0-seed (256 bytes, committed with git +x)
  # Nix preserves the executable bit when importing files to the store.
  hex0 = ./seeds/hex0;

  # Compile patched kaem-nix from source using hex0
  # Like kaem-minimal but when argc < 2, reads $buildScriptPath from
  # the process environment. This allows it to be used as a Nix builder
  # with passAsFile without needing /bin/sh.
  kaemNix = builtins.derivation {
    name = "kaem-minimal-nix";
    inherit system;
    builder = "${hex0}";
    args = [
      "${./seeds/kaem-nix.hex0}"
      (builtins.placeholder "out")
    ];
  };

  # Compile minimal mkdir from source using hex0
  # Creates a single directory (SYS_mkdir with mode 0755).
  # Needed to set up build directory layout before posix-tools
  # provides a full mkdir.
  mkdir = builtins.derivation {
    name = "mkdir-hex0";
    inherit system;
    builder = "${hex0}";
    args = [
      "${./seeds/mkdir.hex0}"
      (builtins.placeholder "out")
    ];
  };

  # Compile minimal ln (symlink) from source using hex0
  # Creates a symbolic link (SYS_symlink). Needed to symlink source
  # files from the Nix store into the build directory.
  ln = builtins.derivation {
    name = "ln-hex0";
    inherit system;
    builder = "${hex0}";
    args = [
      "${./seeds/ln.hex0}"
      (builtins.placeholder "out")
    ];
  };
in
{
  inherit
    hex0
    kaemNix
    mkdir
    ln
    ;

  meta = {
    description = "Bootstrap seeds: hex0 (256B opaque binary) + tools compiled from hex0 source";
    homepage = "https://github.com/oriansj/bootstrap-seeds";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = "i686"; };
  };
}
