# stdenv/bootstrap/stage0-seeds.nix — Bootstrap seeds
#
# The compiler-bootstrap root of trust for AOS.
#
# hex0-seed is the only pre-compiled binary in this compiler-bootstrap ladder.
# Its complete annotated byte source and readable assembly cross-check live in
# seeds/; see seeds/README.md for the contract and audit procedure. The
# 501-byte ELF is intentionally fail-closed rather than byte-golfed.
#
# All other seed tools are COMPILED FROM SOURCE by hex0:
#   kaem       — upstream kaem-minimal, script executor (line-by-line fork/exec)
#   kaemNix    — patched kaem with $buildScriptPath env var support (Nix builder)
#   mkdir      — minimal directory creation (SYS_mkdir)
#   ln         — minimal symlink creation (SYS_symlink)
#
# The seed binary and every source needed to audit or reproduce it are checked
# into the repository under seeds/. No network fetch supplies the seed binary.
#
# The bootstrap targets x86 (32-bit) because MesCC's x86_64 code generator
# is broken (GNU Mes issue #470). Cross-compilation happens after GCC.
#
{buildPlatform, ...}: let
  system = buildPlatform.system;
  buildCpu = buildPlatform.constraints.cpu;
  supportedBuildPlatform =
    buildPlatform.constraints.os
    == "linux"
    && builtins.elem buildCpu [
      "x86_64"
      "i686"
    ];

  # The recursive hash covers the approved bytes and executable marker in one
  # atomic path import. A committed change must update this reviewed value.
  hex0 =
    if !supportedBuildPlatform
    then
      throw ''
        AOS bootstrap: the Linux/i386 hex0 seed cannot execute on ${system}.
        The source-bootstrap ladder through the historical GCC stages is x86-only;
        use an x86_64 or i686 build machine.
      ''
    else
      builtins.path {
        path = ./seeds/hex0;
        name = "aos-hex0-seed";
        sha256 = "sha256-cXs+2H77jIMYt0wXEWyUFCOQVwRCXfHAML1V38xufAE=";
      };

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
    outputHash = "sha256-2dgAEJlSEuKinCpYOv4fgR53qzX/dEvijhF45gyNgew=";
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
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
    outputHash = "sha256-G/O2Jw4TbIra0MmjNUbozHcx6b/Iwq2aW/mZi+DfxkU=";
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
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
    outputHash = "sha256-oXDJn4MzTApLGMGycn0Qa7dNVqba8eJlGq4aNG4SfYo=";
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
  };
in {
  inherit
    hex0
    kaemNix
    mkdir
    ln
    ;

  meta = {
    description = "Auditable AOS hex0 seed and source-compiled bootstrap tools";
    license = [
      "Apache-2.0"
      "GPL-3.0-or-later"
    ];
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
