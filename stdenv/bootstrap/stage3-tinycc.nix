# stdenv/bootstrap/stage3-tinycc.nix — TinyCC compiled by MesCC
#
# TinyCC (tcc) is a small, fast C compiler that can compile itself.
# In the bootstrap chain, MesCC (from stage 2) compiles TinyCC,
# which then serves as the bridge to building GCC.
#
# TinyCC is the first "real" C compiler in the chain — it supports
# enough of the C standard to compile GCC 4.6.4 (with patches).
#
# The build is done in two passes:
#   1. MesCC compiles TinyCC (tcc-mes) — slow but functional
#   2. tcc-mes recompiles TinyCC (tcc-tcc) — faster, more complete
#

{
  mes, # Output of stage2-mes.nix (provides mes and mescc)
  mescc-tools, # Output of stage1-mescc-tools.nix (provides M1, hex2)
  sources, # Attrset with: tinycc-source
  system ? "x86_64-linux",
}:

let
  version = "0.9.27";

  archParams =
    if system == "x86_64-linux" then
      {
        arch = "x86_64";
        tccArch = "x86_64";
        elfBits = "64";
      }
    else if system == "aarch64-linux" then
      {
        arch = "aarch64";
        tccArch = "arm64";
        elfBits = "64";
      }
    else
      throw "stage3-tinycc: unsupported system '${system}'";

  # ---------------------------------------------------------------------------
  # Pass 1: MesCC compiles TinyCC
  # ---------------------------------------------------------------------------
  tcc-mescc = builtins.derivation {
    name = "tinycc-mescc-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${mes}/bin:${mescc-tools}/bin:$PATH"

              WORK="$TMPDIR/tcc-mescc-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract TinyCC source
              if [ -d "${sources.tinycc}" ]; then
                cp -r ${sources.tinycc}/* .
              else
                tar xf ${sources.tinycc}
                cd tinycc-${version} 2>/dev/null || cd tcc-${version} 2>/dev/null || true
              fi
              chmod -R u+w .

              PREFIX="$out"
              mkdir -p "$PREFIX/bin" "$PREFIX/lib/tcc"

              # --- Build TinyCC with MesCC ---
              #
              # MesCC can compile a subset of C sufficient for TinyCC.
              # The build requires some patches to TinyCC to work within
              # MesCC's C subset limitations.
              #
              # TODO: The exact mescc invocation depends on the Mes version
              # and the TinyCC source layout. The general approach:
              #
              #   mescc -D BOOTSTRAP=1 \
              #         -D TCC_TARGET_X86_64 \
              #         -I . \
              #         -I include \
              #         -o tcc \
              #         tcc.c libtcc.c tccpp.c tccgen.c \
              #         tccelf.c tccasm.c tccrun.c \
              #         x86_64-gen.c x86_64-link.c
              #
              # In practice, the live-bootstrap project patches TinyCC
              # to compile cleanly under MesCC and provides a kaem build script.

              echo "TODO: Compile TinyCC with MesCC" >&2
              echo "This requires:" >&2
              echo "  1. Applying bootstrap patches to TinyCC source" >&2
              echo "  2. Running mescc to compile tcc.c and dependencies" >&2
              echo "  3. Using M1 + hex2 to assemble and link the output" >&2

              # Placeholder binary
              cat > "$PREFIX/bin/tcc" << 'TCC_STUB'
        #!/bin/sh
        echo "TinyCC ${version} (pass 1: compiled by MesCC)"
        echo "This is a placeholder. The real tcc should be compiled by mescc."
        exit 1
        TCC_STUB
              chmod +x "$PREFIX/bin/tcc"

              echo "TinyCC pass 1 (mescc) complete"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Pass 2: TinyCC recompiles itself
  # ---------------------------------------------------------------------------
  tcc-tcc = builtins.derivation {
    name = "tinycc-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${tcc-mescc}/bin:${mescc-tools}/bin:$PATH"

              WORK="$TMPDIR/tcc-tcc-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract TinyCC source
              if [ -d "${sources.tinycc}" ]; then
                cp -r ${sources.tinycc}/* .
              else
                tar xf ${sources.tinycc}
                cd tinycc-${version} 2>/dev/null || cd tcc-${version} 2>/dev/null || true
              fi
              chmod -R u+w .

              PREFIX="$out"
              mkdir -p "$PREFIX/bin" "$PREFIX/lib/tcc" "$PREFIX/include"

              # --- Recompile TinyCC with itself ---
              #
              # The pass-1 tcc (compiled by MesCC) is functional enough to
              # recompile TinyCC from its own source. This pass-2 build
              # produces a faster, more standards-compliant compiler.
              #
              # TODO: Build commands for self-hosted TinyCC:
              #
              #   tcc -D TCC_TARGET_X86_64 \
              #       -D CONFIG_TCC_ELFINTERP=\"/lib/ld-linux-x86-64.so.2\" \
              #       -I . -I include \
              #       -o tcc2 \
              #       tcc.c libtcc.c tccpp.c tccgen.c \
              #       tccelf.c tccasm.c tccrun.c \
              #       x86_64-gen.c x86_64-link.c
              #
              # Then verify the output:
              #   ./tcc2 -v

              echo "TODO: Self-host TinyCC (compile tcc with tcc)" >&2

              # Placeholder
              cat > "$PREFIX/bin/tcc" << 'TCC_STUB'
        #!/bin/sh
        echo "TinyCC ${version} (pass 2: self-hosted)"
        echo "This is a placeholder. Should be tcc compiled by tcc."
        exit 1
        TCC_STUB
              chmod +x "$PREFIX/bin/tcc"

              # Install TinyCC headers (needed by later stages)
              if [ -d include ]; then
                cp -r include/* "$PREFIX/include/"
              fi

              # Install the TinyCC runtime library
              # tcc needs libtcc1.a for things like __divdi3
              # TODO: tcc -c lib/libtcc1.c -o libtcc1.o && ar rcs libtcc1.a libtcc1.o
              echo "TODO: Build libtcc1.a runtime library" >&2

              echo "TinyCC ${version} pass 2 (self-hosted) complete"
      ''
    ];
  };

in
tcc-tcc
// {
  inherit version;

  # Export both passes for debugging/verification
  passes = {
    pass1 = tcc-mescc;
    pass2 = tcc-tcc;
  };

  meta = {
    description = "TinyCC — small C compiler, bootstrapped from MesCC";
    homepage = "https://bellard.org/tcc/";
    license = "LGPL-2.1-or-later";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
