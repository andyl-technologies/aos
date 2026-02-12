# stdenv/bootstrap/stage2-mes.nix — GNU Mes (Scheme interpreter + MesCC C compiler)
#
# GNU Mes is a Scheme interpreter that includes MesCC, a C compiler written
# in Scheme. MesCC can compile a subset of C sufficient to build TinyCC.
#
# Built by M2-Planet from mescc-tools (stage 1).
#
# Mes serves as the critical bridge between the assembly-level tools (stage 1)
# and a "real" C compiler (TinyCC in stage 3). MesCC compiles a subset of C
# that is carefully chosen to be sufficient for bootstrapping TinyCC.
#
# The Mes Scheme interpreter also provides the first scripting language
# in the bootstrap chain, replacing the limited kaem script runner.
#

{
  mescc-tools, # Output of stage1-mescc-tools.nix
  sources, # Attrset with: mes-source (GNU Mes source tarball/path)
  system ? "x86_64-linux",
}:

let
  version = "0.27";

  archParams =
    if system == "x86_64-linux" then
      {
        arch = "x86_64";
        archFlag = "--with-arch=x86_64";
      }
    else if system == "aarch64-linux" then
      {
        arch = "aarch64";
        archFlag = "--with-arch=aarch64";
      }
    else
      throw "stage2-mes: unsupported system '${system}'";

  mes = builtins.derivation {
    name = "mes-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${mescc-tools}/bin:$PATH"

              WORK="$TMPDIR/mes-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract Mes source
              if [ -d "${sources.mes}" ]; then
                cp -r ${sources.mes}/* .
              else
                tar xf ${sources.mes}
                cd mes-${version}
              fi
              chmod -R u+w .

              PREFIX="$out"
              mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/include" "$PREFIX/share"

              # --- Phase 1: Build mes.c with M2-Planet ---
              #
              # M2-Planet compiles a subset of C. The Mes source includes
              # M2-Planet-compatible C source files that implement the core
              # Scheme interpreter.
              #
              # The build process:
              #   1. Use M2-Planet to compile mes.c -> mes.M1 (assembly)
              #   2. Use M1 to assemble mes.M1 -> mes.hex2
              #   3. Use hex2 to link mes.hex2 -> mes (ELF binary)

              echo "Building GNU Mes ${version} with M2-Planet..."

              # TODO: The exact M2-Planet invocation for mes.c:
              # M2-Planet reads C source and outputs M1 assembly.
              # The Mes source tree includes a build script (kaem.run or
              # GNUmakefile) that specifies the exact file list and flags.
              #
              # Rough sequence:
              #   M2-Planet \
              #     -f lib/mes/globals.c \
              #     -f lib/linux/${archParams.arch}-mes-m2/crt1.c \
              #     -f lib/linux/${archParams.arch}-mes-m2/mini.c \
              #     -f lib/mes/mini-libc.c \
              #     -f src/mes.c \
              #     -o mes.M1
              #
              #   M1 -f mes.M1 \
              #      -f lib/m2/${archParams.arch}/${archParams.arch}_defs.M1 \
              #      -o mes.hex2
              #
              #   hex2 -f lib/m2/${archParams.arch}/ELF-${archParams.arch}-debug.hex2 \
              #        -f mes.hex2 \
              #        -o mes

              echo "TODO: Compile mes.c with M2-Planet (depends on exact Mes source layout)" >&2

              # --- Phase 2: Install mes binary ---
              # The mes binary is a Scheme interpreter that can:
              #   - Read and evaluate Scheme expressions
              #   - Run MesCC (the C compiler written in Scheme)
              #   - Compile C source to x86/aarch64 assembly

              # Placeholder: copy a marker file so downstream stages can detect this
              cat > "$PREFIX/bin/mes" << 'MES_STUB'
        #!/bin/sh
        echo "GNU Mes ${version} (stub — replace with real build)"
        echo "This is a placeholder. The real mes binary should be built"
        echo "by M2-Planet from the Mes source code."
        exit 1
        MES_STUB
              chmod +x "$PREFIX/bin/mes"

              # --- Phase 3: Install MesCC (C compiler in Scheme) ---
              # MesCC is distributed as part of the Mes source tree.
              # It is a collection of Scheme files that implement a C compiler.

              if [ -d module ]; then
                cp -r module "$PREFIX/share/mes-module"
              fi

              if [ -d lib ]; then
                # Install the C library headers and source that MesCC uses
                cp -r lib "$PREFIX/lib/mes"
              fi

              if [ -d include ]; then
                cp -r include "$PREFIX/include/mes"
              fi

              # --- Phase 4: Install mescc driver script ---
              cat > "$PREFIX/bin/mescc" << MESCC_EOF
        #!/bin/sh
        # MesCC driver — invokes mes with the C compiler module
        exec $PREFIX/bin/mes \\
          --no-auto-compile \\
          -e main \\
          -L $PREFIX/share/mes-module \\
          -C $PREFIX/lib/mes \\
          \$PREFIX/share/mes-module/mescc/mescc.scm \\
          -I $PREFIX/include/mes \\
          -L $PREFIX/lib/mes \\
          "\$@"
        MESCC_EOF
              chmod +x "$PREFIX/bin/mescc"

              echo "GNU Mes ${version} installation complete"
              echo "Installed to: $PREFIX"
              ls -la "$PREFIX/bin/"
      ''
    ];
  };

in
mes
// {
  inherit version;
  meta = {
    description = "GNU Mes — Scheme interpreter and MesCC C compiler for bootstrapping";
    homepage = "https://www.gnu.org/software/mes/";
    license = "GPL-3.0-or-later";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
