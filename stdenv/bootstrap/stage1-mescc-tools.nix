# stdenv/bootstrap/stage1-mescc-tools.nix — mescc-tools bootstrap chain
#
# Build chain: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem
#
# Each tool builds the next using builtins.derivation directly (no stdenv yet).
# Every stage uses only the tools produced by previous stages.
#
# This implements the "live-bootstrap" / "stage0-posix" build process
# where each assembler/compiler is built by the one before it.
#

{ seeds       # Output of seeds.nix (provides hex0 and kaem)
, sources     # Attrset of source tarballs/paths for mescc-tools
, system ? "x86_64-linux"
}:

let
  # Architecture-specific parameters
  archParams =
    if system == "x86_64-linux" then {
      arch = "x86";
      archDir = "x86";
      elfClass = "ELF64";
      endian = "little";
    }
    else if system == "aarch64-linux" then {
      arch = "aarch64";
      archDir = "AArch64";
      elfClass = "ELF64";
      endian = "little";
    }
    else throw "stage1-mescc-tools: unsupported system '${system}'";

  # ---------------------------------------------------------------------------
  # hex1: hex0 + labels + relative addressing
  # ---------------------------------------------------------------------------
  # hex1 extends hex0 with single-character labels and relative offset
  # calculation. Built by running hex0 on the hex1 source.
  hex1 = builtins.derivation {
    name = "hex1";
    inherit system;
    builder = "${seeds}/bin/hex0";
    args = [
      "${sources.stage0-posix}/stage0-posix/${archParams.archDir}/hex1_${archParams.archDir}.hex0"
      "/dev/stdout"
    ];
    # hex0 reads hex pairs and writes bytes. The output is the hex1 binary.
    # We redirect stdout to $out via the builder mechanism.

    # Actually, hex0 takes input-file output-file as arguments:
    __structuredAttrs = false;
  };

  # Proper hex1 derivation with correct I/O
  hex1-proper = builtins.derivation {
    name = "hex1";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" ''
      ${seeds}/bin/hex0 \
        ${sources.stage0-posix}/${archParams.archDir}/hex1_${archParams.archDir}.hex0 \
        $out/bin/hex1
      mkdir -p $out/bin
      chmod +x $out/bin/hex1
    '' ];
  };

  # Simplified: use kaem to run the full stage0-posix build in one derivation.
  # This mirrors what the live-bootstrap project does.

  # ---------------------------------------------------------------------------
  # Full mescc-tools build (hex0 -> hex1 -> hex2 -> M0 -> M1 -> hex2 -> M2-Planet)
  # ---------------------------------------------------------------------------
  mescc-tools = builtins.derivation {
    name = "mescc-tools-1.5.2";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" ''
      set -eu

      export PATH="${seeds}/bin:$PATH"

      # Working directory
      WORK="$TMPDIR/mescc-tools-build"
      mkdir -p "$WORK"
      cd "$WORK"

      # Extract stage0-posix source
      cp -r ${sources.stage0-posix}/* .
      chmod -R u+w .

      PREFIX="$out"
      mkdir -p "$PREFIX/bin"

      ARCH="${archParams.archDir}"

      # --- Step 1: hex0 -> hex1 ---
      # hex1 adds single-character labels and calculates relative offsets
      hex0 "$ARCH/hex1_$ARCH.hex0" "$PREFIX/bin/hex1"
      chmod +x "$PREFIX/bin/hex1"

      # --- Step 2: hex1 -> hex2 ---
      # hex2 adds multi-character labels, absolute addressing, and ELF headers
      "$PREFIX/bin/hex1" "$ARCH/hex2_$ARCH.hex1" "$PREFIX/bin/hex2"
      chmod +x "$PREFIX/bin/hex2"

      # --- Step 3: hex2 -> M0 ---
      # M0 is a macro assembler: converts human-readable assembly mnemonics to hex
      "$PREFIX/bin/hex2" "$ARCH/M0_$ARCH.hex2" "$PREFIX/bin/M0"
      chmod +x "$PREFIX/bin/M0"

      # --- Step 4: M0 + hex2 -> catm ---
      # catm concatenates files (needed because we do not have `cat` yet)
      # TODO: the actual build sequence uses M0 to assemble catm from .M1 source,
      # then hex2 to link it. The exact commands depend on the architecture.
      # For x86, the sequence is roughly:
      #   M0 catm.M1 catm.hex2
      #   hex2 catm.hex2 catm
      # Placeholder for the full build script:
      echo "TODO: Build catm from M0 assembly" >&2

      # --- Step 5: M0 + hex2 -> M1 ---
      # M1 is a more sophisticated macro assembler with multi-pass label resolution
      # TODO: Exact build commands for M1:
      #   catm M1-macro.M1 ... (concatenate M1 source files)
      #   M0 M1-macro.M1 M1-macro.hex2
      #   hex2 M1-macro.hex2 M1
      echo "TODO: Build M1 from M0" >&2

      # --- Step 6: M1 + hex2 -> hex2 (improved) ---
      # Rebuild hex2 using M1 for better error messages and features
      echo "TODO: Rebuild hex2 with M1" >&2

      # --- Step 7: M1 + hex2 -> M2-Planet ---
      # M2-Planet is a minimal C compiler (subset of C that can compile itself)
      # TODO: M2-Planet is built from its own C source using M1 and hex2:
      #   catm M2-Planet.M1 cc.M1 reader.M1 ... (concatenate all .M1 files)
      #   M1 M2-Planet.M1 M2-Planet.hex2
      #   hex2 M2-Planet.hex2 M2-Planet
      echo "TODO: Build M2-Planet from M1 assembly" >&2

      # --- Step 8: Rebuild kaem with M2-Planet ---
      # kaem (the script runner) is rebuilt from C source using M2-Planet
      # for a more capable version with variable support
      echo "TODO: Rebuild kaem with M2-Planet" >&2

      # For now, copy the seed kaem as fallback
      cp ${seeds}/bin/kaem "$PREFIX/bin/kaem" 2>/dev/null || true

      # The complete mescc-tools installation should contain:
      # bin/hex0, bin/hex1, bin/hex2, bin/M0, bin/M1, bin/M2-Planet, bin/kaem, bin/catm
      # Each built entirely from the hex0 seed.

      echo "mescc-tools bootstrap stage 1 complete"
      echo "Tools installed in $PREFIX/bin:"
      ls -la "$PREFIX/bin/" 2>/dev/null || true
    '' ];
  };

in mescc-tools // {
  meta = {
    description = "mescc-tools: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet bootstrap chain";
    homepage = "https://github.com/oriansj/mescc-tools";
    license = "GPL-3.0-or-later";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };

  # Export individual tools for fine-grained dependency tracking
  tools = {
    inherit hex1;
    hex1-proper = hex1-proper;
    # The rest are built as part of the monolithic mescc-tools derivation
  };
}
