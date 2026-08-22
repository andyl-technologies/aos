# Expensive, classification-independent half of drop-one attribution for one
# patch. A shared repository derivation has already computed every 3-way
# full-minus-N branch and recorded conflicts. This derivation reads that
# manifest and builds qemu-system only when its prepared variant dropped clean.
#
# outcome (in $out/outcome): one of
#   conflict      -- N cannot be removed without breaking a later patch's 3-way
#                    application ($out/conflict.env names the conflicting commit
#                    and files).
#   build-failed  -- N drops clean but full-minus-N fails to build ($out/build.log,
#                    $out/failing-symbols).
#   built         -- N drops clean and full-minus-N builds
#                    ($out/variant-qemu-system-x86_64).
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  index,
  attrPath ? "drop-one-build",
  dropOneRepository ?
    import ./_qemu-drop-one-repository.nix {
      inherit pkgs lib qemuPackage;
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
  droppedPatch = builtins.elemAt patchFiles (index - 1);
  configureFlags = lib.escapeShellArgs qemuPackage.passthru.qemuConfigureFlags;
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-build-${toString index}";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.glib.dev
      pkgs.glib.tools
      pkgs.gnumake
      pkgs.grep
      pkgs.libslirp
      pkgs.meson
      pkgs.ninja
      pkgs.pixman
      pkgs.pkg-config
      pkgs.python3
      pkgs.sed
      pkgs.setuptools
      pkgs.distlib
      pkgs.findutils
      pkgs.tar
      pkgs.zlib
    ];
    runtimeDeps = [
      pkgs.dtc
      pkgs.glib
      pkgs.libslirp
      pkgs.pixman
      pkgs.zlib
    ];

    DROPPED_PATCH = droppedPatch;
    DROP_INDEX = toString index;
    DROP_ONE_REPOSITORY = "${dropOneRepository}";

    phases = [
      {
        name = "drop-one-build";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          printf '%s\n' "$DROPPED_PATCH" > "$out/dropped-patch"
          printf '%s\n' "$DROP_INDEX" > "$out/drop-index"

          record_build_failure() {
            echo build-failed > "$out/outcome"
            : > "$out/failing-symbols"
            for log_path in "$out/configure.log" "$out/build.log"; do
              if [ ! -f "$log_path" ]; then
                continue
              fi
              grep -oE "undefined reference to .[A-Za-z_][A-Za-z0-9_]*'" "$log_path" \
                | sed -E "s/.*to .([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
              grep -oE "implicit declaration of function '[A-Za-z_][A-Za-z0-9_]*'" "$log_path" \
                | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
              grep -oE "'[A-Za-z_][A-Za-z0-9_]*' undeclared" "$log_path" \
                | sed -E "s/'([A-Za-z_][A-Za-z0-9_]*)' undeclared/\1/" >> "$out/failing-symbols" || true
              grep -oE "unknown type name '[A-Za-z_][A-Za-z0-9_]*'" "$log_path" \
                | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            done
            LC_ALL=C sort -u "$out/failing-symbols" -o "$out/failing-symbols"
            exit 0
          }

          grep -q '^PASS$' "$DROP_ONE_REPOSITORY/result"
          prepared="$DROP_ONE_REPOSITORY/drop-one/$DROP_INDEX"
          test "$(cat "$prepared/dropped-patch")" = "$DROPPED_PATCH"
          prepared_outcome=$(cat "$prepared/outcome")
          if [ -f "$prepared/rebase.log" ]; then
            cp "$prepared/rebase.log" "$out/rebase.log"
          fi
          if [ "$prepared_outcome" = conflict ]; then
            echo conflict > "$out/outcome"
            cp "$prepared/conflict.env" "$out/conflict.env"
            exit 0
          fi
          test "$prepared_outcome" = drop-clean

          variant_ref=$(cat "$prepared/ref")
          expected_head=$(cat "$prepared/head")
          expected_tree=$(cat "$prepared/tree")
          actual_head=$(git --git-dir="$DROP_ONE_REPOSITORY/repo.git" rev-parse "$variant_ref")
          actual_tree=$(git --git-dir="$DROP_ONE_REPOSITORY/repo.git" rev-parse "$variant_ref^{tree}")
          test "$actual_head" = "$expected_head"
          test "$actual_tree" = "$expected_tree"
          {
            echo "prepared_ref=$variant_ref"
            echo "prepared_head=$actual_head"
            echo "prepared_tree=$actual_tree"
          } > "$out/prepared-ref.env"

          src="$TMPDIR/qemu-src"
          mkdir -p "$src"
          git --git-dir="$DROP_ONE_REPOSITORY/repo.git" archive \
            --format=tar --output="$TMPDIR/qemu-variant.tar" "$variant_ref"
          tar -xf "$TMPDIR/qemu-variant.tar" -C "$src"
          cp -R "$DROP_ONE_REPOSITORY/source-supplement/." "$src/"
          chmod -R u+w "$src"
          echo true > "$out/source-materialized"
          cd "$src"

          # Prepare + build full-minus-N (match the shipped build's effective
          # flags: no -Werror; see _drop-one.nix history for why the git tree
          # otherwise auto-promotes upstream GCC-14 warnings to errors).
          mkdir -p include/aos/crucible
          cp ${qemuPackage.passthru.shmemGeneratedHeader} \
            include/aos/crucible/crucible_shmem_abi.h
          find . -type f -name '*.py' -print | while IFS= read -r f; do
            sed -i "1s|#!/usr/bin/env python3|#!${pkgs.python3}/bin/python3|" "$f"
            sed -i "1s|#!/usr/bin/python3|#!${pkgs.python3}/bin/python3|" "$f"
          done
          export PYTHONPATH="${pkgs.meson}/lib/python3/site-packages:${pkgs.distlib}/lib/python3.14/site-packages:${pkgs.setuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          export PYTHONDONTWRITEBYTECODE=1
          "$CONFIG_SHELL" ./configure \
            --prefix="$TMPDIR/install" \
            ${configureFlags} \
            --disable-werror \
            > "$out/configure.log" 2>&1 || record_build_failure
          rm -f subprojects/.wraplock

          if ninja -C build qemu-system-x86_64 \
            > "$out/build.log" 2>&1; then
            echo built > "$out/outcome"
            cp build/qemu-system-x86_64 "$out/variant-qemu-system-x86_64"
          else
            record_build_failure
          fi
        '';
      }
    ];
  }
