# Expensive, classification-independent half of drop-one attribution for one
# patch. A shared repository derivation has already computed every 3-way
# full-minus-N branch and recorded conflicts. This derivation reads that
# manifest and builds qemu-system only when its prepared variant dropped clean.
#
# outcome (in $out/outcome): one of
#   conflict      -- N cannot be removed without breaking a later patch's 3-way
#                    application ($out/conflict.env names the conflicting commit
#                    and files).
#   build-failed  -- N drops clean but full-minus-N has a compiler/linker failure
#                    tied to a symbol or path introduced by N
#                    ($out/build.log, $out/patch-specific-build-evidence).
#   built         -- N drops clean and full-minus-N builds
#                    ($out/variant-qemu-system-x86_64).
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  index,
  attrPath ? "drop-one-build",
  expectAbsentSymbols ? [],
  dropOneRepository ?
    import ./_qemu-drop-one-repository.nix {
      inherit pkgs lib qemuPackage;
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
  droppedPatch = builtins.elemAt patchFiles (index - 1);
  configureFlags = lib.escapeShellArgs qemuPackage.passthru.qemuConfigureFlags;
  expectedSymbols = builtins.concatStringsSep " " expectAbsentSymbols;
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
    DROPPED_PATCH_SOURCE = "${../../pkgs/emulation/qemu-patches}/${droppedPatch}";
    DROP_INDEX = toString index;
    DROP_ONE_REPOSITORY = "${dropOneRepository}";
    EXPECT_ABSENT_SYMBOLS = expectedSymbols;

    phases = [
      {
        name = "drop-one-build";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          fail() { echo "FAIL: $*" >&2; exit 1; }
          printf '%s\n' "$DROPPED_PATCH" > "$out/dropped-patch"
          printf '%s\n' "$DROP_INDEX" > "$out/drop-index"

          record_attributable_build_failure() {
            : > "$out/failing-symbols"
            grep -oE "undefined reference to .[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*to .([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            grep -oE "implicit declaration of function '[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            grep -oE "'[A-Za-z_][A-Za-z0-9_]*' undeclared" "$out/build.log" \
              | sed -E "s/'([A-Za-z_][A-Za-z0-9_]*)' undeclared/\1/" >> "$out/failing-symbols" || true
            grep -oE "unknown type name '[A-Za-z_][A-Za-z0-9_]*'" "$out/build.log" \
              | sed -E "s/.*'([A-Za-z_][A-Za-z0-9_]*)'/\1/" >> "$out/failing-symbols" || true
            LC_ALL=C sort -u "$out/failing-symbols" -o "$out/failing-symbols"

            grep -E 'FAILED:|(^|[[:space:]])(fatal )?error:|undefined reference|implicit declaration|undeclared|unknown type name' \
              "$out/build.log" > "$out/build-diagnostics" \
              || fail "Ninja failed without a compiler or linker diagnostic"
            : > "$out/patch-specific-build-evidence"
            for symbol in $EXPECT_ABSENT_SYMBOLS; do
              if grep -Fqx "$symbol" "$out/failing-symbols"; then
                printf 'symbol\t%s\n' "$symbol" >> "$out/patch-specific-build-evidence"
              fi
            done
            gawk '
              /^--- a\// { sub(/^--- a\//, ""); if ($0 != "/dev/null") print }
              /^\+\+\+ b\// { sub(/^\+\+\+ b\//, ""); if ($0 != "/dev/null") print }
            ' "$DROPPED_PATCH_SOURCE" | LC_ALL=C sort -u > "$out/dropped-patch-paths"
            while IFS= read -r touched_path; do
              if grep -Fq "$touched_path" "$out/build-diagnostics"; then
                printf 'path\t%s\n' "$touched_path" >> "$out/patch-specific-build-evidence"
              fi
            done < "$out/dropped-patch-paths"
            test -s "$out/patch-specific-build-evidence" \
              || fail "Ninja failure has no diagnostic tied to $DROPPED_PATCH"
            echo build-failed > "$out/outcome"
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
          expected_supplement_hash=$(cat "$DROP_ONE_REPOSITORY/source-supplement.sha256")
          actual_supplement_hash=$(sha256sum "$DROP_ONE_REPOSITORY/source-supplement.tar" \
            | gawk '{ print $1 }')
          test "$actual_supplement_hash" = "$expected_supplement_hash" \
            || fail "shared QEMU source supplement hash mismatch"
          GIT_INDEX_FILE="$TMPDIR/qemu-variant.index" \
            git --git-dir="$DROP_ONE_REPOSITORY/repo.git" read-tree "$variant_ref"
          GIT_INDEX_FILE="$TMPDIR/qemu-variant.index" \
            git --git-dir="$DROP_ONE_REPOSITORY/repo.git" --work-tree="$src" checkout-index \
              --all --prefix="$src/"
          tar -xf "$DROP_ONE_REPOSITORY/source-supplement.tar" -C "$src"
          tar -df "$DROP_ONE_REPOSITORY/source-supplement.tar" -C "$src" \
            || fail "materialized QEMU supplement differs from the verified archive"
          chmod -R u+w "$src"
          echo true > "$out/source-materialized"
          {
            echo "source_inventory_sha256=$(cat "$DROP_ONE_REPOSITORY/source-inventory.sha256")"
            echo "source_supplement_sha256=$actual_supplement_hash"
            echo "source_reconstruction_inventory_consumed=true"
          } > "$out/source-reconstruction.env"
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
          if ! "$CONFIG_SHELL" ./configure \
            --prefix="$TMPDIR/install" \
            ${configureFlags} \
            --disable-werror \
            > "$out/configure.log" 2>&1; then
            fail "full-minus-$DROP_INDEX QEMU configuration failed"
          fi
          rm -f subprojects/.wraplock

          if ninja -C build qemu-system-x86_64 \
            > "$out/build.log" 2>&1; then
            echo built > "$out/outcome"
            cp build/qemu-system-x86_64 "$out/variant-qemu-system-x86_64"
          else
            record_attributable_build_failure
          fi
        '';
      }
    ];
  }
