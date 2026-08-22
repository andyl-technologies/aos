# Expensive, classification-independent half of drop-one attribution for one
# patch. A shared repository derivation has already computed every 3-way
# full-minus-N branch and recorded conflicts. This derivation reads that
# manifest and builds qemu-system only when its prepared variant dropped clean.
#
# outcome (in $out/outcome): one of
#   conflict      -- N cannot be removed without breaking a later patch's 3-way
#                    application ($out/conflict.env names the conflicting commit
#                    and files).
#   build-failed  -- N drops clean but full-minus-N fails to build. The raw log
#                    is classified fail-closed by the cheap `_drop-one.nix`.
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
          fail() { echo "FAIL: $*" >&2; exit 1; }
          printf '%s\n' "$DROPPED_PATCH" > "$out/dropped-patch"
          printf '%s\n' "$DROP_INDEX" > "$out/drop-index"

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
          tar --no-recursion --null --format=gnu --mtime=@0 --owner=0 --group=0 \
            --numeric-owner -C "$src" \
            --files-from="$DROP_ONE_REPOSITORY/source-supplement.entries0" \
            -cf "$TMPDIR/materialized-source-supplement.tar"
          materialized_supplement_hash=$(sha256sum \
            "$TMPDIR/materialized-source-supplement.tar" | gawk '{ print $1 }')
          test "$materialized_supplement_hash" = "$expected_supplement_hash" \
            || fail "materialized QEMU supplement differs from the verified archive"
          GIT_INDEX_FILE="$TMPDIR/qemu-variant.index" \
            git --git-dir="$DROP_ONE_REPOSITORY/repo.git" --work-tree="$src" \
              update-index --refresh \
            || fail "materialized QEMU tracked source cannot refresh its prepared index"
          GIT_INDEX_FILE="$TMPDIR/qemu-variant.index" \
            git --git-dir="$DROP_ONE_REPOSITORY/repo.git" --work-tree="$src" \
              diff-files --quiet -- \
            || fail "materialized QEMU tracked source differs from its prepared ref"
          base_inventory_hash=$(cat "$DROP_ONE_REPOSITORY/source-inventory.sha256")
          expected_source_identity=$(cat "$prepared/source-identity")
          actual_source_identity=$(printf 'crucible.qemu-materialized-source.v1\n%s\n%s\n%s\n' \
            "$actual_tree" "$actual_supplement_hash" "$base_inventory_hash" \
            | sha256sum | gawk '{ print $1 }')
          test "$actual_source_identity" = "$expected_source_identity" \
            || fail "materialized QEMU source identity mismatch"
          chmod -R u+w "$src"
          echo true > "$out/source-materialized"
          {
            echo "source_inventory_sha256=$base_inventory_hash"
            echo "source_supplement_sha256=$actual_supplement_hash"
            echo "materialized_source_identity=$actual_source_identity"
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
            # Preserve the raw failure for the cheap classifier. Attribution is
            # intentionally outside this expensive derivation so parser and
            # policy hardening never rebuild QEMU.
            echo build-failed > "$out/outcome"
          fi
        '';
      }
    ];
  }
