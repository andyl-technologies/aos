{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.prefixBuilds",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = map (patch: patch.file) series.patches;
  configureFlags = lib.escapeShellArgs qemuPackage.passthru.qemuConfigureFlags;
  prefixMetadata =
    builtins.concatStringsSep "\n"
    (map (patch: let
      patchHash = builtins.hashFile "sha256" (patchDir + "/${patch.file}");
    in "${patch.file}|${patch.branchCommit}|${patch.branchTree}|${patchHash}") series.patches);
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-patch-prefix-builds";
    version = "0";
    src = null;

    inherit prefixMetadata;
    passAsFile = ["prefixMetadata"];

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.glib
      pkgs.gnumake
      pkgs.grep
      pkgs.libslirp
      pkgs.meson
      pkgs.ninja
      pkgs.patch
      pkgs.pixman
      pkgs.pkg-config
      pkgs.python3
      pkgs.sed
      pkgs.setuptools
      pkgs.distlib
      pkgs.tar
      pkgs.xz
      pkgs.zlib
    ];
    runtimeDeps = [
      pkgs.glib
      pkgs.libslirp
      pkgs.pixman
      pkgs.zlib
    ];

    phases = [
      {
        name = "build-every-qemu-patch-prefix";
        script = ''
          set -eu

          source_tree_digest() {
            digest=""
            if ! digest=$("$CONFIG_SHELL" -o pipefail -c '
              tar --sort=name --format=gnu --mtime="@0" \
                --owner=0 --group=0 --numeric-owner \
                --exclude="./.git" --exclude="./build" \
                -cf - . \
                | sha256sum
            '); then
              echo "failed to hash the complete QEMU source tree" >&2
              return 1
            fi
            printf '%s\n' "''${digest%% *}"
          }

          mkdir -p "$out/logs"
          source_dir="$TMPDIR/qemu-prefix-source"
          mkdir -p "$source_dir"
          tar -xf ${qemuPackage.src} -C "$source_dir"
          base_source="$source_dir/qemu-${qemuPackage.version}"
          cd "$base_source"

          git init -q
          git config user.name "${series.deterministicAuthorName}"
          git config user.email "${series.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config core.autocrlf false
          printf '/build/\n/include/aos/crucible/crucible_shmem_abi.h\n' \
            >> .git/info/exclude
          git add -A
          GIT_AUTHOR_NAME="${series.deterministicAuthorName}" \
          GIT_AUTHOR_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_AUTHOR_DATE="${series.deterministicBaseDate}" \
          GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
          GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_COMMITTER_DATE="${series.deterministicBaseDate}" \
            git -c commit.gpgsign=false commit -q -m "qemu-${series.qemuVersion}-base"
          test "$(git rev-parse HEAD)" = "${series.patchBranchBaseCommit}"
          test "$(git rev-parse HEAD^{tree})" = "${series.patchBranchBaseTree}"

          : > "$out/prefix-builds.tsv"
          prefix_index=0
          for prefix_patch in ${builtins.concatStringsSep " " patchFiles}; do
            prefix_index=$((prefix_index + 1))
            prefix_name="''${prefix_patch%.patch}"
            prefix_source="$TMPDIR/prefix-$prefix_index-$prefix_name"
            cp -a "$base_source" "$prefix_source"
            cd "$prefix_source"

            current_index=0
            for patch_name in ${builtins.concatStringsSep " " patchFiles}; do
              current_index=$((current_index + 1))
              metadata=$(grep -F -m1 "$patch_name|" "$prefixMetadataPath")
              IFS='|' read -r metadata_patch branch_commit branch_tree expected_patch_hash <<EOF
          $metadata
          EOF
              test "$metadata_patch" = "$patch_name"

              actual_patch_hash=$(sha256sum "${patchDir}/$patch_name" | gawk '{ print $1 }')
              test "$actual_patch_hash" = "$expected_patch_hash"

              patch --batch --forward --fuzz=0 --no-backup-if-mismatch \
                -p1 -i "${patchDir}/$patch_name"
              git add -A
              GIT_AUTHOR_NAME="${series.deterministicAuthorName}" \
              GIT_AUTHOR_EMAIL="${series.deterministicAuthorEmail}" \
              GIT_AUTHOR_DATE="${series.deterministicPatchDate}" \
              GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
              GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
              GIT_COMMITTER_DATE="${series.deterministicPatchDate}" \
                git -c commit.gpgsign=false commit -q -m "''${patch_name%.patch}"
              actual_branch_commit=$(git rev-parse HEAD)
              actual_branch_tree=$(git rev-parse HEAD^{tree})
              test "$actual_branch_commit" = "$branch_commit"
              test "$actual_branch_tree" = "$branch_tree"

              if [ "$current_index" -eq "$prefix_index" ]; then
                break
              fi
            done
            test "$patch_name" = "$prefix_patch"

            mkdir -p include/aos/crucible
            cp ${qemuPackage.passthru.shmemGeneratedHeader} \
              include/aos/crucible/crucible_shmem_abi.h
            shmem_header_hash=$(sha256sum include/aos/crucible/crucible_shmem_abi.h \
              | gawk '{ print $1 }')
            test "$shmem_header_hash" = "${qemuPackage.passthru.shmemHeaderHash}"
            cmp ${qemuPackage.passthru.shmemGeneratedHeader} \
              include/aos/crucible/crucible_shmem_abi.h
            find . -type f -name '*.py' | while IFS= read -r file; do
              sed -i "1s|#!/usr/bin/env python3|#!${pkgs.python3}/bin/python3|" "$file"
              sed -i "1s|#!/usr/bin/python3|#!${pkgs.python3}/bin/python3|" "$file"
            done
            shebang_list="$TMPDIR/$prefix_name.python-shebang-files.list"
            git diff --name-only HEAD -- > "$shebang_list"
            tracked_diff="$out/logs/$prefix_name.tracked-source.after-prep.diff"
            git diff --binary --no-ext-diff --full-index HEAD -- > "$tracked_diff"
            tracked_diff_hash=$(sha256sum "$tracked_diff" | gawk '{ print $1 }')
            source_tree_hash=$(source_tree_digest)
            source_paths="$out/logs/$prefix_name.source-paths.after-prep"
            find . \
              -path './.git' -prune -o \
              -path './build' -prune -o \
              -print | sort > "$source_paths"

            compiler_version=$(cc -dumpfullversion)
            test "$compiler_version" = "14.3.0"

            export PYTHONPATH="${pkgs.meson}/lib/python3/site-packages:${pkgs.distlib}/lib/python3.14/site-packages:${pkgs.setuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
            export PYTHONDONTWRITEBYTECODE=1
            "$CONFIG_SHELL" ./configure \
              --prefix="$TMPDIR/qemu-prefix-install-$prefix_index" \
              ${configureFlags} \
              --enable-werror \
              "--extra-cflags=-Wno-error=array-bounds -Wno-error=stringop-overflow"

            untracked_after_configure=$(git ls-files --others --exclude-standard)
            test "$untracked_after_configure" = "subprojects/.wraplock"
            rm -f subprojects/.wraplock
            test -z "$(git ls-files --others --exclude-standard)"
            find . \
              -path './.git' -prune -o \
              -path './build' -prune -o \
              -print | sort > "$TMPDIR/$prefix_name.source-paths.after-configure"

            comm -23 "$source_paths" \
              "$TMPDIR/$prefix_name.source-paths.after-configure" \
              > "$TMPDIR/$prefix_name.source-paths.removed-by-configure"
            test ! -s "$TMPDIR/$prefix_name.source-paths.removed-by-configure"
            comm -13 "$source_paths" \
              "$TMPDIR/$prefix_name.source-paths.after-configure" \
              > "$TMPDIR/$prefix_name.source-paths.generated-by-configure"
            cat > "$TMPDIR/$prefix_name.source-paths.expected-generated" <<'GENERATED_PATHS'
          ./GNUmakefile
          ./tests/qemu-iotests/scratch
          GENERATED_PATHS
            if ! cmp "$TMPDIR/$prefix_name.source-paths.expected-generated" \
              "$TMPDIR/$prefix_name.source-paths.generated-by-configure"; then
              echo "unexpected source paths generated while configuring $prefix_name" >&2
              diff -u "$TMPDIR/$prefix_name.source-paths.expected-generated" \
                "$TMPDIR/$prefix_name.source-paths.generated-by-configure" >&2 || true
              exit 1
            fi
            rm -f GNUmakefile
            rmdir tests/qemu-iotests/scratch
            find . \
              -path './.git' -prune -o \
              -path './build' -prune -o \
              -print | sort > "$TMPDIR/$prefix_name.source-paths.after-configure-cleanup"
            if ! cmp "$source_paths" \
              "$TMPDIR/$prefix_name.source-paths.after-configure-cleanup"; then
              echo "source path set changed while configuring $prefix_name" >&2
              diff -u "$source_paths" \
                "$TMPDIR/$prefix_name.source-paths.after-configure-cleanup" >&2 || true
              exit 1
            fi
            if [ "$(source_tree_digest)" != "$source_tree_hash" ]; then
              echo "source tree content changed while configuring $prefix_name" >&2
              exit 1
            fi

            git diff --name-only HEAD -- > "$TMPDIR/python-shebang-files.before-build"
            cmp "$shebang_list" "$TMPDIR/python-shebang-files.before-build"
            after_configure_diff="$TMPDIR/$prefix_name.tracked-source.after-configure.diff"
            git diff --binary --no-ext-diff --full-index HEAD -- > "$after_configure_diff"
            cmp "$tracked_diff" "$after_configure_diff"
            test "$(sha256sum "$after_configure_diff" | gawk '{ print $1 }')" = "$tracked_diff_hash"

            build_log="$out/logs/$prefix_name.log"
            test ! -e build/qemu-system-x86_64
            if [ "$prefix_index" -eq 15 ] || \
               [ "$prefix_index" -eq ${toString (builtins.length patchFiles)} ]; then
              if ! ninja -C build -d explain -v -j "$NIX_BUILD_CORES" \
                > "$build_log" 2>&1; then
                cat "$build_log" >&2
                exit 1
              fi
            else
              if ! ninja -C build -d explain -v -j "$NIX_BUILD_CORES" \
                qemu-system-x86_64 > "$build_log" 2>&1; then
                cat "$build_log" >&2
                exit 1
              fi
            fi
            test -x build/qemu-system-x86_64
            if [ "$prefix_index" -eq 15 ] || \
               [ "$prefix_index" -eq ${toString (builtins.length patchFiles)} ]; then
              test -x build/qemu-img
              test -x build/qemu-io
              test -x build/storage-daemon/qemu-storage-daemon
              nm -g build/qemu-system-x86_64 \
                | grep -q ' qemu_plugin_register_blk_cb$'
              printf '%s\n' \
                '{"execute":"qmp_capabilities"}' \
                '{"execute":"quit"}' \
                | build/qemu-system-x86_64 \
                    -machine none \
                    -nodefaults \
                    -display none \
                    -qmp stdio \
                    -blockdev driver=crucible-shmem,node-name=probe,size=4096 \
                    > "$out/logs/$prefix_name.crucible-shmem-realization.log" \
                    2>&1
              grep -q '"return"' \
                "$out/logs/$prefix_name.crucible-shmem-realization.log"
            fi
            grep -E '\[-W(array-bounds=|stringop-overflow=)\]$' "$build_log" \
              | sed -E 's|^\.\./([^:]+:[0-9]+:[0-9]+):.*\[-W([^]]+)\]$|\1:\2|' \
              | sort -u > "$TMPDIR/$prefix_name.upstream-warnings.actual"
            cat > "$TMPDIR/$prefix_name.upstream-warnings.expected" <<'WARNINGS'
          block/qed-check.c:123:41:array-bounds=
          block/qed-check.c:133:31:array-bounds=
          block/qed-check.c:76:41:array-bounds=
          block/qed-check.c:91:31:array-bounds=
          block/qed-cluster.c:106:37:array-bounds=
          block/qed-cluster.c:37:35:array-bounds=
          block/qed-cluster.c:45:18:array-bounds=
          block/qed-cluster.c:50:18:array-bounds=
          block/qed-cluster.c:55:31:array-bounds=
          block/qed-table.c:88:30:array-bounds=
          block/qed-table.c:89:27:array-bounds=
          block/qed.c:1013:25:array-bounds=
          block/qed.c:961:23:array-bounds=
          hw/scsi/virtio-scsi.c:863:65:array-bounds=
          hw/vfio/migration-multifd.c:629:21:stringop-overflow=
          WARNINGS
            if ! cmp "$TMPDIR/$prefix_name.upstream-warnings.expected" \
              "$TMPDIR/$prefix_name.upstream-warnings.actual"; then
              diff -u "$TMPDIR/$prefix_name.upstream-warnings.expected" \
                "$TMPDIR/$prefix_name.upstream-warnings.actual" >&2 || true
              exit 1
            fi
            git diff --name-only HEAD -- > "$TMPDIR/python-shebang-files.after-build"
            cmp "$shebang_list" "$TMPDIR/python-shebang-files.after-build"
            after_build_diff="$TMPDIR/$prefix_name.tracked-source.after-build.diff"
            git diff --binary --no-ext-diff --full-index HEAD -- > "$after_build_diff"
            if ! cmp "$tracked_diff" "$after_build_diff"; then
              echo "tracked source changed during $prefix_name build" >&2
              diff -u "$tracked_diff" "$after_build_diff" >&2 || true
              exit 1
            fi
            test "$(sha256sum "$after_build_diff" | gawk '{ print $1 }')" = "$tracked_diff_hash"
            if [ -n "$(git ls-files --others --exclude-standard)" ]; then
              echo "untracked source files appeared during $prefix_name build" >&2
              git ls-files --others --exclude-standard >&2
              exit 1
            fi
            find . \
              -path './.git' -prune -o \
              -path './build' -prune -o \
              -print | sort > "$TMPDIR/$prefix_name.source-paths.after-build"
            if ! cmp "$source_paths" "$TMPDIR/$prefix_name.source-paths.after-build"; then
              echo "source path set changed while building $prefix_name" >&2
              diff -u "$source_paths" \
                "$TMPDIR/$prefix_name.source-paths.after-build" >&2 || true
              exit 1
            fi
            if [ "$(source_tree_digest)" != "$source_tree_hash" ]; then
              echo "source tree content changed while building $prefix_name" >&2
              exit 1
            fi
            test "$(sha256sum include/aos/crucible/crucible_shmem_abi.h | gawk '{ print $1 }')" = "$shmem_header_hash"
            cmp ${qemuPackage.passthru.shmemGeneratedHeader} \
              include/aos/crucible/crucible_shmem_abi.h

            artifact_hash=$(sha256sum build/qemu-system-x86_64 | gawk '{ print $1 }')
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
              "$prefix_index" \
              "$prefix_patch" \
              "$actual_branch_commit" \
              "$actual_branch_tree" \
              "$actual_patch_hash" \
              "true" \
              "$tracked_diff_hash" \
              "$shmem_header_hash" \
              "$compiler_version" \
              "$artifact_hash" \
              >> "$out/prefix-builds.tsv"
            cd "$TMPDIR"
            rm -rf "$prefix_source"
          done
          rm -rf "$source_dir"

          prefix_count=$(wc -l < "$out/prefix-builds.tsv" | tr -d ' ')
          test "$prefix_count" -eq ${toString (builtins.length patchFiles)}

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          prefix_count=${toString (builtins.length patchFiles)}
          prefix_model=fresh-source-and-build-tree-per-prefix
          prefix_manifest_columns=index,patch,commit,tree,patch_sha256,fresh_source_build,tracked_diff_sha256,shmem_header_sha256,compiler_version,artifact_sha256
          prefix_builds_are_compile_checks=true
          every_patch_prefix_apply_clean=true
          every_patch_prefix_qemu_system_build=true
          qemu_block_utilities_link_at_prefix_15_and_full_series=true
          crucible_shmem_registration_symbol_present_at_prefix_15_and_full_series=true
          crucible_shmem_blockdev_realized_at_prefix_15_and_full_series=true
          every_patch_prefix_fresh_target_absent_before_build=true
          werror_enabled=true
          warnings_as_errors_except=known-upstream-gcc14-allowlist
          known_upstream_warning_allowlist_verified=true
          warning_allowlist_compiler_version=14.3.0
          array_bounds_warning_allowlist_scope=block/qed.c,block/qed-check.c,block/qed-cluster.c,block/qed-table.c,hw/scsi/virtio-scsi.c
          array_bounds_warning_allowlist_count=14
          stringop_overflow_warning_allowlist_scope=hw/vfio/migration-multifd.c
          stringop_overflow_warning_allowlist_count=1
          build_does_not_mutate_source_diff=true
          tracked_source_diff_compared_byte_for_byte=true
          tracked_source_diff_preserved_after_configure_and_build=true
          source_path_set_preserved_outside_build_directory=true
          generated_shmem_header_hash_verified=true
          configure_wraplock_validated_and_removed=true
          every_patch_prefix_source_tree_removed_after_evidence=true
          every_patch_prefix_commit_verified=true
          every_patch_prefix_tree_verified=true
          prefix_manifest_records_patch_hash=true
          prefix_manifest_records_branch_commit=true
          prefix_manifest_records_branch_tree=true
          prefix_manifest_records_fresh_source_build=true
          prefix_manifest_records_tracked_diff_hash=true
          prefix_manifest_records_shmem_header_hash=true
          prefix_manifest_records_compiler_version=true
          prefix_manifest_records_artifact_hash=true
          RESULT
        '';
      }
    ];
  }
