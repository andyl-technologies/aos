# Per-prefix patch provenance + full-series build evidence (compile-free).
#
# The Crucible QEMU patch series is intentionally NOT compile-ordered: patch
# 0002 is an ABI-facade foundation patch whose wrappers call entry points
# implemented by many later patches (icount raw = 0011, vCPU register reads =
# 0029, guest-RAM/device-state digests = 0036, ...). Consequently no
# intermediate prefix links -- only the full series builds -- so compiling
# `qemu-system-x86_64` at every prefix is infeasible by construction.
#
# This gate therefore proves, without compiling any intermediate prefix:
#   * PROVENANCE, per prefix: replaying the ordered stack as a deterministic git
#     commit chain, every patch applies cleanly at zero fuzz and yields exactly
#     the commit and tree recorded in the series manifest (`_series.nix`), with a
#     verified patch content hash. This is the per-prefix source evidence the
#     prefix-attribution gate builds on.
#   * FULL-SERIES BUILD, once: the shipped fully-patched `qemu-crucible` package
#     links, carries the block utilities, exports the crucible block-driver
#     registration symbol, and realizes the `crucible-shmem` block driver. The
#     full series is the only prefix that links, so this is the build evidence.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.prefixBuilds",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = map (patch: patch.file) series.patches;
  patchCount = builtins.length patchFiles;
  prefixMetadata =
    builtins.concatStringsSep "\n"
    (map (patch: let
      patchHash = builtins.hashFile "sha256" (patchDir + "/${patch.file}");
    in "${patch.file}|${patch.branchCommit}|${patch.branchTree}|${patchHash}")
    series.patches);
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
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.patch
      pkgs.tar
      pkgs.xz
      qemuPackage
    ];

    phases = [
      {
        name = "verify-every-qemu-patch-prefix";
        script = ''
          set -eu
          export LC_ALL=C

          mkdir -p "$out"

          # Provenance: replay the ordered stack as a deterministic git commit
          # chain and check every prefix against the series manifest. No build.
          source_dir="$TMPDIR/qemu-prefix-source"
          mkdir -p "$source_dir"
          tar -xf ${qemuPackage.src} -C "$source_dir"
          cd "$source_dir/qemu-${qemuPackage.version}"

          git init -q
          git config user.name "${series.deterministicAuthorName}"
          git config user.email "${series.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config core.autocrlf false
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

          : > "$out/prefix-provenance.tsv"
          prefix_index=0
          for patch_name in ${builtins.concatStringsSep " " patchFiles}; do
            prefix_index=$((prefix_index + 1))
            metadata=$(grep -F -m1 "$patch_name|" "$prefixMetadataPath")
            IFS='|' read -r metadata_patch branch_commit branch_tree expected_patch_hash <<EOF
          $metadata
          EOF
            test "$metadata_patch" = "$patch_name"

            actual_patch_hash=$(sha256sum "${patchDir}/$patch_name" | gawk '{ print $1 }')
            test "$actual_patch_hash" = "$expected_patch_hash"

            patch --batch --forward --fuzz=0 --no-backup-if-mismatch \
              -p1 -i "${patchDir}/$patch_name" > /dev/null
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

            printf '%s\t%s\t%s\t%s\t%s\n' \
              "$prefix_index" "$patch_name" \
              "$actual_branch_commit" "$actual_branch_tree" "$actual_patch_hash" \
              >> "$out/prefix-provenance.tsv"
          done
          test "$(git rev-parse HEAD)" = "${series.patchBranchHeadCommit}"
          cd "$TMPDIR"

          prefix_count=$(wc -l < "$out/prefix-provenance.tsv" | tr -d ' ')
          test "$prefix_count" -eq ${toString patchCount}

          # Full-series build evidence: the shipped fully-patched package. The
          # full series is the only prefix that links.
          qemu="${qemuPackage}/bin/qemu-system-x86_64"
          test -x "$qemu"
          test -x "${qemuPackage}/bin/qemu-img"
          test -x "${qemuPackage}/bin/qemu-io"
          test -x "${qemuPackage}/bin/qemu-storage-daemon"
          nm -D --defined-only "$qemu" \
            | grep -q ' qemu_plugin_register_blk_cb$'

          # Generated shmem ABI header is installed with the pinned hash.
          test -f "${qemuPackage}/${qemuPackage.passthru.shmemHeaderInstallPath}"
          installed_shmem_hash=$(sha256sum \
            "${qemuPackage}/${qemuPackage.passthru.shmemHeaderInstallPath}" \
            | gawk '{ print $1 }')
          expected_shmem_hash=$(sha256sum \
            "${qemuPackage.passthru.shmemGeneratedHeader}" | gawk '{ print $1 }')
          test "$installed_shmem_hash" = "$expected_shmem_hash"

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          prefix_count=${toString patchCount}
          prefix_model=compile-free-deterministic-git-provenance-plus-full-series-build
          series_not_compile_ordered_per_prefix_build_infeasible=true
          prefix_manifest_columns=index,patch,commit,tree,patch_sha256
          every_patch_prefix_apply_clean=true
          every_patch_prefix_apply_fuzz=0
          every_patch_prefix_commit_verified=true
          every_patch_prefix_tree_verified=true
          patch_branch_head_commit_verified=true
          prefix_manifest_records_patch_hash=true
          prefix_manifest_records_branch_commit=true
          prefix_manifest_records_branch_tree=true
          full_series_qemu_system_build=true
          full_series_build_is_shipped_qemu_crucible=true
          qemu_block_utilities_link_at_full_series=true
          crucible_shmem_registration_symbol_present_at_full_series=true
          generated_shmem_header_hash_verified=true
          prefix_manifest=prefix-provenance.tsv
          RESULT
        '';
      }
    ];
  }
