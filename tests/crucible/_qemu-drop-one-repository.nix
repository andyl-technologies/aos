# Computes every full-minus-one patch branch once in a single mutable clone of
# the immutable patch-stack repository, then publishes one read-only object
# database plus a conflict/success manifest for all per-patch build derivations.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchStackRepository ?
    import ./_qemu-patch-stack-repository.nix {
      inherit pkgs lib qemuPackage;
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchCount = builtins.length series.patches;
  patchCommitManifest =
    lib.concatMapStringsSep "\n" (patch: "${patch.file}|${patch.branchCommit}")
    series.patches
    + "\n";
in
  pkgs.mkDerivation {
    pname = "crucible-qemu-drop-one-repository";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.sed
    ];

    passAsFile = ["patchCommitManifest"];
    inherit patchCommitManifest;

    phases = [
      {
        name = "prepare-all-qemu-drop-one-refs";
        script = ''
          set -eu
          export LC_ALL=C

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          grep -q '^PASS$' ${patchStackRepository}/result
          mkdir -p "$out"
          ln -s ${patchStackRepository}/source-supplement.tar \
            "$out/source-supplement.tar"
          ln -s ${patchStackRepository}/source-supplement.sha256 \
            "$out/source-supplement.sha256"
          ln -s ${patchStackRepository}/source-inventory.sha256 \
            "$out/source-inventory.sha256"
          work_repo="$out/repo.git"
          # The immutable source repository is never pruned, so an alternate
          # safely shares all base/patch-stack objects. This output stores only
          # rewritten drop-one commits and refs.
          git clone -q --mirror --shared \
            ${patchStackRepository}/repo.git "$work_repo"
          work_tree="$TMPDIR/drop-one-work-tree"
          git --git-dir="$work_repo" worktree add -q --detach \
            "$work_tree" refs/heads/patch-stack
          cd "$work_tree"
          git config user.name "${series.deterministicAuthorName}"
          git config user.email "${series.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config gc.auto 0
          git config maintenance.auto false

          metadata="$out/drop-one"
          mkdir -p "$metadata"
          printf 'index\tpatch\toutcome\tref\thead\ttree\tconflicting_commit\tconflicting_files\n' \
            > "$metadata/manifest.tsv"

          index=0
          while IFS='|' read -r patch_name drop_commit; do
            index=$((index + 1))
            patch_metadata="$metadata/$index"
            mkdir -p "$patch_metadata"
            printf '%s\n' "$patch_name" > "$patch_metadata/dropped-patch"
            printf '%s\n' "$index" > "$patch_metadata/drop-index"
            test "$(git rev-parse "$drop_commit")" = "$drop_commit" \
              || fail "manifest commit for $patch_name is absent"
            onto=$(git rev-parse "$drop_commit^")

            git checkout -q --detach refs/heads/patch-stack
            if [ "$index" -eq ${toString patchCount} ]; then
              variant_head="$onto"
              rebase_ok=1
            else
              git branch -q --no-track -f drop-one-in-progress refs/heads/patch-stack
              git checkout -q drop-one-in-progress
              if GIT_SEQUENCE_EDITOR=true \
                 GIT_EDITOR=true \
                 GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
                 GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
                 GIT_COMMITTER_DATE="${series.deterministicPatchDate}" \
                 git -c rerere.enabled=false rebase \
                   --onto "$onto" "$drop_commit" drop-one-in-progress \
                   > "$patch_metadata/rebase.log" 2>&1; then
                variant_head=$(git rev-parse HEAD)
                rebase_ok=1
              else
                rebase_ok=0
                rebase_head=$(git rev-parse --verify REBASE_HEAD 2>/dev/null) \
                  || fail "rebase for $patch_name failed without REBASE_HEAD"
                test "$rebase_head" != "$drop_commit" \
                  || fail "rebase for $patch_name conflicted on the dropped commit itself"
                git rev-list "$drop_commit..refs/heads/patch-stack" \
                  | grep -Fqx "$rebase_head" \
                  || fail "rebase for $patch_name failed outside the pinned later stack"
                conflicting_files=$(git diff --name-only --diff-filter=U \
                  | tr '\n' ',' | sed 's/,$//')
                test -n "$conflicting_files" \
                  || fail "rebase for $patch_name failed without unmerged paths"
                conflicting_commit="$rebase_head"
                git rebase --abort > /dev/null 2>&1 || true
              fi
              git checkout -q --detach refs/heads/patch-stack
              git branch -D drop-one-in-progress > /dev/null 2>&1 || true
            fi

            if [ "$rebase_ok" -eq 0 ]; then
              echo conflict > "$patch_metadata/outcome"
              {
                echo "conflicting_replayed_commit=$conflicting_commit"
                echo "conflicting_files=$conflicting_files"
              } > "$patch_metadata/conflict.env"
              printf '%s\t%s\tconflict\t-\t-\t-\t%s\t%s\n' \
                "$index" "$patch_name" "$conflicting_commit" "$conflicting_files" \
                >> "$metadata/manifest.tsv"
              continue
            fi

            variant_ref="refs/heads/drop-one/$index"
            variant_tree=$(git rev-parse "$variant_head^{tree}")
            git --git-dir="$work_repo" update-ref "$variant_ref" "$variant_head"
            echo drop-clean > "$patch_metadata/outcome"
            printf '%s\n' "$variant_ref" > "$patch_metadata/ref"
            printf '%s\n' "$variant_head" > "$patch_metadata/head"
            printf '%s\n' "$variant_tree" > "$patch_metadata/tree"
            printf '%s\t%s\tdrop-clean\t%s\t%s\t%s\t-\t-\n' \
              "$index" "$patch_name" "$variant_ref" "$variant_head" "$variant_tree" \
              >> "$metadata/manifest.tsv"
          done < "$patchCommitManifestPath"

          test "$index" -eq ${toString patchCount}
          cd "$TMPDIR"
          git --git-dir="$work_repo" worktree remove --force "$work_tree"
          git --git-dir="$work_repo" fsck --strict --no-dangling
          cp "$metadata/manifest.tsv" "$out/drop-one-manifest.tsv"

          conflict_count=$(gawk -F '\t' '$3 == "conflict" { count++ } END { print count + 0 }' \
            "$out/drop-one-manifest.tsv")
          clean_count=$(gawk -F '\t' '$3 == "drop-clean" { count++ } END { print count + 0 }' \
            "$out/drop-one-manifest.tsv")
          test $((conflict_count + clean_count)) -eq ${toString patchCount}
          cat > "$out/result" <<RESULT
          PASS
          patch_count=${toString patchCount}
          conflict_count=$conflict_count
          drop_clean_count=$clean_count
          all_drop_one_branches_computed_in_one_repository=true
          successful_refs_retained=true
          conflicts_recorded_in_manifest=true
          conflicts_require_pinned_rebase_head_and_unmerged_paths=true
          RESULT
        '';
      }
    ];
  }
