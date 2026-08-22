# Builds the immutable Git object database shared by QEMU patch provenance,
# regeneration, and drop-one attribution. The 130 MiB upstream archive is
# extracted and indexed exactly once; all downstream variants read commits from
# this repository rather than reconstructing the patch stack independently.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchCount = builtins.length series.patches;
  patchBranchManifest =
    lib.concatMapStringsSep "\n" (patch: let
      subject = patch.branchSubject or (lib.removeSuffix ".patch" patch.file);
    in "${patch.file}|${patch.branchCommit}|${patch.branchTree}|${subject}")
    series.patches
    + "\n";
in
  pkgs.mkDerivation {
    pname = "crucible-qemu-patch-stack-repository";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.sed
      pkgs.tar
      pkgs.xz
    ];

    passAsFile = ["patchBranchManifest"];
    inherit patchBranchManifest;

    phases = [
      {
        name = "build-qemu-patch-stack-repository";
        script = ''
          set -eu
          export LC_ALL=C

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          mkdir -p "$out"
          source_root="$TMPDIR/qemu-source"
          mkdir -p "$source_root"
          tar -xf ${qemuPackage.src} -C "$source_root"
          work_tree="$source_root/qemu-${series.qemuVersion}"
          cd "$work_tree"

          git init -q
          git config user.name "${series.deterministicAuthorName}"
          git config user.email "${series.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config core.autocrlf false
          git config core.abbrev 9
          git config gc.auto 0
          git config maintenance.auto false

          # This is the sole full-tree staging pass in the shared setup.
          git add -A
          GIT_AUTHOR_NAME="${series.deterministicAuthorName}" \
          GIT_AUTHOR_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_AUTHOR_DATE="${series.deterministicBaseDate}" \
          GIT_COMMITTER_NAME="${series.deterministicAuthorName}" \
          GIT_COMMITTER_EMAIL="${series.deterministicAuthorEmail}" \
          GIT_COMMITTER_DATE="${series.deterministicBaseDate}" \
            git -c commit.gpgsign=false commit -q \
              -m "qemu-${series.qemuVersion}-base"

          base_commit=$(git rev-parse HEAD)
          base_tree=$(git rev-parse HEAD^{tree})
          test "$base_commit" = "${series.patchBranchBaseCommit}" \
            || fail "base commit $base_commit does not match ${series.patchBranchBaseCommit}"
          test "$base_tree" = "${series.patchBranchBaseTree}" \
            || fail "base tree $base_tree does not match ${series.patchBranchBaseTree}"
          git branch base "$base_commit"

          bundle_hash=$(sha256sum ${series.patchBranchBundle} | gawk '{ print $1 }')
          test "$bundle_hash" = "${series.patchBranchBundleSha256}" \
            || fail "bundle hash $bundle_hash does not match ${series.patchBranchBundleSha256}"
          git bundle verify ${series.patchBranchBundle} \
            > "$out/patch-branch-bundle.verify" 2>&1
          grep -q '${series.patchBranchBaseCommit}' \
            "$out/patch-branch-bundle.verify" \
            || fail "thin bundle does not name the pinned base prerequisite"
          git fetch -q ${series.patchBranchBundle} \
            "HEAD:refs/heads/patch-stack"

          head_commit=$(git rev-parse refs/heads/patch-stack)
          test "$head_commit" = "${series.patchBranchHeadCommit}" \
            || fail "patch-stack head $head_commit does not match ${series.patchBranchHeadCommit}"
          git merge-base --is-ancestor "$base_commit" refs/heads/patch-stack \
            || fail "patch-stack head is not descended from the pinned base"
          git rev-list --reverse "$base_commit..refs/heads/patch-stack" \
            > "$out/patch-branch-commits.list"
          test "$(wc -l < "$out/patch-branch-commits.list" | tr -d ' ')" \
            -eq ${toString patchCount} \
            || fail "patch-stack commit count does not match the manifest"

          expected_patch_epoch=$(date -d "${series.deterministicPatchDate}" +%s)
          : > "$out/patch-branch-manifest.actual"
          line_number=0
          while IFS='|' read -r patch_name expected_commit expected_tree patch_subject; do
            line_number=$((line_number + 1))
            commit=$(sed -n "''${line_number}p" "$out/patch-branch-commits.list")
            test "$commit" = "$expected_commit" \
              || fail "commit $line_number for $patch_name is $commit, expected $expected_commit"
            tree=$(git rev-parse "$commit^{tree}")
            subject=$(git log -1 --format=%s "$commit")
            test "$tree" = "$expected_tree" \
              || fail "tree for $patch_name is $tree, expected $expected_tree"
            test "$subject" = "$patch_subject" \
              || fail "subject for $patch_name is $subject, expected $patch_subject"
            test "$(git log -1 --format=%at "$commit")" = "$expected_patch_epoch" \
              || fail "$patch_name has a noncanonical author timestamp"
            test "$(git log -1 --format=%ct "$commit")" = "$expected_patch_epoch" \
              || fail "$patch_name has a noncanonical committer timestamp"
            dco_count=$(git log -1 --format=%B "$commit" | gawk '
              /^Signed-off-by:/ { total++ }
              $0 == "Signed-off-by: ${series.deterministicAuthorName} <${series.deterministicAuthorEmail}>" { expected++ }
              END { print (total + 0) ":" (expected + 0) }
            ')
            test "$dco_count" = "1:1" \
              || fail "$patch_name does not have exactly one manifest DCO sign-off"
            printf '%s|%s|%s|%s\n' \
              "$patch_name" "$commit" "$tree" "$subject" \
              >> "$out/patch-branch-manifest.actual"
          done < "$patchBranchManifestPath"
          cmp "$patchBranchManifestPath" "$out/patch-branch-manifest.actual"

          # QEMU's release archive vendors ignored subprojects such as
          # keycodemapdb. They are deliberately absent from the pinned Git base
          # tree, so retain that pristine supplement once for every downstream
          # source materialization.
          git ls-files --others --ignored --exclude-standard -z \
            > "$TMPDIR/source-supplement.paths0"
          supplement_count=$(tr '\0' '\n' < "$TMPDIR/source-supplement.paths0" \
            | wc -l | tr -d ' ')
          test "$supplement_count" -gt 0 \
            || fail "QEMU source supplement unexpectedly has no ignored files"
          tar --null --files-from="$TMPDIR/source-supplement.paths0" \
            -cf "$TMPDIR/source-supplement.tar"
          mkdir -p "$out/source-supplement"
          tar -xf "$TMPDIR/source-supplement.tar" -C "$out/source-supplement"
          test -f "$out/source-supplement/subprojects/keycodemapdb/meson.build" \
            || fail "QEMU keycodemapdb source supplement is incomplete"

          git symbolic-ref HEAD refs/heads/patch-stack
          git clone -q --bare --no-hardlinks . "$out/repo.git"
          git --git-dir="$out/repo.git" symbolic-ref HEAD refs/heads/patch-stack
          git --git-dir="$out/repo.git" fsck --strict --no-dangling

          cat > "$out/result" <<RESULT
          PASS
          qemu_version=${series.qemuVersion}
          patch_count=${toString patchCount}
          source_extractions=1
          full_tree_staging_passes=1
          source_supplement_files=$supplement_count
          ignored_vendored_subprojects_preserved=true
          base_commit=${series.patchBranchBaseCommit}
          base_tree=${series.patchBranchBaseTree}
          head_commit=${series.patchBranchHeadCommit}
          bundle_hash=${series.patchBranchBundleSha256}
          manifest_commits_and_trees_verified=true
          immutable_shared_git_object_database=true
          RESULT
        '';
      }
    ];
  }
