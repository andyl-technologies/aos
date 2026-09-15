# Builds the immutable Git object database shared by QEMU patch provenance and
# regeneration. It proves that the carried patch creates the exact committed
# tree and that the bundle names the same atomic commit.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchPath = ../../pkgs/emulation/qemu-patches + "/${atomicPatch.file}";
in
  pkgs.mkDerivation {
    pname = "crucible-qemu-atomic-patch-repository";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gawk
      pkgs.git
      pkgs.patch
      pkgs.grep
      pkgs.tar
      pkgs.xz
    ];

    passAsFile = ["atomicMessage"];
    atomicMessage = ''
      ${atomicPatch.subject}

      ${atomicPatch.body}

      Signed-off-by: ${atomicPatch.deterministicAuthorName} <${atomicPatch.deterministicAuthorEmail}>
    '';

    phases = [
      {
        name = "build-qemu-atomic-patch-repository";
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
          work_tree="$source_root/qemu-${atomicPatch.qemuVersion}"
          cd "$work_tree"

          git init -q
          git config user.name "${atomicPatch.deterministicAuthorName}"
          git config user.email "${atomicPatch.deterministicAuthorEmail}"
          git config commit.gpgsign false
          git config core.autocrlf false
          git config core.abbrev 9
          git config gc.auto 0
          git config maintenance.auto false

          git add -A
          GIT_AUTHOR_NAME="${atomicPatch.deterministicAuthorName}" \
          GIT_AUTHOR_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
          GIT_AUTHOR_DATE="${atomicPatch.deterministicBaseDate}" \
          GIT_COMMITTER_NAME="${atomicPatch.deterministicAuthorName}" \
          GIT_COMMITTER_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
          GIT_COMMITTER_DATE="${atomicPatch.deterministicBaseDate}" \
            git -c commit.gpgsign=false commit -q \
              -m "qemu-${atomicPatch.qemuVersion}-base"

          base_commit=$(git rev-parse HEAD)
          base_tree=$(git rev-parse HEAD^{tree})
          test "$base_commit" = "${atomicPatch.baseCommit}" \
            || fail "base commit $base_commit does not match ${atomicPatch.baseCommit}"
          test "$base_tree" = "${atomicPatch.baseTree}" \
            || fail "base tree $base_tree does not match ${atomicPatch.baseTree}"
          git branch base "$base_commit"

          patch_hash=$(sha256sum ${patchPath} | gawk '{ print $1 }')
          test "$patch_hash" = "${atomicPatch.sha256}" \
            || fail "atomic patch hash $patch_hash does not match ${atomicPatch.sha256}"
          patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < ${patchPath}
          git add -A
          GIT_AUTHOR_NAME="${atomicPatch.deterministicAuthorName}" \
          GIT_AUTHOR_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
          GIT_AUTHOR_DATE="${atomicPatch.deterministicPatchDate}" \
          GIT_COMMITTER_NAME="${atomicPatch.deterministicAuthorName}" \
          GIT_COMMITTER_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
          GIT_COMMITTER_DATE="${atomicPatch.deterministicPatchDate}" \
            git -c commit.gpgsign=false commit -q -F "$atomicMessagePath"
        '';
      }
      {
        name = "verify-qemu-atomic-patch-repository";
        script = ''
      set -eu
      export LC_ALL=C
      fail() {
        echo "FAIL: $*" >&2
        exit 1
      }
      work_tree="$TMPDIR/qemu-source/qemu-${atomicPatch.qemuVersion}"
      cd "$work_tree"
      base_commit=$(git rev-parse base)
      patch_commit=$(git rev-parse HEAD)
      patch_tree=$(git rev-parse HEAD^{tree})
      test "$patch_commit" = "${atomicPatch.commit}" \
        || fail "reconstructed commit $patch_commit does not match ${atomicPatch.commit}"
      test "$patch_tree" = "${atomicPatch.tree}" \
        || fail "reconstructed tree $patch_tree does not match ${atomicPatch.tree}"
      test "$(git rev-parse HEAD^)" = "$base_commit" \
        || fail "atomic patch does not have the pinned base as its sole parent"
      test "$(git log -1 --format=%s HEAD)" = "${atomicPatch.subject}" \
        || fail "atomic patch subject drifted"
      test "$(git log -1 --format=%B HEAD | grep -c '^Signed-off-by:')" -eq 1 \
        || fail "atomic patch must contain exactly one DCO sign-off"

      bundle_hash=$(sha256sum ${atomicPatch.bundle} | gawk '{ print $1 }')
      test "$bundle_hash" = "${atomicPatch.bundleSha256}" \
        || fail "bundle hash $bundle_hash does not match ${atomicPatch.bundleSha256}"
      git bundle verify ${atomicPatch.bundle} > "$out/atomic-patch-bundle.verify" 2>&1
      grep -q '${atomicPatch.baseCommit}' "$out/atomic-patch-bundle.verify" \
        || fail "thin bundle does not name the pinned base prerequisite"
      git fetch -q ${atomicPatch.bundle} \
        "refs/heads/${atomicPatch.branchRef}:refs/heads/bundled-atomic-patch"
      test "$(git rev-parse refs/heads/bundled-atomic-patch)" = "$patch_commit" \
        || fail "bundle and patch file produce different commits"
      git checkout -q base

      {
        git ls-files --others --exclude-standard -z
        git ls-files --others --ignored --exclude-standard -z
      } | sort -zu > "$TMPDIR/source-supplement.paths0"
      supplement_file_count=$(tr '\0' '\n' < "$TMPDIR/source-supplement.paths0" | wc -l | tr -d ' ')
      test "$supplement_file_count" -gt 0 || fail "QEMU source supplement has no ignored files"
      {
        cat "$TMPDIR/source-supplement.paths0"
        find . -path './.git' -prune -o -type d -print0
      } | sort -zu > "$out/source-supplement.entries0"
      supplement_entry_count=$(tr '\0' '\n' < "$out/source-supplement.entries0" | wc -l | tr -d ' ')
      tar --no-recursion --null --format=gnu --mtime=@0 --owner=0 --group=0 \
        --numeric-owner --files-from="$out/source-supplement.entries0" \
        -cf "$out/source-supplement.tar"
      supplement_hash=$(sha256sum "$out/source-supplement.tar" | gawk '{ print $1 }')
      printf '%s\n' "$supplement_hash" > "$out/source-supplement.sha256"

      reconstructed="$TMPDIR/reconstructed-qemu-source"
      mkdir -p "$reconstructed"
      GIT_INDEX_FILE="$TMPDIR/base-source.index" git read-tree "$base_commit"
      GIT_INDEX_FILE="$TMPDIR/base-source.index" git checkout-index --all --prefix="$reconstructed/"
      tar -xf "$out/source-supplement.tar" -C "$reconstructed"
      tar --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --exclude='./.git' -cf "$TMPDIR/original.tar" -C "$work_tree" .
      tar --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -cf "$TMPDIR/reconstructed.tar" -C "$reconstructed" .
      cmp "$TMPDIR/original.tar" "$TMPDIR/reconstructed.tar" \
        || fail "base archive plus supplement does not reconstruct QEMU source"

      git symbolic-ref HEAD refs/heads/bundled-atomic-patch
      git clone -q --bare --no-hardlinks . "$out/repo.git"
      git --git-dir="$out/repo.git" symbolic-ref HEAD refs/heads/bundled-atomic-patch
      git --git-dir="$out/repo.git" fsck --strict --no-dangling

      cat > "$out/result" <<RESULT
      PASS
      qemu_version=${atomicPatch.qemuVersion}
      atomic_patch=${atomicPatch.file}
      atomic_patch_hash=${atomicPatch.sha256}
      base_commit=${atomicPatch.baseCommit}
      base_tree=${atomicPatch.baseTree}
      commit=${atomicPatch.commit}
      tree=${atomicPatch.tree}
      bundle_hash=${atomicPatch.bundleSha256}
      apply_commit_tree_verified=true
      bundle_matches_patch_commit=true
      dco_verified=true
      source_extractions=1
      full_tree_staging_passes=1
      source_supplement_files=$supplement_file_count
      source_supplement_entries=$supplement_entry_count
      source_supplement_sha256=$supplement_hash
      source_reconstruction_inventory_verified=true
      immutable_shared_git_object_database=true
      RESULT
        '';
      }
    ];
  }
