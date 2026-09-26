# Builds the immutable Git object database shared by QEMU patch provenance and
# regeneration. It independently reconstructs the committed tree from the
# source archive and patch, then authenticates the exact signed commit object
# carried by the pinned bundle and reproduces the patch from that object.
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
          reconstructed_tree=$(git write-tree)
          test "$reconstructed_tree" = "${atomicPatch.tree}" \
            || fail "patch-created tree $reconstructed_tree does not match ${atomicPatch.tree}"
          printf '%s\n' "$reconstructed_tree" > "$out/reconstructed-tree"
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

          signature_header_count() {
            git --git-dir="$1" cat-file commit "$2" \
              | gawk '/^$/ { exit } /^gpgsig / { count++ } END { print count + 0 }'
          }

          has_pinned_sole_parent() {
            parents=$(git --git-dir="$1" rev-list --parents -n 1 "$2") \
              || return 1
            set -- $parents
            test "$#" -eq 2 && test "$2" = "$base_commit"
          }

          work_tree="$TMPDIR/qemu-source/qemu-${atomicPatch.qemuVersion}"
          cd "$work_tree"
          base_commit=$(git rev-parse base)
          reconstructed_tree=$(cat "$out/reconstructed-tree")
          test "$(git write-tree)" = "$reconstructed_tree" \
            || fail "staged patch tree changed between construction and verification"

          bundle_hash=$(sha256sum ${atomicPatch.bundle} | gawk '{ print $1 }')
          test "$bundle_hash" = "${atomicPatch.bundleSha256}" \
            || fail "bundle hash $bundle_hash does not match ${atomicPatch.bundleSha256}"
          git bundle verify ${atomicPatch.bundle} > "$out/atomic-patch-bundle.verify" 2>&1
          grep -Fxq 'The bundle requires this ref:' \
            "$out/atomic-patch-bundle.verify" \
            || fail "bundle does not declare its pinned QEMU base"
          grep -Fxq '${atomicPatch.baseCommit} ' \
            "$out/atomic-patch-bundle.verify" \
            || fail "bundle prerequisite is not the pinned QEMU base"
          test "$(grep -Ec '^[0-9a-f]{40} $' \
            "$out/atomic-patch-bundle.verify")" -eq 1 \
            || fail "bundle must have exactly one prerequisite"
          git fetch -q ${atomicPatch.bundle} \
            "refs/heads/${atomicPatch.branchRef}:refs/heads/bundled-atomic-patch"
          bundle_commit=$(git rev-parse refs/heads/bundled-atomic-patch)
          bundle_tree=$(git rev-parse "$bundle_commit^{tree}")
          test "$bundle_commit" = "${atomicPatch.commit}" \
            || fail "bundle commit $bundle_commit does not match ${atomicPatch.commit}"
          test "$bundle_tree" = "${atomicPatch.tree}" \
            || fail "bundle tree $bundle_tree does not match ${atomicPatch.tree}"
          test "$bundle_tree" = "$reconstructed_tree" \
            || fail "bundle commit and applied patch produce different trees"
          has_pinned_sole_parent .git "$bundle_commit" \
            || fail "bundle commit does not have the pinned base as its sole parent"

          bundle_signature_headers=$(signature_header_count .git "$bundle_commit")
          test "$bundle_signature_headers" -eq 1 \
            || fail "bundle commit must contain exactly one embedded gpgsig header"
          # The pinned bundle and commit hashes bind the exact signature bytes.
          # Signer trust is outside this gate because it has no trusted keyring.

          git cat-file commit "$bundle_commit" \
            | gawk 'body { print } /^$/ { body = 1; next }' \
            > "$TMPDIR/bundle-commit-message"
          cmp "$atomicMessagePath" "$TMPDIR/bundle-commit-message" \
            || fail "bundle commit subject, body, or DCO sign-off drifted"
          dco_count=$(git log -1 --format=%B "$bundle_commit" \
            | grep -Ec '^Signed-off-by: ' || true)
          exact_dco_count=$(git log -1 --format=%B "$bundle_commit" \
            | grep -Fxc 'Signed-off-by: ${atomicPatch.deterministicAuthorName} <${atomicPatch.deterministicAuthorEmail}>' || true)
          test "$dco_count" -eq 1 && test "$exact_dco_count" -eq 1 \
            || fail "bundle commit must contain exactly one matching DCO sign-off"
          test "$(git show -s --format=%an "$bundle_commit")" = "${atomicPatch.deterministicAuthorName}" \
            || fail "bundle commit author name drifted"
          test "$(git show -s --format=%ae "$bundle_commit")" = "${atomicPatch.deterministicAuthorEmail}" \
            || fail "bundle commit author email drifted"
          test "$(git show -s --format=%cn "$bundle_commit")" = "${atomicPatch.deterministicAuthorName}" \
            || fail "bundle commit committer name drifted"
          test "$(git show -s --format=%ce "$bundle_commit")" = "${atomicPatch.deterministicAuthorEmail}" \
            || fail "bundle commit committer email drifted"
          expected_author_epoch=$(date --date='${atomicPatch.deterministicPatchDate}' +%s)
          test "$(git show -s --format=%at "$bundle_commit")" = "$expected_author_epoch" \
            || fail "bundle commit author date drifted"

          git format-patch --stdout --no-signature --no-stat --full-index --binary \
            "$base_commit..$bundle_commit" > "$out/regenerated.patch"
          cmp ${patchPath} "$out/regenerated.patch" \
            || fail "bundle commit does not regenerate the checked atomic patch"

          # The signed commit cannot be reproduced by assigning deterministic
          # commit dates. Prove that an otherwise identical unsigned object is
          # rejected, without adding synthetic objects to the exported repo.
          negative_repo="$TMPDIR/negative-commit-objects.git"
          git clone -q --bare --shared . "$negative_repo"
          unsigned_commit=$(
            GIT_AUTHOR_NAME="${atomicPatch.deterministicAuthorName}" \
            GIT_AUTHOR_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
            GIT_AUTHOR_DATE="${atomicPatch.deterministicPatchDate}" \
            GIT_COMMITTER_NAME="${atomicPatch.deterministicAuthorName}" \
            GIT_COMMITTER_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
            GIT_COMMITTER_DATE="${atomicPatch.deterministicPatchDate}" \
              git --git-dir="$negative_repo" -c commit.gpgsign=false commit-tree \
                "$reconstructed_tree" -p "$base_commit" < "$atomicMessagePath"
          )
          test "$unsigned_commit" != "$bundle_commit" \
            || fail "unsigned reconstruction unexpectedly reproduced signed commit identity"
          test "$(git --git-dir="$negative_repo" rev-parse "$unsigned_commit^{tree}")" = "$bundle_tree" \
            || fail "unsigned negative control does not preserve the patched tree"
          has_pinned_sole_parent "$negative_repo" "$unsigned_commit" \
            || fail "unsigned negative control does not preserve the pinned parent"
          test "$(signature_header_count "$negative_repo" "$unsigned_commit")" -eq 0 \
            || fail "unsigned negative control unexpectedly contains a signature header"

          multi_parent_commit=$(
            GIT_AUTHOR_NAME="${atomicPatch.deterministicAuthorName}" \
            GIT_AUTHOR_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
            GIT_AUTHOR_DATE="${atomicPatch.deterministicPatchDate}" \
            GIT_COMMITTER_NAME="${atomicPatch.deterministicAuthorName}" \
            GIT_COMMITTER_EMAIL="${atomicPatch.deterministicAuthorEmail}" \
            GIT_COMMITTER_DATE="${atomicPatch.deterministicPatchDate}" \
              git --git-dir="$negative_repo" -c commit.gpgsign=false commit-tree \
                "$reconstructed_tree" -p "$base_commit" -p "$unsigned_commit" \
                < "$atomicMessagePath"
          )
          if has_pinned_sole_parent "$negative_repo" "$multi_parent_commit"; then
            fail "sole-parent verifier accepted a two-parent commit"
          fi

          git checkout -q -f base

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
          pinned_bundle_identity_authenticated=true
          bundle_commit_signature_embedded=true
          bundle_commit_tree_matches_reconstruction=true
          bundle_commit_sole_parent_verified=true
          atomic_patch_regenerated_exactly=true
          dco_verified=true
          unsigned_commit_negative_control=true
          sole_parent_negative_control=true
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
