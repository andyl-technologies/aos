{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase2.qemuPatchRegeneration",
  taskIds ? ["T-PATCH-19" "T-PKG-5" "T-DET-24"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  manifestPatchFiles = series.patchFiles;
  patchList = builtins.concatStringsSep " " manifestPatchFiles;
  patchCount = builtins.length manifestPatchFiles;
  patchBranchBundleHash = builtins.hashFile "sha256" series.patchBranchBundle;
  patchBranchCommits =
    map (patch: {
      inherit
        (patch)
        file
        branchCommit
        branchTree
        ;
    })
    series.patches;
  patchBranchMaterial = builtins.toJSON {
    inherit
      (series)
      patchBranchRef
      patchBranchModel
      patchBranchBundleSha256
      patchBranchBaseCommit
      patchBranchBaseTree
      patchBranchHeadCommit
      ;
    inherit patchBranchCommits;
  };
  patchBranchMaterialHash = builtins.hashString "sha256" patchBranchMaterial;
  inherit
    (qemuPackage.passthru)
    patchSeriesHash
    qemuBuildIdentity
    qemuBuildIdentityMaterial
    qemuConfigureFlagsHash
    qemuNixHash
    shmemAbi
    shmemAbiVersion
    shmemHeaderHash
    shmemHeaderInstallPath
    ;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  qemuNixAppliesManifestSeries =
    hasInfix "patchCommand = file:" qemuNix
    && hasInfix "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)" qemuNix;

  missingManifestPatches =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) manifestPatchFiles;
  unmanifestedPatches =
    builtins.filter (patch: !(builtins.elem patch manifestPatchFiles)) patchFiles;

  patchBranchManifest =
    lib.concatMapStringsSep "\n" (patch: let
      subject = lib.removeSuffix ".patch" patch.file;
    in "${patch.file} ${subject} ${patch.branchCommit} ${patch.branchTree}")
    series.patches;

  staticFailures =
    map (patch: "pkgs/emulation/qemu-patches/_series.nix: manifest references absent patch ${patch}")
    missingManifestPatches
    ++ map (patch: "pkgs/emulation/qemu-patches/${patch}: patch is absent from regeneration manifest")
    unmanifestedPatches
    ++ lib.optionals (!qemuNixAppliesManifestSeries) [
      "pkgs/emulation/qemu.nix: patch phase must be generated from series.patchFiles"
    ]
    ++ lib.optionals (series.qemuVersion != qemuPackage.version) [
      "pkgs/emulation/qemu-patches/_series.nix: QEMU version does not match qemu-crucible.version"
    ]
    ++ lib.optionals (patchBranchBundleHash != series.patchBranchBundleSha256) [
      "pkgs/emulation/qemu-patches/crucible-qemu-10.0.0.bundle: bundle hash does not match manifest pin"
    ]
    ++ lib.optionals (patchBranchBundleHash != qemuPackage.passthru.patchBranchBundleHash) [
      "pkgs/emulation/qemu.nix: QEMU package build identity does not consume the patch branch bundle hash"
    ]
    ++ lib.optionals (patchBranchMaterialHash != qemuPackage.passthru.patchBranchMaterialHash) [
      "pkgs/emulation/qemu.nix: QEMU package patch-branch material hash differs from regeneration manifest"
    ]
    ++ lib.optionals (!(hasInfix "series ? import ./qemu-patches/_series.nix" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must consume the patch-series manifest"
    ]
    ++ lib.optionals (!(hasInfix "qemu-build-identity.env" qemuNix && hasInfix "qemu_build_id=" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must install build identity metadata"
    ]
    ++ lib.optionals (!(hasInfix "qemuSimCapability =" qemuNix && hasInfix "qemu_sim_capability=" qemuNix && hasInfix "qemu_shmem_abi=" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must install Crucible sim-capability and shmem ABI metadata"
    ]
    ++ lib.optionals (!(hasInfix "crucible_shmem_abi.h" qemuNix && hasInfix "shmemHeaderHash" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must consume the generated Crucible shmem header"
    ]
    ++ lib.optionals (!(hasInfix "qemu-crucible-shmem-abi-probe.c" qemuNix && hasInfix "CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU package must compile a C-side probe against the generated Crucible shmem header"
    ]
    ++ lib.optionals (!(hasInfix "qemu_nix_hash=" qemuNix && hasInfix "qemu_configure_flags_hash=" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU build identity must include qemu.nix and configure flag material"
    ];
in
  if staticFailures != []
  then throw "crucible phase2 QEMU patch regeneration failed:\n${builtins.concatStringsSep "\n" staticFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-patch-regeneration";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.findutils
        pkgs.gawk
        pkgs.git
        pkgs.grep
        pkgs.patch
        pkgs.sed
        pkgs.tar
        pkgs.xz
        qemuPackage
      ];

      phases = [
        {
          name = "regenerate-qemu-patches";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            validate_artifact_build_id() {
              artifact="$1"
              expected="$2"
              actual=$(sed -n 's/.*"qemu_build_id":"\([^"]*\)".*/\1/p' "$artifact")
              test -n "$actual" || return 1
              test "$actual" = "$expected"
            }

            mkdir -p "$out/regenerated-patches" "$out/drift"

            cat > "$out/patch-branch-manifest.expected" <<'PATCH_BRANCH_MANIFEST'
            ${patchBranchManifest}
            PATCH_BRANCH_MANIFEST

            bundle_hash=$(sha256sum ${series.patchBranchBundle} | gawk '{ print $1 }')
            test "$bundle_hash" = "${series.patchBranchBundleSha256}" \
              || fail "patch branch bundle hash $bundle_hash does not match manifest ${series.patchBranchBundleSha256}"

            work_dir="$TMPDIR/qemu-patch-regeneration"
            generated_dir="$out/regenerated-patches"
            mkdir -p "$work_dir"
            tar -xf ${qemuPackage.src} -C "$work_dir"
            cd "$work_dir/qemu-${series.qemuVersion}"

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
            base_commit=$(git rev-parse HEAD)
            base_tree=$(git rev-parse HEAD^{tree})
            test "$base_commit" = "${series.patchBranchBaseCommit}" \
              || fail "base commit $base_commit does not match manifest ${series.patchBranchBaseCommit}"
            test "$base_tree" = "${series.patchBranchBaseTree}" \
              || fail "base tree $base_tree does not match manifest ${series.patchBranchBaseTree}"

            git bundle verify ${series.patchBranchBundle} \
              > "$out/patch-branch-bundle.verify" 2>&1
            grep -q '${series.patchBranchBaseCommit}' \
              "$out/patch-branch-bundle.verify" \
              || fail "patch branch bundle must record the pinned QEMU base as a thin-bundle prerequisite"
            bundle_bytes=$(wc -c < ${series.patchBranchBundle})
            test "$bundle_bytes" -lt 100000000 \
              || fail "patch branch bundle is $bundle_bytes bytes; repository artifacts must remain below GitHub's 100 MB limit"
            git fetch -q ${series.patchBranchBundle} \
              "refs/heads/${series.patchBranchRef}:refs/heads/patch-stack"
            patch_branch_head=$(git rev-parse refs/heads/patch-stack)
            test "$patch_branch_head" = "${series.patchBranchHeadCommit}" \
              || fail "patch branch head $patch_branch_head does not match manifest ${series.patchBranchHeadCommit}"
            git merge-base --is-ancestor "$base_commit" refs/heads/patch-stack \
              || fail "patch branch head is not descended from the pinned QEMU base"

            git rev-list --reverse "$base_commit..refs/heads/patch-stack" \
              > "$out/patch-branch-commits.list"
            commit_count=$(git rev-list --count "$base_commit..refs/heads/patch-stack")
            test "$commit_count" = "${toString patchCount}" \
              || fail "branch commit count $commit_count does not match manifest count ${toString patchCount}"

            : > "$out/patch-branch-manifest.actual"
            line_number=0
            while read -r patch_name patch_subject expected_commit expected_tree; do
              line_number=$((line_number + 1))
              committed_patch="${patchDir}/$patch_name"
              generated_patch="$generated_dir/$patch_name"
              paths_file="$work_dir/$patch_name.paths"
              commit=$(sed -n "''${line_number}p" "$out/patch-branch-commits.list")
              test "$commit" = "$expected_commit" \
                || fail "commit $line_number for $patch_name is $commit, expected $expected_commit"
              subject=$(git log -1 --format=%s "$commit")
              tree=$(git rev-parse "$commit^{tree}")
              parent_commit=$(git rev-parse "$commit^")
              test "$subject" = "$patch_subject" \
                || fail "subject for $patch_name is $subject, expected $patch_subject"
              test "$tree" = "$expected_tree" \
                || fail "tree for $patch_name is $tree, expected $expected_tree"
              printf '%s %s %s %s\n' "$patch_name" "$subject" "$commit" "$tree" \
                >> "$out/patch-branch-manifest.actual"

              git diff --name-only "$parent_commit" "$commit" > "$paths_file"
              test -s "$paths_file" || fail "branch commit has no diff sections: $patch_name"

              : > "$generated_patch"
              while IFS= read -r changed_path; do
                git diff --unified=3 --no-ext-diff --src-prefix=a/ --dst-prefix=b/ \
                  "$parent_commit" "$commit" -- "$changed_path" \
                  | sed '/^index /d' >> "$generated_patch"
              done < "$paths_file"

              if ! cmp -s "$committed_patch" "$generated_patch"; then
                diff -u "$committed_patch" "$generated_patch" > "$out/drift/$patch_name.diff" || true
                fail "regenerated patch bytes differ for $patch_name; see drift/$patch_name.diff"
              fi
            done < "$out/patch-branch-manifest.expected"

            cmp -s "$out/patch-branch-manifest.expected" "$out/patch-branch-manifest.actual" \
              || fail "patch branch commit manifest differs from actual branch"
            git log --reverse --format=%s "$base_commit..refs/heads/patch-stack" \
              > "$out/commit-order.actual"
            cat > "$out/commit-order.expected" <<'ORDER'
            ${builtins.concatStringsSep "\n" (map (patch: lib.removeSuffix ".patch" patch) manifestPatchFiles)}
            ORDER
            cmp -s "$out/commit-order.expected" "$out/commit-order.actual" \
              || fail "deterministic commit order differs from manifest"

            if find . -name '*.orig' -print -quit | grep -q .; then
              fail "patch regeneration left .orig backup files"
            fi

            : > "$out/patch-series-hashes.txt"
            for patch_name in ${patchList}; do
              patch_hash=$(sha256sum "$generated_dir/$patch_name" | gawk '{ print $1 }')
              printf '%s  %s\n' "$patch_hash" "$patch_name" >> "$out/patch-series-hashes.txt"
            done
            patch_series_hash=$(sha256sum "$out/patch-series-hashes.txt" | gawk '{ print $1 }')
            test "$patch_series_hash" = "${patchSeriesHash}" \
              || fail "patch series hash $patch_series_hash does not match package identity ${patchSeriesHash}"

            apply_dir="$TMPDIR/qemu-regenerated-apply-clean"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            cd "$apply_dir/qemu-${series.qemuVersion}"
            for patch_name in ${patchList}; do
              patch --batch --forward --fuzz=0 --no-backup-if-mismatch \
                -p1 -i "$generated_dir/$patch_name"
            done
            if find . -name '*.orig' -print -quit | grep -q .; then
              fail "clean apply of regenerated series left .orig backup files"
            fi

            cd "$work_dir"
            cat > "$out/build-id-material.txt" <<'BUILD_ID_MATERIAL'
            ${qemuBuildIdentityMaterial}
            BUILD_ID_MATERIAL
            qemu_build_id="${qemuBuildIdentity}"

            identity_file="${qemuPackage}/share/aos/crucible/qemu-build-identity.env"
            test -f "$identity_file" || fail "qemu-crucible build identity metadata is missing"
            cp "$identity_file" "$out/qemu-build-identity.env"
            grep -q '^qemu_version=${series.qemuVersion}$' "$identity_file"
            grep -q '^qemu_source_hash=${series.qemuSourceHash}$' "$identity_file"
            grep -q '^qemu_nix_hash=${qemuNixHash}$' "$identity_file"
            grep -q '^qemu_configure_flags_hash=${qemuConfigureFlagsHash}$' "$identity_file"
            grep -q '^qemu_patch_count=${toString patchCount}$' "$identity_file"
            grep -q '^qemu_patch_series_hash=${patchSeriesHash}$' "$identity_file"
            grep -q '^qemu_patch_branch_ref=${series.patchBranchRef}$' "$identity_file"
            grep -q '^qemu_patch_branch_bundle_hash=${patchBranchBundleHash}$' "$identity_file"
            grep -q '^qemu_patch_branch_base_commit=${series.patchBranchBaseCommit}$' "$identity_file"
            grep -q '^qemu_patch_branch_base_tree=${series.patchBranchBaseTree}$' "$identity_file"
            grep -q '^qemu_patch_branch_head_commit=${series.patchBranchHeadCommit}$' "$identity_file"
            grep -q '^qemu_patch_branch_material_hash=${patchBranchMaterialHash}$' "$identity_file"
            grep -q '^qemu_sim_capability=qemu-crucible$' "$identity_file"
            grep -q '^qemu_shmem_abi_version=${shmemAbiVersion}$' "$identity_file"
            grep -q '^qemu_shmem_abi=${shmemAbi}$' "$identity_file"
            grep -q '^qemu_shmem_header=${shmemHeaderInstallPath}$' "$identity_file"
            grep -q '^qemu_shmem_header_hash=${shmemHeaderHash}$' "$identity_file"
            grep -q '^qemu_build_id=${qemuBuildIdentity}$' "$identity_file"

            changed_build_id=$(
              {
                cat "$out/build-id-material.txt"
                printf 'qemu_version_bump_negative_control=%s\n' "10.0.1"
              } | sha256sum | gawk '{ print $1 }'
            )
            test "$changed_build_id" != "$qemu_build_id" \
              || fail "version-bump negative control did not change build identity"

            cat > "$out/reproduction-artifact.json" <<ARTIFACT
            {"qemu_build_id":"$qemu_build_id","qemu_version":"${series.qemuVersion}","qemu_source_hash":"${series.qemuSourceHash}","qemu_patch_series_hash":"${patchSeriesHash}","qemu_patch_branch_ref":"${series.patchBranchRef}","qemu_patch_branch_bundle_hash":"${patchBranchBundleHash}","qemu_patch_branch_material_hash":"${patchBranchMaterialHash}","qemu_nix_hash":"${qemuNixHash}","qemu_configure_flags_hash":"${qemuConfigureFlagsHash}","qemu_shmem_abi":"${shmemAbi}","qemu_shmem_abi_version":"${shmemAbiVersion}","qemu_shmem_header_hash":"${shmemHeaderHash}"}
            ARTIFACT
            validate_artifact_build_id "$out/reproduction-artifact.json" "$qemu_build_id" \
              || fail "reproduction artifact validator rejected matching QEMU build identity"
            sed "s/$qemu_build_id/$changed_build_id/" "$out/reproduction-artifact.json" \
              > "$out/reproduction-artifact.mutated.json"
            if validate_artifact_build_id "$out/reproduction-artifact.mutated.json" "$qemu_build_id"; then
              fail "reproduction artifact validator accepted a mutated QEMU build identity"
            fi
            if validate_artifact_build_id "$out/reproduction-artifact.json" "$changed_build_id"; then
              fail "reproduction artifact validator accepted a mismatched expected QEMU build identity"
            fi

            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            qemu_version=${series.qemuVersion}
            qemu_source_hash=${series.qemuSourceHash}
            patch_regeneration_from_tracked_stack=true
            patch_branch_bundle_verified=true
            patch_branch_bundle_is_thin=true
            patch_branch_bundle_bytes=$bundle_bytes
            patch_branch_bundle_hash=${patchBranchBundleHash}
            patch_branch_ref=${series.patchBranchRef}
            patch_branch_model=${series.patchBranchModel}
            patch_branch_base_commit=${series.patchBranchBaseCommit}
            patch_branch_base_tree=${series.patchBranchBaseTree}
            patch_branch_head_commit=${series.patchBranchHeadCommit}
            patch_branch_material_hash=${patchBranchMaterialHash}
            branch_base_matches_qemu_pin=true
            branch_head_matches_manifest=true
            branch_commit_count_matches_manifest=true
            branch_commit_order_matches_manifest=true
            patch_branch_commit_hashes_match_manifest=true
            patch_branch_commit_trees_match_manifest=true
            deterministic_author_date_ordering=true
            regenerated_patch_context_lines=3
            regenerated_patch_count=${toString patchCount}
            committed_patch_count=${toString patchCount}
            regenerated_patch_bytes_match_committed=true
            patch_series_hash=${patchSeriesHash}
            apply_clean_regenerated_series=true
            apply_clean_patch_fuzz=0
            qemu_package_patch_phase_generated_from_manifest=true
            qemu_build_identity_metadata_installed=true
            qemu_build_id=${qemuBuildIdentity}
            qemu_nix_hash=${qemuNixHash}
            qemu_configure_flags_hash=${qemuConfigureFlagsHash}
            qemu_sim_capability=qemu-crucible
            qemu_shmem_abi_version=${shmemAbiVersion}
            qemu_shmem_abi=${shmemAbi}
            qemu_shmem_header=${shmemHeaderInstallPath}
            qemu_shmem_header_hash=${shmemHeaderHash}
            qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,patch_series_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash
            artifact_build_id_match=true
            artifact_validator_accepts_match=true
            artifact_validator_rejects_mismatch=true
            artifact_mismatch_regates=true
            changed_build_id_negative_control=$changed_build_id
            changed_build_negative_control=mutated_build_id_material
            qemu_version_bump_regate_enforced=true
            qemu_inert_rerun_by_gate_dependency=true
            RESULT
          '';
        }
      ];
    }
