{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPatchRegeneration",
  taskIds ? ["T-PATCH-24"],
  openTaskIds ? [],
  qemuPackage ? pkgs.qemu-crucible,
  atomicPatchRepository ?
    import ./_qemu-atomic-patch-repository.nix {
      inherit pkgs qemuPackage;
    },
  dependencies ? [],
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchPath = ../../pkgs/emulation/qemu-patches + "/${atomicPatch.file}";
  qemu = qemuPackage.passthru or qemuPackage;
  shmemAbi = qemu.shmemAbi;
  shmemHeaderHash = qemu.shmemHeaderHash;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor hasInfix;
  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        needle = "atomicPatch ? import ./qemu-patches/_atomic-patch.nix";
        reason = "QEMU must consume the direct atomic-patch descriptor";
      }
      {
        needle = "atomicPatchHash = let";
        reason = "QEMU identity must hash the exact atomic patch artifact";
      }
      {
        needle = "< \${atomicPatchPath}";
        reason = "QEMU must apply the atomic patch directly";
      }
      {
        needle = "CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION";
        reason = "QEMU must compile-probe the generated shared-memory ABI header";
      }
    ]
    ++ lib.optionals (qemu.atomicPatchHash != atomicPatch.sha256) [
      "qemu-crucible atomic patch identity differs from the descriptor"
    ]
    ++ lib.optionals (qemu.atomicPatch.commit != atomicPatch.commit) [
      "qemu-crucible atomic commit differs from the descriptor"
    ];
in
  if failures != []
  then throw "QEMU atomic patch regeneration gate failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-atomic-patch-regeneration";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.diffutils pkgs.gawk pkgs.git pkgs.grep];
      phases = [
        {
          name = "verify-atomic-patch-regeneration";
          script = ''
            set -eu
            mkdir -p "$out"

            grep -Fxq PASS "${atomicPatchRepository}/result"
            grep -Fxq 'apply_commit_tree_verified=true' "${atomicPatchRepository}/result"
            grep -Fxq 'bundle_matches_patch_commit=true' "${atomicPatchRepository}/result"
            grep -Fxq 'dco_verified=true' "${atomicPatchRepository}/result"

            git --git-dir="${atomicPatchRepository}/repo.git" format-patch \
              --stdout --no-signature --no-stat --full-index --binary \
              "${atomicPatch.baseCommit}..${atomicPatch.commit}" \
              > "$out/regenerated.patch"
            cmp ${patchPath} "$out/regenerated.patch"

            regenerated_hash=$(sha256sum "$out/regenerated.patch" | gawk '{ print $1 }')
            test "$regenerated_hash" = "${atomicPatch.sha256}"

            identity_file="${qemuPackage}/share/aos/crucible/qemu-build-identity.env"
            grep -Fxq "qemu_atomic_patch_hash=${atomicPatch.sha256}" "$identity_file"
            grep -Fxq "qemu_patch_branch_head_commit=${atomicPatch.commit}" "$identity_file"
            grep -Fxq "qemu_patch_branch_base_commit=${atomicPatch.baseCommit}" "$identity_file"
            grep -q '^qemu_shmem_abi=${shmemAbi}$' "$identity_file"
            grep -q '^qemu_shmem_header_hash=${shmemHeaderHash}$' "$identity_file"

            cp "${atomicPatchRepository}/result" "$out/repository.result"
            cat > "$out/result" <<RESULT
            PASS
            gate=gate:qemu-patch-regeneration
            attr_path=${attrPath}
            qemu_version=${atomicPatch.qemuVersion}
            atomic_patch=${atomicPatch.file}
            atomic_patch_hash=${atomicPatch.sha256}
            atomic_patch_commit=${atomicPatch.commit}
            atomic_patch_tree=${atomicPatch.tree}
            atomic_patch_regenerated_exactly=true
            apply_commit_tree_verified=true
            bundle_matches_patch_commit=true
            qemu_package_identity_verified=true
            qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,atomic_patch_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash
            RESULT
          '';
        }
      ];
      passthru = {
        inherit attrPath taskIds openTaskIds dependencies;
        gateName = "gate:qemu-patch-regeneration";
        atomicPatchRepository = atomicPatchRepository;
      };
    }
