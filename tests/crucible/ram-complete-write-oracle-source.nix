# Reconstructs complete source for a fixed diagnostic, without native execution.
{
  pkgs,
  omitNotification ? false,
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  expectedCommit = "fcf3a33f36506fd0f8418ccf9d026d9ed1f35ec0";
  repository = import ./_qemu-atomic-patch-repository.nix {inherit pkgs;};
  transform = ./ram-complete-write-oracle-transform.py;
  controls = ./ram-complete-write-oracle-transform-tests.py;
  role =
    if omitNotification
    then "notification-adversary"
    else "oracle-positive";
in
  assert atomicPatch.commit == expectedCommit;
    pkgs.mkDerivation {
      pname = "crucible-complete-write-${role}-source";
      version = "0";
      src = null;
      dontStrip = true;
      dontNukeRefs = true;
      dontPatchELF = true;
      buildDeps = [pkgs.coreutils pkgs.diffutils pkgs.git pkgs.grep pkgs.python3 pkgs.tar];
      phases = [
        {
          name = "reconstruct-fixed-oracle-source";
          script = ''
            set -eu
            grep -Fxq PASS ${repository}/result
            grep -Fxq 'commit=${expectedCommit}' ${repository}/result
            grep -Fxq 'pinned_bundle_identity_authenticated=true' ${repository}/result
            grep -Fxq 'source_reconstruction_inventory_verified=true' ${repository}/result

            mkdir -p "$out/source" "$out/evidence"
            git --git-dir=${repository}/repo.git archive ${expectedCommit} \
              | tar -x -C "$out/source"
            tar -xf ${repository}/source-supplement.tar -C "$out/source"
            python3 -B ${controls} \
              --physical-source "$out/source/system/physmem.c" \
              --paged-source "$out/source/plugins/crucible-paged-ram.c" \
              --transform-tool ${transform} \
              > "$out/evidence/source-controls.log" 2>&1
            python3 -B ${transform} \
              --physical-source "$out/source/system/physmem.c" \
              --paged-source "$out/source/plugins/crucible-paged-ram.c" \
              --role ${role} \
              --output-file "$TMPDIR/derived-physmem.c" \
              --manifest "$out/evidence/source-transformation.json"
            set +e
            diff -u --label system/physmem.c --label system/physmem.c \
              "$out/source/system/physmem.c" "$TMPDIR/derived-physmem.c" \
              > "$out/evidence/source-transformation.diff"
            difference_status=$?
            set -e
            test "$difference_status" -eq ${
              if omitNotification
              then "1"
              else "0"
            }
            cp "$TMPDIR/derived-physmem.c" "$out/source/system/physmem.c"

            # Retain the full derived tree and exact recipe; no runtime verdict
            # follows from the source checks or unsigned adversary derivation.
            tar --sort=name --format=gnu --mtime=@0 --owner=0 --group=0 \
              --numeric-owner -cf "$out/corresponding-source.tar" \
              -C "$out/source" .
            sha256sum "$out/corresponding-source.tar" > "$out/evidence/source.sha256"
            cp ${transform} "$out/evidence/transform.py"
            cp ${controls} "$out/evidence/source-controls.py"
            cp ${./ram-complete-write-oracle-evidence.py} "$out/evidence/evidence.py"
            cp ${./ram-complete-write-oracle-evidence-tests.py} "$out/evidence/evidence-controls.py"
            python3 -B ${./ram-complete-write-oracle-evidence-tests.py} \
              --evidence-tool ${./ram-complete-write-oracle-evidence.py} \
              > "$out/evidence/evidence-controls.log" 2>&1
            cat > "$out/result" <<RESULT
            PASS
            artifact_role=test-only-non-distributable-${role}-source
            base_native_commit=${expectedCommit}
            base_native_tree=${atomicPatch.tree}
            base_atomic_patch_sha256=${atomicPatch.sha256}
            notification_omitted_after_first_horizon=${
              if omitNotification
              then "true"
              else "false"
            }
            complete_transformed_corresponding_source_retained=true
            native_execution_qualified=false
            original_payer_and_complete_16k_stack_qualified=false
            RESULT
          '';
        }
      ];
    }
