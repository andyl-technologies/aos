{
  pkgs,
  lib,
  checkpointDeltaFlight,
  attrPath ? "checks.crucible.phase5.gates.exactClosureStreaming",
  taskIds ? ["T-CAM-5.3"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-exact-closure-streaming";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
        checkpointDeltaFlight
      ]
      ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
        '';
      }
      {
        name = "run-exact-closure-streaming";
        script = ''
          set -eu
          target="$TMPDIR/exact-closure-streaming-target"

          run_exact_lib_test() {
            package=$1
            name=$2

            if listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib \
              "$name" \
              -- --exact --list 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$listing" >&2
              exit "$status"
            fi
            test "$(printf '%s\n' "$listing" | grep -Fxc "$name: test")" -eq 1

            if output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib \
              "$name" \
              -- --exact --test-threads=1 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            printf '%s\n' "$output" \
              | grep -Fq 'test result: ok. 1 passed;'
          }

          run_exact_lib_test \
            crucible-api \
            vm_lifecycle::checkpoint_store::tests::portable_closure_inventory_streams_only_authenticated_manifest_objects
          run_exact_lib_test \
            crucible-api \
            vm_lifecycle::checkpoint_store::tests::file_artifact_stream_authenticates_sparse_file_contents
          run_exact_lib_test \
            crucible-api \
            vm_lifecycle::checkpoint_store::tests::chunked_artifact_stream_recreates_sparse_zero_extents
          run_exact_lib_test \
            crucible-campaign \
            merkle::tests::many_deterministic_permutations_produce_one_root_and_valid_closure
          run_exact_lib_test \
            crucible-campaign \
            merkle::tests::incomplete_and_inconsistent_nodes_fail_closed

          grep -Fxq PASS ${checkpointDeltaFlight}/result
          grep -Fxq 'direct_delta_reconstruction_equal=true' \
            ${checkpointDeltaFlight}/result
          grep -Fxq 'checkpoint_restore_equal=true' \
            ${checkpointDeltaFlight}/result

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:exact-closure-streaming
          tasks=${builtins.concatStringsSep "," taskIds}
          live_direct_delta_equivalence=true
          authenticated_file_stream=true
          chunked_sparse_zero_extents_recreated=true
          authenticated_manifest_inventory=true
          streaming_merkle_closure=true
          incomplete_streaming_closure_rejected=true
          RESULT
        '';
      }
    ];
  }
