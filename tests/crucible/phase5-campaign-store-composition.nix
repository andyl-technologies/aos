{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignStoreComposition",
  taskIds ? ["T-CAM-5.5" "T-CAM-5.6" "T-CAM-5.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-store-composition";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
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
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-campaign-store-composition";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-campaign-store-composition-target"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cas \
            --test gate_campaign_store_composition \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cli \
            --features test-double \
            --test gate_campaign_store_composition \
            -- --test-threads=1

          run_exact_lib_test() {
            package=$1
            test_name=$2
            listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$test_name" \
              -- --list)
            printf '%s\n' "$listing" | grep -Fqx "$test_name: test"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$test_name" \
              -- --exact --test-threads=1
          }

          # Cover the admitted specialized layers through their real graph
          # implementations; each exact name is first required to list once.
          for cas_test in \
            content_store::tests::profile_and_namespace_boundaries_compose_at_the_graph_root \
            content_store::tests::compressed_directory_is_a_bounded_versioned_graph_leaf \
            content_store::tests::encrypted_directory_graph_identity_excludes_secret_key_material \
            content_store::tests::compressed_encrypted_directory_is_a_versioned_graph_leaf \
            content_store::tests::logical_and_physical_quotas_compose_without_an_admin_bypass \
            content_store::tests::durable_write_back_survives_restart_and_exposes_exact_retention_roots \
            content_store::tests::write_back_journal_recovers_torn_tail_and_rejects_corruption \
            content_store::tests::packed_store_graph_is_admitted_and_requires_an_isolated_persistent_root \
            content_store::s3::tests::graph_binds_exact_endpoint_capability_and_canonical_configuration
          do
            run_exact_lib_test crucible-cas "$cas_test"
          done

          # Exercise the daemon owner's restart, interrupted journal, quota,
          # cache, write-back-root, packed, and S3 global-GC paths.
          for daemon_test in \
            campaign_gc::tests::policy_aware_gc_evicts_a_wrapped_read_through_cache_with_a_required_copy \
            campaign_gc::tests::write_back_journal_roots_are_planned_and_revalidated_before_gc_deletion \
            campaign_gc::tests::interrupted_apply_retains_journal_and_requires_a_fresh_plan \
            campaign_gc::tests::directory_plan_journal_and_apply_survive_full_backend_restart \
            campaign_gc::tests::compressed_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::compressed_encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::logical_quota_graph_gc_reclaims_admission_capacity_across_restart \
            campaign_gc::tests::packed_graph_admin_drives_restart_safe_logical_gc_without_deleting_live_pack_bytes \
            campaign_gc::tests::s3::s3_graph_admin_drives_global_gc_across_restart
          do
            run_exact_lib_test crucible-daemon "$daemon_test"
          done

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-store-composition
          allowed_transparent_layer_orders=6
          routes=true
          tiers=true
          write_through=true
          write_back=true
          public_store_owner=true
          global_gc=true
          interrupted_gc_journal=true
          packed_restart_and_repack=true
          specialized_layers=compressed,encrypted,compressed-encrypted,logical-quota,physical-quota,namespaced,profile-validated,s3
          RESULT
        '';
      }
    ];
  }
