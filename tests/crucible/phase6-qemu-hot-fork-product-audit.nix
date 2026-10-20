# Certifies the representative nginx/curl product from the retained Phase 7
# flights, without running a second copy of their QEMU stress matrix.
{
  pkgs,
  attrPath ? "checks.crucible.phase6.qemuHotForkProductAudit",
  taskIds ? [],
  readiness,
  nativeAtomic,
  nativeEquivalence,
  nativeScaling,
}:
pkgs.mkDerivation {
  pname = "crucible-phase6-hot-fork-product-audit";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep readiness nativeAtomic nativeEquivalence nativeScaling];
  phases = [
    {
      name = "certify-representative-hot-fork";
      script = ''
        set -eu
        mkdir -p "$out/evidence"

        require_one() {
          expected="$1"
          evidence="$2"
          count=$(grep -Fxc "$expected" "$evidence" || true)
          [ "$count" -eq 1 ] || {
            echo "expected one '$expected' in $evidence, found $count" >&2
            exit 1
          }
        }

        require_present() {
          grep -Fxq "$1" "$2" || {
            echo "missing '$1' in $2" >&2
            exit 1
          }
        }

        for gate in ${readiness} ${nativeAtomic} ${nativeEquivalence} ${nativeScaling}; do
          require_one PASS "$gate/result"
        done
        cp ${readiness}/result "$out/evidence/readiness.result"
        for flight in atomic equivalence scaling; do
          case "$flight" in
            atomic) source=${nativeAtomic} ;;
            equivalence) source=${nativeEquivalence} ;;
            scaling) source=${nativeScaling} ;;
          esac
          tr -d '\r' < "$source/serial.log" > "$out/evidence/$flight.serial.log"
        done

        readiness="$out/evidence/readiness.result"
        atomic="$out/evidence/atomic.serial.log"
        equivalence="$out/evidence/equivalence.serial.log"
        scaling="$out/evidence/scaling.serial.log"

        require_one 'gate=gate:hot-fork-readiness' "$readiness"
        require_one 'rcu_barrier_quiescence_proof_bound=true' "$readiness"
        require_one 'plugin_resource_inventory_stable=true' "$readiness"
        require_one 'plugin_mapping_dontfork_unregistered=false' "$readiness"
        require_one 'private_ring_standalone_source_mapping_unbound=true' "$readiness"
        require_one 'private_ring_live_descriptor_transaction=true' "$readiness"
        require_one 'private_ring_exact_identity_and_seal=true' "$readiness"
        require_one 'template_coordinator_schema_version=29' "$readiness"

        require_one 'gate=gate:world-fork-atomicity' "$atomic"
        require_present 'factory=production-whole-world' "$atomic"
        require_present 'source=two-running-one-permanently-failed' "$atomic"
        require_present 'io=block,ninep' "$atomic"
        require_present 'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial' "$atomic"
        require_present 'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' "$atomic"
        require_present 'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' "$atomic"
        require_present 'native_real_resource_alias_rejected_before=child-readiness,world-publication' "$atomic"
        require_present 'final_resource_audit=process,descriptors,memory,attempt-storage,content-store' "$atomic"
        # The unregistered and unbound mapping checks reject invented proofs;
        # live preparation and adoption require the closed QEMU inventory.
        grep -Fq 'atomic-world phase=source-prepared ' "$atomic"
        grep -Fq 'atomic-world phase=all-world-adopted ' "$atomic"

        require_one 'gate=gate:hot-fork-equivalence' "$equivalence"
        require_present 'reference_tiers=thin-replay,exact-checkpoint' "$equivalence"
        require_present 'child_boundary_matches_capture=true' "$equivalence"
        require_present 'child_suffix_matches_exact_restore=true' "$equivalence"
        require_present 'child_suffix_matches_genesis_replay=true' "$equivalence"
        require_present 'application_http_status=200' "$equivalence"

        require_one 'gate=gate:hot-fork-scaling' "$scaling"
        require_present 'known_dirty_guest_pages=1024' "$scaling"
        require_present 'memory_metrics=VmPTE,VmData,AnonHugePages,numa_maps' "$scaling"
        require_present 'source_private_dirty_late_growth_limit_kib=4096' "$scaling"
        require_present 'source_descriptors_leaked=0' "$scaling"
        require_present 'hot_checkpoint_fallback_authentication=exact-checkpoint-id' "$scaling"
        require_present 'thin_fallback_after_source_retirement=authenticated' "$scaling"
        require_present 'production_whole_world_lifecycles=10000' "$scaling"
        require_present 'final_resource_audit=process,descriptors,memory,attempt-storage,content-store' "$scaling"

        cat > "$out/result" <<RESULT
        PASS
        check=${attrPath}
        gate=gate:hot-fork-product-audit
        tasks=${builtins.concatStringsSep "," taskIds}
        representative_product=nginx,curl,block,ninep
        live_template_quiescence_and_mapping_admitted=true
        private_child_resources_and_rejection_authenticated=true
        dirty_page_growth_and_descriptor_leaks_bounded=true
        exact_restore_and_thin_replay_equivalent=true
        fallback_paths_authenticated=exact,thin
        final_process_descriptor_memory_disk_store_audit=true
        RESULT
      '';
    }
  ];
}
