//! Read-only runtime producer for rotating-rollover checkpoint evidence.
//!
//! The probe samples a fixed set of successful final-config completion
//! ordinals while the completion result and evaluator-owned roots are still
//! live. Each checkpoint uses the nested nonmoving root builder and existing
//! weak heap traversal. It deliberately retains only bounded scalar snapshots:
//! no replay input, relocation plan, forwarding state, collection, memory
//! advice, or heap mutation is constructed here.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_ROTATING_ROLLOVER_PROBE";
const TRAVERSAL_ORDINAL_ENV: &str = "AOS_NIX_ROTATING_ROLLOVER_TRAVERSAL_ORDINAL";
const CHECKPOINT_ORDINALS: [u64; 9] = [160, 176, 192, 224, 256, 288, 320, 352, 357];
const CHECKPOINT_COUNT: usize = CHECKPOINT_ORDINALS.len();

/// One scheduled completion's immutable runtime evidence.
#[derive(Clone, Copy, Debug, Default)]
struct RotatingRolloverCheckpoint {
    ordinal: u64,
    runtime_blockers: usize,
    root_error: bool,
    traversal_error: bool,
    rss_unavailable: bool,
    rss_error: bool,
    rss_bytes: u64,
    traversal_selected: bool,
    roots: super::nested_nonmoving_safepoint_probe::NestedNonmovingRootInventory,
    reservation: crate::eval::heap::NestedNonmovingRuntimeReservationSnapshot,
    heap: crate::eval::heap::NestedNonmovingRuntimeHeapSnapshot,
}

impl RotatingRolloverCheckpoint {
    const fn evidence_complete(self) -> bool {
        self.runtime_blockers == 0
            && !self.root_error
            && !self.traversal_error
            && !self.rss_unavailable
            && !self.rss_error
            && self.traversal_selected
            && self.heap.reconciled
            && self.heap.roots == self.roots.total_roots as u64
            && self.reservation.reservation_present
            && self.reservation.residency_available
            && !self.reservation.residency_error
            && self.reservation.page_size != 0
    }
}

/// Bounded process-local state for the fixed rollover schedule.
#[derive(Debug)]
pub(super) struct RotatingRolloverProbe {
    completions: u64,
    scheduled_attempts: u64,
    duplicate_attempts: u64,
    traversal_ordinal: Option<u64>,
    snapshots: [Option<RotatingRolloverCheckpoint>; CHECKPOINT_COUNT],
}

impl RotatingRolloverProbe {
    /// Enables the producer only for an exact opt-in value of `1`.
    pub(super) fn from_env() -> Option<Self> {
        if !std::env::var(ENABLE_ENV).is_ok_and(|value| value == "1") {
            return None;
        }
        let traversal_ordinal = std::env::var(TRAVERSAL_ORDINAL_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| Self::schedule_index(*ordinal).is_some());
        Some(Self::new(traversal_ordinal))
    }

    const fn new(traversal_ordinal: Option<u64>) -> Self {
        Self {
            completions: 0,
            scheduled_attempts: 0,
            duplicate_attempts: 0,
            traversal_ordinal,
            snapshots: [None; CHECKPOINT_COUNT],
        }
    }

    fn schedule_index(ordinal: u64) -> Option<usize> {
        CHECKPOINT_ORDINALS.binary_search(&ordinal).ok()
    }

    fn record(&mut self, index: usize, snapshot: RotatingRolloverCheckpoint) {
        self.scheduled_attempts = self.scheduled_attempts.saturating_add(1);
        let Some(slot) = self.snapshots.get_mut(index) else {
            return;
        };
        if slot.is_some() {
            self.duplicate_attempts = self.duplicate_attempts.saturating_add(1);
            return;
        }
        *slot = Some(snapshot);
    }
}

impl TreeWalk {
    /// Captures one scheduled completion before any other completion probe runs.
    pub(super) fn note_rotating_rollover_final_config_completion(&mut self, result: Value) {
        let Some(probe) = self.rotating_rollover_probe.as_mut() else {
            return;
        };
        probe.completions = probe.completions.saturating_add(1);
        let ordinal = probe.completions;
        let Some(index) = RotatingRolloverProbe::schedule_index(ordinal) else {
            return;
        };

        let mut snapshot = RotatingRolloverCheckpoint {
            ordinal,
            traversal_selected: probe.traversal_ordinal == Some(ordinal),
            ..RotatingRolloverCheckpoint::default()
        };
        match ProcessResidentMemorySample::current() {
            Ok(Some(sample)) => snapshot.rss_bytes = sample.resident_bytes() as u64,
            Ok(None) => snapshot.rss_unavailable = true,
            Err(_) => snapshot.rss_error = true,
        }
        snapshot.reservation = self.heap.nested_nonmoving_runtime_reservation_snapshot();
        let runtime_blockers = self.nested_nonmoving_runtime_blocker_count();
        snapshot.runtime_blockers = runtime_blockers;
        if snapshot.traversal_selected {
            // Active safepoint blockers make this root set incomplete for
            // admission, but the read-only traversal is still an exact lower
            // bound over every root the current builder can name. Retaining
            // that lower bound is useful for locating the missing ownership
            // without weakening `evidence_complete`, which continues to
            // require zero blockers.
            match self.nested_nonmoving_root_set(result) {
                Ok((roots, inventory)) => {
                    snapshot.roots = inventory;
                    match self.heap.nested_nonmoving_runtime_heap_snapshot(&roots) {
                        Ok(heap) => snapshot.heap = heap,
                        Err(_) => snapshot.traversal_error = true,
                    }
                }
                Err(_) => snapshot.root_error = true,
            }
        }

        if let Some(probe) = self.rotating_rollover_probe.as_mut() {
            probe.record(index, snapshot);
        }
    }

    /// Emits all retained checkpoints and the fail-closed evidence ledger.
    pub(super) fn emit_rotating_rollover_probe_report(&self) {
        let Some(probe) = self.rotating_rollover_probe.as_ref() else {
            return;
        };
        for snapshot in probe.snapshots.iter().flatten().copied() {
            eprintln!(
                "aos_nix_rotating_rollover_checkpoint \
                 ordinal={} evidence_complete={} runtime_blockers={} root_error={} \
                 traversal_error={} rss_unavailable={} rss_error={} rss_bytes={} \
                 sampling_order=process_rss_then_reservation_then_roots_then_traversal \
                 process_rss_pre_scan=true reservation_pre_scan=true \
                 traversal_selected={} traversal_skipped={} \
                 traversal_is_named_root_lower_bound={} \
                 traversal_scratch_pollutes_later_rss=true post_scan_rss_recorded=false \
                 roots={} result_roots={} pending_values={} pending_env_values={} \
                 pending_flat_owners={} native_shadow_values={} \
                 traversal_roots={} retained_seed_roots={} reachable={} allocated={} \
                 unreachable={} reconciled={} root_count_reconciled={} \
                 reservation_present={} reservation_virtual_bytes={} \
                 reservation_used_bytes={} reservation_low_used_bytes={} \
                 reservation_high_used_bytes={} residency_available={} \
                 residency_error={} page_size={} used_pages={} resident_pages={} \
                 flat_string_path_objects={} flat_list_objects={} \
                 flat_attrs_objects={} flat_closure_objects={} \
                 typed_head_objects={} boxed_scalar_objects={} record_objects={} \
                 collection=false mutation=false advice=false",
                snapshot.ordinal,
                snapshot.evidence_complete(),
                snapshot.runtime_blockers,
                snapshot.root_error,
                snapshot.traversal_error,
                snapshot.rss_unavailable,
                snapshot.rss_error,
                snapshot.rss_bytes,
                snapshot.traversal_selected,
                !snapshot.traversal_selected,
                snapshot.traversal_selected && snapshot.runtime_blockers != 0,
                snapshot.roots.total_roots,
                snapshot.roots.result_roots,
                snapshot.roots.pending_values,
                snapshot.roots.pending_env_values,
                snapshot.roots.pending_flat_owners,
                snapshot.roots.native_shadow_values,
                snapshot.heap.roots,
                snapshot.heap.retained_seed_roots,
                snapshot.heap.reachable,
                snapshot.heap.allocated,
                snapshot.heap.unreachable,
                snapshot.heap.reconciled,
                snapshot.heap.roots == snapshot.roots.total_roots as u64,
                snapshot.reservation.reservation_present,
                snapshot.reservation.reservation_virtual_bytes,
                snapshot.reservation.reservation_used_bytes,
                snapshot.reservation.reservation_low_used_bytes,
                snapshot.reservation.reservation_high_used_bytes,
                snapshot.reservation.residency_available,
                snapshot.reservation.residency_error,
                snapshot.reservation.page_size,
                snapshot.reservation.used_pages,
                snapshot.reservation.resident_pages,
                snapshot.heap.flat_string_path_objects,
                snapshot.heap.flat_list_objects,
                snapshot.heap.flat_attrs_objects,
                snapshot.heap.flat_closure_objects,
                snapshot.heap.typed_head_objects,
                snapshot.heap.boxed_scalar_objects,
                snapshot.heap.record_objects,
            );
        }

        let retained = probe.snapshots.iter().flatten().count();
        let complete = probe
            .snapshots
            .iter()
            .flatten()
            .filter(|snapshot| snapshot.evidence_complete())
            .count();
        let missing = CHECKPOINT_COUNT.saturating_sub(retained);
        eprintln!(
            "aos_nix_rotating_rollover_blockers \
             missing_continuous_interval_event_coverage=true \
             missing_disjoint_cross_domain_page_unions=true \
             missing_external_identity_lifecycle=true \
             missing_writable_root_edge_provenance=true \
             missing_exact_destination_layout=true \
             missing_paired_exact_cpp_peak=true \
             missing_old_domain_unmap_evidence=true \
             blocker_domains=7 replay_input_constructed=false \
             admission_engine_called=false collection=false mutation=false advice=false"
        );
        eprintln!(
            "aos_nix_rotating_rollover_conservation \
             schedule_len={} completions={} scheduled_attempts={} retained={} \
             complete={} missing={} duplicate_attempts={} bounded=true \
             traversal_ordinal={:?} single_traversal_per_process=true \
             schedule_fully_observed={} all_checkpoint_evidence_complete={} \
             admitted=false collection=false mutation=false advice=false",
            CHECKPOINT_COUNT,
            probe.completions,
            probe.scheduled_attempts,
            retained,
            complete,
            missing,
            probe.duplicate_attempts,
            probe.traversal_ordinal,
            missing == 0,
            complete == CHECKPOINT_COUNT,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_exact_and_strictly_increasing() {
        assert_eq!(
            CHECKPOINT_ORDINALS,
            [160, 176, 192, 224, 256, 288, 320, 352, 357]
        );
        assert!(CHECKPOINT_ORDINALS.windows(2).all(|pair| pair[0] < pair[1]));
        for (index, ordinal) in CHECKPOINT_ORDINALS.into_iter().enumerate() {
            assert_eq!(RotatingRolloverProbe::schedule_index(ordinal), Some(index));
        }
        assert_eq!(RotatingRolloverProbe::schedule_index(191), None);
        assert_eq!(RotatingRolloverProbe::schedule_index(193), None);
    }

    #[test]
    fn storage_is_bounded_and_duplicate_attempts_conserve() {
        let mut probe = RotatingRolloverProbe::new(Some(192));
        for (index, ordinal) in CHECKPOINT_ORDINALS.into_iter().enumerate() {
            probe.record(
                index,
                RotatingRolloverCheckpoint {
                    ordinal,
                    ..RotatingRolloverCheckpoint::default()
                },
            );
        }
        probe.record(0, RotatingRolloverCheckpoint::default());
        assert_eq!(probe.snapshots.iter().flatten().count(), CHECKPOINT_COUNT);
        assert_eq!(probe.scheduled_attempts, CHECKPOINT_COUNT as u64 + 1);
        assert_eq!(probe.duplicate_attempts, 1);
    }

    #[test]
    fn incomplete_external_evidence_fails_closed() {
        let checkpoint = RotatingRolloverCheckpoint {
            ordinal: 192,
            roots: super::super::nested_nonmoving_safepoint_probe::NestedNonmovingRootInventory {
                total_roots: 1,
                result_roots: 1,
                ..Default::default()
            },
            heap: crate::eval::heap::NestedNonmovingRuntimeHeapSnapshot {
                roots: 1,
                reconciled: true,
                ..Default::default()
            },
            reservation: crate::eval::heap::NestedNonmovingRuntimeReservationSnapshot {
                reservation_present: true,
                residency_available: true,
                page_size: 4096,
                ..Default::default()
            },
            rss_bytes: 1,
            traversal_selected: true,
            ..RotatingRolloverCheckpoint::default()
        };
        assert!(checkpoint.evidence_complete());

        let traversal_skipped = RotatingRolloverCheckpoint {
            traversal_selected: false,
            ..checkpoint
        };
        assert!(!traversal_skipped.evidence_complete());

        let missing_residency = RotatingRolloverCheckpoint {
            reservation: crate::eval::heap::NestedNonmovingRuntimeReservationSnapshot {
                residency_available: false,
                ..checkpoint.reservation
            },
            ..checkpoint
        };
        assert!(!missing_residency.evidence_complete());
    }
}
