//! Fail-closed immutable/scalar packed cutover at a rooted FinalForce portal.
//!
//! The first mutating portal transaction deliberately moves only reachable
//! strings, paths, lists, attrsets, and boxed scalars. Lambdas, primops,
//! thunks, externals, and their frames remain in flat storage. This is a real
//! publication and source-retirement bridge, but it is not the complete
//! thunk/frame rotation required by the memory acceptance target.
//! At the replay-free pre-FinalForce seam only, the healed precise scan also
//! drives a validate-then-retire worker sweep after immutable source removal.
//! That ordering matters: before removal, an otherwise unreachable permanent
//! hash-cons candidate can be resurrected and must keep its worker edges live.
//!
//! Preparation allocates and validates the complete destination, retained-edge
//! healing, weak-index replacements, immutable-source retirement inventory,
//! and exact root stage before installing a packed owner. Once installation
//! succeeds, the transaction only rolls forward: roots are committed
//! allocation-free, and any later audit failure keeps every old source store
//! alive while evaluation continues with the semantically valid packed owner.

use super::*;

const ENABLE_ENV: &str = "AOS_NIX_PACKED_PORTAL_CUTOVER";
const PREFINAL_ENABLE_ENV: &str = "AOS_NIX_PACKED_PREFINAL_CUTOVER";
const ORDINAL_ENV: &str = "AOS_NIX_PACKED_PORTAL_CUTOVER_ORDINAL";
const SAFETY_BYTES_ENV: &str = "AOS_NIX_PACKED_PORTAL_SAFETY_BYTES";
const DEFAULT_ORDINAL: u64 = 160;
const DEFAULT_SAFETY_BYTES: usize = 8 * 1024 * 1024;
const RSS_CEILING_BYTES: usize = 239_054_848;

/// Result of one default-off portal cutover attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PackedPortalCutoverOutcome {
    /// The runtime door was closed or source-untouched preparation declined.
    Declined,
    /// A packed owner and healed roots were published, but old sources remain.
    PublishedSourcesRetained,
    /// Publication passed the zero-alias audit and retired old source stores.
    Retired(PackedPortalCutoverReport),
}

/// Auditable counts for one completed immutable/scalar source retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PackedPortalCutoverReport {
    /// Reachable immutable/scalar objects copied into packed lanes.
    pub(super) moved_objects: usize,
    /// Reachable flat owners left in their existing stores.
    pub(super) retained_objects: usize,
    /// Flat-owner fields rewritten to packed child coordinates.
    pub(super) healed_fields: usize,
    /// Immutable source allocations physically retired.
    pub(super) retired_immutable_objects: usize,
    /// Boxed integer source cells physically retired.
    pub(super) retired_boxed_ints: usize,
    /// Boxed float source cells physically retired.
    pub(super) retired_boxed_floats: usize,
    /// Source-store zero-liveness pages considered for physical advice.
    pub(super) source_candidate_pages: usize,
    /// Source-store pages for which the operating system accepted advice.
    pub(super) source_advised_pages: usize,
    /// Whether immutable or scalar source-store page advice failed.
    pub(super) source_advice_failed: bool,
    /// Unreachable worker closures/records retired after immutable cutover.
    pub(super) retired_worker_objects: usize,
    /// Zero-liveness reservation pages re-enumerated after the worker sweep.
    ///
    /// This includes already-advised immutable pages, so it is not exclusive
    /// worker-lane physical credit.
    pub(super) post_sweep_candidate_pages: usize,
    /// Re-enumerated reservation pages accepted by post-sweep advice.
    pub(super) post_sweep_advised_pages: usize,
    /// Whether reservation advice failed after the worker sweep.
    pub(super) post_sweep_advice_failed: bool,
    /// Initialized bytes in the packed destination owner.
    pub(super) destination_initialized_bytes: usize,
    /// Allocator-capacity bytes in the packed destination owner.
    pub(super) destination_capacity_bytes: usize,
    /// Strictly admitted source/destination overlap peak.
    pub(super) projected_peak_bytes: usize,
    /// Admission margin below the strict half-stock ceiling.
    pub(super) admission_headroom_bytes: usize,
    /// Process RSS observed before destination preparation.
    pub(super) rss_before_bytes: usize,
    /// Process RSS observed after source retirement, when available.
    pub(super) rss_after_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct PreparedTelemetry {
    moved_objects: usize,
    retained_objects: usize,
    destination_initialized_bytes: usize,
    destination_capacity_bytes: usize,
    projected_peak_bytes: usize,
    admission_headroom_bytes: usize,
    rss_before_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreinstallRssAdmission {
    projected_peak_bytes: usize,
    admission_headroom_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
enum PortalRssAdmission {
    LiveProcess,
    Fixed(usize),
}

impl TreeWalk {
    /// Runs the packed transaction at the rooted loop head before FinalForce.
    ///
    /// Unlike the ordinal portal, this seam does not unwind or replay any
    /// evaluator work. A failed preflight or transaction simply leaves the
    /// original flat heap and dispatcher roots in place.
    pub(super) fn maybe_publish_packed_prefinal_cutover(&mut self) {
        if std::env::var(PREFINAL_ENABLE_ENV).ok().as_deref() != Some("1") {
            return;
        }
        let Some(safety_bytes) = packed_portal_safety_bytes() else {
            emit_decline(0, "prefinal-invalid-safety-bytes");
            return;
        };
        let guard = match self.dispatcher_collection_poll_preflight() {
            Ok(guard) => guard,
            Err(error) => {
                emit_decline_with_error(0, "prefinal-collection-preflight", &error);
                return;
            }
        };
        self.publish_packed_portal_roots(
            0,
            guard.into_roots(),
            PortalRssAdmission::LiveProcess,
            safety_bytes,
            true,
        );
    }

    /// Runs the immutable/scalar cutover when its exact portal door is open.
    ///
    /// The guard is always consumed because it names a single suspended heap
    /// state. A closed or malformed runtime door performs no heap mutation.
    pub(super) fn maybe_publish_packed_final_force_portal(
        &mut self,
        ordinal: u64,
        guard: super::collection_poll::CollectionPollGuard,
    ) -> PackedPortalCutoverOutcome {
        if !packed_portal_cutover_enabled(ordinal) {
            return PackedPortalCutoverOutcome::Declined;
        }
        let Some(safety_bytes) = packed_portal_safety_bytes() else {
            emit_decline(ordinal, "invalid-safety-bytes");
            return PackedPortalCutoverOutcome::Declined;
        };
        self.publish_packed_portal_roots(
            ordinal,
            guard.into_roots(),
            PortalRssAdmission::LiveProcess,
            safety_bytes,
            false,
        )
    }

    /// Publishes one already-proven root set under explicit admission inputs.
    ///
    /// This seam keeps environment parsing and process sampling out of focused
    /// transaction tests. All errors before owner installation leave the heap
    /// and roots untouched. Errors after installation retain old sources and
    /// return [`PackedPortalCutoverOutcome::PublishedSourcesRetained`].
    fn publish_packed_portal_roots(
        &mut self,
        ordinal: u64,
        roots: EvalRootSet,
        rss_admission: PortalRssAdmission,
        safety_bytes: usize,
        sweep_workers_after_retirement: bool,
    ) -> PackedPortalCutoverOutcome {
        let scan = match self.heap.scan_precise_roots(&roots) {
            Ok(scan) => scan,
            Err(error) => {
                emit_decline_with_error(ordinal, "precise-scan", &error);
                return PackedPortalCutoverOutcome::Declined;
            }
        };
        // Sampling after the precise scan charges both its retained vectors
        // and any allocator-resident worklist/visited scratch before the
        // destination starts growing.
        let rss_before_bytes = match rss_admission {
            PortalRssAdmission::LiveProcess => match current_rss_bytes() {
                Some(bytes) => bytes,
                None => {
                    emit_decline(ordinal, "post-scan-rss-unavailable");
                    return PackedPortalCutoverOutcome::Declined;
                }
            },
            PortalRssAdmission::Fixed(bytes) => bytes,
        };
        let Some(root_stage_scratch_bytes) = roots
            .len()
            .checked_mul(std::mem::size_of::<(usize, Value)>())
        else {
            emit_decline(ordinal, "root-stage-byte-overflow");
            return PackedPortalCutoverOutcome::Declined;
        };
        let prepared = match self.heap.prepare_packed_publication(
            &scan,
            crate::eval::heap::PackedRotationAdmissionInput {
                current_rss_bytes: rss_before_bytes,
                additional_scratch_bytes: root_stage_scratch_bytes,
                safety_bytes,
            },
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                emit_decline_with_error(ordinal, "preparation", &error);
                return PackedPortalCutoverOutcome::Declined;
            }
        };
        let mut telemetry = PreparedTelemetry {
            moved_objects: prepared.moved_objects(),
            retained_objects: prepared.retained_objects(),
            destination_initialized_bytes: prepared.destination_initialized_bytes(),
            destination_capacity_bytes: prepared.destination_capacity_bytes(),
            projected_peak_bytes: prepared.projected_peak_bytes(),
            admission_headroom_bytes: prepared.admission_headroom_bytes(),
            rss_before_bytes,
        };
        let root_stage = match self.stage_packed_mutator_roots(prepared.root_rewrites()) {
            Ok(stage) => stage,
            Err(error) => {
                emit_decline_with_error(ordinal, "root-stage", &error);
                return PackedPortalCutoverOutcome::Declined;
            }
        };
        if root_stage.capacity_bytes() != Some(root_stage_scratch_bytes) {
            emit_decline(ordinal, "root-stage-capacity-changed");
            return PackedPortalCutoverOutcome::Declined;
        }
        if matches!(rss_admission, PortalRssAdmission::LiveProcess) {
            let Some(final_admission) = preinstall_peak_admission(ordinal, safety_bytes) else {
                return PackedPortalCutoverOutcome::Declined;
            };
            telemetry.projected_peak_bytes = telemetry
                .projected_peak_bytes
                .max(final_admission.projected_peak_bytes);
            telemetry.admission_headroom_bytes = RSS_CEILING_BYTES - telemetry.projected_peak_bytes;
        }
        drop(scan);
        drop(roots);

        let commit = match self.heap.publish_prepared_packed(prepared) {
            Ok(commit) => commit,
            Err(error) => {
                emit_decline_with_error(ordinal, "owner-install", &error);
                return PackedPortalCutoverOutcome::Declined;
            }
        };
        let (published, root_plan) = commit.into_parts();
        debug_assert_eq!(root_plan.len(), root_stage.rewrite_count());
        drop(root_plan);
        self.commit_packed_mutator_roots(root_stage);

        // Identity-keyed memo entries cannot survive source-coordinate reuse.
        // A borrow conflict is impossible at the declared portal, but remains
        // a fail-closed post-publication condition rather than a panic.
        let memo_cleared = match self.force_payload_memo.try_borrow_mut() {
            Ok(mut memo) => {
                memo.clear();
                true
            }
            Err(error) => {
                emit_published_retained(ordinal, telemetry, "memo-clear", &error);
                false
            }
        };
        if !memo_cleared {
            return PackedPortalCutoverOutcome::PublishedSourcesRetained;
        }

        let healed_roots = match self.mutator_root_set() {
            Ok(roots) => roots,
            Err(error) => {
                emit_published_retained(ordinal, telemetry, "healed-roots", &error);
                return PackedPortalCutoverOutcome::PublishedSourcesRetained;
            }
        };
        let healed_scan = match self.heap.scan_precise_roots(&healed_roots) {
            Ok(scan) => scan,
            Err(error) => {
                emit_published_retained(ordinal, telemetry, "healed-scan", &error);
                return PackedPortalCutoverOutcome::PublishedSourcesRetained;
            }
        };
        let audited = match self
            .heap
            .audit_packed_source_aliases(&healed_scan, published)
        {
            Ok(audited) => audited,
            Err(failure) => {
                eprintln!(
                    "aos_nix_packed_portal_cutover_retained \
                     ordinal={ordinal} stage=source-alias-audit \
                     residual_aliases={} moved_objects={} \
                     retained_objects={} destination_initialized_bytes={} \
                     destination_capacity_bytes={} projected_peak_bytes={} \
                     admission_headroom_bytes={} rss_before_bytes={}",
                    failure.residual_aliases(),
                    telemetry.moved_objects,
                    telemetry.retained_objects,
                    telemetry.destination_initialized_bytes,
                    telemetry.destination_capacity_bytes,
                    telemetry.projected_peak_bytes,
                    telemetry.admission_headroom_bytes,
                    telemetry.rss_before_bytes,
                );
                drop(failure.into_published());
                return PackedPortalCutoverOutcome::PublishedSourcesRetained;
            }
        };
        drop(healed_roots);

        let retirement = match self.heap.retire_published_packed_source(audited) {
            Ok(report) => report,
            Err(error) => {
                emit_published_retained(ordinal, telemetry, "source-retirement", &error);
                return PackedPortalCutoverOutcome::PublishedSourcesRetained;
            }
        };
        let worker_retirement = if sweep_workers_after_retirement {
            match self
                .heap
                .sweep_unreachable_worker_records_from_precise_scan(&healed_scan)
            {
                Ok(report) => Some(report),
                Err(error) => {
                    // The scan-driven collector validates its complete
                    // selection before mutation. Immutable publication is
                    // already committed, so a decline here keeps that
                    // semantically valid owner and continues forward.
                    emit_worker_sweep_decline(ordinal, telemetry, &error);
                    None
                }
            }
        } else {
            None
        };
        drop(healed_scan);
        let rss_after_bytes = current_rss_bytes().unwrap_or(0);
        let immutable = retirement.immutable();
        let scalars = retirement.scalars();
        let (scalar_candidate_pages, scalar_advised_pages, scalar_advice_failed) =
            match scalars.zero_page_advice() {
                Some(Ok(advice)) => (advice.candidate_pages(), advice.applied_pages(), false),
                Some(Err(_)) => (0, 0, true),
                None => (0, 0, false),
            };
        let report = PackedPortalCutoverReport {
            moved_objects: retirement.moved_objects(),
            retained_objects: retirement.retained_objects(),
            healed_fields: retirement.healed_fields(),
            retired_immutable_objects: immutable.retired_objects,
            retired_boxed_ints: scalars.retired_ints(),
            retired_boxed_floats: scalars.retired_floats(),
            source_candidate_pages: immutable
                .candidate_pages
                .saturating_add(scalar_candidate_pages),
            source_advised_pages: immutable.advised_pages.saturating_add(scalar_advised_pages),
            source_advice_failed: immutable.advice_failed || scalar_advice_failed,
            retired_worker_objects: worker_retirement.map_or(0, |report| report.swept()),
            post_sweep_candidate_pages: worker_retirement
                .map_or(0, |report| report.candidate_pages),
            post_sweep_advised_pages: worker_retirement.map_or(0, |report| report.advised_pages),
            post_sweep_advice_failed: worker_retirement.is_some_and(|report| report.advice_failed),
            destination_initialized_bytes: telemetry.destination_initialized_bytes,
            destination_capacity_bytes: telemetry.destination_capacity_bytes,
            projected_peak_bytes: telemetry.projected_peak_bytes,
            admission_headroom_bytes: telemetry.admission_headroom_bytes,
            rss_before_bytes,
            rss_after_bytes,
        };
        eprintln!(
            "aos_nix_packed_portal_cutover \
             ordinal={ordinal} moved_objects={} retained_objects={} \
             healed_fields={} retired_immutable_objects={} \
             retired_boxed_ints={} retired_boxed_floats={} \
             source_candidate_pages={} source_advised_pages={} \
             source_advice_failed={} retired_worker_objects={} \
             post_sweep_candidate_pages={} \
             post_sweep_advised_pages={} post_sweep_advice_failed={} \
             destination_initialized_bytes={} destination_capacity_bytes={} \
             projected_peak_bytes={} admission_headroom_bytes={} \
             rss_before_bytes={} rss_after_bytes={}",
            report.moved_objects,
            report.retained_objects,
            report.healed_fields,
            report.retired_immutable_objects,
            report.retired_boxed_ints,
            report.retired_boxed_floats,
            report.source_candidate_pages,
            report.source_advised_pages,
            report.source_advice_failed,
            report.retired_worker_objects,
            report.post_sweep_candidate_pages,
            report.post_sweep_advised_pages,
            report.post_sweep_advice_failed,
            report.destination_initialized_bytes,
            report.destination_capacity_bytes,
            report.projected_peak_bytes,
            report.admission_headroom_bytes,
            report.rss_before_bytes,
            report.rss_after_bytes,
        );
        PackedPortalCutoverOutcome::Retired(report)
    }
}

fn packed_portal_cutover_enabled(ordinal: u64) -> bool {
    if std::env::var(ENABLE_ENV).ok().as_deref() != Some("1") {
        return false;
    }
    let selected = std::env::var(ORDINAL_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_ORDINAL);
    selected == ordinal
}

fn packed_portal_safety_bytes() -> Option<usize> {
    match std::env::var(SAFETY_BYTES_ENV) {
        Ok(value) => value.parse::<usize>().ok(),
        Err(std::env::VarError::NotPresent) => Some(DEFAULT_SAFETY_BYTES),
        Err(std::env::VarError::NotUnicode(_)) => None,
    }
}

fn current_rss_bytes() -> Option<usize> {
    ProcessResidentMemorySample::current()
        .ok()
        .flatten()
        .map(ProcessResidentMemorySample::resident_bytes)
}

fn preinstall_peak_admission(ordinal: u64, safety_bytes: usize) -> Option<PreinstallRssAdmission> {
    let Some(current) = current_rss_bytes() else {
        emit_decline(ordinal, "preinstall-rss-unavailable");
        return None;
    };
    let peak = match crate::heap::peak_resident_memory_bytes(
        crate::heap::PeakResidentMemoryScope::SelfProcess,
    ) {
        Ok(Some(bytes)) => usize::try_from(bytes).ok(),
        Ok(None) => None,
        Err(error) => {
            emit_decline_with_error(ordinal, "preinstall-peak-rss", &error);
            return None;
        }
    };
    let Some(peak) = peak else {
        emit_decline(ordinal, "preinstall-peak-rss-unavailable");
        return None;
    };
    let Some(admission) = preinstall_rss_admission(current, peak, safety_bytes) else {
        let projected_peak = current.max(peak).checked_add(safety_bytes);
        eprintln!(
            "aos_nix_packed_portal_cutover_decline \
             ordinal={ordinal} stage=preinstall-rss-ceiling \
             current_rss_bytes={current} peak_rss_bytes={peak} \
             safety_bytes={safety_bytes} projected_peak_bytes={projected_peak:?} \
             ceiling_bytes={RSS_CEILING_BYTES}"
        );
        return None;
    };
    Some(admission)
}

fn preinstall_rss_admission(
    current_rss_bytes: usize,
    peak_rss_bytes: usize,
    safety_bytes: usize,
) -> Option<PreinstallRssAdmission> {
    let projected_peak_bytes = current_rss_bytes
        .max(peak_rss_bytes)
        .checked_add(safety_bytes)?;
    if projected_peak_bytes >= RSS_CEILING_BYTES {
        return None;
    }
    Some(PreinstallRssAdmission {
        projected_peak_bytes,
        admission_headroom_bytes: RSS_CEILING_BYTES - projected_peak_bytes,
    })
}

fn emit_decline(ordinal: u64, stage: &'static str) {
    eprintln!("aos_nix_packed_portal_cutover_decline ordinal={ordinal} stage={stage}");
}

fn emit_decline_with_error(ordinal: u64, stage: &'static str, error: &impl std::fmt::Display) {
    eprintln!(
        "aos_nix_packed_portal_cutover_decline ordinal={ordinal} stage={stage} reason={error}"
    );
}

fn emit_published_retained(
    ordinal: u64,
    telemetry: PreparedTelemetry,
    stage: &'static str,
    error: &impl std::fmt::Display,
) {
    eprintln!(
        "aos_nix_packed_portal_cutover_retained \
         ordinal={ordinal} stage={stage} reason={error} \
         moved_objects={} retained_objects={} \
         destination_initialized_bytes={} destination_capacity_bytes={} \
         projected_peak_bytes={} admission_headroom_bytes={} \
         rss_before_bytes={}",
        telemetry.moved_objects,
        telemetry.retained_objects,
        telemetry.destination_initialized_bytes,
        telemetry.destination_capacity_bytes,
        telemetry.projected_peak_bytes,
        telemetry.admission_headroom_bytes,
        telemetry.rss_before_bytes,
    );
}

fn emit_worker_sweep_decline(
    ordinal: u64,
    telemetry: PreparedTelemetry,
    error: &impl std::fmt::Display,
) {
    eprintln!(
        "aos_nix_packed_prefinal_worker_sweep_decline \
         ordinal={ordinal} stage=post-source-retirement reason={error} \
         immutable_and_scalar_sources_already_retired=true \
         moved_objects={} retained_objects={} \
         destination_initialized_bytes={} destination_capacity_bytes={} \
         rss_before_bytes={}",
        telemetry.moved_objects,
        telemetry.retained_objects,
        telemetry.destination_initialized_bytes,
        telemetry.destination_capacity_bytes,
        telemetry.rss_before_bytes,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::string::NixString;
    use crate::syntax::parse_str;

    fn evaluator() -> TreeWalk {
        let parsed = parse_str("null").expect("source parses");
        let resolved = resolve_ast(parsed).expect("source resolves");
        let ir = aos_nix_dialect::nix_lower(resolved).expect("source lowers");
        TreeWalk::new(&ir)
    }

    #[test]
    fn transaction_moves_immutable_root_and_retires_its_source() {
        let mut evaluator = evaluator();
        let source = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"portal".to_vec()))
            .expect("source allocates");
        evaluator.transient_value_stack_roots.push(source);
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, source)
            .expect("root allocates");

        let outcome = evaluator.publish_packed_portal_roots(
            160,
            roots,
            PortalRssAdmission::Fixed(0),
            0,
            true,
        );

        let PackedPortalCutoverOutcome::Retired(report) = outcome else {
            panic!("portal transaction did not retire its source: {outcome:?}");
        };
        let replacement = evaluator.transient_value_stack_roots[0];
        assert!(!replacement.raw_eq(source));
        assert_eq!(report.moved_objects, 1);
        assert_eq!(report.retained_objects, 0);
        assert_eq!(report.retired_immutable_objects, 1);
        assert!(evaluator.heap.get_string(source).is_err());
        assert_eq!(
            evaluator
                .heap
                .get_string_view(replacement)
                .expect("packed root resolves")
                .bytes(),
            b"portal"
        );
    }

    #[test]
    fn unsupported_root_stage_declines_before_owner_installation() {
        let mut evaluator = evaluator();
        let source = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"unsupported".to_vec()))
            .expect("source allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_with_scope(0, source)
            .expect("unsupported root allocates");

        let outcome = evaluator.publish_packed_portal_roots(
            160,
            roots,
            PortalRssAdmission::Fixed(0),
            0,
            true,
        );

        assert_eq!(outcome, PackedPortalCutoverOutcome::Declined);
        assert!(evaluator.heap.packed_generation().is_none());
        assert_eq!(
            evaluator
                .heap
                .get_string(source)
                .expect("source remains live")
                .bytes(),
            b"unsupported"
        );
    }

    #[test]
    fn prefinal_transaction_retires_only_workers_absent_from_healed_scan() {
        let mut evaluator = evaluator();
        let source = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"portal".to_vec()))
            .expect("source allocates");
        let live = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("live thunk allocates");
        let dead = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(IrId::new(2)))
            .expect("dead thunk allocates");
        evaluator.transient_value_stack_roots.push(source);
        evaluator.transient_value_stack_roots.push(live);
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, source)
            .expect("source root allocates");
        roots
            .try_push_value_stack(1, live)
            .expect("worker root allocates");

        let outcome =
            evaluator.publish_packed_portal_roots(0, roots, PortalRssAdmission::Fixed(0), 0, true);

        let PackedPortalCutoverOutcome::Retired(report) = outcome else {
            panic!("prefinal transaction did not retire: {outcome:?}");
        };
        assert_eq!(report.retired_worker_objects, 1);
        evaluator
            .heap
            .get_thunk(live)
            .expect("scanned worker remains live");
        assert!(evaluator.heap.get_thunk(dead).is_err());
    }

    #[test]
    fn final_live_admission_charges_peak_and_safety_strictly() {
        let admitted = preinstall_rss_admission(100, 200, 300)
            .expect("peak plus safety remains below the ceiling");
        assert_eq!(admitted.projected_peak_bytes, 500);
        assert_eq!(admitted.admission_headroom_bytes, RSS_CEILING_BYTES - 500);

        assert_eq!(
            preinstall_rss_admission(RSS_CEILING_BYTES - 2, 0, 1),
            Some(PreinstallRssAdmission {
                projected_peak_bytes: RSS_CEILING_BYTES - 1,
                admission_headroom_bytes: 1,
            })
        );
        assert_eq!(preinstall_rss_admission(RSS_CEILING_BYTES - 1, 0, 1), None);
        assert_eq!(preinstall_rss_admission(usize::MAX, 0, 1), None);
    }
}
