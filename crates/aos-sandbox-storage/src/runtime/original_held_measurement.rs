//! Resident original requests and exclusive loans for confined held measurement.
//!
//! Attempting is installed before the first kernel pair. A failed or unwound
//! attempt remains resident and cannot sample a replacement deadline. The
//! short loan rejoins the actual startup, signature pins, protected selection
//! and clock before each transport boundary; it never exports portable effect
//! authority or proves that another owner is drained.

use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V3, MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1,
    decode_acquire_request,
};

use crate::activation::{StorageOriginalWorkerStartupCauseV3, StorageOriginalWorkerStartupV3};
use crate::live_export_request_trust::{
    AuthenticatedStorageNativeRequestV2, StorageLiveExportRequestTrustErrorV1,
};
use crate::process::original_cutoff::{
    MAXIMUM_ORIGINAL_BODY_BYTES, OriginalWorkerCutoffErrorV3, encode_cutoff,
};
use crate::process::{
    HeldReaderOwnerCaptureV3, OriginalHeldWorkerProgressV3, SystemdHeldSnapshotReaderV1,
};

use super::*;

const MAXIMUM_RESIDENT_ORIGINALS: usize = 8;
const ORIGINAL_RESERVATION_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_RESIDENT_BYTES: usize = MAXIMUM_RESIDENT_ORIGINALS * ORIGINAL_RESERVATION_BYTES;
pub(super) const MAXIMUM_ORIGINAL_RECHECKS: usize = 24;
// The sole existing signed Root envelope has 140 framing/signer bytes and a
// 64-byte signature. This is an allocation bound, not a parallel serializer.
const SIGNED_ROOT_OVERHEAD_BYTES: usize = 204;
const SIGNED_NATIVE_OVERHEAD_BYTES: usize = 24 + 184;
const MAXIMUM_SELECTION_BYTES: usize = 6 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalHeldMeasurementErrorV3 {
    #[error(transparent)]
    Startup(#[from] StorageOriginalWorkerStartupCauseV3),
    #[error(transparent)]
    Trust(#[from] StorageLiveExportRequestTrustErrorV1),
    #[error(transparent)]
    Runtime(#[from] StorageRuntimeError),
    #[error(transparent)]
    Service(#[from] crate::service::StorageServiceError),
    #[error(transparent)]
    Issuance(#[from] crate::native_issuance::StorageNativeIssuanceErrorV1),
    #[error(transparent)]
    Policy(#[from] crate::resolver::protected_catalog::StorageResolverPolicyError),
    #[error(transparent)]
    Worker(#[from] ZfsWorkerError),
    #[error(transparent)]
    Tree(#[from] crate::held_snapshot_tree::HeldSnapshotTreeErrorV1),
    #[error(transparent)]
    Session(#[from] aos_sandbox_linux::process::FixedProcessRetainedSessionError<OriginalWorkerCutoffErrorV3>),
    #[error(transparent)]
    Wire(#[from] OriginalWorkerCutoffErrorV3),
    #[error("original measurement allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("original measurement admission bound is exhausted")]
    Bound,
    #[error("original measurement is closed or differs from its retained request")]
    Closed,
    #[error("original worker receive failed; the concrete cause remains resident")]
    RetainedReceive,
    #[error("original worker connection admission failed; its custody remains resident")]
    RetainedAdmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OriginalPhase {
    Attempting,
    Measured,
    Unavailable,
    Failed,
}

/// Counts failed partial attempts too; there is no removal or cold constructor.
#[derive(Default)]
pub(super) struct ResidentOriginalMeasurementsV3 {
    pub(super) originals: Vec<ResidentOriginalV3>,
    reserved_bytes: usize,
    pub(super) closed: bool,
    pub(super) first_admission_failure: Option<OriginalHeldMeasurementErrorV3>,
}

pub(super) struct ResidentOriginalV3 {
    acquisition: ObjectDigest,
    pub(super) signed_request: Vec<u8>,
    pub(super) first: Option<RawPairedClockSample>,
    pub(super) cutoff: Option<u64>,
    cutoff_bytes: Vec<u8>,
    pub(super) phase: OriginalPhase,
    pub(super) dispatch: Option<repair_worker_drain::WorkerDispatchLease>,
    reader: Option<SystemdHeldSnapshotReaderV1>,
    reader_capture: HeldReaderOwnerCaptureV3,
    progress: OriginalHeldWorkerProgressV3,
    pub(super) held: Option<StorageHeldSnapshotReadbackWithMountV1>,
    rechecks: Vec<OriginalHeldWorkerProgressV3>,
    pub(super) reply: Option<aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3>,
    pub(super) packet: Option<Vec<u8>>,
    pub(super) deliveries: [Option<Result<(), ()>>; MAXIMUM_ORIGINAL_RECHECKS],
    pub(super) next_delivery: usize,
    pub(super) first_failure: Option<OriginalHeldMeasurementErrorV3>,
}

impl ResidentOriginalMeasurementsV3 {
    pub(super) fn begin(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
    ) -> Result<(usize, bool), OriginalHeldMeasurementErrorV3> {
        if self.closed {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        // Pre-arm before allocation or decoding. Only this successful begin
        // reopens admission; panic, allocation failure and early return do not.
        self.closed = true;
        let request = authenticated.request();
        let maximum = SIGNED_NATIVE_OVERHEAD_BYTES
            .checked_add(MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1)
            .and_then(|size| size.checked_add(SIGNED_ROOT_OVERHEAD_BYTES))
            .and_then(|size| {
                size.checked_add(request.request().signed_root_request().subject().len())
            })
            .and_then(|size| size.checked_add(60 + 24 + MAXIMUM_SELECTION_BYTES))
            .filter(|size| *size <= MAXIMUM_ORIGINAL_BODY_BYTES)
            .ok_or(OriginalHeldMeasurementErrorV3::Bound)?;
        let root = decode_acquire_request(request.request().signed_root_request().subject())
            .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?;
        if root.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V3
            || root.kernel_coupled()
        {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        let acquisition = root.acquisition_id();
        if let Some(index) = self
            .originals
            .iter()
            .position(|original| original.acquisition == acquisition)
        {
            let original = &self.originals[index];
            let bytes = request.to_canonical_bytes();
            if bytes
                .len()
                .checked_add(60 + 24 + MAXIMUM_SELECTION_BYTES)
                .is_none_or(|size| size > maximum)
                || bytes != original.signed_request
                || !matches!(original.phase, OriginalPhase::Measured | OriginalPhase::Unavailable)
                || original.first_failure.is_some()
            {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            self.closed = false;
            return Ok((index, false));
        }
        let reserved = reserve_original_budget(self.originals.len(), self.reserved_bytes)?;
        self.originals.try_reserve(1)?;
        let index = self.originals.len();
        self.originals.push(ResidentOriginalV3 {
            acquisition,
            signed_request: Vec::new(),
            first: None,
            cutoff: None,
            cutoff_bytes: Vec::new(),
            phase: OriginalPhase::Attempting,
            dispatch: None,
            reader: None,
            reader_capture: HeldReaderOwnerCaptureV3::default(),
            progress: OriginalHeldWorkerProgressV3::default(),
            held: None,
            rechecks: Vec::new(),
            reply: None,
            packet: None,
            deliveries: [None; MAXIMUM_ORIGINAL_RECHECKS],
            next_delivery: 0,
            first_failure: None,
        });
        self.reserved_bytes = reserved;

        // The complete request is bounded before the existing serializer grows
        // any nested Vec. No bytes or signed fields are synthesized here.
        let bytes = request.to_canonical_bytes();
        if bytes
            .len()
            .checked_add(60 + 24 + MAXIMUM_SELECTION_BYTES)
            .is_none_or(|size| size > maximum)
        {
            return Err(OriginalHeldMeasurementErrorV3::Bound);
        }
        self.originals[index].signed_request = bytes;
        self.closed = false;
        Ok((index, true))
    }
}

/// Cannot outlive or replace the actual startup/request/current-cut borrowers.
pub(crate) struct OriginalWorkerLoanV3<'owner, 'request, 'trust> {
    startup: &'owner mut StorageOriginalWorkerStartupV3,
    authenticated: &'request AuthenticatedStorageNativeRequestV2<'trust>,
    coordinator: &'owner StorageAdmissionCoordinator,
    policies: &'owner ProtectedStorageResolverPolicyDirectoryV1,
    cut: &'owner StorageHeldSnapshotCatalogCutV1,
    policy_head: StorageResolverPolicyCatalogBindingV1,
    pool_guid: u64,
    first: RawPairedClockSample,
    cutoff: u64,
    cutoff_bytes: &'owner [u8],
    open: bool,
}

impl OriginalWorkerLoanV3<'_, '_, '_> {
    pub(crate) fn check(&mut self) -> Result<RawPairedClockSample, OriginalHeldMeasurementErrorV3> {
        if !self.open {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        self.open = false;
        self.startup.recheck()?;
        self.authenticated.recheck()?;
        let selector = StorageHeldSnapshotSelectorV1 {
            storage_handle: self.cut.snapshot.dataset().storage_handle(),
            source_guid: self.cut.snapshot.dataset().guid(),
            snapshot_guid: self.cut.snapshot.guid(),
            hold_id: self.cut.hold_id,
        };
        let current = self
            .coordinator
            .held_snapshot_catalog_cut(selector)
            .map_err(StorageRuntimeError::Admission)?;
        self.cut
            .ensure_unchanged(&current)
            .map_err(StorageRuntimeError::Admission)?;
        let policy = self.policies.load()?;
        if policy.binding()? != self.policy_head
            || policy.expected_pool_guid_for_root(current.snapshot.dataset().root())?
                != self.pool_guid
        {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        let later = trusted_paired_clock_sample()?;
        validate_original_clock(self.authenticated.request(), self.first, later, self.cutoff)?;
        self.authenticated.recheck()?;
        self.startup.recheck()?;

        // Slow authority readbacks must not leave a stale pre-effect sample.
        let final_pair = trusted_paired_clock_sample()?;
        validate_original_clock(self.authenticated.request(), self.first, final_pair, self.cutoff)?;
        self.open = true;
        Ok(final_pair)
    }

    pub(crate) fn cutoff_bytes(&self) -> &[u8] {
        self.cutoff_bytes
    }

    pub(crate) const fn clock_scope(&self) -> (RawPairedClockSample, u64) {
        (self.first, self.cutoff)
    }
}

impl StorageBrokerRuntime {
    /// Returns the resident index, not a replacement mount or portable grant.
    pub(super) fn measure_original_authenticated_request(
        &mut self,
        index: usize,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
    ) -> Result<usize, StorageRuntimeError> {
        self.original_measurements.closed = true;
        let original = &mut self.original_measurements.originals[index];
        let result = (|| {
            if original.phase != OriginalPhase::Attempting
                || original.first.is_none()
                || original.dispatch.is_none()
            {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            let startup = self
                .original_worker_startup
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            startup.recheck()?;
            authenticated.recheck()?;
            let first = original.first.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let cutoff = original.cutoff.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;

            let claims = authenticated.request().request().claims();
            let catalog = claims.catalog();
            let (_, claim) = catalog
                .select_under_head(
                    catalog.generation(),
                    catalog.digest(),
                    catalog.namespace_digest(),
                    claims.selection().0,
                )
                .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?;
            let selector = StorageHeldSnapshotSelectorV1::from_native_claim(&claim)
                .map_err(StorageRuntimeError::Admission)?;
            let cut = self
                .coordinator
                .held_snapshot_catalog_cut(selector)
                .map_err(StorageRuntimeError::Admission)?;
            if !cut.matches_native_journal_claim(&claim) {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            let policies = self
                .resolver_policies
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let policy = policies.load()?;
            let policy_head = policy.binding()?;
            let pool_guid = policy.expected_pool_guid_for_root(cut.snapshot.dataset().root())?;
            if pool_guid != claim.pool_guid() {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            original.reader = Some(SystemdHeldSnapshotReaderV1::capture_new(
                crate::process::open_cgroup_root()?,
                self.held_reader_state_directory
                    .as_deref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
                &mut original.reader_capture,
            )?);
            let reader = original
                .reader
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let mut loan = OriginalWorkerLoanV3 {
                startup,
                authenticated,
                coordinator: &self.coordinator,
                policies,
                cut: &cut,
                policy_head,
                pool_guid,
                first,
                cutoff,
                cutoff_bytes: &original.cutoff_bytes,
                open: true,
            };
            loan.check()?;
            reader.begin_original(&mut loan, &mut original.progress)?;
            let binding = HeldSnapshotWorkerBindingV1 {
                pool_guid,
                catalog: cut.catalog,
                authority_sequence: cut.authority_sequence,
                nonce: random_challenge()?,
            };
            let first_probe = self.helper.observe_original_held_snapshot(
                &cut.snapshot,
                cut.hold_id,
                binding,
                &mut loan,
                &mut original.progress,
            )?;
            let (observed_pool, physical_observation_digest) = require_original_probe(first_probe)?;
            if observed_pool != pool_guid {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            let measured_tree = reader.measure_original_with_mount(
                &cut.snapshot,
                pool_guid,
                cut.materialized_state_digest,
                random_challenge()?,
                &mut loan,
                &mut original.progress,
            )?;
            let second_probe = self.helper.observe_original_held_snapshot(
                &cut.snapshot,
                cut.hold_id,
                HeldSnapshotWorkerBindingV1 {
                    nonce: random_challenge()?,
                    ..binding
                },
                &mut loan,
                &mut original.progress,
            )?;
            let (post_pool, post_measurement_observation_digest) = require_original_probe(second_probe)?;
            loan.check()?;
            if post_pool != pool_guid
                || !identity_observation_matches_snapshot_metadata(measured_tree.identity, cut.metadata)
                || !cut.matches_native_claim(
                    &claim,
                    pool_guid,
                    measured_tree.content_digest,
                    measured_tree.mounted_snapshot_guid,
                )
            {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            reader.finish_original(&mut loan, &mut original.progress)?;
            // All ephemeral authority loans end before the original descriptor
            // moves or any subsequent issuance/journal/signing operation.
            drop(loan);
            let mount = original.progress.take_measured_mount()?;
            original.held = Some(StorageHeldSnapshotReadbackWithMountV1 {
                readback: StorageHeldSnapshotReadbackV1 {
                    cut,
                    pool_guid,
                    policy_head,
                    physical_observation_digest,
                    measured_tree,
                    post_measurement_observation_digest,
                },
                mount,
                #[cfg(test)]
                synthetic_fixture: None,
            });
            original
                .held
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .verify_mount()?;
            Ok::<_, OriginalHeldMeasurementErrorV3>(())
        })();
        match result {
            Ok(()) => {
                original.phase = OriginalPhase::Measured;
                Ok(index)
            }
            Err(cause) => {
                original.phase = OriginalPhase::Failed;
                original.first_failure = Some(cause);
                // The resident dispatch lease remains held until genuine
                // death/population proof and exact fence retirement. No EOF,
                // timeout or socket shutdown is projected into drain authority.
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                Err(StorageRuntimeError::ReopenRequired)
            }
        }
    }
}

impl StorageBrokerRuntime {
    /// Samples the first genuine pair once, before any issuance read or launch.
    pub(super) fn initialize_original_scope(
        &mut self,
        index: usize,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
    ) -> Result<(), OriginalHeldMeasurementErrorV3> {
        let original = &mut self.original_measurements.originals[index];
        if original.first.is_some() || original.cutoff.is_some() || original.dispatch.is_some() {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        original.dispatch = Some(
            self.worker_dispatch
                .enter()
                .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?,
        );
        self.original_worker_startup
            .as_mut()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
            .recheck()?;
        authenticated.recheck()?;
        let first = trusted_paired_clock_sample()?;
        original.first = Some(first);
        let cutoff = original_fail_stop_deadline(authenticated.request(), first)?;
        original.cutoff = Some(cutoff);
        original.cutoff_bytes = encode_cutoff(&original.signed_request, first, cutoff)?;
        Ok(())
    }

    /// Rechecks the same original mount without creating a replacement root.
    pub(super) fn recheck_original_measurement(
        &mut self,
        index: usize,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
    ) -> Result<StorageHeldSnapshotCatalogCutV1, OriginalHeldMeasurementErrorV3> {
        let original = &mut self.original_measurements.originals[index];
        if original.phase != OriginalPhase::Measured
            || original.rechecks.len() >= MAXIMUM_ORIGINAL_RECHECKS
        {
            return Err(OriginalHeldMeasurementErrorV3::Bound);
        }
        // Twenty-four bounded one-probe spans plus the initial three-stage
        // span fit the already admitted 8 MiB resident reservation. Every
        // span has at most sixteen receive slots, at most 4096-byte READYs,
        // and a 128 KiB outbound body; no entry is removed on failure.
        original.rechecks.try_reserve(1)?;
        original.rechecks.push(OriginalHeldWorkerProgressV3::for_probe());
        let progress = original
            .rechecks
            .last_mut()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        let held = original
            .held
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        let expected = &held.readback;
        let mut loan = OriginalWorkerLoanV3 {
            startup: self
                .original_worker_startup
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
            authenticated,
            coordinator: &self.coordinator,
            policies: self
                .resolver_policies
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
            cut: &expected.cut,
            policy_head: expected.policy_head,
            pool_guid: expected.pool_guid,
            first: original.first.ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
            cutoff: original.cutoff.ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
            cutoff_bytes: &original.cutoff_bytes,
            open: true,
        };
        loan.check()?;
        held.verify_mount()?;
        let reader = original
            .reader
            .as_mut()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        reader.begin_original(&mut loan, progress)?;
        let observed = self.helper.observe_original_held_snapshot(
            &expected.cut.snapshot,
            expected.cut.hold_id,
            HeldSnapshotWorkerBindingV1 {
                pool_guid: expected.pool_guid,
                catalog: expected.cut.catalog,
                authority_sequence: expected.cut.authority_sequence,
                nonce: random_challenge()?,
            },
            &mut loan,
            progress,
        )?;
        let (pool_guid, _) = require_original_probe(observed)?;
        if pool_guid != expected.pool_guid {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        loan.check()?;
        reader.finish_original(&mut loan, progress)?;
        drop(loan);
        held.verify_mount()?;
        let selector = StorageHeldSnapshotSelectorV1 {
            storage_handle: expected.cut.snapshot.dataset().storage_handle(),
            source_guid: expected.cut.snapshot.dataset().guid(),
            snapshot_guid: expected.cut.snapshot.guid(),
            hold_id: expected.cut.hold_id,
        };
        let current = self
            .coordinator
            .held_snapshot_catalog_cut(selector)
            .map_err(StorageRuntimeError::Admission)?;
        expected
            .cut
            .ensure_unchanged(&current)
            .map_err(StorageRuntimeError::Admission)?;
        Ok(current)
    }
}

fn require_original_probe(
    observed: HeldSnapshotPhysicalObservationV1,
) -> Result<(u64, ObjectDigest), OriginalHeldMeasurementErrorV3> {
    match observed {
        HeldSnapshotPhysicalObservationV1::Matched { pool_guid, digest } => Ok((pool_guid, digest)),
        HeldSnapshotPhysicalObservationV1::Mismatch => Err(OriginalHeldMeasurementErrorV3::Closed),
    }
}

fn reserve_original_budget(
    count: usize,
    bytes: usize,
) -> Result<usize, OriginalHeldMeasurementErrorV3> {
    // Arithmetic refusal remains before count refusal and any growth.
    let reserved = bytes
        .checked_add(ORIGINAL_RESERVATION_BYTES)
        .filter(|bytes| *bytes <= MAXIMUM_RESIDENT_BYTES)
        .ok_or(OriginalHeldMeasurementErrorV3::Bound)?;
    if count >= MAXIMUM_RESIDENT_ORIGINALS {
        return Err(OriginalHeldMeasurementErrorV3::Bound);
    }
    Ok(reserved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_partial_entries_consume_the_same_resident_count_and_byte_budget() {
        assert_eq!(
            reserve_original_budget(0, 0).unwrap(),
            ORIGINAL_RESERVATION_BYTES,
        );
        assert_eq!(
            reserve_original_budget(7, 7 * ORIGINAL_RESERVATION_BYTES).unwrap(),
            MAXIMUM_RESIDENT_BYTES,
        );
        assert!(matches!(
            reserve_original_budget(8, 0),
            Err(OriginalHeldMeasurementErrorV3::Bound),
        ));
        assert!(matches!(
            reserve_original_budget(0, MAXIMUM_RESIDENT_BYTES),
            Err(OriginalHeldMeasurementErrorV3::Bound),
        ));
        assert!(matches!(
            reserve_original_budget(0, usize::MAX),
            Err(OriginalHeldMeasurementErrorV3::Bound),
        ));
    }
}
