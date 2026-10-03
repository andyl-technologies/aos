//! Live native receipt issuance and continuously retained original-root escrow.
//!
//! The separate issuance row is durable before send. Escrow deliberately is
//! not reconstructed from that row: a cold remount could have identical bytes
//! while naming a different kernel object. Missing local escrow proves only
//! missing Storage-local custody, not absence of a Provider-held descriptor.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, BorrowedFd};

use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, StorageNativeAcceptanceV3, StorageNativeAcquireReplyV3,
    decode_acquire_request,
};

use super::*;
use crate::live_export_request_trust::AuthenticatedStorageNativeRequestV2;
use crate::native_issuance::StorageNativeIssuanceErrorV1;
use crate::storage_zfs_hold_key::StorageZfsHoldKeyV1;

/// Retains original kernel objects and immutable signed replies for this process.
#[derive(Default)]
pub(super) struct StorageNativeEscrowV2 {
    originals: BTreeMap<[u8; 32], NativeOriginalV2>,
}

#[cfg(test)]
impl StorageNativeEscrowV2 {
    pub(super) fn count_for_test(&self) -> usize {
        self.originals.len()
    }
}

/// Supplies synthetic physical evidence only to unit tests of real owner ordering.
#[cfg(test)]
pub(super) struct SyntheticNativeRuntimeV2 {
    pub(super) held: Option<StorageHeldSnapshotReadbackWithMountV1>,
    pub(super) reply_override: Option<StorageNativeAcquireReplyV3>,
    pub(super) cut: StorageHeldSnapshotCatalogCutV1,
    pub(super) clock: RawPairedClockSample,
    pub(super) measurements: usize,
    pub(super) stale_cut: bool,
}

struct NativeOriginalV2 {
    held: StorageHeldSnapshotReadbackWithMountV1,
    reply: StorageNativeAcquireReplyV3,
    packet: Vec<u8>,
    fail_stop_boottime: u64,
    initial_clock: RawPairedClockSample,
}

pub(crate) fn original_fail_stop_deadline(
    request: &SignedStorageNativeAcquireRequestV2,
    clock: RawPairedClockSample,
) -> Result<u64, StorageRuntimeError> {
    validate_native_request_clock(request, clock)?;
    // The paired sample exposes integer wall seconds. Subtract the unknown
    // fractional second instead of allowing BOOTTIME to extend signed expiry.
    let remaining = request
        .request()
        .claims()
        .validity()
        .1
        .checked_sub(clock.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or(StorageRuntimeError::Recovery)?;
    clock
        .boottime_nanoseconds()
        .checked_add(remaining)
        .ok_or(StorageRuntimeError::Recovery)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCustodyActionV2 {
    MeasureNew,
    ReplayOriginal,
    Unavailable,
}

fn native_custody_action(
    retained: Option<&StorageNativeAcceptanceV3>,
    original: Option<&StorageNativeAcquireReplyV3>,
) -> Result<NativeCustodyActionV2, StorageRuntimeError> {
    match (retained, original) {
        (None, None) => Ok(NativeCustodyActionV2::MeasureNew),
        (Some(_), None) => Ok(NativeCustodyActionV2::Unavailable),
        (Some(retained), Some(original)) => {
            validate_original_acceptance(retained, original)?;
            Ok(NativeCustodyActionV2::ReplayOriginal)
        }
        (None, Some(_)) => Err(StorageRuntimeError::Recovery),
    }
}

/// Distinguishes delivery ambiguity from missing local custody without releasing interest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageNativeDeliveryOutcomeV2 {
    /// The exact signed reply and original FD were accepted by the socket.
    Delivered,
    /// The peer may have received the reply; original escrow remains retained.
    SendAmbiguous,
    /// Durable interest exists without Storage-local escrow; no absence is asserted.
    Unavailable,
}

/// Checks current original scope, without treating a restarted peer as a new request.
///
/// # Errors
///
/// Rejects kernel-coupled scope, changed boot, or an expired/future signed interval.
pub(crate) fn validate_native_request_clock(
    request: &SignedStorageNativeAcquireRequestV2,
    clock: RawPairedClockSample,
) -> Result<(), StorageRuntimeError> {
    let root = decode_acquire_request(request.request().signed_root_request().subject())
        .map_err(|_| StorageRuntimeError::Recovery)?;
    let (issued, expires) = request.request().claims().validity();
    if root.kernel_coupled()
        || root.boot_id() != clock.host_boot_id()
        || clock.wall_seconds() < issued
        || clock.wall_seconds() >= expires
        || clock.wall_seconds() >= root.deadline_seconds()
    {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

impl StorageBrokerRuntime {
    /// Stores the original interest/unsigned2/signed2 prefix before its one offer.
    ///
    /// The carrier and original reader stay resident on every refusal. This
    /// fixed route never invokes legacy accept_live, retries an old offer,
    /// clears dispatch debt, or reconstructs an original after restart.
    pub(crate) fn offer_original_held_native(
        &mut self,
        mut carrier: super::original_held_measurement::OriginalHeldCarrierV1,
        trust: &crate::live_export_request_trust::StorageLiveExportRequestTrustV1,
        verifier: &crate::peer::ProviderLiveExportPeerVerifier,
        key: &StorageZfsHoldKeyV1,
    ) -> Result<StorageNativeDeliveryOutcomeV2, StorageRuntimeError> {
        use super::original_held_measurement::{OriginalHeldMeasurementErrorV3 as Error, OriginalPhase};
        use crate::native_issuance::held_completion::{StorageHeldIssuanceRowV2, StorageHeldStepV1 as Step};
        use aos_sandbox_source_provider_protocol::native_held_completion::{
            NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner,
            NativeHeldSectionTagV1 as Tag,
            frame::{NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1},
            suffix::NativeHeldCompletionSuffixV1,
            witness::{NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1,
                NativeHeldRecordFamilyV1 as Family, StorageNativeHeldWitnessV1,
                native_held_record_byte_digest_v1},
        };

        let _crossing = carrier.unwind_fence();
        let mut resident_index = None;
        let result = (|| {
            let request = carrier.request.as_ref().ok_or(Error::Closed)?;
            let authenticated = trust.verify_native(request)?;
            let (index, new) = self.original_measurements.begin(&authenticated)?;
            self.original_measurements.closed = true;
            if !new || self.original_measurements.originals[index].held_carrier.is_some() {
                return Err(Error::Closed);
            }
            // A refused new child never replaces the earlier offered carrier.
            resident_index = Some(index);
            self.initialize_original_scope(index, &authenticated)?;
            let retained = self.native_issuance.as_mut().ok_or(Error::Closed)?
                .retained_acceptance(request)?;
            if retained.is_some() {
                // Even an equal cold row cannot justify a fresh mount or offer.
                return Err(Error::Closed);
            }
            self.measure_original_authenticated_request(index, &authenticated)?;
            self.recheck_original_measurement(index, &authenticated)?;
            let original = &self.original_measurements.originals[index];
            let first = original.first.ok_or(Error::Closed)?;
            let cutoff = original.cutoff.ok_or(Error::Closed)?;
            let clock = trusted_paired_clock_sample()?;
            validate_original_clock(request, first, clock, cutoff)?;
            let reply = key.sign_native_reply(&authenticated,
                original.held.as_ref().ok_or(Error::Closed)?, random_challenge()?, clock)?;
            self.original_measurements.originals[index].reply = Some(reply);

            let current = self.recheck_original_measurement(index, &authenticated)?;
            let original = &self.original_measurements.originals[index];
            let held = original.held.as_ref().ok_or(Error::Closed)?;
            let reply = original.reply.as_ref().ok_or(Error::Closed)?;
            let clock = trusted_paired_clock_sample()?;
            validate_original_clock(request, first, clock, cutoff)?;
            key.verify_native_reply(&authenticated, held, reply, clock)?;
            carrier.interest = Some(self.native_issuance.as_mut().ok_or(Error::Closed)?
                .original_held_interest(&authenticated, held, reply,
                    carrier.root.as_ref().ok_or(Error::Closed)?, &current, key)?);
            carrier.readbacks[0] = Some(self.native_issuance.as_mut().ok_or(Error::Closed)?
                .store_original_held_row(carrier.interest.as_ref().ok_or(Error::Closed)?,
                    Step::InterestRecorded, &mut carrier.appends[0])?);

            // The witness derives from the actual committed interest and the
            // same current writers/child, not a prospective TX or decoded pin.
            let interest = carrier.interest.as_ref().ok_or(Error::Closed)?;
            let root = carrier.root.as_ref().ok_or(Error::Closed)?;
            let (trust_sequence, generation, file) = trust.held_trust_cut()?;
            let witness = NativeHeldOwnerWitnessV1::Storage(StorageNativeHeldWitnessV1 {
                local_socket_cookie: carrier.child.as_ref().ok_or(Error::Closed)?
                    .peer().socket_cookie().get(),
                primary_sequence: self.coordinator.native_metadata_readback_cut(
                    Path::new("/var/lib/aos/sandbox-storage"))
                    .map_err(StorageRuntimeError::Admission)?.0,
                workspace_sequence: self.workspaces.as_ref().ok_or(Error::Closed)?
                    .native_metadata_readback_cut(Path::new("/var/lib/aos/sandbox-storage"))
                    .map_err(StorageRuntimeError::WorkspaceCatalog)?.journal_sequence(),
                request_trust_sequence: trust_sequence,
                issuance_sequence: carrier.readbacks[0].ok_or(Error::Closed)?,
                request_trust_generation: generation,
                request_trust_file: file,
                issuance: NativeHeldByteWitnessV1::new(Family::StorageIssuance,
                    interest.key().to_vec(), native_held_record_byte_digest_v1(
                        Family::StorageIssuance, &interest.key(), &interest.to_canonical_bytes()?)?)?,
            });
            let claims = request.request().claims();
            let scope = aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldScopeV1 {
                provider_attempt: claims.attempt().1,
                original_native_request: request.digest(),
                ..*root.scope()
            };
            let prepared = PreparedNativeHeldControlV1::new(Kind::StorageHeld, scope,
                root.digest(), vec![
                    NativeHeldSectionV1::new(Tag::Witness, witness.to_canonical_bytes()?)?,
                    NativeHeldSectionV1::new(Tag::RootPrepared, root.to_canonical_bytes())?,
                    NativeHeldSectionV1::new(Tag::NativeReply, reply.to_canonical_bytes())?,
                ], NativeHeldSignerV1::Storage(key.verifier().projection().0))?;
            carrier.prepared = Some(StorageHeldIssuanceRowV2::new(request.clone(),
                reply.acceptance().acceptance().clone(), None,
                NativeHeldCompletionSuffixV1::new(Owner::Storage, 1, scope.flight,
                    Some(prepared), vec![root.clone()])?)?);
            carrier.readbacks[1] = Some(self.native_issuance.as_mut().ok_or(Error::Closed)?
                .store_original_held_row(carrier.prepared.as_ref().ok_or(Error::Closed)?,
                    Step::HeldPrepared, &mut carrier.appends[1])?);

            // Slow message/key preparation occurs inside the concrete signer,
            // before its last genuine stored-original paired-clock check.
            let mut signing = self.stored_original_held_signing_loan(
                index, &authenticated, trust, &carrier, verifier)?;
            let control = key.sign_stored_original_held_control(&mut signing)?;
            drop(signing);
            carrier.control = Some(control);
            self.recheck_original_measurement(index, &authenticated)?;
            let original = &self.original_measurements.originals[index];
            let reply = original.reply.as_ref().ok_or(Error::Closed)?;
            let clock = trusted_paired_clock_sample()?;
            validate_original_clock(request, first, clock, cutoff)?;
            key.verify_native_reply(&authenticated, original.held.as_ref().ok_or(Error::Closed)?, reply, clock)?;
            trust.verify_held_archive(carrier.control.as_ref().ok_or(Error::Closed)?, key.verifier())?;
            carrier.stored = Some(StorageHeldIssuanceRowV2::new(request.clone(),
                reply.acceptance().acceptance().clone(), None,
                NativeHeldCompletionSuffixV1::new(Owner::Storage, 2, scope.flight, None,
                    vec![carrier.root.as_ref().ok_or(Error::Closed)?.clone(),
                        carrier.control.as_ref().ok_or(Error::Closed)?.clone()])?)?);
            carrier.readbacks[2] = Some(self.native_issuance.as_mut().ok_or(Error::Closed)?
                .store_original_held_row(carrier.stored.as_ref().ok_or(Error::Closed)?,
                    Step::HeldStored, &mut carrier.appends[2])?);
            carrier.control_packet = Some(carrier.control.as_ref().ok_or(Error::Closed)?.to_canonical_bytes());
            self.original_measurements.originals[index].packet = Some(reply.to_canonical_bytes());

            self.check_original_held_offer(index, &authenticated, trust, verifier, key, &carrier)?;
            carrier.sends[0] = Some(carrier.child.as_mut().ok_or(Error::Closed)?
                .send(carrier.control_packet.as_deref().ok_or(Error::Closed)?));
            if carrier.sends[0].as_ref().is_some_and(Result::is_err) {
                return Err(Error::Closed);
            }
            self.check_original_held_offer(index, &authenticated, trust, verifier, key, &carrier)?;
            let original = &self.original_measurements.originals[index];
            carrier.sends[1] = Some(carrier.child.as_mut().ok_or(Error::Closed)?
                .send_with_descriptors(original.packet.as_deref().ok_or(Error::Closed)?,
                    &[original.held.as_ref().ok_or(Error::Closed)?.mount.as_fd()]));
            if carrier.sends[1].as_ref().is_some_and(Result::is_err) {
                return Err(Error::Closed);
            }
            self.check_original_held_offer(index, &authenticated, trust, verifier, key, &carrier)?;
            Ok::<_, Error>(StorageNativeDeliveryOutcomeV2::Delivered)
        })();

        // The actual send error remains in its original result slot; a closed
        // marker must not replace that first cause or erase attempted transfer.
        if let Err(cause) = result {
            if !carrier.sends.iter().any(|send| send.as_ref().is_some_and(Result::is_err)) {
                carrier.first_failure = Some(cause);
            }
            if let Some(index) = resident_index {
                let original = &mut self.original_measurements.originals[index];
                original.phase = OriginalPhase::Failed;
                original.held_carrier = Some(carrier);
                self.original_measurements.closed = true;
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
            } else {
                self.original_measurements.closed = true;
                self.original_measurements.failed_carrier = Some(carrier);
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
            }
            return Err(StorageRuntimeError::ReopenRequired);
        }
        let index = resident_index.ok_or(StorageRuntimeError::ReopenRequired)?;
        self.original_measurements.originals[index].held_carrier = Some(carrier);
        self.original_measurements.held_carrier_in_flight = false;
        self.original_measurements.closed = false;
        // Dispatch/reader/child/interest remain held for the unimplemented
        // relay and settlement route. A successful syscall is not Drain.
        Ok(StorageNativeDeliveryOutcomeV2::Delivered)
    }

    fn check_original_held_offer(
        &mut self, index: usize,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        trust: &crate::live_export_request_trust::StorageLiveExportRequestTrustV1,
        verifier: &crate::peer::ProviderLiveExportPeerVerifier,
        key: &StorageZfsHoldKeyV1,
        carrier: &super::original_held_measurement::OriginalHeldCarrierV1,
    ) -> Result<(), super::original_held_measurement::OriginalHeldMeasurementErrorV3> {
        use super::original_held_measurement::OriginalHeldMeasurementErrorV3 as Error;
        self.native_issuance.as_mut().ok_or(Error::Closed)?
            .held_row_readback(carrier.stored.as_ref().ok_or(Error::Closed)?)?;
        self.native_issuance.as_mut().ok_or(Error::Closed)?
            .require_original_held_roles(trust, key)?;
        self.recheck_original_measurement(index, authenticated)?;
        let child = carrier.child.as_ref().ok_or(Error::Closed)?;
        let execution = carrier.execution.ok_or(Error::Closed)?;
        if verifier.verify_connection_typed(child.peer())? != execution {
            return Err(Error::Closed);
        }
        for record in &carrier.records {
            verifier.verify_record_typed(execution, child.peer(),
                &record.as_ref().ok_or(Error::Closed)?.subject)?;
        }
        let original = &self.original_measurements.originals[index];
        let first = original.first.ok_or(Error::Closed)?;
        let cutoff = original.cutoff.ok_or(Error::Closed)?;
        let clock = trusted_paired_clock_sample()?;
        key.verify_native_reply(authenticated, original.held.as_ref().ok_or(Error::Closed)?,
            original.reply.as_ref().ok_or(Error::Closed)?, clock)?;
        key.recheck()?;
        authenticated.recheck()?;
        self.original_worker_startup.as_mut().ok_or(Error::Closed)?.recheck()?;
        validate_original_clock(authenticated.request(), first, trusted_paired_clock_sample()?, cutoff)?;
        Ok(())
    }

    fn native_clock(&self) -> Result<RawPairedClockSample, StorageRuntimeError> {
        #[cfg(test)]
        if let Some(fixture) = &self.native_fixture {
            return Ok(fixture.clock);
        }
        trusted_paired_clock_sample()
    }

    fn measure_native_original(
        &mut self,
        claim: &ZfsHeldSnapshotProofV1,
    ) -> Result<StorageHeldSnapshotReadbackWithMountV1, StorageRuntimeError> {
        #[cfg(test)]
        if let Some(fixture) = &mut self.native_fixture {
            fixture.measurements += 1;
            return fixture.held.take().ok_or(StorageRuntimeError::Recovery);
        }
        self.observe_native_held_snapshot_claim_with_mount(claim)
    }

    /// Accepts and delivers only the original measured mount under retained writers.
    ///
    /// All three writers were acquired primary -> workspace -> issuance at
    /// runtime construction and remain held throughout this call. The outer
    /// dispatch lease also covers signing, acceptance/readback, and send.
    ///
    /// # Errors
    ///
    /// Rejects changed authority/cut, unsafe journal custody, conflicting intent,
    /// invalid original FD, or expired original delivery. Ambiguous journal I/O
    /// requires process reopen; ambiguous send retains the live original.
    pub(crate) fn with_native_acquire_delivery_v2(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        key: &StorageZfsHoldKeyV1,
        deliver: impl FnOnce(&[u8], BorrowedFd<'_>, u64) -> Result<(), ()>,
    ) -> Result<StorageNativeDeliveryOutcomeV2, StorageRuntimeError> {
        if self.original_worker_startup.is_some() {
            return self.with_original_worker_native_delivery(authenticated, key, deliver);
        }
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if !self.readiness.permits_catalog_methods() || self.workspaces.is_none() {
            return Err(StorageRuntimeError::Recovery);
        }
        authenticated
            .recheck()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let request = authenticated.request();
        let initial_clock = self.native_clock()?;
        validate_native_request_clock(request, initial_clock)?;
        let initial_deadline = original_fail_stop_deadline(request, initial_clock)?;
        let retained = self
            .native_issuance
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .retained_acceptance(request);
        let retained = self.finish_native_issuance(retained)?;
        let request_key = *request.digest().as_bytes();

        // This check precedes measurement. An accepted cold row can NEVER
        // trigger a new reader mount, receipt timestamp, or issuance identity.
        let action = native_custody_action(
            retained.as_ref(),
            self.native_escrow
                .originals
                .get(&request_key)
                .map(|original| &original.reply),
        )?;
        if action == NativeCustodyActionV2::Unavailable {
            return Ok(StorageNativeDeliveryOutcomeV2::Unavailable);
        }
        if action == NativeCustodyActionV2::MeasureNew {
            let claims = request.request().claims();
            let catalog = claims.catalog();
            let (_, snapshot) = catalog
                .select_under_head(
                    catalog.generation(),
                    catalog.digest(),
                    catalog.namespace_digest(),
                    claims.selection().0,
                )
                .map_err(|_| StorageRuntimeError::Recovery)?;
            let held = self.measure_native_original(&snapshot)?;
            self.recheck_native_original(&held)?;
            validate_original_clock(
                request,
                initial_clock,
                self.native_clock()?,
                initial_deadline,
            )?;
            let reply = key
                .sign_native_reply(
                    authenticated,
                    &held,
                    random_challenge()?,
                    self.native_clock()?,
                )
                .map_err(|_| StorageRuntimeError::Recovery)?;
            #[cfg(test)]
            let reply = self
                .native_fixture
                .as_mut()
                .and_then(|fixture| fixture.reply_override.take())
                .unwrap_or(reply);
            let current = self.recheck_native_original(&held)?;
            let clock = self.native_clock()?;
            validate_original_clock(request, initial_clock, clock, initial_deadline)?;
            // The same verifier protects initial durable acceptance and
            // retry: signed topology scalars must match this original
            // confined readback, not merely their own signed digest.
            key.verify_native_reply(authenticated, &held, &reply, clock)
                .map_err(|_| StorageRuntimeError::Recovery)?;
            validate_original_clock(
                request,
                initial_clock,
                self.native_clock()?,
                initial_deadline,
            )?;
            let accepted = self
                .native_issuance
                .as_mut()
                .ok_or(StorageRuntimeError::Recovery)?
                .accept_live(authenticated, &held, &reply, &current);
            self.finish_native_issuance(accepted)?;

            // A failed/ambiguous send must not destroy the only escrow. Keep
            // the stable signed packet and FD before attempting any transfer.
            let packet = reply.to_canonical_bytes();
            self.native_escrow.originals.insert(
                request_key,
                NativeOriginalV2 {
                    held,
                    reply,
                    packet,
                    fail_stop_boottime: initial_deadline,
                    initial_clock,
                },
            );
        }

        // Temporarily move the original out only to split the runtime borrow;
        // every Result path below reinstalls it before returning.
        let original = self
            .native_escrow
            .originals
            .remove(&request_key)
            .ok_or(StorageRuntimeError::Recovery)?;
        let outcome = self.deliver_native_original(authenticated, key, &original, deliver);
        self.native_escrow.originals.insert(request_key, original);
        outcome
    }

    /// Uses the same issuance/signature engines with resident original custody.
    ///
    /// Unlike the legacy local escrow loan, no mount, signed reply or packet is
    /// removed from its resident owner around a fallible call or user delivery.
    /// The original paired sample and absolute cutoff are never regenerated.
    fn with_original_worker_native_delivery(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        key: &StorageZfsHoldKeyV1,
        deliver: impl FnOnce(&[u8], BorrowedFd<'_>, u64) -> Result<(), ()>,
    ) -> Result<StorageNativeDeliveryOutcomeV2, StorageRuntimeError> {
        use super::original_held_measurement::{OriginalHeldMeasurementErrorV3, OriginalPhase};

        let (index, new) = match self.original_measurements.begin(authenticated) {
            Ok(entry) => entry,
            Err(cause) => {
                if self.original_measurements.first_admission_failure.is_none() {
                    self.original_measurements.first_admission_failure = Some(cause);
                }
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                return Err(StorageRuntimeError::ReopenRequired);
            }
        };
        // Panic, a caught unwind in the caller, and every early Err leave this
        // admission closed. Only the same complete successful attempt reopens.
        self.original_measurements.closed = true;
        let result = (|| {
            if !self.readiness.permits_catalog_methods() || self.workspaces.is_none() {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            if new {
                self.initialize_original_scope(index, authenticated)?;
            } else {
                self.original_measurements.originals[index].dispatch = Some(
                    self.worker_dispatch
                        .enter()
                        .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?,
                );
            }
            authenticated.recheck()?;
            self.original_worker_startup
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .recheck()?;
            let original = &self.original_measurements.originals[index];
            let first = original.first.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let cutoff = original.cutoff.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            validate_original_clock(
                authenticated.request(),
                first,
                trusted_paired_clock_sample()?,
                cutoff,
            )?;

            let retained = self
                .native_issuance
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .retained_acceptance(authenticated.request());
            let retained = retained?;
            let action = native_custody_action(
                retained.as_ref(),
                self.original_measurements.originals[index].reply.as_ref(),
            )?;
            if action == NativeCustodyActionV2::Unavailable {
                self.original_measurements.originals[index].phase = OriginalPhase::Unavailable;
                return Ok(StorageNativeDeliveryOutcomeV2::Unavailable);
            }
            if action == NativeCustodyActionV2::MeasureNew {
                if !new {
                    return Err(OriginalHeldMeasurementErrorV3::Closed);
                }
                self.measure_original_authenticated_request(index, authenticated)?;
                self.recheck_original_measurement(index, authenticated)?;
                validate_original_clock(
                    authenticated.request(),
                    first,
                    trusted_paired_clock_sample()?,
                    cutoff,
                )?;
                let original = &self.original_measurements.originals[index];
                let held = original
                    .held
                    .as_ref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
                let reply = key.sign_native_reply(
                    authenticated,
                    held,
                    random_challenge()?,
                    trusted_paired_clock_sample()?,
                )?;
                // The immutable reply enters the same resident owner before
                // any subsequent physical/journal check can fail or unwind.
                self.original_measurements.originals[index].reply = Some(reply);
                let current = self.recheck_original_measurement(index, authenticated)?;
                let clock = trusted_paired_clock_sample()?;
                validate_original_clock(authenticated.request(), first, clock, cutoff)?;
                let original = &self.original_measurements.originals[index];
                let held = original
                    .held
                    .as_ref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
                let reply = original
                    .reply
                    .as_ref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
                key.verify_native_reply(authenticated, held, reply, clock)?;
                validate_original_clock(
                    authenticated.request(),
                    first,
                    trusted_paired_clock_sample()?,
                    cutoff,
                )?;
                let accepted = self
                    .native_issuance
                    .as_mut()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                    .accept_live(authenticated, held, reply, &current);
                accepted?;
                let original = &mut self.original_measurements.originals[index];
                original.packet = Some(
                    original
                        .reply
                        .as_ref()
                        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                        .to_canonical_bytes(),
                );
            }

            self.recheck_original_measurement(index, authenticated)?;
            let retained = self
                .native_issuance
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .retained_acceptance(authenticated.request());
            let retained = retained?.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let original = &mut self.original_measurements.originals[index];
            let held = original
                .held
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            let reply = original
                .reply
                .as_ref()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
            validate_original_acceptance(&retained, reply)?;
            if held.observe_root()? != *retained.descriptor()
                || reply.receipt().signer() != key.verifier().projection().0
            {
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
            key.recheck()?;
            authenticated.recheck()?;
            self.original_worker_startup
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .recheck()?;
            let clock = trusted_paired_clock_sample()?;
            validate_original_clock(authenticated.request(), first, clock, cutoff)?;
            key.verify_native_reply(authenticated, held, reply, clock)?;
            validate_original_clock(
                authenticated.request(),
                first,
                trusted_paired_clock_sample()?,
                cutoff,
            )?;
            let delivery_index = original.next_delivery;
            if delivery_index >= original.deliveries.len() {
                return Err(OriginalHeldMeasurementErrorV3::Bound);
            }
            original.next_delivery += 1;
            let delivery = deliver(
                original
                    .packet
                    .as_deref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
                held.mount.as_fd(),
                cutoff,
            );
            self.original_measurements.originals[index].deliveries[delivery_index] = Some(delivery);
            // A late post-send refusal cannot undo transfer. Keep the exact
            // send observation and original escrow; never report no-send or
            // release consumer interest when the syscall straddled the cutoff.
            validate_original_clock(
                authenticated.request(),
                first,
                trusted_paired_clock_sample()?,
                cutoff,
            )?;
            authenticated.recheck()?;
            self.original_worker_startup
                .as_mut()
                .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
                .recheck()?;
            validate_original_clock(
                authenticated.request(),
                first,
                trusted_paired_clock_sample()?,
                cutoff,
            )?;
            Ok(match delivery {
                Ok(()) => StorageNativeDeliveryOutcomeV2::Delivered,
                Err(()) => StorageNativeDeliveryOutcomeV2::SendAmbiguous,
            })
        })();
        match result {
            Ok(outcome) => {
                self.original_measurements.originals[index].dispatch = None;
                self.original_measurements.closed = false;
                Ok(outcome)
            }
            Err(cause) => {
                let original = &mut self.original_measurements.originals[index];
                if original.first_failure.is_none() {
                    original.first_failure = Some(cause);
                }
                original.phase = OriginalPhase::Failed;
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                Err(StorageRuntimeError::ReopenRequired)
            }
        }
    }

    fn deliver_native_original(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        key: &StorageZfsHoldKeyV1,
        original: &NativeOriginalV2,
        deliver: impl FnOnce(&[u8], BorrowedFd<'_>, u64) -> Result<(), ()>,
    ) -> Result<StorageNativeDeliveryOutcomeV2, StorageRuntimeError> {
        self.recheck_native_original(&original.held)?;
        let retained = self
            .native_issuance
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .retained_acceptance(authenticated.request());
        let retained = self
            .finish_native_issuance(retained)?
            .ok_or(StorageRuntimeError::Recovery)?;
        validate_original_acceptance(&retained, &original.reply)?;
        if original.held.observe_root()? != *retained.descriptor()
            || original.reply.receipt().signer() != key.verifier().projection().0
        {
            return Err(StorageRuntimeError::Recovery);
        }
        key.recheck().map_err(|_| StorageRuntimeError::Recovery)?;
        authenticated
            .recheck()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let clock = self.native_clock()?;
        validate_original_clock(
            authenticated.request(),
            original.initial_clock,
            clock,
            original.fail_stop_boottime,
        )?;
        key.verify_native_reply(authenticated, &original.held, &original.reply, clock)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        validate_original_clock(
            authenticated.request(),
            original.initial_clock,
            self.native_clock()?,
            original.fail_stop_boottime,
        )?;
        Ok(
            match deliver(
                &original.packet,
                original.held.mount.as_fd(),
                original.fail_stop_boottime,
            ) {
                Ok(()) => StorageNativeDeliveryOutcomeV2::Delivered,
                Err(()) => StorageNativeDeliveryOutcomeV2::SendAmbiguous,
            },
        )
    }

    /// Rejoins current primary cut, physical hold, exact policy, and original FD.
    ///
    /// The worker may read the hold again, but this path never creates/remounts
    /// the root. Its immutable bytes and measurement remain those of escrow.
    fn recheck_native_original(
        &mut self,
        held: &StorageHeldSnapshotReadbackWithMountV1,
    ) -> Result<StorageHeldSnapshotCatalogCutV1, StorageRuntimeError> {
        #[cfg(test)]
        if let Some(fixture) = &self.native_fixture {
            if fixture.stale_cut {
                return Err(StorageRuntimeError::Recovery);
            }
            held.readback
                .cut
                .ensure_unchanged(&fixture.cut)
                .map_err(|_| StorageRuntimeError::Recovery)?;
            held.verify_mount()?;
            return Ok(fixture.cut.clone());
        }
        let expected = &held.readback;
        let selector = StorageHeldSnapshotSelectorV1 {
            storage_handle: expected.cut.snapshot.dataset().storage_handle(),
            source_guid: expected.cut.snapshot.dataset().guid(),
            snapshot_guid: expected.cut.snapshot.guid(),
            hold_id: expected.cut.hold_id,
        };
        let initial = self.coordinator.held_snapshot_catalog_cut(selector)?;
        expected
            .cut
            .ensure_unchanged(&initial)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let policies = self
            .resolver_policies
            .as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        let before_policy = policies.load().map_err(|_| StorageRuntimeError::Recovery)?;
        validate_original_policy(expected, &before_policy)?;
        let (pool, _) = classify_held_snapshot_worker_result(
            &mut self.readiness,
            self.helper.observe_held_snapshot(
                &initial.snapshot,
                initial.hold_id,
                HeldSnapshotWorkerBindingV1 {
                    pool_guid: expected.pool_guid,
                    catalog: initial.catalog,
                    authority_sequence: initial.authority_sequence,
                    nonce: random_challenge()?,
                },
            ),
        )?;
        if pool != expected.pool_guid {
            return Err(StorageRuntimeError::Recovery);
        }
        let current = self.coordinator.held_snapshot_catalog_cut(selector)?;
        expected
            .cut
            .ensure_unchanged(&current)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let after_policy = policies.load().map_err(|_| StorageRuntimeError::Recovery)?;
        validate_original_policy(expected, &after_policy)?;
        held.verify_mount()?;
        Ok(current)
    }

    fn finish_native_issuance<T>(
        &mut self,
        result: Result<T, StorageNativeIssuanceErrorV1>,
    ) -> Result<T, StorageRuntimeError> {
        result.map_err(|error| match error {
            StorageNativeIssuanceErrorV1::Journal(_) => {
                self.readiness = StorageRuntimeReadiness::ReopenRequired;
                StorageRuntimeError::ReopenRequired
            }
            _ => StorageRuntimeError::Recovery,
        })
    }
}

pub(crate) fn validate_original_clock(
    request: &SignedStorageNativeAcquireRequestV2,
    initial: RawPairedClockSample,
    later: RawPairedClockSample,
    deadline: u64,
) -> Result<(), StorageRuntimeError> {
    validate_native_request_clock(request, later)?;
    initial
        .validate_later_sample(later)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    if later.boottime_nanoseconds() >= deadline {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn validate_original_acceptance(
    retained: &StorageNativeAcceptanceV3,
    reply: &StorageNativeAcquireReplyV3,
) -> Result<(), StorageRuntimeError> {
    if retained != reply.acceptance().acceptance()
        || retained.receipt_digest() != reply.receipt().digest()
    {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

fn validate_original_policy(
    expected: &StorageHeldSnapshotReadbackV1,
    policy: &crate::resolver::protected_catalog::LoadedStorageResolverPolicyCatalogV1,
) -> Result<(), StorageRuntimeError> {
    if policy
        .binding()
        .map_err(|_| StorageRuntimeError::Recovery)?
        != expected.policy_head
        || policy
            .expected_pool_guid_for_root(expected.cut.snapshot.dataset().root())
            .map_err(|_| StorageRuntimeError::Recovery)?
            != expected.pool_guid
    {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}
