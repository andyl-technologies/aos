//! Live native receipt issuance and continuously retained original-root escrow.
//!
//! The separate issuance row is durable before send. Escrow deliberately is
//! not reconstructed from that row: a cold remount could have identical bytes
//! while naming a different kernel object. Missing local escrow proves only
//! missing Storage-local custody, not absence of a Provider-held descriptor.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, BorrowedFd};

use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, StorageNativeAcceptanceV2, StorageNativeAcquireReplyV2,
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

/// Supplies synthetic physical evidence only to unit tests of real owner ordering.
#[cfg(test)]
pub(super) struct SyntheticNativeRuntimeV2 {
    pub(super) held: Option<StorageHeldSnapshotReadbackWithMountV1>,
    pub(super) cut: StorageHeldSnapshotCatalogCutV1,
    pub(super) clock: RawPairedClockSample,
    pub(super) measurements: usize,
    pub(super) stale_cut: bool,
}

struct NativeOriginalV2 {
    held: StorageHeldSnapshotReadbackWithMountV1,
    reply: StorageNativeAcquireReplyV2,
    packet: Vec<u8>,
    fail_stop_boottime: u64,
    initial_clock: RawPairedClockSample,
}

fn original_fail_stop_deadline(
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
    retained: Option<&StorageNativeAcceptanceV2>,
    original: Option<&StorageNativeAcquireReplyV2>,
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
            let current = self.recheck_native_original(&held)?;
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

fn validate_original_clock(
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
    retained: &StorageNativeAcceptanceV2,
    reply: &StorageNativeAcquireReplyV2,
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
