//! Original hot-owner clock continuity for the private native completion seam.
//!
//! One paired kernel sample and conservative BOOTTIME deadline precede
//! Requested. Every retry retains that same anchor; it cannot create one from
//! historical wall bounds. Version-7 Requested retains the same raw pair and
//! fixed deadline. Only exact protected replay and the same kernel adapter can
//! restore continuity; historical rows without that block remain closed.

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SignedStorageNativeAcquireRequestV2, decode_acquire_request,
    digest_signed_request,
};

use crate::ProviderLedgerError;
use crate::ledger::native_completion::{
    NativeAcquireClockAnchorV1, NativeAcquireCompletionRecordV2,
};

const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";

/// Requires the protected original anchor at every live runtime entry.
///
/// # Errors
///
/// Rejects malformed canonical artifacts or any historical no-clock row.
pub(crate) fn retained_clock_anchor(
    record: &NativeAcquireCompletionRecordV2,
) -> Result<NativeAcquireClockAnchorV1, ProviderLedgerError> {
    record
        .validate_canonical_artifacts()
        .map_err(crate::transaction::map_pure_ledger_error)?;
    record
        .original_clock
        .ok_or(ProviderLedgerError::Unavailable)
}

#[derive(Debug)]
pub(crate) struct NativeAcquireClockGuardV1 {
    initial: RawPairedClockSample,
    deadline: u64,
    root_request_digest: ObjectDigest,
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
    session_binding: ObjectDigest,
    issued_seconds: i64,
    expires_seconds: i64,
}

impl NativeAcquireClockGuardV1 {
    /// Borrows the original sample and cutoff before a native request is signed.
    ///
    /// This projection does not recapture time or establish currentness. The
    /// owner must still recheck this same guard before every protected effect.
    pub(crate) const fn original_sample_and_deadline(&self) -> (RawPairedClockSample, u64) {
        (self.initial, self.deadline)
    }

    /// Projects a staged expiry through the original conservative cutoff engine.
    ///
    /// This read-only projection does not sample time or establish currentness.
    ///
    /// # Errors
    ///
    /// Rejects an invalid cutoff or an extension of the original authorization.
    pub(crate) fn original_stage_deadline(&self, expiry: i64) -> Result<u64, ProviderLedgerError> {
        let deadline = conservative_deadline(self.initial, expiry)?;
        if deadline > self.deadline || expiry > self.expires_seconds {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(deadline)
    }

    /// Reconstitutes an original anchor after the owner joins the protected row.
    ///
    /// # Errors
    ///
    /// Rejects historical no-clock rows, changed protected graph links, a
    /// foreign clock adapter, expired authorization, or kernel discontinuity.
    pub(crate) fn from_retained_record(
        record: &NativeAcquireCompletionRecordV2,
        attempt: &crate::model::AttemptRecordV1,
        acquisition: &crate::model::AcquisitionRecordV1,
    ) -> Result<Self, ProviderLedgerError> {
        let anchor = retained_clock_anchor(record)?;
        record
            .validate_provider_graph(attempt, acquisition)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        let signed = record
            .canonical_request
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let root = decode_acquire_request(signed.request().signed_root_request().subject())
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let expires_seconds = signed.request().claims().validity().1;
        if anchor.initial().provenance().as_bytes() != KERNEL_CLOCK_PROVENANCE
            || anchor.initial().wall_seconds() < attempt.verified_at_seconds
            || expires_seconds > attempt.deadline_seconds
            || expires_seconds > root.deadline_seconds()
            || signed.request().signed_root_request().to_canonical_bytes() != attempt.signed_request
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let guard = Self {
            initial: anchor.initial(),
            deadline: anchor.deadline(),
            root_request_digest: record.root_request_digest,
            acquisition_id: record.acquisition_id,
            attempt_digest: record.attempt_digest,
            session_binding: record.session_binding,
            issued_seconds: attempt.verified_at_seconds,
            expires_seconds,
        };
        guard.require_request(signed)?;
        Ok(guard)
    }

    /// Projects the same original pair for one exact Requested carrier.
    ///
    /// # Errors
    ///
    /// Rejects changed request scope or an expiry extending the original guard.
    pub(crate) fn durable_anchor(
        &self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<NativeAcquireClockAnchorV1, ProviderLedgerError> {
        self.require_request(request)?;
        let anchor = NativeAcquireClockAnchorV1::new_untrusted(self.initial, request)
            .map_err(crate::transaction::map_pure_ledger_error)?;
        if anchor.deadline() > self.deadline
            || request.request().claims().validity().1 > self.expires_seconds
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(anchor)
    }

    /// Joins the retained clock block to the same live original anchor.
    ///
    /// # Errors
    ///
    /// Rejects missing historical metadata or any substituted original pair.
    pub(crate) fn require_record(
        &self,
        record: &NativeAcquireCompletionRecordV2,
    ) -> Result<(), ProviderLedgerError> {
        let request = record
            .canonical_request
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        if record.original_clock != Some(self.durable_anchor(request)?) {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(())
    }

    /// Captures the kernel pair before the first challenge and Requested append.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched boot, expired authorization, invalid
    /// retained Root request, or unrepresentable conservative deadline.
    pub(crate) fn before_challenge(
        original: &SignedSourceProviderRequestV1,
        attempt_digest: ObjectDigest,
        verified_at: i64,
        authorization_expires: i64,
    ) -> Result<Self, ProviderLedgerError> {
        let initial = kernel_clock()?;
        let root = decode_acquire_request(original.subject())
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let issued_seconds = verified_at;
        let expires_seconds = root.deadline_seconds().min(authorization_expires);
        if initial.host_boot_id() != root.boot_id()
            || initial.wall_seconds() < issued_seconds
            || initial.wall_seconds() >= expires_seconds
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(Self {
            deadline: conservative_deadline(initial, expires_seconds)?,
            initial,
            root_request_digest: digest_signed_request(original),
            acquisition_id: root.acquisition_id(),
            attempt_digest,
            session_binding: root.session_binding(),
            issued_seconds,
            expires_seconds,
        })
    }

    /// Checks exact native scope without replacing the original local anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for changed scope or failed original-clock continuity.
    pub(crate) fn require_request(
        &self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<(), ProviderLedgerError> {
        let claims = request.request().claims();
        if self.root_request_digest
            != digest_signed_request(request.request().signed_root_request())
            || self.acquisition_id != claims.provider_acquisition().1
            || self.attempt_digest != claims.attempt().1
            || self.session_binding != claims.holder_session().1
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        self.revalidate(Some(claims.validity().1))
    }

    /// Checks the original Root request and attempt against the retained anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for substituted Root bytes, attempt, or expired clocks.
    pub(crate) fn require_original(
        &self,
        original: &SignedSourceProviderRequestV1,
        attempt: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        if self.root_request_digest != digest_signed_request(original)
            || self.attempt_digest != attempt
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        self.revalidate(None)
    }

    /// Rechecks the same kernel pair and any narrower signed receipt expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for clock discontinuity, deadline overflow, or expiry.
    pub(crate) fn revalidate(
        &self,
        receipt_expires: Option<i64>,
    ) -> Result<(), ProviderLedgerError> {
        self.validate_sample(kernel_clock()?, receipt_expires)
    }

    fn validate_sample(
        &self,
        later: RawPairedClockSample,
        receipt_expires: Option<i64>,
    ) -> Result<(), ProviderLedgerError> {
        self.initial
            .validate_later_sample(later)
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        let expires = receipt_expires.map_or(self.expires_seconds, |receipt| {
            receipt.min(self.expires_seconds)
        });
        // Any narrower receipt intersection is derived from the SAME original
        // pair, never a fresh wall-time-to-BOOTTIME rebasing on delivery/retry.
        let deadline = self
            .deadline
            .min(conservative_deadline(self.initial, expires)?);
        if later.wall_seconds() < self.issued_seconds
            || later.wall_seconds() >= expires
            || later.boottime_nanoseconds() >= deadline
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(())
    }
}

fn conservative_deadline(
    initial: RawPairedClockSample,
    expires: i64,
) -> Result<u64, ProviderLedgerError> {
    // Like Storage, subtract the unknown fractional wall second rather than
    // allowing local BOOTTIME to extend a signed absolute expiry.
    let remaining = expires
        .checked_sub(initial.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or(ProviderLedgerError::Unavailable)?;
    initial
        .boottime_nanoseconds()
        .checked_add(remaining)
        .ok_or(ProviderLedgerError::Unavailable)
}

fn kernel_clock() -> Result<RawPairedClockSample, ProviderLedgerError> {
    let boot = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| ProviderLedgerError::Unavailable)?
        .into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let after = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| ProviderLedgerError::Unavailable)?
        .into_bytes();
    if boot != after {
        return Err(ProviderLedgerError::Unavailable);
    }
    let nanoseconds = u64::try_from(boottime.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boottime.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(ProviderLedgerError::Unavailable)?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
            .map_err(|_| ProviderLedgerError::Unavailable)?,
        boot,
        wall,
        nanoseconds,
    )
    .map_err(|_| ProviderLedgerError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;

    fn sample(wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [1; 16],
            wall,
            boottime,
        )
        .unwrap()
    }

    fn guard() -> NativeAcquireClockGuardV1 {
        let initial = sample(100, 1_000_000_000);
        NativeAcquireClockGuardV1 {
            initial,
            deadline: conservative_deadline(initial, 130).unwrap(),
            root_request_digest: ObjectDigest::from_bytes([3; 32]),
            acquisition_id: ObjectDigest::from_bytes([2; 32]),
            attempt_digest: ObjectDigest::from_bytes([4; 32]),
            session_binding: ObjectDigest::from_bytes([5; 32]),
            issued_seconds: 100,
            expires_seconds: 130,
        }
    }

    #[test]
    fn native_clock_reuses_original_anchor_and_intersects_receipt_without_rebasing() {
        let guard = guard();
        let later = sample(110, 11_000_000_000);
        guard.validate_sample(later, None).unwrap();
        guard.validate_sample(later, Some(120)).unwrap();
        assert_eq!(guard.deadline, 30_000_000_000);
        // All four stages and exact retries compare against the immutable pair.
        for _ in 0..4 {
            guard.validate_sample(later, Some(120)).unwrap();
        }
        // Small wall-clock corrections admitted by the shared policy cannot
        // move the original monotonic fail-stop deadline in either direction.
        guard
            .validate_sample(sample(109, 11_000_000_000), None)
            .unwrap();
        guard
            .validate_sample(sample(111, 11_000_000_000), None)
            .unwrap();
        assert_eq!(guard.deadline, 30_000_000_000);
        assert!(
            guard
                .validate_sample(sample(119, 20_000_000_000), Some(120))
                .is_err()
        );
        assert!(
            guard
                .validate_sample(sample(129, 30_000_000_000), None)
                .is_err()
        );
        assert!(conservative_deadline(guard.initial, 101).is_err());
        assert!(conservative_deadline(sample(100, u64::MAX), 130).is_err());
    }

    #[test]
    fn native_clock_rejects_rollback_boot_provenance_and_elapsed_drift() {
        let guard = guard();
        for later in [
            sample(99, 2_000_000_000),
            sample(101, 999_999_999),
            sample(101, 10_000_000_000),
            sample(130, 31_000_000_000),
        ] {
            assert!(guard.validate_sample(later, None).is_err());
        }
        let changed_boot = RawPairedClockSample::new_untrusted(
            guard.initial.provenance(),
            [4; 16],
            101,
            2_000_000_000,
        )
        .unwrap();
        let changed_reader = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"bad-kernel-clock").unwrap(),
            [1; 16],
            101,
            2_000_000_000,
        )
        .unwrap();
        assert!(guard.validate_sample(changed_boot, None).is_err());
        assert!(guard.validate_sample(changed_reader, None).is_err());
    }

    // These checks use the existing clock DATA fixture and the real hot-map
    // value/retention helper. They do not construct installed packet brands or
    // claim that a journal append or live admission was executed.
    #[test]
    fn native_preappend_refusals_drop_local_clocks_without_hot_entries() {
        let custody =
            BTreeMap::<ObjectDigest, crate::native_completion::NativeAcquireHotCustodyV3>::new();
        for _ in 0..64 {
            let local = Arc::new(guard());
            let observed = Arc::downgrade(&local);
            assert_eq!(Arc::strong_count(&local), 1);

            // Before the final callback, a refusal drops the local admission's
            // only strong reference. Nothing is retained in the owner map.
            drop(local);

            assert!(observed.upgrade().is_none());
            assert!(custody.is_empty());
        }
    }

    #[test]
    fn native_possible_append_keeps_same_arc_without_replacing_original_anchor() {
        let acquisition = ObjectDigest::from_bytes([2; 32]);
        let mut custody = BTreeMap::new();
        let local = Arc::new(guard());
        let observed = Arc::downgrade(&local);
        crate::acquire::retain_original_clock(&mut custody, acquisition, &local).unwrap();
        assert!(Arc::ptr_eq(&custody[&acquisition].clock, &local));

        // A replay clone is the same anchor, not a new capture. Retention is
        // idempotent and neither replaces the map value nor clears its fields.
        let original_address = &custody[&acquisition] as *const _;
        let replay = Arc::clone(&custody[&acquisition].clock);
        crate::acquire::retain_original_clock(&mut custody, acquisition, &replay).unwrap();
        assert_eq!(&custody[&acquisition] as *const _, original_address);
        let recaptured = Arc::new(guard());
        assert!(
            crate::acquire::retain_original_clock(&mut custody, acquisition, &recaptured).is_err()
        );
        assert!(Arc::ptr_eq(&custody[&acquisition].clock, &local));
        assert_eq!(custody.len(), 1);

        // Once the callback ran, an uncertain append drops only local owners.
        // The map still owns the original sample; no recapture is substituted.
        drop(recaptured);
        drop(replay);
        drop(local);
        assert!(observed.upgrade().is_some());
        assert!(custody[&acquisition].source_root.is_none());
        assert_eq!(Arc::strong_count(&custody[&acquisition].clock), 1);
    }
}
