//! Original hot-owner clock continuity for the private native completion seam.
//!
//! One paired kernel sample and conservative BOOTTIME deadline precede
//! Requested. Every retry retains that same anchor; it cannot create one from
//! historical wall bounds. The guard is intentionally not serialized, so a
//! cold owner preserves unresolved rows and interests but cannot complete.

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SignedStorageNativeAcquireRequestV2, decode_acquire_request,
    digest_signed_request,
};

use crate::ProviderLedgerError;

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
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| ProviderLedgerError::Unavailable)?,
        boot,
        wall,
        nanoseconds,
    )
    .map_err(|_| ProviderLedgerError::Unavailable)
}

#[cfg(test)]
mod tests {
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
}
