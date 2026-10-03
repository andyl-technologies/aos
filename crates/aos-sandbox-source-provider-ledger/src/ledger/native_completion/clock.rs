//! Non-authorizing original paired-clock metadata in the native owner row.
//!
//! The protected owner records this block once before dispatch. Decoding raw
//! clock claims does not authenticate a clock, restore a session, or renew the
//! original request. Positive recovery needs the owner's exact graph joins
//! and a fresh sample from the same kernel adapter.
//!
//! ```text
//! provenance:16 | original-boot:16 | original-wall:i64be |
//! original-boottime:u64be | fixed-deadline:u64be
//! ```

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, decode_acquire_request,
};

use super::super::LedgerFormatErrorV1;
use super::super::codec::{Decoder, Encoder};

pub(super) const RAW_PAIR_BYTES: usize = 48;
pub(super) const CLOCK_BYTES: usize = RAW_PAIR_BYTES + 8;

/// Retains raw original clock claims without granting completion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAcquireClockAnchorV1 {
    initial: RawPairedClockSample,
    deadline: u64,
}

impl NativeAcquireClockAnchorV1 {
    /// Binds one raw original pair to the exact signed native expiry.
    ///
    /// # Errors
    ///
    /// Rejects negative wall time, wrong original boot, a pair after issuance,
    /// or a conservative deadline that is expired or cannot be represented.
    pub fn new_untrusted(
        initial: RawPairedClockSample,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<Self, LedgerFormatErrorV1> {
        let anchor = Self {
            initial,
            deadline: conservative_deadline(initial, request.request().claims().validity().1)?,
        };
        anchor.validate_request(request)?;
        Ok(anchor)
    }

    /// Returns the immutable raw original pair.
    #[must_use]
    pub const fn initial(self) -> RawPairedClockSample {
        self.initial
    }

    /// Returns the exclusive, immutable local BOOTTIME deadline.
    #[must_use]
    pub const fn deadline(self) -> u64 {
        self.deadline
    }

    /// Checks canonical clock/request crosslinks, not clock authenticity.
    ///
    /// # Errors
    ///
    /// Rejects changed boot, original wall bounds, or a noncanonical deadline.
    pub fn validate_request(
        self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<(), LedgerFormatErrorV1> {
        let root = decode_acquire_request(request.request().signed_root_request().subject())
            .map_err(|_| LedgerFormatErrorV1::Corrupt("native clock Root request"))?;
        let (issued, expires) = request.request().claims().validity();
        if self.initial.host_boot_id() != root.boot_id()
            || self.initial.wall_seconds() < 0
            || self.initial.wall_seconds() > issued
            || self.deadline <= self.initial.boottime_nanoseconds()
            || self.deadline != conservative_deadline(self.initial, expires)?
        {
            return Err(LedgerFormatErrorV1::Corrupt("native original clock claims"));
        }
        Ok(())
    }

    pub(super) fn encode(self, body: &mut Encoder) {
        encode_raw_pair(self.initial, body);
        body.u64(self.deadline);
    }

    pub(super) fn decode(body: &mut Decoder<'_>) -> Result<Self, LedgerFormatErrorV1> {
        Ok(Self {
            initial: decode_raw_pair(body)?,
            deadline: body.u64()?,
        })
    }
}

// Original Source metadata and the old anchor use the same raw48 encoding.
// These helpers serialize claims only; they never sample or authenticate a clock.
pub(super) fn encode_raw_pair(initial: RawPairedClockSample, body: &mut Encoder) {
    body.array(&initial.provenance().as_bytes());
    body.array(&initial.host_boot_id());
    body.i64(initial.wall_seconds());
    body.u64(initial.boottime_nanoseconds());
}

pub(super) fn decode_raw_pair(
    body: &mut Decoder<'_>,
) -> Result<RawPairedClockSample, LedgerFormatErrorV1> {
    let provenance = RawClockProvenance::new_untrusted(body.nonzero_array()?)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("native clock provenance"))?;
    RawPairedClockSample::new_untrusted(
        provenance,
        body.nonzero_array()?,
        body.nonnegative_i64()?,
        body.u64()?,
    )
    .map_err(|_| LedgerFormatErrorV1::Corrupt("native original clock pair"))
}

pub(super) fn conservative_deadline(
    initial: RawPairedClockSample,
    expires: i64,
) -> Result<u64, LedgerFormatErrorV1> {
    expires
        .checked_sub(initial.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|remaining| initial.boottime_nanoseconds().checked_add(remaining))
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native clock deadline overflow or expiry",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_anchor56_preserves_independent_raw48_then_deadline8_bytes() {
        let initial = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [2; 16],
            100,
            1_000_000_000,
        )
        .unwrap();
        let anchor = NativeAcquireClockAnchorV1 {
            initial,
            deadline: 30_000_000_000,
        };
        let mut encoded = Encoder::with_capacity(56);
        anchor.encode(&mut encoded);
        let mut expected = b"aos-kernel-clock".to_vec();
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&100_i64.to_be_bytes());
        expected.extend_from_slice(&1_000_000_000_u64.to_be_bytes());
        expected.extend_from_slice(&30_000_000_000_u64.to_be_bytes());

        assert_eq!(RAW_PAIR_BYTES, 48);
        assert_eq!(CLOCK_BYTES, 56);
        assert_eq!(encoded.as_slice(), expected);
        let mut decoded = Decoder::new(&expected);
        assert_eq!(
            NativeAcquireClockAnchorV1::decode(&mut decoded).unwrap(),
            anchor,
        );
        decoded.finish().unwrap();
        for offset in [0, 16] {
            let mut invalid = expected.clone();
            invalid[offset..offset + 16].fill(0);
            assert!(NativeAcquireClockAnchorV1::decode(&mut Decoder::new(&invalid)).is_err());
        }
        let mut invalid = expected;
        invalid[32..40].copy_from_slice(&(-1_i64).to_be_bytes());
        assert!(NativeAcquireClockAnchorV1::decode(&mut Decoder::new(&invalid)).is_err());
    }

    #[test]
    fn native_clock_deadline_rejects_exact_expiry_fraction_and_arithmetic_overflow() {
        let sample = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [1; 16],
            100,
            1_000_000_000,
        )
        .unwrap();
        assert_eq!(conservative_deadline(sample, 130).unwrap(), 30_000_000_000);
        for expiry in [99, 100, 101] {
            assert!(conservative_deadline(sample, expiry).is_err());
        }
        assert!(conservative_deadline(sample, i64::MAX).is_err());
        let overflow = RawPairedClockSample::new_untrusted(
            sample.provenance(),
            sample.host_boot_id(),
            100,
            u64::MAX,
        )
        .unwrap();
        assert!(conservative_deadline(overflow, 130).is_err());
    }
}
