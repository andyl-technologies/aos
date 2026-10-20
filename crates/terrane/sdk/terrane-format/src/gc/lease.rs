//! Encodes the singleton collector lease and its pure fencing checks.
//!
//! The registered lease compares holder, epoch and expiry as one complete value:
//!
//! ```text
//! GcLease = {1: holder, 2: epoch, 3: expiry}
//! ```
//!
//! Acquisition and renewal construct conditional-write proposals. Callers must
//! obtain the authoritative current lease and clock, publish by conditional
//! write, and stop after losing ownership. These records grant no physical
//! collection authority.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::cbor::{self, Decoder};

/// A collector record or safety policy is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcError {
    /// A record violates canonical CBOR encoding.
    Cbor(cbor::Error),
    /// A field violates its registered schema.
    Schema,
    /// The grace or deletion window is too short.
    Window,
    /// A duration or fencing epoch cannot be represented.
    Exhausted,
    /// The holder no longer owns an unexpired lease.
    LeaseLost,
}

impl From<cbor::Error> for GcError {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl fmt::Display for GcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cbor(_) => "invalid collector CBOR",
            Self::Schema => "invalid collector record",
            Self::Window => "collector windows violate G > C or D >= G",
            Self::Exhausted => "collector time or epoch exhausted",
            Self::LeaseLost => "collector lease lost",
        })
    }
}

impl core::error::Error for GcError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            _ => None,
        }
    }
}

/// A singleton collector lease compared as a complete conditional-write value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcLease {
    /// Identity of the process holding the lease.
    pub holder: String,
    /// Monotone fencing epoch, including after expiry and takeover.
    pub epoch: u64,
    /// Expiry in authoritative store seconds since the Unix epoch.
    pub expiry: u64,
}

impl GcLease {
    /// Constructs an initial lease or a higher-epoch takeover of an expired lease.
    ///
    /// # Errors
    /// Rejects a live previous lease, empty holder, zero duration, or overflow.
    pub fn acquire(
        holder: String,
        now: u64,
        duration: u64,
        previous: Option<&Self>,
    ) -> Result<Self, GcError> {
        if holder.is_empty() || duration == 0 {
            return Err(GcError::Schema);
        }
        if previous.is_some_and(|lease| now < lease.expiry) {
            return Err(GcError::LeaseLost);
        }
        let epoch = previous.map_or(Ok(1), |lease| {
            lease.epoch.checked_add(1).ok_or(GcError::Exhausted)
        })?;
        let expiry = now.checked_add(duration).ok_or(GcError::Exhausted)?;
        Ok(Self {
            holder,
            epoch,
            expiry,
        })
    }

    /// Extends an unexpired lease without changing holder or fencing epoch.
    ///
    /// # Errors
    /// Rejects expiry, zero duration, overflow, or a nonincreasing expiry.
    pub fn renew(&self, now: u64, duration: u64) -> Result<Self, GcError> {
        let expiry = now.checked_add(duration).ok_or(GcError::Exhausted)?;
        if now >= self.expiry || expiry <= self.expiry {
            return Err(GcError::LeaseLost);
        }
        Ok(Self {
            holder: self.holder.clone(),
            epoch: self.epoch,
            expiry,
        })
    }

    /// Validates ownership against the authoritative current lease and clock.
    ///
    /// # Errors
    /// Rejects any holder, epoch, expiry, or complete-record mismatch or expiry.
    pub fn check(&self, current: Option<&Self>, now: u64) -> Result<(), GcError> {
        if current != Some(self) || now >= self.expiry {
            return Err(GcError::LeaseLost);
        }
        Ok(())
    }

    /// Encodes the registered GcLease map.
    ///
    /// # Errors
    /// Rejects an empty holder.
    pub fn encode(&self) -> Result<Vec<u8>, GcError> {
        if self.holder.is_empty() {
            return Err(GcError::Schema);
        }
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 3);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_text(&mut bytes, &self.holder);
        cbor::write_uint(&mut bytes, 2);
        cbor::write_uint(&mut bytes, self.epoch);
        cbor::write_uint(&mut bytes, 3);
        cbor::write_uint(&mut bytes, self.expiry);
        Ok(bytes)
    }

    /// Decodes the exact registered GcLease map without trailing values.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unknown fields, missing fields, and empty holder.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.map(bytes.len())? != 3 {
            return Err(GcError::Schema);
        }
        key(&mut decoder, 1)?;
        let holder = String::from(decoder.text(bytes.len())?);
        key(&mut decoder, 2)?;
        let epoch = decoder.uint()?;
        key(&mut decoder, 3)?;
        let expiry = decoder.uint()?;
        decoder.finish()?;
        if holder.is_empty() {
            return Err(GcError::Schema);
        }
        Ok(Self {
            holder,
            epoch,
            expiry,
        })
    }
}

/// Checks the next canonical map key against its registered collector field.
///
/// # Errors
/// Returns a CBOR error for an invalid integer or a schema error for another key.
pub(super) fn key(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), GcError> {
    if decoder.uint()? != expected {
        return Err(GcError::Schema);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Checks byte compatibility and complete-value lease fencing.

    #![allow(
        clippy::unwrap_used,
        reason = "Test fixtures and assertions intentionally panic on failure."
    )]

    use super::*;

    // Independently written registered map: holder A, epoch 1, expiry 20.
    const LEASE_BYTES: &[u8] = &[0xa3, 0x01, 0x61, b'A', 0x02, 0x01, 0x03, 0x14];

    fn lease() -> GcLease {
        GcLease {
            holder: "A".into(),
            epoch: 1,
            expiry: 20,
        }
    }

    #[test]
    fn gc_lease_canonical_bytes_match_independent_map() {
        let record = lease();

        assert_eq!(record.encode().unwrap(), LEASE_BYTES);
        assert_eq!(GcLease::decode(LEASE_BYTES).unwrap(), record);
    }

    #[test]
    fn gc_lease_rejects_noncanonical_or_incomplete_maps() {
        let invalid: &[(&str, &[u8])] = &[
            ("missing expiry", &[0xa2, 1, 0x61, b'A', 2, 1]),
            ("empty holder", &[0xa3, 1, 0x60, 2, 1, 3, 20]),
            ("duplicate key", &[0xa3, 1, 0x61, b'A', 2, 1, 2, 20]),
            ("unordered keys", &[0xa3, 2, 1, 1, 0x61, b'A', 3, 20]),
            ("unknown key", &[0xa3, 1, 0x61, b'A', 2, 1, 4, 20]),
            (
                "nonminimal epoch",
                &[0xa3, 1, 0x61, b'A', 2, 0x18, 1, 3, 20],
            ),
            ("trailing value", &[0xa3, 1, 0x61, b'A', 2, 1, 3, 20, 0]),
            ("indefinite map", &[0xbf, 1, 0x61, b'A', 2, 1, 3, 20, 0xff]),
            ("truncated holder", &[0xa3, 1, 0x78, 0xff]),
        ];

        for (case, bytes) in invalid {
            assert!(GcLease::decode(bytes).is_err(), "{case}");
        }

        let mut record = lease();
        record.holder.clear();
        assert_eq!(record.encode(), Err(GcError::Schema));
    }

    #[test]
    fn gc_lease_check_requires_the_whole_current_value_before_expiry() {
        let record = lease();
        let mut different_holder = record.clone();
        different_holder.holder = "B".into();
        let mut different_epoch = record.clone();
        different_epoch.epoch += 1;
        let mut different_expiry = record.clone();
        different_expiry.expiry += 1;

        assert_eq!(record.check(Some(&record), 19), Ok(()));
        assert_eq!(record.check(None, 19), Err(GcError::LeaseLost));
        for current in [different_holder, different_epoch, different_expiry] {
            assert_eq!(record.check(Some(&current), 19), Err(GcError::LeaseLost));
        }
        assert_eq!(record.check(Some(&record), 20), Err(GcError::LeaseLost));
        assert_eq!(record.check(Some(&record), 21), Err(GcError::LeaseLost));
    }

    #[test]
    fn gc_lease_acquisition_increments_epoch_only_after_expiry() {
        let initial = GcLease::acquire("A".into(), 10, 10, None).unwrap();

        assert_eq!(initial, lease());
        assert_eq!(
            GcLease::acquire("B".into(), 19, 10, Some(&initial)),
            Err(GcError::LeaseLost)
        );

        let takeover = GcLease::acquire("B".into(), 20, 10, Some(&initial)).unwrap();

        assert_eq!(takeover.holder, "B");
        assert_eq!(takeover.epoch, 2);
        assert_eq!(takeover.expiry, 30);
        assert_eq!(initial.check(Some(&takeover), 20), Err(GcError::LeaseLost));
    }

    #[test]
    fn gc_lease_acquisition_rejects_empty_holder_zero_duration_and_overflow() {
        assert_eq!(
            GcLease::acquire(String::new(), 10, 10, None),
            Err(GcError::Schema)
        );
        assert_eq!(
            GcLease::acquire("A".into(), 10, 0, None),
            Err(GcError::Schema)
        );
        assert_eq!(
            GcLease::acquire("A".into(), u64::MAX, 1, None),
            Err(GcError::Exhausted)
        );

        let exhausted = GcLease {
            holder: "A".into(),
            epoch: u64::MAX,
            expiry: 20,
        };

        assert_eq!(
            GcLease::acquire("B".into(), 20, 10, Some(&exhausted)),
            Err(GcError::Exhausted)
        );
    }

    #[test]
    fn gc_lease_renewal_extends_expiry_without_changing_holder_or_epoch() {
        let record = lease();

        let renewed = record.renew(15, 10).unwrap();

        assert_eq!(renewed.holder, record.holder);
        assert_eq!(renewed.epoch, record.epoch);
        assert_eq!(renewed.expiry, 25);
        assert_eq!(record.check(Some(&renewed), 15), Err(GcError::LeaseLost));
        assert_eq!(renewed.check(Some(&renewed), 24), Ok(()));
    }

    #[test]
    fn gc_lease_renewal_rejects_expiry_nonincreasing_expiry_and_overflow() {
        let record = lease();

        assert_eq!(record.renew(20, 10), Err(GcError::LeaseLost));
        assert_eq!(record.renew(15, 0), Err(GcError::LeaseLost));
        assert_eq!(record.renew(15, 4), Err(GcError::LeaseLost));
        assert_eq!(record.renew(15, 5), Err(GcError::LeaseLost));
        assert_eq!(record.renew(u64::MAX, 1), Err(GcError::Exhausted));
    }
}
