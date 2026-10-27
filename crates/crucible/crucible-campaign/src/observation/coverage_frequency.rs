//! Saturating global coverage-identity frequency records.
//!
//! A campaign snapshot's coverage root maps each coverage identity seen by a
//! canonical observation to the number of canonical observations whose
//! coverage projection names it:
//!
//! ```text
//! coverage root:
//!   coverage_identity_frequency_key(identity) -> CoverageIdentityFrequency
//! CoverageIdentityFrequency (crucible.campaign.coverage-identity-frequency v1):
//!   schema_version: u32
//!   count:          u64    // 1..=COVERAGE_IDENTITY_FREQUENCY_SATURATION
//! ```
//!
//! The count saturates at [`COVERAGE_IDENTITY_FREQUENCY_SATURATION`]. Branch
//! guidance only distinguishes a frequency of one (novelty) and the rarity
//! contribution `max(1, Q / f)`, which is exactly one for every frequency at or
//! beyond the saturation point. Saturated identities therefore stop generating
//! index writes without changing any guidance value. A record carries no
//! identity, so one record per distinct count is shared by every identity with
//! that count.

use super::*;

/// Count at which a coverage identity's global frequency stops growing.
///
/// With the rarity scale `Q`, `floor(Q / f)` is one for every
/// `f >= floor(Q / 2) + 1`, and such an identity is never globally unique.
pub const COVERAGE_IDENTITY_FREQUENCY_SATURATION: u64 = crate::BRANCH_RARITY_SCALE / 2 + 1;

const COVERAGE_IDENTITY_FREQUENCY_RECORD_BYTES: usize = 16;

/// Saturating number of canonical observations naming one coverage identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageIdentityFrequency {
    schema_version: u32,
    count: u64,
}

impl CoverageIdentityFrequency {
    /// Builds one saturating frequency record.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] when `count` is zero, or
    /// [`CampaignCodecError::LimitExceeded`] when it exceeds
    /// [`COVERAGE_IDENTITY_FREQUENCY_SATURATION`].
    pub const fn new(count: u64) -> Result<Self, CampaignCodecError> {
        if count == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "coverage identity frequency must be positive",
            });
        }
        if count > COVERAGE_IDENTITY_FREQUENCY_SATURATION {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "coverage-identity-frequency",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            count,
        })
    }

    /// Returns the saturating canonical-observation count.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns whether the count has reached the saturation point.
    #[must_use]
    pub const fn is_saturated(&self) -> bool {
        self.count == COVERAGE_IDENTITY_FREQUENCY_SATURATION
    }

    /// Returns the record after one more canonical observation names the
    /// identity, holding a saturated count at the saturation point.
    #[must_use]
    pub const fn incremented(self) -> Self {
        if self.is_saturated() {
            return self;
        }
        Self {
            schema_version: self.schema_version,
            count: self.count + 1,
        }
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, zero, oversaturated, or
    /// oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > COVERAGE_IDENTITY_FREQUENCY_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "coverage-identity-frequency-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the content identity of this record's envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if envelope construction fails.
    pub fn content_id(&self) -> Result<ContentId, CampaignCodecError> {
        Ok(crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CoverageIdentityFrequency,
            BTreeSet::new(),
            self.canonical_bytes(),
        )?
        .content_id())
    }
}

impl Canonical for CoverageIdentityFrequency {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.count.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(u64::decode(decoder)?)
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn frequency_saturates_where_rarity_contributions_reach_one() {
        let saturation = COVERAGE_IDENTITY_FREQUENCY_SATURATION;

        assert_eq!(crate::BRANCH_RARITY_SCALE / saturation, 1);
        assert_eq!(crate::BRANCH_RARITY_SCALE / (saturation - 1), 2);

        let last = CoverageIdentityFrequency::new(saturation - 1)
            .expect("unsaturated count")
            .incremented();
        assert!(last.is_saturated());
        assert_eq!(last.incremented(), last);
    }

    #[test]
    fn frequency_records_round_trip_and_reject_zero_and_oversaturated_counts() {
        let record = CoverageIdentityFrequency::new(7).expect("positive count");
        let bytes = record.canonical_bytes();

        assert_eq!(
            CoverageIdentityFrequency::from_canonical_bytes(&bytes).expect("canonical bytes"),
            record
        );
        assert!(CoverageIdentityFrequency::new(0).is_err());
        assert!(
            CoverageIdentityFrequency::new(COVERAGE_IDENTITY_FREQUENCY_SATURATION + 1).is_err()
        );
    }
}
