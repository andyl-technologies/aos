//! Validated public identity for one operator-installed physical quota policy.
//!
//! Identifiers are bounded non-secret names; they grant no storage authority.

use crate::content_store::StoreError;

const MAX_PHYSICAL_QUOTA_POLICY_ID_BYTES: usize = 512;
const MAX_PHYSICAL_QUOTA_POLICY_SEGMENT_BYTES: usize = 255;

/// Validated non-secret identity of one physical-filesystem quota policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorePhysicalQuotaPolicyId(String);

impl StorePhysicalQuotaPolicyId {
    /// Validates one bounded slash-separated quota-policy identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the value is empty,
    /// exceeds 512 bytes, contains an empty, `.` or `..` segment, has a segment
    /// longer than 255 bytes, or uses characters outside ASCII letters,
    /// digits, `.`, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PHYSICAL_QUOTA_POLICY_ID_BYTES
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_PHYSICAL_QUOTA_POLICY_SEGMENT_BYTES
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidComposition {
                reason: "store physical-quota policy identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated policy identifier spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
