//! Immutable app-random campaign-branch replay plans.
//!
//! The host sends one node-local plan as the third descriptor attached to the
//! control-protocol v2 `Setup` frame. The descriptor contains exactly this
//! bounded, language-neutral byte format:
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "CRUCABP1"
//! 8       4     schema version = 1, big-endian
//! 12      4     entry count, big-endian
//! 16      ...   entries in strictly increasing draw-index order
//!
//! entry:
//! 0       8     node-local zero-based draw index, big-endian
//! 8       8     expected full seeded draw, big-endian
//! 16      8     value to serve, big-endian
//! 24      32    canonical campaign SelectionId bytes
//! 56      2     canonical stream-name byte length, big-endian
//! 58      N     UTF-8 canonical stream name
//! ```
//!
//! The plugin does not interpret campaign objects. It authenticates the live
//! request position, stream, and seeded draw against this plan before serving
//! the selected value. The Apache host independently resolves the retained
//! `SelectionId` and validates its opportunity, domain, provenance, parent,
//! and selected value before the resulting schedule can be accepted.

use thiserror::Error;

/// Frozen magic at the start of every branch-plan body.
pub const APP_RANDOM_BRANCH_PLAN_MAGIC: [u8; 8] = *b"CRUCABP1";
/// Canonical branch-plan schema version.
pub const APP_RANDOM_BRANCH_PLAN_VERSION: u32 = 1;
/// Maximum number of branch substitutions in one node-local plan.
pub const MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES: usize = 4_096;
/// Maximum canonical byte length of one node-local plan.
pub const MAX_APP_RANDOM_BRANCH_PLAN_BYTES: usize = 4 * 1024 * 1024;
/// Maximum UTF-8 byte length of a canonical app-random stream name.
pub const MAX_APP_RANDOM_BRANCH_PLAN_STREAM_BYTES: usize = 1_024;

const HEADER_LEN: usize = 16;
const ENTRY_FIXED_LEN: usize = 58;

/// One exact producer substitution in a node-local replay plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRandomBranchPlanEntry {
    draw_index: u64,
    expected_raw_value: u64,
    selected_value: u64,
    selection_id: [u8; 32],
    stream_name: String,
}

impl AppRandomBranchPlanEntry {
    /// Builds one validated producer substitution.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomBranchPlanError::InvalidStreamName`] when the stream
    /// name is empty, exceeds the plan profile, or is not the canonical
    /// length-framed app-random stream syntax.
    pub fn new(
        draw_index: u64,
        expected_raw_value: u64,
        selected_value: u64,
        selection_id: [u8; 32],
        stream_name: impl Into<String>,
    ) -> Result<Self, AppRandomBranchPlanError> {
        let stream_name = stream_name.into();
        validate_stream_name(&stream_name)?;
        Ok(Self {
            draw_index,
            expected_raw_value,
            selected_value,
            selection_id,
            stream_name,
        })
    }

    /// Returns the node-local zero-based draw index.
    #[must_use]
    pub const fn draw_index(&self) -> u64 {
        self.draw_index
    }

    /// Returns the full seeded draw required at this position.
    #[must_use]
    pub const fn expected_raw_value(&self) -> u64 {
        self.expected_raw_value
    }

    /// Returns the value that the plugin must serve.
    #[must_use]
    pub const fn selected_value(&self) -> u64 {
        self.selected_value
    }

    /// Returns the exact canonical campaign selection identity.
    #[must_use]
    pub const fn selection_id(&self) -> [u8; 32] {
        self.selection_id
    }

    /// Returns the canonical node-qualified RNG stream name.
    #[must_use]
    pub fn stream_name(&self) -> &str {
        &self.stream_name
    }
}

/// One complete node-local immutable branch replay plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppRandomBranchPlan {
    entries: Vec<AppRandomBranchPlanEntry>,
}

impl AppRandomBranchPlan {
    /// Builds a plan after validating count, order, and encoded-size bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomBranchPlanError`] when the entry count or encoded
    /// bytes exceed the protocol profile, or draw indices are not strictly
    /// increasing.
    pub fn new(entries: Vec<AppRandomBranchPlanEntry>) -> Result<Self, AppRandomBranchPlanError> {
        validate_entries(&entries)?;
        Ok(Self { entries })
    }

    /// Returns the ordered plan entries.
    #[must_use]
    pub fn entries(&self) -> &[AppRandomBranchPlanEntry] {
        &self.entries
    }

    /// Encodes this plan in the canonical descriptor-body format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let encoded_len = encoded_len(&self.entries).unwrap_or(HEADER_LEN);
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&APP_RANDOM_BRANCH_PLAN_MAGIC);
        bytes.extend_from_slice(&APP_RANDOM_BRANCH_PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.draw_index.to_be_bytes());
            bytes.extend_from_slice(&entry.expected_raw_value.to_be_bytes());
            bytes.extend_from_slice(&entry.selected_value.to_be_bytes());
            bytes.extend_from_slice(&entry.selection_id);
            bytes.extend_from_slice(&(entry.stream_name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(entry.stream_name.as_bytes());
        }
        bytes
    }

    /// Decodes one complete canonical descriptor body.
    ///
    /// # Errors
    ///
    /// Returns [`AppRandomBranchPlanError`] when the body is oversized,
    /// truncated, noncanonical, uses another magic or version, exceeds the
    /// entry profile, or contains invalid entry ordering or stream names.
    pub fn decode(bytes: &[u8]) -> Result<Self, AppRandomBranchPlanError> {
        if bytes.len() > MAX_APP_RANDOM_BRANCH_PLAN_BYTES {
            return Err(AppRandomBranchPlanError::PlanTooLarge {
                bytes: bytes.len(),
                maximum: MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
            });
        }
        if bytes.len() < HEADER_LEN {
            return Err(AppRandomBranchPlanError::Truncated);
        }
        if bytes[..8] != APP_RANDOM_BRANCH_PLAN_MAGIC {
            return Err(AppRandomBranchPlanError::InvalidMagic);
        }
        let version = read_u32(bytes, 8)?;
        if version != APP_RANDOM_BRANCH_PLAN_VERSION {
            return Err(AppRandomBranchPlanError::UnsupportedVersion { version });
        }
        let count = usize::try_from(read_u32(bytes, 12)?).map_err(|_error| {
            AppRandomBranchPlanError::EntryCountTooLarge {
                count: usize::MAX,
                maximum: MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES,
            }
        })?;
        if count > MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES {
            return Err(AppRandomBranchPlanError::EntryCountTooLarge {
                count,
                maximum: MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES,
            });
        }

        let mut cursor = HEADER_LEN;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let fixed_end = cursor
                .checked_add(ENTRY_FIXED_LEN)
                .ok_or(AppRandomBranchPlanError::Truncated)?;
            let fixed = bytes
                .get(cursor..fixed_end)
                .ok_or(AppRandomBranchPlanError::Truncated)?;
            let draw_index = read_u64(fixed, 0)?;
            let expected_raw_value = read_u64(fixed, 8)?;
            let selected_value = read_u64(fixed, 16)?;
            let mut selection_id = [0_u8; 32];
            selection_id.copy_from_slice(&fixed[24..56]);
            let stream_len = usize::from(u16::from_be_bytes([fixed[56], fixed[57]]));
            if stream_len == 0 || stream_len > MAX_APP_RANDOM_BRANCH_PLAN_STREAM_BYTES {
                return Err(AppRandomBranchPlanError::InvalidStreamName {
                    bytes: stream_len,
                    maximum: MAX_APP_RANDOM_BRANCH_PLAN_STREAM_BYTES,
                });
            }
            cursor = fixed_end;
            let stream_end = cursor
                .checked_add(stream_len)
                .ok_or(AppRandomBranchPlanError::Truncated)?;
            let stream = bytes
                .get(cursor..stream_end)
                .ok_or(AppRandomBranchPlanError::Truncated)?;
            let stream_name = std::str::from_utf8(stream)
                .map_err(|_error| AppRandomBranchPlanError::InvalidUtf8)?
                .to_owned();
            entries.push(AppRandomBranchPlanEntry::new(
                draw_index,
                expected_raw_value,
                selected_value,
                selection_id,
                stream_name,
            )?);
            cursor = stream_end;
        }
        if cursor != bytes.len() {
            return Err(AppRandomBranchPlanError::TrailingBytes {
                bytes: bytes.len() - cursor,
            });
        }
        Self::new(entries)
    }
}

fn validate_entries(entries: &[AppRandomBranchPlanEntry]) -> Result<(), AppRandomBranchPlanError> {
    if entries.len() > MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES {
        return Err(AppRandomBranchPlanError::EntryCountTooLarge {
            count: entries.len(),
            maximum: MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES,
        });
    }
    for pair in entries.windows(2) {
        if pair[0].draw_index >= pair[1].draw_index {
            return Err(AppRandomBranchPlanError::DrawIndicesNotIncreasing {
                prior: pair[0].draw_index,
                next: pair[1].draw_index,
            });
        }
    }
    let bytes = encoded_len(entries)?;
    if bytes > MAX_APP_RANDOM_BRANCH_PLAN_BYTES {
        return Err(AppRandomBranchPlanError::PlanTooLarge {
            bytes,
            maximum: MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
        });
    }
    Ok(())
}

fn validate_stream_name(stream_name: &str) -> Result<(), AppRandomBranchPlanError> {
    if stream_name.is_empty()
        || stream_name.len() > MAX_APP_RANDOM_BRANCH_PLAN_STREAM_BYTES
        || !super::app_random_transport::app_random_stream_name_is_canonical(stream_name)
    {
        return Err(AppRandomBranchPlanError::InvalidStreamName {
            bytes: stream_name.len(),
            maximum: MAX_APP_RANDOM_BRANCH_PLAN_STREAM_BYTES,
        });
    }
    Ok(())
}

fn encoded_len(entries: &[AppRandomBranchPlanEntry]) -> Result<usize, AppRandomBranchPlanError> {
    entries.iter().try_fold(HEADER_LEN, |bytes, entry| {
        bytes
            .checked_add(ENTRY_FIXED_LEN)
            .and_then(|bytes| bytes.checked_add(entry.stream_name.len()))
            .ok_or(AppRandomBranchPlanError::PlanTooLarge {
                bytes: usize::MAX,
                maximum: MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
            })
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AppRandomBranchPlanError> {
    let field = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(AppRandomBranchPlanError::Truncated)?;
    let mut value = [0_u8; 4];
    value.copy_from_slice(field);
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AppRandomBranchPlanError> {
    let field = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(AppRandomBranchPlanError::Truncated)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(field);
    Ok(u64::from_be_bytes(value))
}

/// Invalid canonical app-random campaign-branch replay plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRandomBranchPlanError {
    /// The body is too short for its header or one declared entry.
    #[error("app-random branch plan is truncated")]
    Truncated,
    /// The fixed plan magic differs.
    #[error("app-random branch plan magic is invalid")]
    InvalidMagic,
    /// The schema version is not supported.
    #[error("app-random branch plan version {version} is unsupported")]
    UnsupportedVersion {
        /// Unsupported version.
        version: u32,
    },
    /// The entry count exceeds the fixed profile.
    #[error("app-random branch plan has {count} entries, maximum {maximum}")]
    EntryCountTooLarge {
        /// Actual entry count.
        count: usize,
        /// Maximum admitted entry count.
        maximum: usize,
    },
    /// The canonical body exceeds the fixed byte profile.
    #[error("app-random branch plan has {bytes} bytes, maximum {maximum}")]
    PlanTooLarge {
        /// Actual or overflow-saturated byte count.
        bytes: usize,
        /// Maximum admitted byte count.
        maximum: usize,
    },
    /// Entry positions are duplicate or out of order.
    #[error("app-random branch draw indices are not increasing: {prior} then {next}")]
    DrawIndicesNotIncreasing {
        /// Prior entry draw index.
        prior: u64,
        /// Next entry draw index.
        next: u64,
    },
    /// A stream name is empty, oversized, or not canonical app-random syntax.
    #[error("app-random branch stream name has {bytes} bytes or invalid syntax; maximum {maximum}")]
    InvalidStreamName {
        /// Actual stream-name byte count.
        bytes: usize,
        /// Maximum admitted byte count.
        maximum: usize,
    },
    /// A stream name is not valid UTF-8.
    #[error("app-random branch stream name is not valid UTF-8")]
    InvalidUtf8,
    /// Bytes remain after the declared entries.
    #[error("app-random branch plan has {bytes} trailing bytes")]
    TrailingBytes {
        /// Trailing byte count.
        bytes: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_random_transport::app_random_stream_name;

    #[test]
    fn branch_plan_round_trips_and_freezes_big_endian_layout() {
        let plan = AppRandomBranchPlan::new(vec![
            AppRandomBranchPlanEntry::new(
                3,
                0x0102_0304_0506_0708,
                7,
                [0xabu8; 32],
                app_random_stream_name("node-a", "guest"),
            )
            .unwrap_or_else(|error| panic!("entry should validate: {error}")),
        ])
        .unwrap_or_else(|error| panic!("plan should validate: {error}"));
        let bytes = plan.encode();
        assert_eq!(&bytes[..8], b"CRUCABP1");
        assert_eq!(&bytes[8..12], &[0, 0, 0, 1]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 1]);
        assert_eq!(&bytes[16..24], &[0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(AppRandomBranchPlan::decode(&bytes), Ok(plan));
    }

    #[test]
    fn branch_plan_rejects_duplicate_positions_and_trailing_bytes() {
        let stream = app_random_stream_name("node-a", "guest");
        let entry = AppRandomBranchPlanEntry::new(3, 5, 7, [1; 32], stream)
            .unwrap_or_else(|error| panic!("entry should validate: {error}"));
        assert!(matches!(
            AppRandomBranchPlan::new(vec![entry.clone(), entry]),
            Err(AppRandomBranchPlanError::DrawIndicesNotIncreasing { .. })
        ));

        let mut bytes = AppRandomBranchPlan::default().encode();
        bytes.push(0);
        assert_eq!(
            AppRandomBranchPlan::decode(&bytes),
            Err(AppRandomBranchPlanError::TrailingBytes { bytes: 1 })
        );
    }
}
