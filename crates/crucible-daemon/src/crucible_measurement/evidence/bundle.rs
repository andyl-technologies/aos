//! A replay leaf carried together with the segments it references.
//!
//! In process, a bundle holds read handles to the stores that hold its
//! segments, so carrying one costs no segment copies. Some carriers have no
//! segment store: the resume request of the lifecycle
//! API, a savepoint handle file, and a guarded run's result after its private
//! repository is gone. They carry a bundle instead:
//!
//! ```text
//! "crucible.measurement-evidence-bundle.v1\0"
//! u32 leaf length, canonical replay leaf
//! u32 segment count
//! per segment, in manifest order: u32 length, encoded segment
//! ```
//!
//! All integers are big-endian. Decoding requires exactly the segments the
//! leaf references, in order, each deriving its referenced identity.

use super::*;
use crate::AttemptLogSegmentSources;
use crate::attempt_event_log::MemorySegmentStore;

const BUNDLE_MAGIC: &[u8] = b"crucible.measurement-evidence-bundle.v1\0";

/// A replay leaf and read access to every log segment it references.
///
/// Two bundles are equal when their leaves are: a leaf names its segments by
/// content identity, and every constructor authenticates them.
#[derive(Clone, Debug)]
pub struct CrucibleMeasurementEvidenceBundle {
    evidence: CrucibleMeasurementReplayEvidence,
    segments: AttemptLogSegmentSources,
}

impl PartialEq for CrucibleMeasurementEvidenceBundle {
    fn eq(&self, other: &Self) -> bool {
        self.evidence == other.evidence
    }
}

impl Eq for CrucibleMeasurementEvidenceBundle {}

impl CrucibleMeasurementEvidenceBundle {
    /// Copies the segments `evidence` references out of `source`.
    ///
    /// Use [`Self::referencing`] when `source` outlives the bundle, to avoid
    /// holding the segments in memory.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError::EventLog`] when a referenced
    /// segment is absent from `source` or fails authentication.
    pub fn collect(
        evidence: CrucibleMeasurementReplayEvidence,
        source: &dyn AttemptLogSegmentSource,
    ) -> Result<Self, CrucibleMeasurementError> {
        let mut segments = MemorySegmentStore::default();
        for segment in evidence.segments() {
            segments.copy_from(source, segment)?;
        }
        Ok(Self {
            evidence,
            segments: segments.into(),
        })
    }

    /// Pairs `evidence` with the stores that hold its segments, without
    /// copying them.
    ///
    /// Each referenced segment is read once and authenticated, one at a time.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError::EventLog`] when a referenced
    /// segment is absent from `segments` or fails authentication.
    pub fn referencing(
        evidence: CrucibleMeasurementReplayEvidence,
        segments: AttemptLogSegmentSources,
    ) -> Result<Self, CrucibleMeasurementError> {
        for segment in evidence.segments() {
            let bytes = segments.segment(segment.id).map_err(|source| {
                crate::attempt_event_log::AttemptEventLogError::Store { source }
            })?;
            crate::decode_segment(segment, &bytes)?;
        }
        Ok(Self { evidence, segments })
    }

    /// Returns the replay leaf.
    #[must_use]
    pub const fn evidence(&self) -> &CrucibleMeasurementReplayEvidence {
        &self.evidence
    }

    /// Returns the stores holding the referenced segments, usable as the
    /// leaf's segment source.
    #[must_use]
    pub const fn segments(&self) -> &AttemptLogSegmentSources {
        &self.segments
    }

    /// Splits the bundle into its leaf and segment stores.
    #[must_use]
    pub fn into_parts(self) -> (CrucibleMeasurementReplayEvidence, AttemptLogSegmentSources) {
        (self.evidence, self.segments)
    }

    /// Returns the bundle's bytes under a caller-selected ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError::EvidenceTooLarge`] when the bundle
    /// exceeds `maximum_bytes`, or the leaf's encoding error.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, CrucibleMeasurementError> {
        let leaf = self.evidence.canonical_bytes()?;
        let referenced = self.evidence.segments();
        let segment_bytes = referenced
            .iter()
            .map(|segment| segment.encoded_bytes)
            .fold(0_u64, u64::saturating_add);
        let length = (BUNDLE_MAGIC.len() + leaf.len() + 8) as u64
            + segment_bytes
            + 4 * referenced.len() as u64;
        let actual = usize::try_from(length).unwrap_or(usize::MAX);
        if actual > maximum_bytes {
            return Err(CrucibleMeasurementError::EvidenceTooLarge {
                actual,
                maximum: maximum_bytes,
            });
        }

        let mut bytes = Vec::with_capacity(actual);
        bytes.extend_from_slice(BUNDLE_MAGIC);
        push_record(&mut bytes, &leaf)?;
        push_length(&mut bytes, referenced.len())?;
        for segment in referenced {
            let encoded = self.segments.segment(segment.id).map_err(|source| {
                crate::attempt_event_log::AttemptEventLogError::Store { source }
            })?;
            push_record(&mut bytes, &encoded)?;
        }
        Ok(bytes)
    }

    /// Decodes and checks bundle bytes under a caller-selected ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CrucibleMeasurementError`] when the bytes exceed
    /// `maximum_bytes`, are truncated or trailing, carry an invalid leaf, or
    /// do not carry exactly the referenced segments in order.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, CrucibleMeasurementError> {
        if bytes.len() > maximum_bytes {
            return Err(CrucibleMeasurementError::EvidenceTooLarge {
                actual: bytes.len(),
                maximum: maximum_bytes,
            });
        }
        let mut rest = bytes
            .strip_prefix(BUNDLE_MAGIC)
            .ok_or_else(|| malformed("bundle magic"))?;

        let evidence =
            CrucibleMeasurementReplayEvidence::from_canonical_bytes(take_record(&mut rest)?)?;
        let count = take_length(&mut rest)?;
        if count != evidence.segments().len() {
            return Err(malformed("bundle segment count"));
        }
        let mut segments = MemorySegmentStore::default();
        for segment in evidence.segments() {
            let id = segments.insert(take_record(&mut rest)?.to_vec())?;
            if id != segment.id {
                return Err(malformed("bundle segment order"));
            }
        }
        if !rest.is_empty() {
            return Err(malformed("bundle trailing bytes"));
        }
        Ok(Self {
            evidence,
            segments: segments.into(),
        })
    }
}

fn push_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), CrucibleMeasurementError> {
    let length = u32::try_from(length).map_err(|_| malformed("bundle length"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn push_record(bytes: &mut Vec<u8>, record: &[u8]) -> Result<(), CrucibleMeasurementError> {
    push_length(bytes, record.len())?;
    bytes.extend_from_slice(record);
    Ok(())
}

fn take_length(rest: &mut &[u8]) -> Result<usize, CrucibleMeasurementError> {
    let (length, tail) = rest
        .split_first_chunk::<4>()
        .ok_or_else(|| malformed("bundle truncated"))?;
    *rest = tail;
    usize::try_from(u32::from_be_bytes(*length)).map_err(|_| malformed("bundle length"))
}

fn take_record<'bytes>(rest: &mut &'bytes [u8]) -> Result<&'bytes [u8], CrucibleMeasurementError> {
    let length = take_length(rest)?;
    if rest.len() < length {
        return Err(malformed("bundle truncated"));
    }
    let (record, tail) = rest.split_at(length);
    *rest = tail;
    Ok(record)
}

fn malformed(reason: &str) -> CrucibleMeasurementError {
    CrucibleMeasurementError::EvidenceEncoding {
        reason: reason.to_owned(),
    }
}
