//! Allocation-free identity of the normalized causal event-log segment.
//!
//! The borrowed stream emits the stored segment's exact binary field order.
//! Proof validators therefore need neither cloned entries nor material strings.

use std::fmt::{self, Display, Write};

use super::*;

/// Digest and dimensions of a canonical causal event-log segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventLogCausalIdentity {
    content_hash: ContentHash,
    canonical_bytes: usize,
    events: usize,
}

impl EventLogCausalIdentity {
    /// Returns the digest of the canonical binary segment.
    #[must_use]
    pub const fn content_hash(self) -> ContentHash {
        self.content_hash
    }

    /// Returns the exact encoded segment byte count.
    #[must_use]
    pub const fn canonical_bytes(self) -> usize {
        self.canonical_bytes
    }

    /// Returns the number of normalized causal entries.
    #[must_use]
    pub const fn events(self) -> usize {
        self.events
    }
}

/// Streams the canonical causal segment identity from borrowed entries.
///
/// Observational entries are omitted and causal sequence numbers start at zero,
/// matching [`event_log_causal_projection`]. No owned event or encoded segment
/// is constructed.
///
/// # Errors
///
/// Returns the original scratch admission refusal, canonical rendering failure,
/// or encoded length overflow.
pub fn event_log_causal_identity(
    entries: &[SchedulerEventLogEntry],
) -> Result<EventLogCausalIdentity, crate::EngineError> {
    segment_identity(scheduler_event_log_empty_prefix(), entries, true)
}

pub(crate) fn scheduler_event_log_segment_identity(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> Result<EventLogCausalIdentity, crate::EngineError> {
    segment_identity(previous_prefix, entries, false)
}

fn segment_identity(
    previous_prefix: ContentHash,
    entries: &[SchedulerEventLogEntry],
    causal_only: bool,
) -> Result<EventLogCausalIdentity, crate::EngineError> {
    let budget = crate::owned_decode::current_budget();
    let _scratch = budget
        .as_ref()
        .map(|budget| budget.reserve_scratch_bytes(std::mem::size_of::<SegmentHasher>() as u64))
        .transpose()
        .map_err(|source| crate::EngineError::ArtifactDecodeAdmission { source })?;
    let events = entries
        .iter()
        .filter(|entry| !causal_only || entry.class == SchedulerEventLogClass::Causal)
        .count();
    let mut output = SegmentHasher {
        hasher: blake3::Hasher::new(),
        bytes: 0,
    };
    output.write_bytes(EVENT_LOG_SEGMENT_BINARY_MAGIC)?;
    output.write_bytes(&EVENT_LOG_SEGMENT_BINARY_VERSION.to_le_bytes())?;
    output.write_bytes(&previous_prefix.bytes)?;
    output.write_u64(events as u64)?;

    for (sequence, entry) in entries
        .iter()
        .filter(|entry| !causal_only || entry.class == SchedulerEventLogClass::Causal)
        .enumerate()
    {
        let sequence = if causal_only {
            sequence as u64
        } else {
            entry.sequence
        };
        let material = scheduler_event_log_entry_material(
            sequence,
            &entry.at,
            &entry.source,
            entry.level,
            entry.class,
            &entry.event_payload,
            &entry.payload,
        );
        let content_hash = if causal_only {
            crate::model::hash_canonical_display(
                "crucible.scheduler.event-log.entry.v5",
                &material,
            )?
        } else {
            entry.content_hash
        };
        output.write_u64(sequence)?;
        output.write_u64(entry.at.virtual_time.ticks)?;
        output.write_u64(entry.at.stamp.tick.ticks)?;
        match entry.at.stamp.retired {
            Some(retired) => {
                output.write_bytes(&[EVENT_LOG_SEGMENT_NODE_PRESENT])?;
                output.write_u64(retired.retired)?;
            }
            None => output.write_bytes(&[EVENT_LOG_SEGMENT_NODE_ABSENT])?,
        }
        match &entry.at.stamp.node {
            Some(node) => {
                output.write_bytes(&[EVENT_LOG_SEGMENT_NODE_PRESENT])?;
                output.write_display(&node.name)?;
            }
            None => output.write_bytes(&[EVENT_LOG_SEGMENT_NODE_ABSENT])?,
        }
        output.write_display(&scheduler_event_log_source_material(
            "entry.source",
            &entry.source,
        ))?;
        output.write_bytes(&[event_level_code(entry.level), event_class_code(entry.class)])?;
        output.write_display(&entry.event_payload.kind())?;
        output.write_u64(entry.event_payload.attributes().len() as u64)?;
        output.write_bytes(&content_hash.bytes)?;
        output.write_display(&material)?;
    }

    Ok(EventLogCausalIdentity {
        content_hash: ContentHash {
            bytes: *output.hasher.finalize().as_bytes(),
        },
        canonical_bytes: output.bytes,
        events,
    })
}

struct SegmentHasher {
    hasher: blake3::Hasher,
    bytes: usize,
}

impl SegmentHasher {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), crate::EngineError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(render_error)?;
        self.hasher.update(bytes);
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), crate::EngineError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_display(&mut self, material: &impl Display) -> Result<(), crate::EngineError> {
        let length = crate::model::canonical_display_len(material)?;
        self.write_u64(length as u64)?;
        let before = self.bytes;
        write!(self, "{material}").map_err(|_| render_error())?;
        if self.bytes.checked_sub(before) != Some(length) {
            return Err(render_error());
        }
        Ok(())
    }
}

impl Write for SegmentHasher {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
        self.hasher.update(text.as_bytes());
        self.bytes = bytes;
        Ok(())
    }
}

fn render_error() -> crate::EngineError {
    crate::EngineError::ArtifactDecodeAdmission {
        source: crate::owned_decode::DecodeAdmissionError::new(fmt::Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_identity_matches_normalized_binary_segment()
    -> Result<(), Box<dyn std::error::Error>> {
        let _scope = crate::test_support::fixture_decode_scope(1024 * 1024)?;
        let at = VirtualTime { ticks: 17 };
        let causal = SchedulerEventLogEntry::execution_budget_exhausted(8, at, "streamé水")?;
        let diagnostic = SchedulerEventLogEntry::diagnostic(
            9,
            at,
            EventDiagnosticPayload::new("poll", EventLevel::Debug, BTreeMap::new()),
        )?;
        let stamped = causal.clone().with_time_for_test(EventLogTime {
            virtual_time: at,
            stamp: EventLogTickStamp {
                node: Some(NodeId {
                    name: String::from("node-é水"),
                }),
                tick: SimInstant { ticks: 23 },
                retired: Some(Icount { retired: 41 }),
            },
        })?;
        for entries in [
            Vec::new(),
            vec![diagnostic.clone()],
            vec![stamped],
            vec![causal.clone(), diagnostic, causal],
        ] {
            let previous = ContentHash { bytes: [173; 32] };
            let original = scheduler_event_log_segment_bytes(previous, &entries)?;
            let direct = scheduler_event_log_segment_identity(previous, &entries)?;
            assert_eq!(direct.content_hash(), ContentHash::from_bytes(&original));
            assert_eq!(direct.canonical_bytes(), original.len());
            assert_eq!(direct.events(), entries.len());

            let borrowed = event_log_causal_identity(&entries)?;
            let owned = event_log_causal_projection(&entries)?;
            assert_eq!(borrowed.content_hash(), owned.content_hash());
            assert_eq!(borrowed.canonical_bytes(), owned.canonical_bytes().len());
            assert_eq!(borrowed.events(), owned.len());
        }
        Ok(())
    }
}
