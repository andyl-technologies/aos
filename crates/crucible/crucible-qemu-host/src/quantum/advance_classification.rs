//! Host-held record of how one advance's completion was classified.
//!
//! Two different histories leave the same quiesced slot fields behind a
//! pause at the node's own coordinate: the plugin answered the new advance
//! with a fresh zero-length boundary, or the host accepted the boundary the
//! previous clamp left in place. The checkpoint guard holds the second case
//! pending until the publication changes, so a stall report has to say
//! whether that guard was armed for the advance, what released it, and which
//! publication generation the host finally classified:
//!
//! ```text
//! classification=guard_start:1100,guard_release:changed/status:2/logical:1100/idle_wake:1100/gen:812,fence_gen:810,discovery_gen:814
//! ```
//!
//! The record is diagnostic only. It is written beside the decisions it
//! describes and never feeds a classification or a guest-visible value.

use std::fmt;

/// What released the zero-length checkpoint guard during one advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointGuardRelease {
    /// A network output stop owned the publication.
    OutputStop,
    /// A native console operation stop owned the publication.
    ConsoleStop,
    /// A fresh publication released a deferred native console run report.
    NativeReport,
    /// The slot no longer matched the guarded coordinate.
    Changed {
        status: u8,
        logical: u64,
        idle_wake: u64,
        publish_gen: u32,
    },
}

impl fmt::Display for CheckpointGuardRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputStop => formatter.write_str("output-stop"),
            Self::ConsoleStop => formatter.write_str("console-stop"),
            Self::NativeReport => formatter.write_str("native-report"),
            Self::Changed {
                status,
                logical,
                idle_wake,
                publish_gen,
            } => write!(
                formatter,
                "changed/status:{status}/logical:{logical}/idle_wake:{idle_wake}/gen:{publish_gen}"
            ),
        }
    }
}

/// Guard and generation evidence for the advance a clamp completed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AdvanceClassification {
    guard_start: Option<u64>,
    guard_release: Option<CheckpointGuardRelease>,
    fence_publish_gen: Option<u32>,
    discovery_publish_gen: Option<u32>,
}

impl AdvanceClassification {
    /// Starts the record for a new advance with its initial guard coordinate.
    pub(crate) const fn begin(guard_start: Option<u64>) -> Self {
        Self {
            guard_start,
            guard_release: None,
            fence_publish_gen: None,
            discovery_publish_gen: None,
        }
    }

    /// Replaces the guard coordinate a first poll derived for this advance.
    pub(crate) const fn note_guard_start(&mut self, guard_start: Option<u64>) {
        self.guard_start = guard_start;
    }

    /// Records the pre-wake generation armed with this advance's fence.
    pub(crate) const fn note_fence(&mut self, publish_gen: Option<u32>) {
        self.fence_publish_gen = publish_gen;
    }

    /// Records the first guard release; later releases add nothing new.
    pub(crate) fn note_release(&mut self, release: CheckpointGuardRelease) {
        self.guard_release.get_or_insert(release);
    }

    /// Returns the record completed by the publication the host classified.
    pub(crate) const fn classified(mut self, publish_gen: u32) -> Self {
        self.discovery_publish_gen = Some(publish_gen);
        self
    }
}

impl fmt::Display for AdvanceClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("classification=guard_start:")?;
        write_optional(formatter, self.guard_start)?;
        formatter.write_str(",guard_release:")?;
        write_optional(formatter, self.guard_release)?;
        formatter.write_str(",fence_gen:")?;
        write_optional(formatter, self.fence_publish_gen)?;
        formatter.write_str(",discovery_gen:")?;
        write_optional(formatter, self.discovery_publish_gen)
    }
}

fn write_optional(
    formatter: &mut fmt::Formatter<'_>,
    value: Option<impl fmt::Display>,
) -> fmt::Result {
    match value {
        Some(value) => write!(formatter, "{value}"),
        None => formatter.write_str("none"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_classified_advance_names_its_guard_and_generations() {
        let mut record = AdvanceClassification::begin(Some(1100));
        record.note_fence(Some(810));
        record.note_release(CheckpointGuardRelease::Changed {
            status: 2,
            logical: 1100,
            idle_wake: 1100,
            publish_gen: 812,
        });
        record.note_release(CheckpointGuardRelease::OutputStop);

        assert_eq!(
            record.classified(814).to_string(),
            "classification=guard_start:1100,guard_release:changed/status:2/logical:1100/idle_wake:1100/gen:812,fence_gen:810,discovery_gen:814"
        );
    }

    #[test]
    fn an_unguarded_advance_prints_none_for_absent_evidence() {
        assert_eq!(
            AdvanceClassification::begin(None).to_string(),
            "classification=guard_start:none,guard_release:none,fence_gen:none,discovery_gen:none"
        );
    }
}
