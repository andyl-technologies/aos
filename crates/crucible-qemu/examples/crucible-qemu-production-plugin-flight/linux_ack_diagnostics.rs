//! Fixed-size discriminators for an already-refused Linux ACK transcript.
//!
//! Console framing follows host socket availability, rather than an original
//! guest write coordinate. Separate digests locate a difference without changing
//! the combined transcript, its strict comparison, or successful result fields.
//! Control subdigests observe the same raw-retirement, stop-classification, and
//! idle-state bytes already included in the original transcript.

use super::{ObservableEvent, ObservableEventPayload};

pub(super) struct TranscriptDiagnostics {
    control: blake3::Hasher,
    raw: blake3::Hasher,
    classification: blake3::Hasher,
    idle: blake3::Hasher,
    framed_console: blake3::Hasher,
    console_bytes: blake3::Hasher,
    console_event_count: u64,
    console_byte_count: u64,
}

impl TranscriptDiagnostics {
    pub(super) fn new() -> Self {
        Self {
            control: blake3::Hasher::new(),
            raw: blake3::Hasher::new(),
            classification: blake3::Hasher::new(),
            idle: blake3::Hasher::new(),
            framed_console: blake3::Hasher::new(),
            console_bytes: blake3::Hasher::new(),
            console_event_count: 0,
            console_byte_count: 0,
        }
    }

    /// Observes only console events accepted by the original validator.
    pub(super) fn record_validated_console(&mut self, events: &[ObservableEvent]) {
        self.framed_console
            .update(&(events.len() as u64).to_le_bytes());
        for event in events {
            if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
                self.framed_console.update(&event.at().ticks.to_le_bytes());
                self.framed_console
                    .update(&(bytes.len() as u64).to_le_bytes());
                self.framed_console.update(bytes);
                self.console_bytes.update(bytes);

                // Original return and per-boundary spool limits make overflow
                // unreachable. Saturation cannot introduce a new refusal path.
                self.console_event_count = self.console_event_count.saturating_add(1);
                self.console_byte_count =
                    self.console_byte_count.saturating_add(bytes.len() as u64);
            }
        }
    }

    pub(super) fn finish(self) -> TranscriptDigests {
        TranscriptDigests {
            control: self.control.finalize(),
            raw: self.raw.finalize(),
            classification: self.classification.finalize(),
            idle: self.idle.finalize(),
            framed_console: self.framed_console.finalize(),
            console_bytes: self.console_bytes.finalize(),
            console_event_count: self.console_event_count,
            console_byte_count: self.console_byte_count,
        }
    }
}

/// Forwards the original serialization and selected fields without new reads.
pub(super) struct ControlTranscript<'a> {
    canonical: &'a mut blake3::Hasher,
    diagnostics: &'a mut TranscriptDiagnostics,
}

impl<'a> ControlTranscript<'a> {
    pub(super) fn new(
        canonical: &'a mut blake3::Hasher,
        diagnostics: &'a mut TranscriptDiagnostics,
    ) -> Self {
        Self {
            canonical,
            diagnostics,
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.canonical.update(bytes);
        self.diagnostics.control.update(bytes);
    }

    pub(super) fn update_raw(&mut self, bytes: &[u8]) {
        self.update(bytes);
        self.diagnostics.raw.update(bytes);
    }

    pub(super) fn update_classification(&mut self, bytes: &[u8]) {
        self.update(bytes);
        self.diagnostics.classification.update(bytes);
    }

    pub(super) fn update_idle(&mut self, bytes: &[u8]) {
        self.update(bytes);
        self.diagnostics.idle.update(bytes);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TranscriptDigests {
    pub(super) control: blake3::Hash,
    pub(super) raw: blake3::Hash,
    pub(super) classification: blake3::Hash,
    pub(super) idle: blake3::Hash,
    pub(super) framed_console: blake3::Hash,
    pub(super) console_bytes: blake3::Hash,
    pub(super) console_event_count: u64,
    pub(super) console_byte_count: u64,
}

impl std::fmt::Display for TranscriptDigests {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "control_blake3={},raw_blake3={},classification_blake3={},idle_blake3={},console_framing_blake3={},console_bytes_blake3={},console_events={},console_bytes={}",
            self.control.to_hex(),
            self.raw.to_hex(),
            self.classification.to_hex(),
            self.idle.to_hex(),
            self.framed_console.to_hex(),
            self.console_bytes.to_hex(),
            self.console_event_count,
            self.console_byte_count,
        )
    }
}
