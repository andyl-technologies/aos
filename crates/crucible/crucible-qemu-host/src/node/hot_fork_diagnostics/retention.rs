//! Bounded retention for one child's private diagnostics stream.
//!
//! A child owner drains the stream for the child's whole life, so the stream
//! length follows run length. Retention therefore keeps only what its readers
//! consume: the total drained byte count, the final
//! [`MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES`] bytes quoted by failure
//! reports, and the incremental control-row fold behind the advisory summary.
//! Every reader reports how many leading bytes the tail omits, so truncation is
//! explicit rather than silent.

use super::summary::ControlDiagnosticsFold;

/// Most trailing child diagnostic bytes retained for failure reports.
///
/// Earlier bytes are drained, counted, and folded into the control summary,
/// then discarded.
pub const MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES: usize = 64 * 1024;

/// Drained-byte count, bounded tail, and control fold for one stream.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DiagnosticRetention {
    stream_bytes: u64,
    /// Holds up to twice the tail bound so trimming stays amortized; only the
    /// final bound's worth is ever exposed.
    tail: Vec<u8>,
    summary: ControlDiagnosticsFold,
}

impl DiagnosticRetention {
    pub(super) fn bind_child_process_id(&mut self, child_process_id: u32) {
        self.summary.bind_child_process_id(child_process_id);
    }

    /// Accounts for one drained chunk in arrival order.
    pub(super) fn ingest(&mut self, bytes: &[u8]) {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.stream_bytes = self.stream_bytes.saturating_add(length);
        self.summary.ingest(bytes);

        let kept = &bytes[bytes
            .len()
            .saturating_sub(MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES)..];
        self.tail.extend_from_slice(kept);
        if self.tail.len() > 2 * MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES {
            let excess = self.tail.len() - MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES;
            self.tail.drain(..excess);
        }
    }

    /// Returns every byte drained so far, including omitted ones.
    pub(super) const fn stream_bytes(&self) -> u64 {
        self.stream_bytes
    }

    /// Returns the final retained bytes in arrival order.
    pub(super) fn tail(&self) -> &[u8] {
        let start = self
            .tail
            .len()
            .saturating_sub(MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES);
        &self.tail[start..]
    }

    /// Returns how many leading drained bytes the tail no longer holds.
    pub(super) fn omitted_bytes(&self) -> u64 {
        let tail = u64::try_from(self.tail().len()).unwrap_or(u64::MAX);
        self.stream_bytes.saturating_sub(tail)
    }

    pub(super) fn control_diagnostics_summary(&self) -> String {
        self.summary.render(self.stream_bytes)
    }

    pub(super) fn into_tail(mut self) -> Vec<u8> {
        let start = self
            .tail
            .len()
            .saturating_sub(MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES);
        self.tail.drain(..start);
        self.tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_only_the_final_bound_across_many_chunks() {
        let mut retention = DiagnosticRetention::default();
        let chunk = [0x5a_u8; 8192];
        for _ in 0..64 {
            retention.ingest(&chunk);
        }
        retention.ingest(b"final");

        let stream_bytes = 64 * 8192 + 5;
        assert_eq!(retention.stream_bytes(), stream_bytes);
        assert_eq!(
            retention.tail().len(),
            MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES
        );
        assert!(retention.tail().ends_with(b"final"));
        assert_eq!(
            retention.omitted_bytes(),
            stream_bytes - MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES as u64
        );
        assert!(retention.tail.len() <= 2 * MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES);
        assert_eq!(
            retention.into_tail().len(),
            MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_TAIL_BYTES
        );
    }

    #[test]
    fn short_streams_are_retained_whole() {
        let mut retention = DiagnosticRetention::default();
        retention.ingest(b"branch ");
        retention.ingest(b"stderr");

        assert_eq!(retention.tail(), b"branch stderr");
        assert_eq!(retention.omitted_bytes(), 0);
        assert!(
            retention
                .control_diagnostics_summary()
                .starts_with("stream_bytes=13 accepted_rows=0")
        );
    }

    #[test]
    fn fold_matches_the_whole_stream_summary_for_any_chunking() {
        let row = "CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=153 raw_icount=7 token_kind=observed token_before=2 token_after=2\n";
        let mut stream = b"unrelated\n".to_vec();
        for _ in 0..40 {
            stream.extend_from_slice(row.as_bytes());
        }
        stream.extend_from_slice(
            format!("CRUCIBLE-CONTROL-CALLBACK-V1 {}\n", "x".repeat(600)).as_bytes(),
        );
        stream.extend_from_slice(b"CRUCIBLE-CONTROL-CALLBACK-V1 incomplete");
        let expected = super::super::summary::control_diagnostics_summary(&stream, 153);

        for chunk in [1, 7, 512, 513, stream.len()] {
            let mut retention = DiagnosticRetention::default();
            retention.bind_child_process_id(153);
            for piece in stream.chunks(chunk) {
                retention.ingest(piece);
            }
            assert_eq!(
                retention.control_diagnostics_summary(),
                expected,
                "chunk {chunk}"
            );
        }
        assert!(expected.contains(
            "accepted_rows=40 rejected_rows=1 tail_rows=32 omitted_rows=8 incomplete_last_row=true"
        ));
    }
}
