//! Bounded retention of the RR control trace rows since the last acknowledgement.
//!
//! A stalled node usually shows its cause right after the last request QEMU
//! acknowledged: the next request, its coalesced doorbells, and the wake that
//! never reached a claim. A plain final-row tail loses that context once the
//! host keeps re-ringing the doorbell. The window therefore anchors at the
//! most recent `phase=ack` boundary row and keeps the first rows from that
//! anchor plus the final rows of the trace, eliding the middle when the window
//! is longer than both. It always includes at least the final
//! [`MINIMUM_TAIL_ROWS`] rows, so a short window still carries the context
//! that the earlier 32-row tail did.
//!
//! The summary header produced by the caller reports the window as follows:
//!
//! ```text
//! bytes=<n> sha256=<hex> rows=<n> tail_rows=<retained> omitted_rows=<n> window_anchor=ack|start window_start_row=<1-based> elided_rows=<n> [elided_after_row=<1-based>]
//! ```
//!
//! Memory is bounded by [`HEAD_ROWS`] plus [`TAIL_ROWS`] rows of at most 512
//! bytes each, independent of the trace length.

use std::collections::VecDeque;

/// Final rows retained even when the last acknowledgement is more recent.
pub(super) const MINIMUM_TAIL_ROWS: usize = 32;

/// Rows retained from the most recent acknowledgement onward.
pub(super) const HEAD_ROWS: usize = 256;

/// Final rows retained after the head when the window exceeds the head.
pub(super) const TAIL_ROWS: usize = 256;

// The final ring also supplies the minimum tail before a recent anchor.
const _: () = assert!(TAIL_ROWS >= MINIMUM_TAIL_ROWS && HEAD_ROWS >= MINIMUM_TAIL_ROWS);

const ACKNOWLEDGEMENT_PREFIX: &str = "crucible_sim_rr_control_boundary phase=ack ";

/// Streaming retention of the rows since the last acknowledged RR request.
#[derive(Debug, Default)]
pub(super) struct RrTraceWindow {
    rows: usize,
    anchor: usize,
    acknowledged: bool,
    head: Vec<String>,
    tail: VecDeque<(usize, String)>,
}

/// The retained rows and their position in the complete trace.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RetainedRrTrace {
    /// Retained rows in trace order.
    pub(super) rows: Vec<String>,
    /// Whether the window starts at an acknowledgement row.
    pub(super) acknowledged: bool,
    /// One-based row number of the first retained row.
    pub(super) start_row: usize,
    /// Rows inside the window that were not retained.
    pub(super) elided_rows: usize,
    /// One-based row number after which `elided_rows` rows are missing.
    pub(super) elided_after_row: Option<usize>,
}

impl RrTraceWindow {
    /// Admits the next schema-checked row of the trace.
    pub(super) fn push(&mut self, row: &str) {
        let index = self.rows;
        self.rows += 1;

        if row.starts_with(ACKNOWLEDGEMENT_PREFIX) {
            self.anchor = index;
            self.acknowledged = true;
            self.head.clear();
        }
        if self.head.len() < HEAD_ROWS {
            self.head.push(row.to_owned());
        }

        if self.tail.len() == TAIL_ROWS {
            self.tail.pop_front();
        }
        self.tail.push_back((index, row.to_owned()));
    }

    /// Returns the number of rows admitted so far.
    pub(super) fn rows(&self) -> usize {
        self.rows
    }

    /// Finishes the trace and returns the bounded window.
    pub(super) fn finish(self) -> RetainedRrTrace {
        let start = self.anchor.min(self.rows.saturating_sub(MINIMUM_TAIL_ROWS));
        let head_end = self.anchor + self.head.len();

        // Context before a recent anchor comes only from the final ring,
        // which covers it because the ring is at least the minimum tail.
        let mut rows: Vec<String> = self
            .tail
            .iter()
            .filter(|(index, _)| (start..self.anchor).contains(index))
            .map(|(_, row)| row.clone())
            .collect();
        rows.extend(self.head);

        let mut after_head = self
            .tail
            .into_iter()
            .filter(|(index, _)| *index >= head_end)
            .peekable();
        let resume = after_head.peek().map_or(self.rows, |(index, _)| *index);
        let elided_rows = resume - head_end;
        rows.extend(after_head.map(|(_, row)| row));

        RetainedRrTrace {
            rows,
            acknowledged: self.acknowledged,
            start_row: start + 1,
            elided_rows,
            elided_after_row: (elided_rows > 0).then_some(head_end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary(phase: &str, request: usize, ack: usize) -> String {
        format!(
            "crucible_sim_rr_control_boundary phase={phase} request={request} ack={ack} complete={ack} token=0x0 state=5"
        )
    }

    fn window_of(rows: &[String]) -> RetainedRrTrace {
        let mut window = RrTraceWindow::default();
        for row in rows {
            window.push(row);
        }
        window.finish()
    }

    #[test]
    fn short_trace_without_acknowledgement_is_retained_whole() {
        let rows: Vec<_> = (0..10).map(|n| boundary("request", n, 0)).collect();

        let retained = window_of(&rows);

        assert_eq!(retained.rows, rows);
        assert!(!retained.acknowledged);
        assert_eq!(retained.start_row, 1);
        assert_eq!((retained.elided_rows, retained.elided_after_row), (0, None));
    }

    #[test]
    fn recent_acknowledgement_still_keeps_the_minimum_tail() {
        let mut rows: Vec<_> = (0..100).map(|n| boundary("request", n, 0)).collect();
        rows.push(boundary("ack", 100, 100));
        rows.push(boundary("complete", 100, 100));

        let retained = window_of(&rows);

        assert_eq!(retained.rows, rows[rows.len() - MINIMUM_TAIL_ROWS..]);
        assert!(retained.acknowledged);
        assert_eq!(retained.start_row, rows.len() - MINIMUM_TAIL_ROWS + 1);
        assert_eq!(retained.elided_rows, 0);
    }

    #[test]
    fn window_since_acknowledgement_outlives_the_final_tail() {
        // A lost wake: request 2 is never acknowledged while the host keeps
        // re-ringing, so the decisive rows sit far before the final 32.
        let mut rows = vec![boundary("request", 1, 0), boundary("ack", 1, 1)];
        rows.push(boundary("request", 2, 1));
        rows.extend((0..150).map(|_| boundary("wake-drain", 2, 1)));
        let anchor = 1;

        let retained = window_of(&rows);

        assert_eq!(retained.rows, rows[anchor..]);
        assert_eq!(retained.rows[1], boundary("request", 2, 1));
        assert_eq!(retained.start_row, anchor + 1);
        assert_eq!(retained.elided_rows, 0);
    }

    #[test]
    fn long_window_keeps_its_head_and_final_rows_within_the_bound() {
        let mut rows = vec![boundary("request", 1, 0); 40];
        rows.push(boundary("ack", 1, 1));
        let anchor = rows.len() - 1;
        rows.extend((0..2_000).map(|n| boundary("coalesce", n + 2, 1)));

        let retained = window_of(&rows);

        assert_eq!(retained.rows.len(), HEAD_ROWS + TAIL_ROWS);
        assert_eq!(retained.rows[..HEAD_ROWS], rows[anchor..anchor + HEAD_ROWS]);
        assert_eq!(retained.rows[HEAD_ROWS..], rows[rows.len() - TAIL_ROWS..]);
        assert_eq!(retained.start_row, anchor + 1);
        assert_eq!(
            retained.elided_rows,
            rows.len() - anchor - HEAD_ROWS - TAIL_ROWS
        );
        assert_eq!(retained.elided_after_row, Some(anchor + HEAD_ROWS));
    }

    #[test]
    fn a_later_acknowledgement_restarts_the_window() {
        let mut rows = vec![boundary("ack", 1, 1)];
        rows.extend((0..300).map(|_| boundary("wake-drain", 2, 1)));
        rows.push(boundary("ack", 2, 2));
        rows.extend((0..40).map(|_| boundary("complete", 2, 2)));
        let anchor = 301;

        let retained = window_of(&rows);

        assert_eq!(retained.rows, rows[anchor..]);
        assert_eq!(retained.start_row, anchor + 1);
    }
}
