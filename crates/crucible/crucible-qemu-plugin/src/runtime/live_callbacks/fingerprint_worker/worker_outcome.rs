//! Classifies actual worker receipts independently from capture cancellation.
//!
//! These pure checks issue no native grant. Production supplies facts returned
//! by the authenticated Source operation and keeps its actual owning receipts.
// SPDX-License-Identifier: GPL-2.0-only

/// Contains the exact returned take shape, without borrowing its native owner.
#[derive(Clone, Copy)]
pub(super) struct TakeReceipt {
    pub(super) status: i32,
    pub(super) work_empty: bool,
    pub(super) workspace_address: usize,
    pub(super) workspace_length: usize,
}

impl TakeReceipt {
    /// Identifies only the authenticated native closing branch's empty response.
    ///
    /// Native publishes closing before calling module close, so this response
    /// can precede the local closed flag. It stops entry, never grants more work.
    pub(super) fn is_cooperative_close(self) -> bool {
        self.status == -libc::ESHUTDOWN
            && self.work_empty
            && self.workspace_address == 0
            && self.workspace_length == 0
    }
}

/// Contains an actual canceled Work journal and its expected incarnation.
#[derive(Clone, Copy)]
pub(super) struct CancelledWork {
    pub(super) expected_material: u64,
    pub(super) expected_work: u64,
    pub(super) material: u64,
    pub(super) work: u64,
    pub(super) cancelled: u32,
    pub(super) result: i32,
    pub(super) complete_attempted: u32,
}

impl CancelledWork {
    /// Matches a same-incarnation native cancellation without an executed complete.
    pub(super) fn matches(self) -> bool {
        self.material != 0
            && self.work != 0
            && self.material == self.expected_material
            && self.work == self.expected_work
            && self.cancelled == 1
            && self.result == -libc::ECANCELED
            && self.complete_attempted == 0
    }
}

/// Distinguishes an entry stop from successful completion of its captured job.
#[derive(Clone, Copy)]
pub(super) enum JobOutcome {
    Completed,
    NativeClosed,
}

/// Names the retained first module outcome without discarding other journals.
#[derive(Clone, Copy)]
pub(super) enum PrimaryFailure {
    Absent,
    CaptureCancelled,
    Other,
}

/// Determines entry health from its retained primary and independent failures.
///
/// A canceled capture remains a negative transaction. Actual close evidence
/// merely prevents that transaction from fabricating a worker malfunction.
pub(super) fn entry_failed(
    primary: PrimaryFailure,
    close_observed: bool,
    independent_failure: bool,
) -> bool {
    independent_failure
        || match primary {
            PrimaryFailure::Absent => false,
            PrimaryFailure::CaptureCancelled => !close_observed,
            PrimaryFailure::Other => true,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed_receipt() -> TakeReceipt {
        TakeReceipt {
            status: -libc::ESHUTDOWN,
            work_empty: true,
            workspace_address: 0,
            workspace_length: 0,
        }
    }

    #[test]
    fn only_the_exact_empty_native_shutdown_response_is_cooperative() {
        let receipt = closed_receipt();
        assert!(receipt.is_cooperative_close());
        assert!(
            !TakeReceipt {
                status: -libc::EIO,
                ..receipt
            }
            .is_cooperative_close()
        );
        assert!(
            !TakeReceipt {
                status: 0,
                ..receipt
            }
            .is_cooperative_close()
        );
        assert!(
            !TakeReceipt {
                work_empty: false,
                ..receipt
            }
            .is_cooperative_close()
        );
        assert!(
            !TakeReceipt {
                workspace_address: 1,
                ..receipt
            }
            .is_cooperative_close()
        );
        assert!(
            !TakeReceipt {
                workspace_length: 1,
                ..receipt
            }
            .is_cooperative_close()
        );
    }

    #[test]
    fn canceled_work_requires_the_exact_serials_and_unattempted_completion() {
        let receipt = CancelledWork {
            expected_material: 7,
            expected_work: 11,
            material: 7,
            work: 11,
            cancelled: 1,
            result: -libc::ECANCELED,
            complete_attempted: 0,
        };
        assert!(receipt.matches());
        assert!(
            !CancelledWork {
                material: 8,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                work: 12,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                material: 0,
                expected_material: 0,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                work: 0,
                expected_work: 0,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                cancelled: 0,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                result: 0,
                ..receipt
            }
            .matches()
        );
        assert!(
            !CancelledWork {
                complete_attempted: 1,
                ..receipt
            }
            .matches()
        );
    }

    #[test]
    fn canceled_transaction_does_not_fabricate_a_closed_worker_malfunction() {
        assert!(!entry_failed(PrimaryFailure::CaptureCancelled, true, false));
        assert!(entry_failed(PrimaryFailure::CaptureCancelled, false, false));
        assert!(!entry_failed(PrimaryFailure::Absent, false, false));
        assert!(entry_failed(PrimaryFailure::Other, true, false));
    }

    #[test]
    fn independent_failure_survives_an_earlier_cancellation() {
        assert!(entry_failed(PrimaryFailure::CaptureCancelled, true, true));
        assert!(entry_failed(PrimaryFailure::Absent, true, true));
    }
}
