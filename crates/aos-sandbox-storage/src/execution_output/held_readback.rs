//! Writer-held, nonauthorizing AOSEOR03 readback for a future owner cut.
//!
//! The Storage journal remains exclusively locked while this guard borrows
//! its ledger. A matching row and local head do not prove Controller,
//! environment, Host, physical ZFS, or effect-handoff currentness.

use aos_sandbox::runtime_execution::ProtectedAcceptedExecutionOutputV2;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    ExecutionOutputLedgerErrorV1, ExecutionOutputLedgerV1, NAMESPACE, ProtectedRetainedOutputV1,
    RetainedOutputRecord, STATE_RETAINED, reservation_key,
};

/// Holds one exact Storage row and head under the ledger's exclusive writer.
///
/// This is a local readback, not a cross-owner admission or Host grant. The
/// caller must revalidate it at each later boundary while retaining this
/// borrow and separately establish every other owner's custody.
#[must_use = "the Storage writer must remain held through the intended readback cut"]
pub struct HeldExecutionOutputReadbackV1<'ledger> {
    ledger: &'ledger ExecutionOutputLedgerV1,
    retained: ProtectedRetainedOutputV1,
}

impl HeldExecutionOutputReadbackV1<'_> {
    /// Borrows the exact MAC-verified AOSEOR03 row and observed head.
    #[must_use]
    pub const fn readback(&self) -> &ProtectedRetainedOutputV1 {
        &self.retained
    }

    /// Rechecks the named Storage writer, exact row, and unchanged journal head.
    ///
    /// # Errors
    ///
    /// Rejects a replaced journal or lock name, poisoned writer, changed
    /// head, or changed, deleted, or corrupt reservation.
    pub fn revalidate(&self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        self.ledger.validate_held_readback(&self.retained)
    }
}

impl ExecutionOutputLedgerV1 {
    /// Holds the exact accepted-v2 output row under the Storage journal writer.
    ///
    /// This accepts only an owner-minted accepted-output witness and compares
    /// its complete output and assignment binding to the retained AOSEOR03
    /// row. That witness may be historical; neither it nor this guard proves
    /// a simultaneous Controller, environment, Host, or physical Storage cut.
    ///
    /// # Errors
    ///
    /// Rejects stale or mismatched accepted output, absent or corrupt Storage
    /// custody, an unhealthy writer, or replaced journal and lock names.
    pub fn hold_accepted_output_for_barrier(
        &self,
        accepted: &ProtectedAcceptedExecutionOutputV2,
    ) -> Result<HeldExecutionOutputReadbackV1<'_>, ExecutionOutputLedgerErrorV1> {
        let reservation = accepted.reservation();
        if accepted.currentness().output_reservation() != reservation.record_digest()
            || accepted
                .currentness()
                .runtime()
                .currentness()
                .assignment_digest()
                != reservation.output().assignment().digest()
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        let expected = RetainedOutputRecord {
            execution: *reservation.execution().as_bytes(),
            create: *reservation.create_operation().as_bytes(),
            assignment: *reservation.output().assignment().digest().as_bytes(),
            claim_digest: *reservation.record_digest().as_bytes(),
            bytes: reservation.output().admitted_bytes(),
            maximum_stdout_bytes: accepted.maximum_stdout_bytes(),
            maximum_stderr_bytes: accepted.maximum_stderr_bytes(),
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        };
        let retained = self.read_exact_record_for_barrier(&expected)?;
        self.hold_readback(retained)
    }

    fn read_exact_record_for_barrier(
        &self,
        expected: &RetainedOutputRecord,
    ) -> Result<ProtectedRetainedOutputV1, ExecutionOutputLedgerErrorV1> {
        if expected.state != STATE_RETAINED
            || expected.delete_operation != [0; 16]
            || expected
                .maximum_stdout_bytes
                .checked_add(expected.maximum_stderr_bytes)
                != Some(expected.bytes)
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        self.journal.validate_held_protected_names()?;

        let location = reservation_key(expected.execution);
        let bytes = self
            .journal
            .get(NAMESPACE, &location)
            .ok_or(ExecutionOutputLedgerErrorV1::NotCurrent)?;
        let digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        let retained =
            self.read_protected_retained_output(expected.execution, expected.create, digest)?;
        if retained.assignment_digest.as_bytes() != &expected.assignment
            || retained.claim_digest.as_bytes() != &expected.claim_digest
            || retained.admitted_bytes != expected.bytes
            || retained.maximum_stdout_bytes != expected.maximum_stdout_bytes
            || retained.maximum_stderr_bytes != expected.maximum_stderr_bytes
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        self.journal.validate_held_protected_names()?;
        Ok(retained)
    }

    fn hold_readback(
        &self,
        retained: ProtectedRetainedOutputV1,
    ) -> Result<HeldExecutionOutputReadbackV1<'_>, ExecutionOutputLedgerErrorV1> {
        self.validate_held_readback(&retained)?;
        Ok(HeldExecutionOutputReadbackV1 {
            ledger: self,
            retained,
        })
    }

    fn validate_held_readback(
        &self,
        retained: &ProtectedRetainedOutputV1,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        self.journal.validate_held_protected_names()?;
        self.revalidate_retained_output(retained)?;
        self.journal.validate_held_protected_names()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox::{Journal, JournalError, JournalLimits};
    use tempfile::TempDir;

    use super::*;
    use crate::execution_output::ExecutionOutputLedgerKeyV1;

    fn protected_ledger(directory: &TempDir) -> ExecutionOutputLedgerV1 {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "output.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let key = ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32]).unwrap();
        ExecutionOutputLedgerV1::from_journal(journal, 10, key).unwrap()
    }

    fn record(execution: u8, bytes: u64) -> RetainedOutputRecord {
        RetainedOutputRecord {
            execution: [execution; 16],
            create: [3; 16],
            assignment: [4; 32],
            claim_digest: [5; 32],
            bytes,
            maximum_stdout_bytes: bytes,
            maximum_stderr_bytes: 0,
            state: STATE_RETAINED,
            delete_operation: [0; 16],
        }
    }

    #[test]
    fn held_readback_replays_exact_zero_and_capture_rows() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let zero = record(1, 0);
        let capture = record(2, 3);
        ledger.reserve_record(zero.clone()).unwrap();
        ledger.reserve_record(capture.clone()).unwrap();
        drop(ledger);

        let ledger = protected_ledger(&directory);
        for expected in [&zero, &capture] {
            let retained = ledger.read_exact_record_for_barrier(expected).unwrap();
            let held = ledger.hold_readback(retained).unwrap();
            assert_eq!(held.readback().execution(), expected.execution);
            assert_eq!(held.readback().create_operation(), expected.create);
            assert_eq!(held.readback().admitted_bytes(), expected.bytes);
            held.revalidate().unwrap();
        }
    }

    #[test]
    fn held_readback_rejects_a_changed_head_and_foreign_claim_fields() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let expected = record(1, 3);
        ledger.reserve_record(expected.clone()).unwrap();
        let retained = ledger.read_exact_record_for_barrier(&expected).unwrap();

        for changed in [
            RetainedOutputRecord {
                execution: [9; 16],
                ..expected.clone()
            },
            RetainedOutputRecord {
                create: [9; 16],
                ..expected.clone()
            },
            RetainedOutputRecord {
                assignment: [9; 32],
                ..expected.clone()
            },
            RetainedOutputRecord {
                claim_digest: [9; 32],
                ..expected.clone()
            },
            RetainedOutputRecord {
                maximum_stdout_bytes: 2,
                maximum_stderr_bytes: 1,
                ..expected.clone()
            },
            RetainedOutputRecord {
                bytes: 2,
                maximum_stdout_bytes: 2,
                ..expected.clone()
            },
        ] {
            assert!(matches!(
                ledger.read_exact_record_for_barrier(&changed),
                Err(ExecutionOutputLedgerErrorV1::NotCurrent)
            ));
        }

        ledger.reserve_record(record(2, 1)).unwrap();
        assert!(matches!(
            ledger.hold_readback(retained),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
    }

    #[test]
    fn held_readback_rejects_replaced_journal_and_lock_names() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let expected = record(1, 0);
        ledger.reserve_record(expected.clone()).unwrap();
        let retained = ledger.read_exact_record_for_barrier(&expected).unwrap();
        let held = ledger.hold_readback(retained).unwrap();

        for name in ["output.journal", "output.journal.lock"] {
            let current = directory.path().join(name);
            let retained_name = directory.path().join(format!("{name}.retained"));
            fs::rename(&current, &retained_name).unwrap();
            fs::write(&current, []).unwrap();
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();

            assert!(matches!(
                held.revalidate(),
                Err(ExecutionOutputLedgerErrorV1::Journal(
                    JournalError::StaleAuthoritySnapshot
                ))
            ));
            assert!(matches!(
                ledger.hold_readback(retained),
                Err(ExecutionOutputLedgerErrorV1::Journal(
                    JournalError::StaleAuthoritySnapshot
                ))
            ));

            fs::remove_file(&current).unwrap();
            fs::rename(&retained_name, &current).unwrap();
            held.revalidate().unwrap();
        }
    }

    #[test]
    fn held_readback_requires_a_protected_writer() {
        let directory = TempDir::new().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("output.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let key = ExecutionOutputLedgerKeyV1::new([1; 16], [2; 32]).unwrap();
        let mut ledger = ExecutionOutputLedgerV1::from_journal(journal, 10, key).unwrap();
        let expected = record(1, 0);
        ledger.reserve_record(expected.clone()).unwrap();

        assert!(matches!(
            ledger.read_exact_record_for_barrier(&expected),
            Err(ExecutionOutputLedgerErrorV1::Journal(
                JournalError::ProtectedBoundary
            ))
        ));
    }
}
