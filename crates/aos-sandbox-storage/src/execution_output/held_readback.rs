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

const HELD_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.storage.held-output-readback.v1\0";

/// Names one exact Storage row/head for a nonauthorizing held readback.
///
/// The caller must obtain the expected AOSEOR03 digest and head independently.
/// A nonce only binds this invocation's response; it is not a durable replay
/// ledger or a cross-process lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageHeldOutputRequestV1 {
    nonce: [u8; 16],
    expected_record_digest: ObjectDigest,
    expected_journal_sequence: u64,
}

impl StorageHeldOutputRequestV1 {
    /// Constructs an exact, nonzero readback challenge.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce, record digest, or journal head.
    pub fn new(
        nonce: [u8; 16],
        expected_record_digest: ObjectDigest,
        expected_journal_sequence: u64,
    ) -> Result<Self, ExecutionOutputLedgerErrorV1> {
        if nonce == [0; 16]
            || expected_record_digest.as_bytes() == &[0; 32]
            || expected_journal_sequence == 0
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }

        Ok(Self {
            nonce,
            expected_record_digest,
            expected_journal_sequence,
        })
    }

    /// Returns the caller's challenge nonce.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
}

/// Borrows an exact Storage response only while its protected writer is held.
///
/// The response cannot escape the callback that receives it. Even a copied
/// row/head is historical after that callback; it grants no Host effect.
pub struct StorageHeldOutputResponseV1<'held> {
    nonce: [u8; 16],
    request_digest: ObjectDigest,
    held: &'held HeldExecutionOutputReadbackV1<'held>,
}

impl StorageHeldOutputResponseV1<'_> {
    /// Returns the challenge nonce echoed under this held Storage readback.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the digest of the exact challenge and accepted-output fields.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Borrows the MAC-verified AOSEOR03 row and Storage journal head.
    #[must_use]
    pub const fn readback(&self) -> &ProtectedRetainedOutputV1 {
        self.held.readback()
    }

    /// Rechecks the named protected writer, row, and head during the caller's cut.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, a changed head, or an absent or changed row.
    pub fn revalidate(&self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        self.held.revalidate()
    }
}

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
    /// Runs a Storage-only callback while an exact accepted-output row is held.
    ///
    /// The callback's result may contain an error, but cannot contain the
    /// borrowed response. Storage rechecks its protected writer and row after
    /// the callback even when that result is an error. A future bidirectional
    /// session must retain this writer through a cross-owner settlement; this
    /// local callback does not establish Controller, environment, or Host cuts.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched accepted claim, challenged digest or head, or
    /// changed Storage custody before or after the callback.
    pub fn with_held_accepted_output_for_barrier<T>(
        &self,
        accepted: &ProtectedAcceptedExecutionOutputV2,
        request: StorageHeldOutputRequestV1,
        inspect: impl for<'held> FnOnce(StorageHeldOutputResponseV1<'held>) -> T,
    ) -> Result<T, ExecutionOutputLedgerErrorV1> {
        let held = self.hold_accepted_output_for_barrier(accepted)?;
        let expected = RetainedOutputRecord::from_accepted(accepted)?;
        self.with_held_exact_record(&expected, request, held, inspect)
    }

    fn with_held_exact_record<T>(
        &self,
        expected: &RetainedOutputRecord,
        request: StorageHeldOutputRequestV1,
        held: HeldExecutionOutputReadbackV1<'_>,
        inspect: impl for<'held> FnOnce(StorageHeldOutputResponseV1<'held>) -> T,
    ) -> Result<T, ExecutionOutputLedgerErrorV1> {
        let retained = held.readback();
        if retained.record_digest != request.expected_record_digest
            || retained.journal_sequence != request.expected_journal_sequence
        {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        let request_digest = held_request_digest(&request, expected);
        Self::with_held_guard(held, |held| {
            inspect(StorageHeldOutputResponseV1 {
                nonce: request.nonce,
                request_digest,
                held,
            })
        })
    }

    /// Holds an exact existing row/head through one read-only session callback.
    ///
    /// The transport must independently authenticate its peer and bind its
    /// begin, proof, and terminal records. This callback only preserves the
    /// Storage writer and rechecks the exact row before releasing it.
    ///
    /// # Errors
    ///
    /// Rejects absent, deleted, changed, or replaced protected Storage state.
    pub(crate) fn with_held_existing_output_for_session<T>(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: ObjectDigest,
        expected_journal_sequence: u64,
        inspect: impl FnOnce(&HeldExecutionOutputReadbackV1<'_>) -> T,
    ) -> Result<T, ExecutionOutputLedgerErrorV1> {
        let held = self.hold_existing_output_for_query(execution, create, record_digest)?;
        if held.readback().journal_sequence() != expected_journal_sequence {
            return Err(ExecutionOutputLedgerErrorV1::NotCurrent);
        }
        Self::with_held_guard(held, inspect)
    }

    fn with_held_guard<T>(
        held: HeldExecutionOutputReadbackV1<'_>,
        inspect: impl FnOnce(&HeldExecutionOutputReadbackV1<'_>) -> T,
    ) -> Result<T, ExecutionOutputLedgerErrorV1> {
        held.revalidate()?;
        let result = inspect(&held);
        held.revalidate()?;
        Ok(result)
    }

    /// Holds an exact AOSEOR03 selector for an authenticated Host read-only query.
    ///
    /// # Errors
    ///
    /// Rejects an absent, changed, or deleted row, or an unhealthy protected
    /// journal and lock. The selector is not accepted-Create authority.
    pub(crate) fn hold_existing_output_for_query(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: ObjectDigest,
    ) -> Result<HeldExecutionOutputReadbackV1<'_>, ExecutionOutputLedgerErrorV1> {
        self.journal.validate_held_protected_names()?;
        let retained = self.read_protected_retained_output(execution, create, record_digest)?;
        self.hold_readback(retained)
    }

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
        let expected = RetainedOutputRecord::from_accepted(accepted)?;
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

fn held_request_digest(
    request: &StorageHeldOutputRequestV1,
    expected: &RetainedOutputRecord,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(HELD_REQUEST_DOMAIN);
    digest.update(request.nonce);
    digest.update(request.expected_record_digest.as_bytes());
    digest.update(request.expected_journal_sequence.to_be_bytes());
    digest.update(expected.execution);
    digest.update(expected.create);
    digest.update(expected.assignment);
    digest.update(expected.claim_digest);
    digest.update(expected.bytes.to_be_bytes());
    digest.update(expected.maximum_stdout_bytes.to_be_bytes());
    digest.update(expected.maximum_stderr_bytes.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
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

    fn challenge(
        ledger: &ExecutionOutputLedgerV1,
        expected: &RetainedOutputRecord,
        nonce: u8,
    ) -> StorageHeldOutputRequestV1 {
        let retained = ledger.read_exact_record_for_barrier(expected).unwrap();
        StorageHeldOutputRequestV1::new(
            [nonce; 16],
            retained.record_digest(),
            retained.journal_sequence(),
        )
        .unwrap()
    }

    #[test]
    fn held_endpoint_returns_exact_zero_and_capture_rows_only_inside_callback() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let zero = record(1, 0);
        let capture = record(2, 3);
        ledger.reserve_record(zero.clone()).unwrap();
        ledger.reserve_record(capture.clone()).unwrap();
        drop(ledger);

        let ledger = protected_ledger(&directory);
        for expected in [&zero, &capture] {
            let request = challenge(&ledger, expected, 9);
            let retained = ledger.read_exact_record_for_barrier(expected).unwrap();
            let held = ledger.hold_readback(retained).unwrap();
            let returned = ledger
                .with_held_exact_record(expected, request, held, |response| {
                    response.revalidate().unwrap();
                    assert_eq!(response.nonce(), request.nonce());
                    assert_eq!(
                        response.request_digest(),
                        held_request_digest(&request, expected)
                    );
                    assert_eq!(response.readback(), &retained);
                    response.readback().admitted_bytes()
                })
                .unwrap();
            assert_eq!(returned, expected.bytes);
        }
    }

    #[test]
    fn held_endpoint_rejects_zero_challenge_and_stale_or_foreign_replay() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let first = record(1, 0);
        let second = record(2, 0);
        ledger.reserve_record(first.clone()).unwrap();
        let first_request = challenge(&ledger, &first, 7);
        assert!(
            StorageHeldOutputRequestV1::new(
                [0; 16],
                first_request.expected_record_digest,
                first_request.expected_journal_sequence,
            )
            .is_err()
        );
        assert!(
            StorageHeldOutputRequestV1::new(
                [7; 16],
                ObjectDigest::from_bytes([0; 32]),
                first_request.expected_journal_sequence,
            )
            .is_err()
        );
        assert!(
            StorageHeldOutputRequestV1::new([7; 16], first_request.expected_record_digest, 0,)
                .is_err()
        );

        ledger.reserve_record(second.clone()).unwrap();
        let first_current = ledger.read_exact_record_for_barrier(&first).unwrap();
        let first_held = ledger.hold_readback(first_current).unwrap();
        let mut invoked = false;
        assert!(matches!(
            ledger.with_held_exact_record(&first, first_request, first_held, |_| {
                invoked = true;
            }),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(!invoked);

        let second_current = ledger.read_exact_record_for_barrier(&second).unwrap();
        let second_held = ledger.hold_readback(second_current).unwrap();
        let foreign = StorageHeldOutputRequestV1::new(
            [8; 16],
            first_current.record_digest(),
            second_current.journal_sequence(),
        )
        .unwrap();
        assert!(matches!(
            ledger.with_held_exact_record(&second, foreign, second_held, |_| {
                invoked = true;
            }),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(!invoked);
        assert_ne!(
            held_request_digest(&first_request, &first),
            held_request_digest(&challenge(&ledger, &first, 8), &first)
        );
        assert_ne!(
            held_request_digest(&challenge(&ledger, &first, 8), &first),
            held_request_digest(&challenge(&ledger, &second, 8), &second)
        );
    }

    #[test]
    fn held_endpoint_rechecks_writer_names_after_callback_failure() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let expected = record(1, 0);
        ledger.reserve_record(expected.clone()).unwrap();
        let request = challenge(&ledger, &expected, 9);
        let retained = ledger.read_exact_record_for_barrier(&expected).unwrap();
        let held = ledger.hold_readback(retained).unwrap();
        let lock = directory.path().join("output.journal.lock");
        let old_lock = directory.path().join("output.journal.lock.old");

        let result = ledger.with_held_exact_record(&expected, request, held, |_| {
            fs::rename(&lock, &old_lock).unwrap();
            fs::write(&lock, []).unwrap();
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
            Err::<(), _>("caller failed")
        });

        assert!(matches!(
            result,
            Err(ExecutionOutputLedgerErrorV1::Journal(
                JournalError::StaleAuthoritySnapshot
            ))
        ));
        fs::remove_file(&lock).unwrap();
        fs::rename(&old_lock, &lock).unwrap();
    }

    #[test]
    fn held_session_keeps_exact_zero_byte_row_and_head_through_callback() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let expected = record(1, 0);
        ledger.reserve_record(expected.clone()).unwrap();
        let retained = ledger.read_exact_record_for_barrier(&expected).unwrap();

        let observed = ledger
            .with_held_existing_output_for_session(
                expected.execution,
                expected.create,
                retained.record_digest(),
                retained.journal_sequence(),
                |held| {
                    held.revalidate().unwrap();
                    *held.readback()
                },
            )
            .unwrap();
        assert_eq!(observed, retained);

        ledger.reserve_record(record(2, 0)).unwrap();
        let mut invoked = false;
        assert!(matches!(
            ledger.with_held_existing_output_for_session(
                expected.execution,
                expected.create,
                retained.record_digest(),
                retained.journal_sequence(),
                |_| {
                    invoked = true;
                },
            ),
            Err(ExecutionOutputLedgerErrorV1::NotCurrent)
        ));
        assert!(!invoked);
    }

    #[test]
    fn held_session_rejects_writer_replacement_after_terminal_callback() {
        let directory = TempDir::new().unwrap();
        let mut ledger = protected_ledger(&directory);
        let expected = record(1, 0);
        ledger.reserve_record(expected.clone()).unwrap();
        let retained = ledger.read_exact_record_for_barrier(&expected).unwrap();
        let journal = directory.path().join("output.journal");
        let old_journal = directory.path().join("output.journal.old");

        let result = ledger.with_held_existing_output_for_session(
            expected.execution,
            expected.create,
            retained.record_digest(),
            retained.journal_sequence(),
            |_| {
                fs::rename(&journal, &old_journal).unwrap();
                fs::write(&journal, []).unwrap();
                fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
            },
        );

        assert!(matches!(
            result,
            Err(ExecutionOutputLedgerErrorV1::Journal(
                JournalError::StaleAuthoritySnapshot
            ))
        ));
        fs::remove_file(&journal).unwrap();
        fs::rename(&old_journal, &journal).unwrap();
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

            let queried = ledger
                .hold_existing_output_for_query(
                    expected.execution,
                    expected.create,
                    retained.record_digest(),
                )
                .unwrap();
            assert_eq!(queried.readback(), &retained);
            queried.revalidate().unwrap();
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
