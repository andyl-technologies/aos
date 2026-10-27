//! Completes Cache readonly observations through the sole actual native opening.
//!
//! Directory binding precedes limit validation, parser/semantic scratch retains
//! its ordinary disposal order, and a successful full semantic remainder stays
//! resident through the rejecting tail and late actual native/index transfer.
//! This private driver accepts no supplied map, File, successful view or loan.

use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, CanonicalOrdinaryReadonlyOpeningV1,
    NativeJournalDataErrorV1,
    coordinator::indexed_replay::CanonicalIndexedReplayErrorV1,
};
use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;

use super::{
    CacheCompactionSelectionV1, CacheJournalInstanceV1, Journal, JournalError,
    JournalLimits, RecoveryReport,
};
use super::readonly::{ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal};

fn native_error(cause: NativeJournalDataErrorV1) -> JournalError {
    CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into()
}

impl Journal {
    pub(super) fn open_actual_ordinary_readonly_v1(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: Option<(u64, u64)>,
        #[cfg(test)] fixture: bool,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let mut opening = CanonicalOrdinaryReadonlyOpeningV1::<JournalError>::new();
        let mut semantic = ColdReplayOriginalV1::new();
        let mut converted = None;
        let mut identities = None;
        let body: Result<(), JournalError> = (|| {
            #[cfg(test)]
            if fixture {
                opening.prepare_fixture_directory_once_v1(directory, name, limits, uid)?;
            } else {
                opening.prepare_original_directory_once_v1(
                    directory,
                    name,
                    limits,
                    uid,
                    expected_directory,
                )?;
            }
            #[cfg(not(test))]
            opening.prepare_original_directory_once_v1(
                directory,
                name,
                limits,
                uid,
                expected_directory,
            )?;

            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())
                .map_err(CanonicalJournalMechanicalErrorV1::from)
                .map_err(JournalError::from)?;
            opening.prepare_bound_files_once_v1(None)?;
            identities = opening.identities_data_v1();
            if opening.capture_metadata_once_v1()? > limits.maximum_journal_bytes {
                return Err(JournalError::from(CanonicalJournalMechanicalErrorV1::JournalTooLarge));
            }
            let (identity, mut cursor) = opening
                .begin_original_replay_once_v1()
                .map_err(native_error)?;
            semantic
                .observe_ordinary_indexed_once(&mut cursor, identity, limits)
                .map_err(|_| JournalError::boundary())?;
            converted = Some(
                semantic
                    .take_remainder_once()
                    .ok_or(JournalError::boundary())?,
            );
            Ok(())
        })();

        let native_selected =
            opening.replay_failure_v1().is_some() || opening.index_failure_v1().is_some();
        semantic.dispose_ordinary_prospective_v1();
        let current = opening.dispose_ordinary_current_once_v1();
        let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
        let pending = opening.dispose_ordinary_pending_once_v1();
        if let Err(body) = body {
            let replay_errors = opening.take_ordinary_replay_errors_once_v1();
            let physical = opening.take_ordinary_native_error_once_v1();
            if let Some(cause) = physical {
                return Err(cause);
            }
            if native_selected {
                if let Ok((index, native)) = replay_errors {
                    if let Some(cause) = index {
                        return Err(JournalError::from(CanonicalJournalMechanicalErrorV1::from(cause)));
                    }
                    if let Some(cause) = native {
                        return Err(native_error(cause));
                    }
                }
            }
            drop(current);
            drop(pending);
            let upper_native = match upper_native {
                Some(CanonicalIndexedReplayErrorV1::Native(cause)) => Some(JournalError::from_ordinary_native_v1(cause)),
                Some(CanonicalIndexedReplayErrorV1::Closed) | None => None,
            };
            let upper_semantic = upper_semantic.map(JournalError::from);
            return Err(upper_native.or(upper_semantic).unwrap_or(body));
        }
        current.map_err(native_error)?;
        pending.map_err(native_error)?;

        if let Err(cause) = opening.finish_retained_tail_once_v1() {
            drop(converted.take());
            drop(opening.take_ordinary_replay_errors_once_v1());
            return Err(opening
                .take_ordinary_native_error_once_v1()
                .unwrap_or_else(|| cause.into()));
        }
        let selection = CacheCompactionSelectionV1::Other;
        let mut native = match opening
            .take_held_with_late_payload_once_v1(selection, CacheJournalInstanceV1)
        {
            Some(native) => Some(native),
            None => {
                drop(converted.take());
                drop(opening.take_ordinary_replay_errors_once_v1());
                return Err(opening
                    .take_ordinary_native_error_once_v1()
                    .unwrap_or(JournalError::boundary()));
            }
        };
        let (journal, report) = Self::from_opening_originals_v1(
            &mut native,
            &mut converted,
        )
        .ok_or(JournalError::boundary())?;
        let (directory_identity, file_identity, lock_identity) =
            identities.ok_or(JournalError::boundary())?;
        let readback = ReadOnlyProtectedJournal {
            journal,
            named_receiving: None,
            witness: ReadOnlyJournalNameWitness {
                physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::from_original_parts((
                    directory.to_owned(), name.to_owned(), uid,
                    directory_identity, file_identity, lock_identity,
                )),
            },
        };
        Ok((readback, report))
    }
}
