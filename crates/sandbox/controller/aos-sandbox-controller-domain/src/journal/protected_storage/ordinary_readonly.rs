//! Completes immediate readonly observations using the actual common acquisition.
//!
//! The original directory and optional binding precede limit validation. The
//! ordinary parser and semantic scratch keep their ordered disposal windows;
//! the full successful remainder stays resident through the rejecting tail.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryReadonlyOpeningV1, NativeJournalDataErrorV1,
};

use super::super::ordinary_semantics::OrdinarySemanticReplayOriginalV1;
use super::super::{
    CanonicalJournalMechanicalErrorV1, JournalAuthorityInstance, RecoveryReport,
    project_idempotency_record_error, validate_limits,
};
use super::*;

fn native_error(cause: NativeJournalDataErrorV1) -> JournalError {
    CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into()
}

impl Journal {
    pub(in crate::journal) fn open_actual_ordinary_readonly_v1(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        expected_directory: Option<(u64, u64)>,
        #[cfg(test)] fixture: bool,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let mut opening = CanonicalOrdinaryReadonlyOpeningV1::<JournalError>::new();
        let mut semantic = OrdinarySemanticReplayOriginalV1::new();
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

            validate_limits(limits)?;
            opening.prepare_bound_files_once_v1(None)?;
            identities = opening.identities_data_v1();
            if opening.capture_metadata_once_v1()? > limits.maximum_journal_bytes {
                return Err(JournalError::JournalTooLarge);
            }
            let (identity, mut cursor) = opening
                .begin_original_replay_once_v1()
                .map_err(native_error)?;
            semantic
                .observe_once(
                    &mut cursor,
                    identity,
                    limits,
                    None,
                    #[cfg(target_os = "linux")]
                    None,
                )
                .map_err(|()| JournalError::ProtectedBoundary)?;
            converted = Some(
                semantic
                    .take_remainder_once()
                    .ok_or(JournalError::ProtectedBoundary)?,
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
                        return Err(project_idempotency_record_error(cause));
                    }
                    if let Some(cause) = native {
                        return Err(native_error(cause));
                    }
                }
            }
            drop(current);
            drop(pending);
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
        let selection = Self::actual_compaction_selection_v1(directory, name);
        let mut native = match opening
            .take_held_with_late_payload_once_v1(selection, JournalAuthorityInstance)
        {
            Some(native) => Some(native),
            None => {
                drop(converted.take());
                drop(opening.take_ordinary_replay_errors_once_v1());
                return Err(opening
                    .take_ordinary_native_error_once_v1()
                    .unwrap_or(JournalError::ProtectedBoundary));
            }
        };
        #[cfg(target_os = "linux")]
        let mut captured = None;
        let (journal, report) = Self::from_actual_ordinary_held_v1(
            &mut native,
            &mut converted,
            #[cfg(target_os = "linux")]
            &mut captured,
        )
        .ok_or(JournalError::ProtectedBoundary)?;
        let (directory_identity, file_identity, lock_identity) =
            identities.ok_or(JournalError::ProtectedBoundary)?;
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
