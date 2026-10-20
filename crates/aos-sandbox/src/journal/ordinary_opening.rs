//! Drives actual immediate ordinary acquisitions through the common native owner.
//!
//! Paths remain the existing ordinary allocation policy. Protected variants
//! acquire their own actual directory/native originals, and no File, map,
//! prefix, Arc, completed DTO or caller-defined stage can enter this driver.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryOpeningOriginalsV1, NativeJournalDataErrorV1,
};
use aos_sandbox_journal::recovery::RecoveryTailMode;

use super::native_backing::Selection;
use super::ordinary_semantics::OrdinarySemanticReplayOriginalV1;
use super::*;

pub(super) enum OrdinaryPathV1<'path> {
    Unprotected(&'path Path),
    StorageOperatorEmpty,
    Protected {
        directory: &'path Path,
        name: &'path str,
        uid: u32,
        allow_create: bool,
    },
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    Fixture {
        directory: &'path Path,
        name: &'path str,
        uid: u32,
        allow_create: bool,
    },
}

fn native_error(cause: NativeJournalDataErrorV1) -> JournalError {
    CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into()
}

impl Journal {
    pub(super) fn open_actual_ordinary_v1(
        request: OrdinaryPathV1<'_>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        let mut semantic = OrdinarySemanticReplayOriginalV1::new();
        let mut converted = None;
        let (prepared, selection, repair) = match request {
            OrdinaryPathV1::Unprotected(path) => {
                // The existing public entry validates these before lock IO.
                validate_limits(limits)?;
                (
                    opening.prepare_unprotected_ordinary_once_v1(path, limits),
                    Self::unprotected_compaction_selection_v1(),
                    true,
                )
            }
            OrdinaryPathV1::StorageOperatorEmpty => {
                let directory = Path::new(protected_storage::STORAGE_OPERATOR_STATE_DIRECTORY);
                let name = protected_storage::STORAGE_OPERATOR_JOURNAL_NAME;
                (
                    opening.prepare_empty_ordinary_once_v1(directory, name, limits, 0),
                    Self::actual_compaction_selection_v1(directory, name),
                    false,
                )
            }
            OrdinaryPathV1::Protected {
                directory,
                name,
                uid,
                allow_create,
            } => (
                opening.prepare_ordinary_once_v1(directory, name, limits, uid, allow_create),
                Self::actual_compaction_selection_v1(directory, name),
                allow_create,
            ),
            #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
            OrdinaryPathV1::Fixture {
                directory,
                name,
                uid,
                allow_create,
            } => (
                opening.prepare_fixture_ordinary_once_v1(
                    directory,
                    name,
                    limits,
                    uid,
                    allow_create,
                ),
                Self::actual_compaction_selection_v1(directory, name),
                allow_create,
            ),
        };
        let replayed = (|| {
            prepared.map_err(native_error)?;
            let identity = opening
                .prepare_parser_identity_once_v1()
                .map_err(native_error)?;
            let mut cursor = opening
                .begin_indexed_replay_once_v1()
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
        if let Err(body) = replayed {
            let native_selected =
                opening.native_failure_v1().is_some() || opening.index_failure_v1().is_some();
            semantic.dispose_ordinary_prospective_v1();
            let current_disposal = opening.dispose_ordinary_current_once_v1();
            let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
            let pending_disposal = opening.dispose_ordinary_pending_once_v1();
            let errors = opening.into_ordinary_errors_v1();
            if let Ok((index, native)) = errors {
                if native_selected {
                    if let Some(cause) = index {
                        return Err(project_idempotency_record_error(cause));
                    }
                    if let Some(cause) = native {
                        return Err(native_error(cause));
                    }
                }
            }
            if let Some(cause) = upper_native.or(upper_semantic) {
                return Err(cause);
            }
            // These independent pure disposal results cannot mask the reached
            // native or semantic body; their actual owners have already ended.
            drop(current_disposal);
            drop(pending_disposal);
            return Err(body);
        }

        // Like replay() returning its successful remainder, all transient
        // parser/semantic scratch ends before tail metadata, repair and seek.
        semantic.dispose_ordinary_prospective_v1();
        opening
            .dispose_ordinary_current_once_v1()
            .map_err(native_error)?;
        drop(semantic.into_ordinary_errors());
        opening
            .dispose_ordinary_pending_once_v1()
            .map_err(native_error)?;
        let tail = if repair {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        };
        if let Err(projected) = opening.finish_replayed_tail_once_v1(tail) {
            drop(converted.take());
            return Err(Self::ordinary_opening_disposed_error_v1(
                opening,
                native_error(projected),
            ));
        }

        let mut native = match opening
            .take_held_with_late_payload_once_v1(selection, JournalAuthorityInstance)
        {
            Some(native) => Some(native),
            None => {
                drop(converted.take());
                return Err(Self::ordinary_opening_disposed_error_v1(
                    opening,
                    JournalError::ProtectedBoundary,
                ));
            }
        };
        #[cfg(target_os = "linux")]
        let mut captured = None;
        Self::from_actual_ordinary_held_v1(
            &mut native,
            &mut converted,
            #[cfg(target_os = "linux")]
            &mut captured,
        )
        .ok_or(JournalError::ProtectedBoundary)
    }

    fn ordinary_opening_disposed_error_v1(
        opening: CanonicalOrdinaryOpeningOriginalsV1,
        fallback: JournalError,
    ) -> JournalError {
        match opening.into_ordinary_errors_v1() {
            Ok((Some(index), _)) => project_idempotency_record_error(index),
            Ok((None, Some(native))) => native_error(native),
            Ok((None, None)) => fallback,
            Err(original) => {
                drop(original);
                fallback
            }
        }
    }

    fn unprotected_compaction_selection_v1() -> Selection {
        #[cfg(target_os = "linux")]
        {
            runtime_deployment_history::OriginalCompactionSelectionV1::Other
        }
        #[cfg(not(target_os = "linux"))]
        {
            ()
        }
    }

    pub(super) fn actual_compaction_selection_v1(directory: &Path, name: &str) -> Selection {
        #[cfg(target_os = "linux")]
        {
            runtime_deployment_history::OriginalCompactionSelectionV1::capture(directory, name)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (directory, name);
            ()
        }
    }
}
