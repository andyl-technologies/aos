//! Constructs Source's real provider/challenge holder through common acquisition.
//!
//! Native opening, the sole byte parser, private index and tail finalization all
//! belong to the actual canonical opening. Source creates its private purpose
//! identity only after that same bundle completes. No supplied native parts,
//! map, Arc or replay-success DATA can construct this owner.

use std::path::Path;
use std::sync::Arc;

use super::semantic_replay::SourceSemanticReplayOriginalV1;
use super::{Journal, JournalAuthorityInstance, JournalError, JournalLimits};
use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryOpeningOriginalsV1;
use aos_sandbox_broker::canonical_journal::RecoveryReport;
use aos_sandbox_journal::recovery::RecoveryTailMode;

enum Input<'path> {
    Unprotected(&'path Path),
    Protected {
        directory: &'path Path,
        name: &'path str,
        create: bool,
    },
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    Fixture {
        directory: &'path Path,
        name: &'path str,
        uid: u32,
    },
}

impl Journal {
    /// Opens the actual ordinary provider or challenge journal and sibling lock.
    ///
    /// This existing unprotected alternative provides no protected Source claim.
    /// Callers must not fall back here after protected acquisition refuses.
    ///
    /// # Errors
    /// Preserves actual bounds, lock, native IO, canonical replay or semantic
    /// failure. Only the existing incomplete-tail repair policy is applied.
    pub fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        open(
            Input::Unprotected(path.as_ref()),
            limits,
            RecoveryTailMode::RepairIncomplete,
        )
    }

    /// Opens a root-owned provider or challenge journal under its held directory.
    ///
    /// The common no-follow root-ancestry resolver and exact final directory,
    /// journal and lock checks remain in force. This may provision the journal
    /// and repairs only its existing incomplete tail; it grants no role itself.
    ///
    /// # Errors
    /// Preserves protected path/owner/mode, lock, IO, schema or replay failure.
    pub fn open_protected_at(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        open(
            Input::Protected {
                directory: directory.as_ref(),
                name,
                create: true,
            },
            limits,
            RecoveryTailMode::RepairIncomplete,
        )
    }

    /// Opens an already provisioned root-owned journal without creating storage.
    ///
    /// Missing files, stale compaction files and incomplete tails refuse. The
    /// same complete protected ancestry and file checks precede role claims.
    ///
    /// # Errors
    /// Preserves actual protected acquisition, IO or complete replay refusal.
    pub fn open_existing_protected_at(
        directory: impl AsRef<Path>,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        open(
            Input::Protected {
                directory: directory.as_ref(),
                name,
                create: false,
            },
            limits,
            RecoveryTailMode::RejectIncomplete,
        )
    }

    /// Opens the existing fixture-only final private directory recipe.
    ///
    /// The exact final-directory/file/lock protections remain unchanged. Only
    /// this debug fixture entry omits production root-ancestry validation.
    ///
    /// # Errors
    /// Preserves final-directory, owner/mode, lock, native or semantic failure.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    #[doc(hidden)]
    pub fn open_protected_at_uid(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        open(
            Input::Fixture {
                directory,
                name,
                uid,
            },
            limits,
            RecoveryTailMode::RepairIncomplete,
        )
    }
}

fn open(
    input: Input<'_>,
    limits: JournalLimits,
    tail: RecoveryTailMode,
) -> Result<(Journal, RecoveryReport), JournalError> {
    // Both originals are initially inert. Provider's ordinary allocation policy
    // is unchanged; this constructor creates no receiving bank or paid role.
    let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
    let mut semantic = SourceSemanticReplayOriginalV1::new();
    let body = (|| {
        match input {
            Input::Unprotected(path) => opening.prepare_unprotected_ordinary_once_v1(path, limits),
            Input::Protected {
                directory,
                name,
                create,
            } => opening.prepare_ordinary_once_v1(directory, name, limits, 0, create),
            #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
            Input::Fixture {
                directory,
                name,
                uid,
            } => opening.prepare_fixture_ordinary_once_v1(directory, name, limits, uid, true),
        }
        .map_err(JournalError::from_ordinary_native_v1)?;

        let identity = opening
            .prepare_parser_identity_once_v1()
            .map_err(JournalError::from_ordinary_native_v1)?;
        {
            let mut cursor = opening
                .begin_indexed_replay_once_v1()
                .map_err(JournalError::from_ordinary_native_v1)?;
            semantic
                .observe_ordinary_once(&mut cursor, identity, limits, None)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        opening
            .finish_replayed_tail_once_v1(tail)
            .map_err(JournalError::from_ordinary_native_v1)?;

        let remainder = semantic
            .take_remainder_once()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (held, report) = opening
            .take_held_with_late_payload_once_v1((), JournalAuthorityInstance)
            .ok_or(JournalError::ProtectedBoundary)?;
        let authority_instance = Arc::clone(
            held.instance_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?
                .comparison_arc_v1(),
        );
        Ok((
            Journal {
                held,
                authority_instance,
                source_challenge_history: remainder.source_challenge_history,
                source_original_replay: remainder.source_original_replay,
                source_history_compacted: remainder.source_history_compacted,
            },
            report,
        ))
    })();

    match body {
        Ok(completed) => Ok(completed),
        Err(body) => {
            let native_selected =
                opening.native_failure_v1().is_some() || opening.index_failure_v1().is_some();
            semantic.dispose_ordinary_prospective_v1();
            let current_disposal = opening.dispose_ordinary_current_once_v1();
            let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
            let pending_disposal = opening.dispose_ordinary_pending_once_v1();
            let (index, native) = match opening.into_ordinary_errors_v1() {
                Ok(errors) => errors,
                Err(original) => {
                    drop(original);
                    return Err(body);
                }
            };
            if native_selected {
                if let Some(cause) = index {
                    return Err(cause.into());
                }
                if let Some(cause) = native {
                    return Err(JournalError::from_ordinary_native_v1(cause));
                }
            }
            if let Some(cause) = upper_native {
                return Err(cause);
            }
            if let Some(cause) = upper_semantic {
                return Err(cause);
            }
            // Mechanical disposition never replaces the earlier body cause.
            drop(current_disposal);
            drop(pending_disposal);
            Err(body)
        }
    }
}
