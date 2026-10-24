//! Retains Source Release's actual same-file read and independent posts.
//!
//! The genuine Source writer, separately held challenge view and existing copy
//! allowance remain the only inputs. The common holder supplies its own file
//! to the sole canonical parser; no external bytes or successful replay can
//! create this original or become Source authority.

use aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness;

mod geometry;

use super::original::SourceOriginalChallengeHistoryViewV5;
use super::reread::SourceCompletedReplayV1;
use super::{Journal, JournalError};

#[derive(Clone, Copy)]
enum First {
    Readback,
    Protection,
    CopyBound,
    Native,
    Comparison,
    NamedPost,
    ChallengePost,
}

pub(super) struct OriginalReleaseSourceCutCaptureV1 {
    readback: Option<Result<(), JournalError>>,
    protection: Option<Result<ProtectedWriterNameWitness, JournalError>>,
    copy_bound: Option<Result<(), JournalError>>,
    native: Option<Result<SourceCompletedReplayV1, JournalError>>,
    comparison: Option<Result<(), JournalError>>,
    named_post: Option<Result<(), JournalError>>,
    challenge_post: Option<Result<(), JournalError>>,
    first: Option<First>,
    error_transferred: bool,
}

impl OriginalReleaseSourceCutCaptureV1 {
    pub(super) fn postcheck_debt(&self) -> Option<&JournalError> {
        self.named_post
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .or_else(|| {
                self.challenge_post
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
            })
    }

    fn transfer_first_error(&mut self) -> Option<JournalError> {
        if self.error_transferred {
            return None;
        }
        let error = match self.first? {
            First::Readback => self.readback.take().and_then(Result::err),
            First::Protection => self.protection.take().and_then(Result::err),
            First::CopyBound => self.copy_bound.take().and_then(Result::err),
            First::Native => self.native.take().and_then(Result::err),
            First::Comparison => self.comparison.take().and_then(Result::err),
            First::NamedPost => self.named_post.take().and_then(Result::err),
            First::ChallengePost => self.challenge_post.take().and_then(Result::err),
        };
        self.error_transferred = error.is_some();
        error
    }
}

impl Journal {
    pub(super) fn observe_original_release_source_cut_into_v1(
        &self,
        challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
        readback: Result<(), JournalError>,
        destination: &mut Option<OriginalReleaseSourceCutCaptureV1>,
    ) -> Result<(), JournalError> {
        if destination.is_some() {
            std::process::abort();
        }
        *destination = Some(OriginalReleaseSourceCutCaptureV1 {
            first: readback.is_err().then_some(First::Readback),
            readback: Some(readback),
            protection: None,
            copy_bound: None,
            native: None,
            comparison: None,
            named_post: None,
            challenge_post: None,
            error_transferred: false,
        });
        let Some(captured) = destination.as_mut() else {
            std::process::abort();
        };
        captured.protection = Some((|| {
            super::original::writer::require_fixed(self)?;
            self.source_original_replay
                .validate_challenges(challenges)?;
            self.native_view().writer_witness::<JournalError>()
        })());
        if matches!(captured.protection, Some(Err(_))) {
            captured.first.get_or_insert(First::Protection);
        }
        captured.copy_bound = Some((|| {
            let witness = captured
                .protection
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes = self.original_release_source_replay_copy_bytes_v1(
                witness.file().byte_len(),
                challenges,
            )?;
            if bytes > self.native_view().limits().maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded(
                    "Source original Release replay copy",
                ));
            }
            Ok(())
        })());
        if matches!(captured.copy_bound, Some(Err(_))) {
            captured.first.get_or_insert(First::CopyBound);
        }
        if matches!(captured.readback, Some(Ok(())))
            && matches!(captured.protection, Some(Ok(_)))
            && matches!(captured.copy_bound, Some(Ok(())))
        {
            captured.native = Some((|| {
                let witness = captured
                    .protection
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                super::reread::captured(
                    &self.held,
                    witness.file().byte_len(),
                    self.native_view().limits(),
                    challenges,
                )
            })());
            if matches!(captured.native, Some(Err(_))) {
                captured.first.get_or_insert(First::Native);
            }
            if let Some(Ok(replayed)) = &captured.native {
                captured.comparison = Some((|| {
                    let witness = captured
                        .protection
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    self.ensure_protected_authority()?;
                    replayed
                        .history
                        .as_ref()
                        .ok_or(JournalError::ProtectedBoundary)?
                        .require_completed(
                            self.native_view().next_sequence(),
                            witness.file().byte_len(),
                        )?;
                    replayed.require_same_data(self, witness.file().byte_len())?;
                    super::original::writer::require_original_release_source_replay_v1(
                        self, replayed, challenges,
                    )
                })());
                if matches!(captured.comparison, Some(Err(_))) {
                    captured.first.get_or_insert(First::Comparison);
                }
            }
        }

        // The same existing posts are owed after body or copy refusal. A
        // failed protection still reaches the fixed-name fallback; neither
        // observation supplies health, a challenge renewal or append permission.
        captured.named_post = Some(match &captured.protection {
            Some(Ok(witness)) => (|| {
                self.require_protected_names_current()?;
                self.native_view()
                    .require_writer_witness::<JournalError>(witness)
            })(),
            _ => super::original::writer::require_fixed(self),
        });
        if matches!(captured.named_post, Some(Err(_))) {
            captured.first.get_or_insert(First::NamedPost);
        }
        captured.challenge_post = Some(challenges.validate_current());
        if matches!(captured.challenge_post, Some(Err(_))) {
            captured.first.get_or_insert(First::ChallengePost);
        }
        if captured.first.is_some() {
            return match captured.transfer_first_error() {
                Some(cause) => Err(cause),
                None => std::process::abort(),
            };
        }
        Ok(())
    }
}
