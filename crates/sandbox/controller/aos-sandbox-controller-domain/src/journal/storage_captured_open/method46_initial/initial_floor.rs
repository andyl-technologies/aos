//! Holds the manual Source's empty floor writer beside its original main.
//!
//! Empty name preparation precedes approval. The existing captured writer and
//! replay engine acquires the floor lock without creation, tail repair or
//! compaction cleanup. Neither Journal nor private auth leaves this owner.

use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{
    SIDECAR_NAME_V1, sidecar_limits_v1,
};

use super::*;

pub(super) struct InitialFloorOriginal {
    opening: FixedProtectedCapturedJournalOpenV1,
    fixed: Option<Result<ResourceVector, JournalError>>,
    limits: Option<Result<JournalLimits, JournalError>>,
    main: approval_currentness::ApprovalCurrentnessOriginalV1,
    names: floor_names::EmptyFloorNamesOriginal,
    prepare: Option<Result<(), JournalError>>,
    replay_quote: Option<Result<ResourceVector, JournalError>>,
    empty: Option<Result<(), JournalError>>,
    preparation_after: Option<Result<(), JournalError>>,
    currentness: approval_currentness::ApprovalCurrentnessOriginalV1,
    currentness_before: Option<Result<(), JournalError>>,
    floor_post: super::super::super::ProtectedJournalCurrentnessOriginalsV1,
    post: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
}

impl InitialFloorOriginal {
    pub(super) fn new() -> Self {
        Self {
            opening: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedMethod46InitialFloor(None),
            ),
            fixed: None,
            limits: None,
            main:
                approval_currentness::ApprovalCurrentnessOriginalV1::for_fixed_sibling_publication(),
            names: floor_names::EmptyFloorNamesOriginal::new(),
            prepare: None,
            replay_quote: None,
            empty: None,
            preparation_after: None,
            currentness:
                approval_currentness::ApprovalCurrentnessOriginalV1::for_fixed_sibling_publication(),
            currentness_before: None,
            floor_post: super::super::super::ProtectedJournalCurrentnessOriginalsV1::new(),
            post: None,
            closed: None,
        }
    }

    pub(super) fn quote_fixed_once(
        &mut self,
        main: &Journal,
        replayed: FileIdentity,
        role: Method46InitialServiceRoleV1,
        uid: u32,
    ) -> Option<ResourceVector> {
        if self.fixed.is_some() || self.prepare.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.opening.recipe =
            ProtectedCapturedJournalRecipeV1::JoinedMethod46InitialFloor(Some((role, uid)));
        self.limits = Some(sidecar_limits_v1(main.configured_limits()).map_err(JournalError::from));
        self.fixed = Some((|| {
            if !matches!(self.limits, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary);
            }
            let depth = if role == Method46InitialServiceRoleV1::StorageBroker {
                6
            } else {
                7
            };
            let path_bytes = u16::try_from(directory(role).len() + SIDECAR_NAME_V1.len())
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let native =
                ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(
                    depth, path_bytes,
                )
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let names = floor_names::EmptyFloorNamesOriginal::receiving_demand()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let bookends = self
                .main
                .quote_once(main, replayed)
                .ok_or(JournalError::ProtectedBoundary)?;
            native
                .checked_add(native)
                .and_then(|sum| sum.checked_add(names))
                .and_then(|sum| sum.checked_add(bookends))
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        self.fixed.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn prepare_once(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.prepare.is_some() || self.closed.is_some() || !matches!(self.fixed, Some(Ok(_))) {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.prepare = Some((|| {
            self.main.before_once(main)?;
            let uid = self
                .opening
                .recipe
                .uid()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.names.prepare_once(main, uid)?;
            let limits = self
                .limits
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.opening
                .prepare_once(limits, CapturedJournalOpenModeV1::ExistingOnly);
            if self.opening.captured_extent().is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if matches!(self.prepare, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn quote_replay_once(&mut self) -> Option<ResourceVector> {
        if self.replay_quote.is_some()
            || self.closed.is_some()
            || !matches!(self.prepare, Some(Ok(())))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.replay_quote = Some((|| {
            let extent = self
                .opening
                .captured_extent()
                .ok_or(JournalError::ProtectedBoundary)?;
            if extent.native_bytes != 0 {
                return Err(JournalError::ProtectedBoundary);
            }
            extent
                .dominant_native_receiving_demand_v1()?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)
                .map_err(|_| JournalError::ProtectedBoundary)
        })());
        self.replay_quote.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn replay_once(&mut self) -> Result<(), JournalError> {
        if self.empty.is_some()
            || self.closed.is_some()
            || !matches!(self.replay_quote, Some(Ok(_)))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.opening.replay_once();
        self.empty = Some((|| {
            if !self.opening.replay_ready() {
                return Err(JournalError::ProtectedBoundary);
            }
            let journal = self
                .opening
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            if journal.snapshot_sequence() != 1 || journal.all_records().next().is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if matches!(self.empty, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn quote_currentness_once(&mut self) -> Option<ResourceVector> {
        if !matches!(self.empty, Some(Ok(()))) || self.closed.is_some() {
            return None;
        }
        self.currentness.quote_once(
            self.opening.original.journal_data_v1()?,
            self.opening
                .original
                .captured_replay_file_identity_data_v1()?,
        )
    }

    pub(super) fn begin_currentness_once(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.currentness_before.is_some()
            || self.closed.is_some()
            || !matches!(self.empty, Some(Ok(())))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.currentness_before = Some(
            self.currentness.before_once(
                self.opening
                    .original
                    .journal_data_v1()
                    .ok_or(JournalError::ProtectedBoundary)?,
            ),
        );
        self.preparation_after = Some(self.main.finish_after_owed(main));
        if self.ready() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn journal_and_replayed_data(&self) -> Option<(&Journal, FileIdentity)> {
        Some((
            self.opening.original.journal_data_v1()?,
            self.opening
                .original
                .captured_replay_file_identity_data_v1()?,
        ))
    }

    pub(super) fn ready(&self) -> bool {
        self.failure().is_none()
            && self.names.ready()
            && self.opening.replay_ready()
            && matches!(self.empty, Some(Ok(())))
            && matches!(self.currentness_before, Some(Ok(())))
            && matches!(self.preparation_after, Some(Ok(())))
            && self.post.is_none()
    }

    pub(super) fn finish_after_owed(&mut self, main: &Journal) -> Result<(), JournalError> {
        if self.prepare.is_none() {
            return Ok(());
        }
        let _names = self.names.finish_after_owed(main);
        if self.preparation_after.is_none() {
            self.preparation_after = Some(self.main.finish_after_owed(main));
        }
        if self.post.is_none() {
            self.post = Some((|| {
                if let Some(limits) = self.opening.limits {
                    self.opening.original.check_named_currentness_retaining(
                        self.opening
                            .recipe
                            .directory()
                            .ok_or(JournalError::ProtectedBoundary)?,
                        SIDECAR_NAME_V1,
                        limits,
                        self.opening
                            .recipe
                            .uid()
                            .ok_or(JournalError::ProtectedBoundary)?,
                        &mut self.floor_post,
                    )?;
                }
                Ok(())
            })());
            self.floor_post.settle_positive_once_v1();
        }
        // A failed name re-resolution cannot suppress the separately paid held
        // metadata post on the same floor writer.
        let currentness = if let Some(journal) = self.opening.original.journal_data_v1() {
            self.currentness.finish_after_owed(journal)
        } else {
            Ok(())
        };
        if self.failure().is_none() && currentness.is_ok() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.limits
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.fixed
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.main.before_failure())
            .or_else(|| self.names.failure())
            .or_else(|| {
                self.prepare
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.replay_quote
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.opening.failure())
            .or_else(|| {
                self.empty
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.currentness.before_failure())
            .or_else(|| self.main.after_failure())
            .or_else(|| {
                self.preparation_after
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.floor_post
            .failure()
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.currentness.after_failure())
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure().or_else(|| self.after_failure())
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_initial_floor_fixed_once(&mut self) -> Option<ResourceVector> {
        if !self.readback_available_data() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.initial_floor.quote_fixed_once(
            self.inner.original.journal_data_v1()?,
            self.inner
                .original
                .captured_replay_file_identity_data_v1()?,
            self.fixed_role?,
            self.inner.recipe.uid()?,
        )
    }

    pub(crate) fn prepare_initial_floor_once(&mut self) -> Result<(), JournalError> {
        self.initial_floor.prepare_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
        )
    }

    pub(crate) fn quote_initial_floor_replay_once(&mut self) -> Option<ResourceVector> {
        self.initial_floor.quote_replay_once()
    }

    pub(crate) fn replay_initial_floor_once(&mut self) -> Result<(), JournalError> {
        self.initial_floor.replay_once()
    }

    pub(crate) fn quote_initial_floor_currentness_once(&mut self) -> Option<ResourceVector> {
        self.initial_floor.quote_currentness_once()
    }

    pub(crate) fn begin_initial_floor_currentness_once(&mut self) -> Result<(), JournalError> {
        self.initial_floor.begin_currentness_once(
            self.inner
                .original
                .journal_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?,
        )
    }

    pub(crate) fn initial_floor_ready(&self) -> bool {
        self.initial_floor.ready()
    }

    pub(crate) fn finish_initial_floor_after_owed(&mut self) -> Result<(), JournalError> {
        let Some(main) = self.inner.original.journal_data_v1() else {
            return Ok(());
        };
        self.initial_floor.finish_after_owed(main)
    }
}

#[cfg(test)]
mod tests;
