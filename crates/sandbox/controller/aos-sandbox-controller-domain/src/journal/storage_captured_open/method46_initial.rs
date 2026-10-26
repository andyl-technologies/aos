//! Retains existing main-writer mechanics for the genuine initial Source.
//!
//! Only the startup owner enters this crate-private adapter after paying its
//! fixed acquisition and the actual held prefix. The shared writer engine
//! forbids creation, compaction cleanup and tail repair. No Journal escapes,
//! and mechanical nonemptiness supplies no schema, approval or TPM grant.

use aos_sandbox_broker::receiving::Method46InitialServiceRoleV1;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

use super::*;

mod approval_currentness;
mod floor_names;
mod initial_floor;
mod initial_intent;
mod namespace;
mod readback;

#[derive(Debug, thiserror::Error)]
enum ReplayDemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Schema(#[from] super::super::broker_session_receiving::StorageSessionGeometryRefusalV1),
}

pub(super) const fn directory(role: Method46InitialServiceRoleV1) -> &'static str {
    match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => {
            controller::directory(crate::ControllerInitialBrokerSessionRoleV1::Storage)
        }
        Method46InitialServiceRoleV1::StorageBroker => {
            FixedProtectedJournalRecipeV1::BrokerSession.directory()
        }
    }
}

pub(crate) struct Method46InitialMainWriterOriginalV1 {
    inner: FixedProtectedCapturedJournalOpenV1,
    entered: bool,
    fixed: Option<Result<ResourceVector, AccountingError>>,
    fixed_role: Option<Method46InitialServiceRoleV1>,
    replay_quote: Option<Result<ResourceVector, ReplayDemandError>>,
    nonempty: Option<Result<(), JournalError>>,
    post: Option<Result<(), JournalError>>,
    post_original: super::super::ProtectedJournalCurrentnessOriginalsV1,
    closed: Option<JournalError>,
    readback: readback::MainMapReadbackOriginalV1,
    approval_currentness: approval_currentness::ApprovalCurrentnessOriginalV1,
    initial_intent: initial_intent::InitialIntentOriginal,
    initial_floor: initial_floor::InitialFloorOriginal,
    namespace: namespace::MainNamespaceOriginalV1,
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedMethod46InitialMain(None),
            ),
            entered: false,
            fixed: None,
            fixed_role: None,
            replay_quote: None,
            nonempty: None,
            post: None,
            post_original: super::super::ProtectedJournalCurrentnessOriginalsV1::new(),
            closed: None,
            readback: readback::MainMapReadbackOriginalV1::new(),
            approval_currentness: approval_currentness::ApprovalCurrentnessOriginalV1::new(),
            initial_intent: initial_intent::InitialIntentOriginal::new(),
            initial_floor: initial_floor::InitialFloorOriginal::new(),
            namespace: namespace::MainNamespaceOriginalV1::new(),
        }
    }

    fn fixed_demand(role: Method46InitialServiceRoleV1) -> Result<ResourceVector, AccountingError> {
        let depth = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => 7,
            Method46InitialServiceRoleV1::StorageBroker => 6,
        };
        let path_bytes =
            u16::try_from(directory(role).len() + "session.journal".len()).map_err(|_| {
                AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                }
            })?;
        let native = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(
            depth, path_bytes,
        )?;
        // The ordinary supplier covers acquisition plus two retained failed
        // traversals. A second full allowance also covers our independently
        // owed final traversal, without crediting a future positive disposal.
        native.checked_add(native)
    }

    pub(crate) fn quote_fixed_once(
        &mut self,
        role: Method46InitialServiceRoleV1,
    ) -> Option<ResourceVector> {
        if self.fixed.is_some() || self.entered || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.fixed = Some(Self::fixed_demand(role));
        self.fixed_role = Some(role);
        self.fixed.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn prepare_once(&mut self, role: Method46InitialServiceRoleV1, controller_uid: u32) {
        if self.entered
            || self.closed.is_some()
            || controller_uid == 0
            || self.fixed_role != Some(role)
            || !matches!(self.fixed, Some(Ok(_)))
            || self.replay_quote.is_some()
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.entered = true;
        let uid = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => controller_uid,
            Method46InitialServiceRoleV1::StorageBroker => 0,
        };
        self.inner.recipe =
            ProtectedCapturedJournalRecipeV1::JoinedMethod46InitialMain(Some((role, uid)));
        self.inner.prepare_once(
            super::super::broker_session_receiving::protected_session_journal_limits_v1(),
            CapturedJournalOpenModeV1::ExistingOnly,
        );
    }

    fn replay_demand(&self) -> Result<ResourceVector, ReplayDemandError> {
        let extent = self
            .inner
            .captured_extent()
            .ok_or(JournalError::ProtectedBoundary)?;
        let schema = super::super::broker_session_receiving::schema_demand(extent)?;
        let retained = ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                crate::method46_initial_startup::METHOD46_INITIAL_SESSION_SCHEMA_BYTES_V1 as u64,
            )
            .with(
                D::MetadataEntries,
                crate::method46_initial_startup::METHOD46_INITIAL_SESSION_SCHEMA_CELLS_V1 as u64,
            );
        // The real Source pays before replay consumes this native extent. The
        // second recipe covers retained codec originals beside comparison DATA.
        Ok(extent
            .dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(schema)?
            .checked_add(schema)?
            .checked_add(retained)?)
    }

    pub(crate) fn quote_replay_once(&mut self) -> Option<ResourceVector> {
        if self.replay_quote.is_some() || self.closed.is_some() || !self.entered {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.replay_quote = Some(self.replay_demand());
        self.replay_quote.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn replay_once(&mut self) -> Result<(), JournalError> {
        if self.nonempty.is_some()
            || self.closed.is_some()
            || !self.entered
            || !matches!(self.replay_quote, Some(Ok(_)))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.inner.replay_once();
        self.nonempty = Some((|| {
            if !self.inner.replay_ready() {
                return Err(JournalError::ProtectedBoundary);
            }
            let journal = self
                .inner
                .original
                .journal_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            // Nonempty refers to committed native history. A valid history
            // can have an empty current map after all its rows were deleted.
            if journal.snapshot_sequence() <= 1 || journal.snapshot_sequence() == u64::MAX {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if matches!(self.nonempty, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn finish_post(&mut self) -> Result<(), JournalError> {
        if !self.entered {
            return if self.closed.is_none() {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }
        if self.post.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        // A failed map-before/hash cannot suppress its separately paid after.
        let _readback_after = self.finish_readback_after_owed();
        let _approval_after = self.finish_approval_currentness_after_owed();
        let _intent_after = self.finish_initial_intent_after_owed();
        let _floor_after = self.finish_initial_floor_after_owed();
        self.post = Some((|| {
            self.inner.original.check_named_currentness_retaining(
                self.inner
                    .recipe
                    .directory()
                    .ok_or(JournalError::ProtectedBoundary)?,
                self.inner.recipe.name(),
                self.inner.limits.ok_or(JournalError::ProtectedBoundary)?,
                self.inner
                    .recipe
                    .uid()
                    .ok_or(JournalError::ProtectedBoundary)?,
                &mut self.post_original,
            )
        })());
        self.post_original.settle_positive_once_v1();
        if self.failure().is_none() && matches!(self.nonempty, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.inner
            .failure()
            .or_else(|| {
                self.fixed
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.replay_quote
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.nonempty
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.namespace.failure())
            .or_else(|| self.initial_floor.before_failure())
            // Preserve chronological prefixes across the nested intervals:
            // main readback before, approval before, readback after, approval after.
            .or_else(|| self.readback.before_failure())
            .or_else(|| self.approval_currentness.before_failure())
            .or_else(|| self.readback.after_failure())
            .or_else(|| self.approval_currentness.after_failure())
            .or_else(|| self.approval_currentness.order_failure())
            .or_else(|| self.initial_intent.failure())
            .or_else(|| self.initial_floor.after_failure())
            .or_else(|| self.post_original.failure())
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method46_initial_main_writer_mechanics_refuse_without_fixed_admission() {
        let mut writer = Method46InitialMainWriterOriginalV1::new();

        writer.prepare_once(Method46InitialServiceRoleV1::StorageBroker, 811);

        assert!(!writer.entered);
        assert!(writer.inner.limits.is_none());
        assert!(writer.inner.captured_extent().is_none());
        assert!(writer.failure().is_some());
        assert!(
            writer
                .quote_fixed_once(Method46InitialServiceRoleV1::StorageBroker)
                .is_none()
        );
        assert!(writer.finish_post().is_err());
    }

    #[test]
    fn method46_initial_main_writer_fixed_quote_cannot_change_purpose() {
        let mut writer = Method46InitialMainWriterOriginalV1::new();
        assert!(
            writer
                .quote_fixed_once(Method46InitialServiceRoleV1::StorageBroker)
                .is_some()
        );

        writer.prepare_once(Method46InitialServiceRoleV1::ControllerStorageClient, 811);

        assert!(!writer.entered);
        assert!(writer.inner.limits.is_none());
        assert_eq!(
            writer.fixed_role,
            Some(Method46InitialServiceRoleV1::StorageBroker)
        );
        assert!(writer.failure().is_some());
    }

    #[test]
    fn method46_initial_main_writer_replay_refuses_before_native_preparation() {
        let mut writer = Method46InitialMainWriterOriginalV1::new();

        assert!(writer.quote_replay_once().is_none());
        assert!(writer.replay_once().is_err());

        assert!(!writer.entered);
        assert!(!writer.inner.replay_entered);
        assert!(writer.inner.limits.is_none());
        assert!(writer.nonempty.is_none());
        assert!(writer.failure().is_some());
    }
}
