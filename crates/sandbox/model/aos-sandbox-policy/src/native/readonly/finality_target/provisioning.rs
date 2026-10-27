//! Suspends the same fixed reader at provisioning's existing upper frontiers.
//!
//! Session decoding, Source tree selection, financial admissions and clocks
//! remain with the genuine enclosing programme. Each method retains this
//! target's actual reader/model; no rows, successful post or completed owner
//! can be supplied to adopt a native observation.

use super::super::stopped_history::RootCreateStoppedHistoricalOriginalV2;
use super::{
    Model, ReadError, ResourceVector, RootFinalityReadKindV1 as Kind,
    RootFinalityReadOriginalV1 as Target, RootFixedNativeReadbackV1,
};
use std::error::Error;
use std::mem::size_of;

impl Target {
    /// Bounds the real scope-end close, take and destructor argument planes.
    ///
    /// The containing scope admits this once before constructing its targets.
    /// All targets are disposed sequentially on that same stack; no native
    /// opening, model allocation or future role geometry is included here.
    pub fn scope_disposal_control_bytes_v2() -> Option<usize> {
        let receivers = size_of::<&mut Self>().checked_mul(3)?.checked_mul(2)?;
        let taken = size_of::<Option<Box<super::Reader>>>()
            .max(size_of::<Option<Box<Model>>>()).checked_mul(3)?;
        let close = size_of::<ReadError>().checked_mul(3)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?;
        receivers.checked_add(taken)?.checked_add(close)
    }

    // This negative-only state cannot erase a real earlier post failure or
    // allow the actual public constructor to reopen a retired target.
    fn close_scope_inner_v2(&mut self) {
        if !matches!(self.posts, Some(Err(_))) {
            self.posts = Some(Err(ReadError::ProtectedBoundary));
        }
    }

    /// Drops only the actual reader at its enclosing scope's original slot.
    ///
    /// This permanently closes the target. The actual upper scope calls this
    /// only from Drop, retaining failed readers through every owed observation.
    /// It is distinct from Delete's successful completed-DATA transfer.
    #[doc(hidden)]
    pub fn dispose_scope_reader_v2(&mut self) {
        self.close_scope_inner_v2();
        drop(self.reader.take());
    }

    /// Drops only the same model after the enclosing scope's original clocks.
    ///
    /// No model is returned, replaced or adopted. Reader and model disposal
    /// can span the same existing upper fields without a callback or raw getter.
    #[doc(hidden)]
    pub fn dispose_scope_model_v2(&mut self) {
        self.close_scope_inner_v2();
        drop(self.model.take());
    }

    /// Prices the reached provisioning recipe and its additional staged ports.
    ///
    /// # Errors
    /// Returns native geometry, representation or accounting refusal.
    pub fn provisioning_fixed_demand_v2(kind: Kind) -> Result<ResourceVector, ReadError> {
        let controls = Self::provisioning_control_bytes_v2(kind)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ReadError::JournalTooLarge)?;
        Self::fixed_kind_demand_v1(kind)?
            .checked_add(
                ResourceVector::ZERO
                    .with(aos_sandbox_model::ResourceDimension::MemoryBytes, controls),
            )
            .map_err(ReadError::ReceivingAccounting)
    }

    // Each group names the actual new caller/ABI/return planes. Only the
    // selected fixed recipe's reached group is admitted; maps and old native
    // reader/model recipes remain separately priced by the existing engine.
    fn provisioning_control_bytes_v2(kind: Kind) -> Option<usize> {
        type Unit = Result<(), ReadError>;
        type Demand = Result<ResourceVector, ReadError>;
        type View<'a> = Result<RootFixedNativeReadbackV1<'a>, ReadError>;
        let replay = size_of::<(&mut Self, Option<(u64, u64)>)>()
            .checked_mul(3)?
            .checked_add(size_of::<Unit>().checked_mul(3)?.checked_mul(2)?)?;
        let posts = size_of::<&mut Self>()
            .checked_mul(3)?
            .checked_add(size_of::<&Self>().checked_mul(3)?)?
            .checked_add(size_of::<View<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?)?;
        let quote = size_of::<Kind>()
            .checked_mul(3)?
            .checked_add(size_of::<Demand>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?;
        let common = replay.checked_add(posts)?.checked_add(quote)?;
        let extra = match kind {
            Kind::StorageSession => size_of::<(&mut Self, (u64, u64))>().checked_mul(3)?,
            Kind::CacheCurrent(_) => size_of::<&Self>().checked_mul(3)?.checked_add(
                size_of::<
                    Result<
                        aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1<'_>,
                        ReadError,
                    >,
                >()
                .checked_mul(3)?,
            )?,
            Kind::Controller
            | Kind::ControllerStopped { .. }
            | Kind::Source
            | Kind::SourceRelease => {
                let model = size_of::<&mut Self>()
                    .checked_mul(3)?
                    .checked_mul(3)?
                    .checked_add(size_of::<&Self>().checked_mul(3)?.checked_mul(4)?)?
                    .checked_add(size_of::<Unit>().checked_mul(3)?.checked_mul(3)?)?
                    .checked_add(size_of::<Demand>().checked_mul(3)?)?
                    .checked_add(size_of::<bool>().checked_mul(3)?)?
                    .checked_add(
                        size_of::<Option<&(dyn Error + 'static)>>()
                            .checked_mul(3)?
                            .checked_mul(2)?,
                    )?;
                if matches!(kind, Kind::ControllerStopped { .. }) {
                    model
                        .checked_add(size_of::<&mut Self>().checked_mul(3)?)?
                        .checked_add(
                            size_of::<Result<RootCreateStoppedHistoricalOriginalV2, ReadError>>()
                                .checked_mul(3)?,
                        )?
                } else {
                    model
                }
            }
            Kind::HostSession | Kind::NetworkSession | Kind::MountSession => 0,
        };
        common.checked_add(extra)
    }

    /// Audits the same full prefix without charging an unused readonly model.
    ///
    /// # Errors
    /// Returns the actual retained full-history geometry or native refusal.
    pub fn audited_semantic_only_v2(&mut self) -> Result<ResourceVector, ReadError> {
        let reader = self.reader_mut()?;
        reader.audit_once();
        reader.additional_semantic_demand_v1()
    }

    /// Prices the same actual reader's readonly model at its upper sum frontier.
    ///
    /// # Errors
    /// Returns the original model geometry or incomplete reader refusal.
    pub fn model_receiving_demand_v2(&self) -> Result<ResourceVector, ReadError> {
        Model::receiving_demand_v1(self.reader()?)
    }

    /// Replays the same actual reader while leaving upper joins before its post.
    ///
    /// # Errors
    /// Refuses reentry or retains the actual replay cause in this target.
    pub fn replay_only_once_v2(&mut self) -> Result<(), ReadError> {
        self.replay_selected_once_v2(None)
    }

    /// Replays the same Session reader through its original marked coordinates.
    ///
    /// # Errors
    /// Refuses a non-Session recipe, reentry or failed native marked replay.
    pub fn replay_marked_once_v2(&mut self, position: (u64, u64)) -> Result<(), ReadError> {
        if !matches!(self.kind, Kind::StorageSession) {
            return Err(ReadError::ProtectedBoundary);
        }
        self.replay_selected_once_v2(Some(position))
    }

    fn replay_selected_once_v2(&mut self, position: Option<(u64, u64)>) -> Result<(), ReadError> {
        if self.replay.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }
        self.replay = Some(self.replay_reader_inner_v2(position));
        if matches!(self.replay, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    /// Performs the same reader's independently owed intrinsic native post.
    pub fn finish_native_post_once_v2(&mut self) {
        if let Some(reader) = self.reader.as_mut() {
            reader.finish_post_once();
        }
    }

    /// Borrows the same real reader after its native post.
    ///
    /// # Errors
    /// Returns the original reader's incomplete or failed post disposition.
    pub fn posted_readback_v2(&self) -> Result<RootFixedNativeReadbackV1<'_>, ReadError> {
        self.reader()?.terminal_native_v1()
    }

    /// Transfers only this target's actual native inputs at the late model slot.
    ///
    /// # Errors
    /// Refuses another model, non-model recipe or failed actual model adoption.
    pub fn adopt_posted_model_once_v2(&mut self) -> Result<(), ReadError> {
        if !self.kind.uses_model() || self.model.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }
        self.adopt_posted_model_inner_v2()
    }

    /// Performs only the same model's independently owed parent post.
    pub fn finish_model_post_once_v2(&mut self) {
        if let Some(model) = self.model.as_mut() {
            model.finish_parent_post_once_v1();
        }
    }

    /// Requires the actual same model's positive parent post.
    ///
    /// # Errors
    /// Refuses an absent, incomplete or failed actual model post.
    pub fn require_model_post_v2(&self) -> Result<(), ReadError> {
        self.model
            .as_ref()
            .ok_or(ReadError::ProtectedBoundary)?
            .require_parent_post_v1()
    }

    /// Reports whether this same target has entered its actual model transfer.
    ///
    /// This disposal/diagnostic DATA does not report successful adoption.
    #[must_use]
    pub fn model_entered_data_v2(&self) -> bool {
        self.model.is_some()
    }

    /// Borrows the same actual Cache reader's namespace and durable DATA.
    ///
    /// # Errors
    /// Refuses absent or incomplete real Cache replay.
    pub fn cache_raw_view_v2(
        &self,
    ) -> Result<aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1<'_>, ReadError>
    {
        self.reader()?.cache_raw_view_v1()
    }

    /// Takes the opaque proof earned by this actual STOPPED Controller reader.
    ///
    /// # Errors
    /// Refuses absent history, incomplete replay, failed posts or repeated take.
    pub fn take_stopped_historical_v2(
        &mut self,
    ) -> Result<RootCreateStoppedHistoricalOriginalV2, ReadError> {
        self.reader_mut()?.take_create_stopped_historical_v2()
    }

    /// Borrows the original reader's separately retained native post failure.
    pub fn native_post_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.reader
            .as_ref()
            .and_then(|reader| reader.post_failure())
    }

    /// Borrows the same model's separately retained parent-post failure.
    pub fn model_post_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.model
            .as_ref()
            .and_then(|model| model.parent_post_failure_v1())
    }
}

#[cfg(test)]
mod scope_disposal_tests {
    use super::*;

    #[test]
    fn closed_scope_cannot_construct_a_replacement_reader() {
        let mut target = Target::new(Kind::Controller);

        target.dispose_scope_reader_v2();
        target.dispose_scope_model_v2();

        assert!(target.construct_reader_once_v1().is_err());
        assert!(target.reader.is_none());
        assert!(target.model.is_none());
        assert!(target.require_complete_v1().is_err());
    }

    #[test]
    fn scope_disposal_keeps_the_same_earlier_owned_post_error() {
        let mut target = Target::new(Kind::Controller);
        target.posts = Some(Err(ReadError::Mechanical(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::Io(
                std::io::Error::other("retained original post cause"),
            ),
        )));
        let before = target.posts.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as *const ReadError);

        target.dispose_scope_reader_v2();
        target.dispose_scope_model_v2();

        let after = target.posts.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as *const ReadError);
        assert_eq!(before, after);
        assert!(target.construct_reader_once_v1().is_err());
    }
}
