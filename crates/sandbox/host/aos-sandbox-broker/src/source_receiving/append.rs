//! Retains actual Source append stages until the same semantic return boundary.

use std::sync::Arc;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::canonical_journal::append_stages::{CanonicalAppendStagesV1, CanonicalAppendPublishedDataV1};
use crate::canonical_journal::coordinator::selected_append::{SelectedAppendCustodyV1, SelectedAppendGuardV1};
use super::{SourceCoordinatorWriterV1, SourceNativeErrorV1};

pub(super) struct SourceAppendBodyV1 {
    pub(super) stages: CanonicalAppendStagesV1<JournalTransaction>,
    pub(super) conflict: Option<SourceNativeErrorV1>,
}

impl SourceAppendBodyV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stages.failure().or_else(|| self.conflict.as_ref().map(|cause| cause as _))
    }
}

/// Retains the original permanently parked append failure without cloning it.
pub struct SourceAppendFailureOriginalV1 {
    custody: Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>,
}

impl SourceAppendFailureOriginalV1 {
    /// Borrows the actual first retained native or stage failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.custody.parked_body().and_then(SourceAppendBodyV1::failure)
    }
}

impl std::fmt::Debug for SourceAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SourceAppendFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for SourceAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Source native append was refused"),
        }
    }
}

impl std::error::Error for SourceAppendFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { self.failure() }
}

/// Holds one real Source append through native publication and upper posts.
///
/// Its constructor is private. Abandonment moves the whole reached stage to
/// the same writer's precharged permanent sink and prevents positive reuse.
#[must_use]
pub struct SourcePreparedAppendV1 {
    pub(super) storage: SelectedAppendGuardV1<SourceAppendBodyV1>,
}

impl SourcePreparedAppendV1 {
    /// Moves this actual failed preparation to its same original permanent sink.
    pub fn into_failure_original_v1(mut self) -> SourceAppendFailureOriginalV1 {
        if let Some(body) = self.storage.body_mut() {
            if body.failure().is_none() { body.conflict = Some(SourceNativeErrorV1::Closed); }
        }
        let failure = SourceAppendFailureOriginalV1 { custody: Arc::clone(self.storage.custody()) };
        self.storage.park_unfinished();
        failure
    }

    /// Borrows the first actual reached stage failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage.body().and_then(SourceAppendBodyV1::failure)
    }
}

impl std::fmt::Debug for SourcePreparedAppendV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SourcePreparedAppendV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl<P> SourceCoordinatorWriterV1<P> {
    pub(super) fn prepare_source_append_once(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<SourcePreparedAppendV1, SourceNativeErrorV1> {
        self.require_append_entry_v1(transaction)?;
        self.prepare_source_append_inner_v1(transaction)
    }

    // Ordinary entry and the closed active-Delete borrower share this body.
    // The latter must independently prove its actual exclusive scope first.
    pub(super) fn prepare_source_append_inner_v1(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<SourcePreparedAppendV1, SourceNativeErrorV1> {
        if !self.native_post_active || !self.append_prepaid {
            return Err(SourceNativeErrorV1::Closed);
        }
        if !self.custody.enter() {
            return Err(SourceNativeErrorV1::Closed);
        }
        if let Err(cause) = self.require_append_representation(transaction) {
            self.custody.close();
            self.debit_failure = Some(cause);
            return Err(SourceNativeErrorV1::Closed);
        }
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction.clone());
        if stages.project_once(self.physical.native.native()).is_ok() {
            let _encoded = stages.encode_once(self.physical.native.native());
        }
        Ok(SourcePreparedAppendV1 {
            storage: SelectedAppendGuardV1::new(Arc::clone(&self.custody),
                SourceAppendBodyV1 { stages, conflict: None }),
        })
    }

    pub(super) fn require_stage<'stage>(
        &self,
        stage: &'stage mut SourcePreparedAppendV1,
    ) -> Result<&'stage mut SourceAppendBodyV1, SourceNativeErrorV1> {
        if !Arc::ptr_eq(stage.storage.custody(), &self.custody)
            || self.has_native_uncertainty_v1() || !self.custody.is_active()
        { return Err(SourceNativeErrorV1::Closed); }
        let body = stage.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if body.failure().is_some() {
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(body)
    }

    pub(super) fn publish_source_append_once(
        &mut self,
        stage: &mut SourcePreparedAppendV1,
    ) -> Result<CanonicalAppendPublishedDataV1, SourceNativeErrorV1> {
        let body = self.require_stage(stage)?;
        let published = body.stages.publish_once(self.physical.native.native_mut())
            .map_err(|_| SourceNativeErrorV1::Closed)?;
        self.durable_end = published.durable_bytes;
        Ok(published)
    }

    pub(super) fn apply_next_source_record_once(
        &mut self,
        stage: &mut SourcePreparedAppendV1,
    ) -> Result<bool, SourceNativeErrorV1> {
        let body = self.require_stage(stage)?;
        let native = self.physical.native.native_mut();
        match body.stages.apply_next_record_once(native, &mut self.physical.index) {
            Ok(applied) => Ok(applied),
            Err(_) => { native.poison(); Err(SourceNativeErrorV1::Closed) }
        }
    }

    /// Applies the next actual record and verifies the coordinator's same step.
    ///
    /// # Errors
    /// Retains native/index refusal or an unequal expected record and poisons reuse.
    pub fn apply_source_record_once(
        &mut self,
        stage: &mut SourcePreparedAppendV1,
        record: &JournalRecord,
    ) -> Result<(), SourceNativeErrorV1> {
        let applied = self.apply_next_source_record_once(stage);
        let body = stage.storage.body_mut().ok_or(SourceNativeErrorV1::Closed)?;
        if !matches!(applied, Ok(true)) || body.stages.last_applied_record() != Some(record) {
            self.physical.native.native_mut().poison();
            body.conflict.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

    pub(super) fn dispose_source_append_once(
        &mut self,
        stage: &mut SourcePreparedAppendV1,
    ) -> Result<(), SourceNativeErrorV1> {
        if !self.require_stage(stage)?.stages.is_published() {
            return Err(SourceNativeErrorV1::Closed);
        }
        if self.provisioning_scope_active {
            let body = self.require_stage(stage)?;
            let published = body.stages.published_coordinates().ok_or(SourceNativeErrorV1::Closed)?;
            let digest = aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
                std::slice::from_ref(body.stages.transaction()));
            if self.provisioning_transaction != Some(digest)
                || published.following != self.next_sequence()
                || published.durable_bytes != self.durable_end
            {
                return Err(SourceNativeErrorV1::Closed);
            }
            self.provisioning_publication = Some((digest, published));
        }
        let completed = stage.storage.take_body().ok_or(SourceNativeErrorV1::Closed)?;
        drop(completed);
        self.custody.release_active();
        Ok(())
    }
}
