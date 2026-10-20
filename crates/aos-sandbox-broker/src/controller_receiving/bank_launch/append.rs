//! Retains native stages for the trusted Controller semantic coordinator.
//!
//! Only the genuine paired startup gives its coordinator this staged port.
//! Domain remains trusted to run its sole semantic, fence and final-crossing
//! engine in the established order. These mechanical stages do NOT enforce
//! those semantics or prove any purpose success. Role loans have no such port.

use std::sync::Arc;

use crate::canonical_journal::coordinator::selected_append::{
    SelectedAppendCustodyV1, SelectedAppendGuardV1,
};

use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::canonical_journal::append_stages::{
    CanonicalAppendPublishedDataV1, CanonicalAppendStagesV1,
};

use super::identity::ControllerWriterIdentityV1;
use super::writer::ControllerFixedWriterOriginalV1;
use super::ControllerBankLaunchErrorV1;

/// Keeps the shared original storage without changing the Controller owner.
pub(super) type ControllerAppendCustodyV1 = SelectedAppendCustodyV1<ControllerAppendBodyV1>;

pub(super) struct ControllerAppendBodyV1 {
    stages: CanonicalAppendStagesV1<JournalTransaction>,
    conflict: Option<ControllerBankLaunchErrorV1>,
}

/// Retains a lower-produced receipt from actual append/apply/publication only.
///
/// No upper CommitResult or success scalar constructs this original. Bank pins
/// this SAME allocation before ACK/Confirm and separately rejoins its real map.
pub(super) struct ControllerDurableAppendReceiptV1 {
    pub(super) identity: Arc<ControllerWriterIdentityV1>,
    pub(super) transaction: [u8; 16],
    pub(super) storage_use_claimed: std::sync::atomic::AtomicBool,
    pub(super) head: u64,
    pub(super) following: u64,
    pub(super) durable_bytes: u64,
    pub(super) materialized: usize,
}

impl ControllerAppendBodyV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stages.failure().or_else(|| self.conflict.as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

/// Keeps the same actual first append failure with its original identity.
///
/// No successful value or imported cause constructs this negative original.
/// Its native source remains stable after other error owners are dropped; all
/// actual body/encoded/native partials stay in the already-paid sticky sink.
pub struct ControllerAppendFailureOriginalV1 {
    identity: Arc<ControllerWriterIdentityV1>,
    custody: Arc<ControllerAppendCustodyV1>,
}

impl ControllerAppendFailureOriginalV1 {
    /// Borrows the actual parked cause without a lock or copied classification.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.custody.parked_body().and_then(ControllerAppendBodyV1::failure)
    }

    /// Bounds these newly returned inline error carriers before preparation.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)
    }
}

impl std::fmt::Debug for ControllerAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ControllerAppendFailureOriginalV1")
            .field("failure", &self.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControllerAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Controller append original was refused"),
        }
    }
}

impl std::error::Error for ControllerAppendFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

/// Retains one actual Controller append preparation through all semantic posts.
///
/// It has no public constructor, raw writer, File or descriptor projection. Its
/// immutable frame/coordinate outputs are DATA only. An early upper error or
/// abandoned stage moves every reached owned value to the SAME writer's sink
/// and permanently closes that writer; ordinary field Drop cannot release it.
#[must_use]
pub struct ControllerPreparedAppendV1 {
    identity: Arc<ControllerWriterIdentityV1>,
    storage: SelectedAppendGuardV1<ControllerAppendBodyV1>,
}

impl ControllerPreparedAppendV1 {
    /// Moves this negative preparation into its SAME original permanent sink.
    ///
    /// The returned error borrows the exact resident cause through that original
    /// allocation. This performs no new allocation, native work or role admission.
    #[must_use]
    pub fn into_failure_original_v1(mut self) -> ControllerAppendFailureOriginalV1 {
        if let Some(body) = self.storage.body_mut() {
            if body.failure().is_none() {
                body.conflict = Some(ControllerBankLaunchErrorV1::Conflict);
            }
        }
        let failure = ControllerAppendFailureOriginalV1 {
            identity: Arc::clone(&self.identity),
            custody: Arc::clone(self.storage.custody()),
        };
        self.storage.park_unfinished();
        failure
    }


    /// Borrows the actual transaction retained by this stage as comparison DATA.
    #[must_use]
    pub fn transaction(&self) -> Option<&JournalTransaction> {
        self.storage.body().map(|body| body.stages.transaction())
    }

    /// Borrows the last record whose native and index steps both completed.
    #[must_use]
    pub fn last_applied_record(&self) -> Option<&JournalRecord> {
        self.storage.body().and_then(|body| body.stages.last_applied_record())
    }

    /// Copies coordinates produced by this stage's actual native publication.
    #[must_use]
    pub fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        self.storage.body().and_then(|body| body.stages.published_coordinates())
    }

    /// Borrows the SAME encoder's actual frame vector without moving it.
    ///
    /// # Errors
    /// Refuses a missing or failed projected/encoded native stage.
    pub fn encoded_frames(&self) -> Result<&[Vec<u8>], ControllerBankLaunchErrorV1> {
        let body = self.storage.body().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        body.stages.encoded_frames().ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    /// Copies the actual existing native projection result as DATA.
    ///
    /// # Errors
    /// Leaves the precise native projection error resident in this stage.
    pub fn projected_materialized_bytes(&self) -> Result<usize, ControllerBankLaunchErrorV1> {
        self.storage.body().and_then(|body| body.stages.projected_materialized_bytes())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)
    }

    /// Borrows the first reached actual native/index/arithmetic refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.storage.body().and_then(ControllerAppendBodyV1::failure)
    }
}

// The actual upper Journal error may own this whole preparation. Its source
// borrows the same resident native cause without cloning it or locking a sink.
impl std::fmt::Debug for ControllerPreparedAppendV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ControllerPreparedAppendV1")
            .field("failure", &self.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ControllerPreparedAppendV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("Controller append stage was refused"),
        }
    }
}

impl std::error::Error for ControllerPreparedAppendV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

impl Drop for ControllerPreparedAppendV1 {
    fn drop(&mut self) {
        // Park before identity and other Controller fields are released.
        self.storage.park_unfinished();
    }
}

impl<P> ControllerFixedWriterOriginalV1<P> {
    /// Prepares the same native projection and encoder for its trusted caller.
    ///
    /// This private entry accepts only the actual coordinator's transaction.
    /// Its closed shape debit runs before the retained copy/encoder grows.
    /// The returned carrier is retained even when either native stage failed.
    pub(super) fn prepare_coordinator_append(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<ControllerPreparedAppendV1, ControllerBankLaunchErrorV1> {
        self.require_healthy()?;
        if !self.append_custody.enter() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        if let Err(cause) = self.require_append_representation(transaction) {
            self.append_custody.close();
            self.append_debit_failure = Some(cause);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let mut stages = CanonicalAppendStagesV1::new_retaining_v1(transaction.clone());
        if stages.project_once(self.physical.native.native()).is_ok() {
            let _encoded = stages.encode_once(self.physical.native.native());
        }
        Ok(ControllerPreparedAppendV1 {
            identity: Arc::clone(&self.identity),
            storage: SelectedAppendGuardV1::new(
                Arc::clone(&self.append_custody),
                ControllerAppendBodyV1 { stages, conflict: None },
            ),
        })
    }

    fn require_stage<'stage>(
        &self,
        stage: &'stage mut ControllerPreparedAppendV1,
    ) -> Result<&'stage mut ControllerAppendBodyV1, ControllerBankLaunchErrorV1> {
        if !Arc::ptr_eq(&stage.identity, &self.identity)
            || !Arc::ptr_eq(stage.storage.custody(), &self.append_custody)
            || self.append_custody.is_closed()
            || !self.append_custody.is_active()
            || self.fenced || self.physical.native.native().is_poisoned()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let body = stage.storage.body_mut().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if body.failure().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(body)
    }

    // The actual upper engine calls this immediately after encode and before
    // any expected-length metadata, preserving its old checked arithmetic cut.
    pub(super) fn coordinator_coordinates(
        &self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<(u64, u64), ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        body.stages.coordinates_once().map_err(|_| ControllerBankLaunchErrorV1::Conflict)
    }

    pub(super) fn expected_coordinator_length(
        &self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<u64, ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        body.stages.expected_length_once(self.physical.native.native())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)
    }

    pub(super) fn append_coordinator_prepared(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<u64, ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        body.stages.append_once(self.physical.native.native_mut())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)
    }

    pub(super) fn apply_next_coordinator_record(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<bool, ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        let native = self.physical.native.native_mut();
        match body.stages.apply_next_record_once(native, &mut self.physical.index) {
            Ok(applied) => Ok(applied),
            Err(_) => {
                // Native/index uncertainty belongs to this selected owner. The
                // shared ordinary stage keeps its original poison schedule.
                native.poison();
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    pub(super) fn apply_coordinator_record(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
        expected_record: &JournalRecord,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        let native = self.physical.native.native_mut();
        let applied = body.stages.apply_next_record_once(native, &mut self.physical.index);
        if !matches!(applied, Ok(true)) || body.stages.last_applied_record() != Some(expected_record) {
            // The ordinary shared DATA engine retains its old no-extra-poison
            // index failure contract. This selected owner separately fences its
            // actual ambiguous prefix and retains the WHOLE failed stage.
            native.poison();
            body.conflict.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn publish_coordinator_append(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<CanonicalAppendPublishedDataV1, ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        let published = body.stages.publish_once(self.physical.native.native_mut())
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        // This private original is produced ONLY by actual shared publication
        // on this writer. Passive published DATA cannot enter from a caller.
        self.last_receipt = Some(Arc::new(ControllerDurableAppendReceiptV1 {
            identity: Arc::clone(&self.identity), transaction: published.transaction,
            storage_use_claimed: std::sync::atomic::AtomicBool::new(false),
            head: published.head, following: published.following,
            durable_bytes: published.durable_bytes, materialized: published.materialized_bytes,
        }));
        self.record_durable_end(published.durable_bytes);
        Ok(published)
    }

    // Called only at the actual coordinator's old positive return boundary,
    // after cache_gate.own_successor and every required semantic post. It takes
    // no caller success Boolean and changes no resource debit or Bank state.
    pub(super) fn dispose_coordinator_append(
        &mut self,
        stage: &mut ControllerPreparedAppendV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let body = self.require_stage(stage)?;
        if !body.stages.is_published() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let completed = stage.storage.take_body().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        // All fallible checks precede disposal. These native DATA captures carry
        // no future authority; the actual written prefix and indexes stay owned.
        drop(completed);
        self.append_custody.release_active();
        Ok(())
    }
}
