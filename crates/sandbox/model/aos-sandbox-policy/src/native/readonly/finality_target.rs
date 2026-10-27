//! Retains one fixed finality reader, its model and independently owed posts.
//!
//! A genuine purpose owns this target from inert construction. It performs its
//! own fixed/native/semantic admissions and clock checks between the named
//! stages below. This owner supplies no purpose, financial or mutation grant,
//! and accepts no completed model, supplied opening or successful admission.

mod delete;
mod provisioning;

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use super::error::RootReadonlyErrorV1 as ReadError;
use super::model::RootReadonlyModelOriginalsV1 as Model;
use super::{RootFixedNativeReadOriginalsV1 as Reader, RootFixedNativeReadbackV1};

/// Selects an existing fixed comparison recipe, without supplying a path.
#[derive(Clone, Copy)]
pub enum RootFinalityReadKindV1 {
    /// Selects the existing fixed Controller comparison reader.
    Controller,
    /// Selects the existing fixed Storage Session comparison reader.
    StorageSession,
    /// Selects the existing fixed Host Session comparison reader.
    HostSession,
    /// Selects the existing fixed Network Session comparison reader.
    NetworkSession,
    /// Selects the existing fixed Mount Session comparison reader.
    MountSession,
    /// Selects the existing fixed Source comparison reader.
    Source,
    /// Selects the existing fixed Source release comparison reader.
    SourceRelease,
    /// Selects the existing Controller reader with its native STOPPED audit.
    ControllerStopped {
        /// The original Create operation.
        parent: aos_sandbox_model::OperationId,
        /// The original project.
        project: aos_sandbox_model::ProjectId,
        /// The original sandbox.
        sandbox: aos_sandbox_model::SandboxId,
    },
    /// Selects one of the existing five fixed Cache comparison journals.
    CacheCurrent(aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1),
}

impl RootFinalityReadKindV1 {
    fn reader(self) -> Reader {
        match self {
            Self::Controller => Reader::controller_current_v1(),
            Self::StorageSession => Reader::default(),
            Self::HostSession => Reader::host_session_v2(),
            Self::NetworkSession => Reader::network_session_v2(),
            Self::MountSession => Reader::mount_session_v2(),
            Self::Source => Reader::source_current_v1(),
            Self::SourceRelease => Reader::source_release_v1(),
            Self::ControllerStopped { parent, project, sandbox } =>
                Reader::controller_create_stopped_history_v2(parent, project, sandbox),
            Self::CacheCurrent(role) => Reader::cache_current_v1(role),
        }
    }

    fn fixed_demand(self) -> Result<ResourceVector, ReadError> {
        match self {
            Self::Controller => Reader::controller_current_fixed_demand_v1(),
            Self::StorageSession => Reader::fixed_demand_v1(),
            Self::HostSession => Reader::host_session_fixed_demand_v2(),
            Self::NetworkSession => Reader::network_session_fixed_demand_v2(),
            Self::MountSession => Reader::mount_session_fixed_demand_v2(),
            Self::Source => Reader::source_current_fixed_demand_v1(),
            Self::SourceRelease => Reader::source_release_fixed_demand_v1(),
            Self::ControllerStopped { .. } => Reader::controller_current_fixed_demand_v1(),
            Self::CacheCurrent(role) => Reader::cache_current_fixed_demand_v1(role),
        }
    }

    fn uses_model(self) -> bool {
        matches!(self, Self::Controller | Self::ControllerStopped { .. } | Self::Source | Self::SourceRelease)
    }
}

/// Preserves names and durable coordinates before the same model transfer.
#[derive(Clone, Copy)]
pub struct RootFinalityNativeCutDataV1 {
    /// The historical physical journal names.
    pub names: ProtectedJournalNamesV1,
    /// The historical durable next sequence.
    pub next: u64,
    /// The historical durable byte end.
    pub end: u64,
}

impl RootFinalityNativeCutDataV1 {
    /// Compares the complete historical names and durable-coordinate encoding.
    pub fn matches_encoded_data_v3(self, encoded: &[u8]) -> bool {
        encoded.len() == 64
            && self.names.to_bytes().as_slice() == &encoded[..48]
            && self.next.to_be_bytes().as_slice() == &encoded[48..56]
            && self.end.to_be_bytes().as_slice() == &encoded[56..]
    }
}

/// Owns one real reader from preparation through replay, adoption and posts.
///
/// Its containing purpose retains the separate financial and clock failures.
/// Mechanical completion here never supplies that purpose's final authority.
pub struct RootFinalityReadOriginalV1 {
    kind: RootFinalityReadKindV1,
    reader: Option<Box<Reader>>,
    model: Option<Box<Model>>,
    completed: Option<super::completed::RootFixedCompletedReadDataV2>,
    cut: Option<RootFinalityNativeCutDataV1>,
    replay: Option<Result<(), ReadError>>,
    posts: Option<Result<(), ReadError>>,
}

impl RootFinalityReadOriginalV1 {
    /// Creates one inert fixed-recipe comparison owner without IO or a grant.
    pub fn new(kind: RootFinalityReadKindV1) -> Self {
        Self {
            kind,
            reader: None,
            model: None,
            completed: None,
            cut: None,
            replay: None,
            posts: None,
        }
    }

    // The containing purpose pays these nested constructor/return planes in
    // its genuine original pre-entry quote, before constructing this owner.
    // Its resident field is already part of that actual containing layout.
    /// Bounds additional nested construction and return interfaces without funding them.
    pub fn construction_control_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<RootFinalityReadKindV1>().checked_mul(2)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
    }

    // Separate method-entry and retained-result controls are additional to the
    // existing Reader/Model recipes. No map, frame payload or file is repeated.
    fn stage_control_bytes_v1() -> Option<usize> {
        type ResultUnit = Result<(), ReadError>;
        type ResultDemand = Result<ResourceVector, ReadError>;
        type ResultReader<'a> = Result<&'a Reader, ReadError>;
        type ResultReaderMut<'a> = Result<&'a mut Reader, ReadError>;
        type ResultModel<'a> = Result<&'a Model, ReadError>;

        let entries = size_of::<&Self>().checked_mul(16)?
            .checked_add(size_of::<&mut Self>().checked_mul(12)?)?
            .checked_add(size_of::<RootFinalityReadKindV1>().checked_mul(8)?)?
            .checked_add(size_of::<u32>().checked_mul(2)?)?
            .checked_add(size_of::<bool>().checked_mul(8)?)?;
        let results = size_of::<ResultUnit>().checked_mul(16)?
            .checked_add(size_of::<ResultDemand>().checked_mul(8)?)?
            .checked_add(size_of::<ResultReader<'_>>().checked_mul(6)?)?
            .checked_add(size_of::<ResultReaderMut<'_>>().checked_mul(8)?)?
            .checked_add(size_of::<ResultModel<'_>>().checked_mul(4)?)?
            .checked_add(size_of::<Result<usize, ReadError>>().checked_mul(2)?)?
            .checked_add(size_of::<Result<RootFinalityNativeCutDataV1, ReadError>>()
                .checked_mul(4)?)?
            .checked_add(size_of::<Result<RootFixedNativeReadbackV1<'_>, ReadError>>()
                .checked_mul(6)?)?
            // The separate late cut getter calls the same complete gate, then
            // returns the original saved DATA after positive owed posts.
            .checked_add(size_of::<&Self>().checked_mul(6)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootFinalityNativeCutDataV1, ReadError>>()
                .checked_mul(3)?)?;
        let transfers = size_of::<RootFinalityNativeCutDataV1>().checked_mul(3)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(12)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(4)?)?;
        // The by-kind fixed entry adds two actual quote return interfaces;
        // the inert-construction static route retains its checked width too.
        let fixed_entries = size_of::<Result<ResourceVector, ReadError>>()
            .checked_mul(6)?
            .checked_add(size_of::<RootFinalityReadKindV1>().checked_mul(6)?)?
            .checked_add(size_of::<&Self>().checked_mul(3)?)?
            .checked_add(size_of::<Result<u64, std::num::TryFromIntError>>()
                .checked_mul(3)?)?;
        // The extracted replay/adoption bodies add their own real method
        // argument and return planes to every reached shared invocation.
        let shared_transfers = size_of::<(&mut Self, Option<(u64, u64)>)>().checked_mul(3)?
            .checked_add(size_of::<ResultUnit>().checked_mul(3)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(3)?)?
            .checked_add(size_of::<ResultUnit>().checked_mul(3)?)?;
        entries.checked_add(results)?.checked_add(transfers)?.checked_add(fixed_entries)?
            .checked_add(shared_transfers)?
            .checked_add(Self::completed_transfer_control_bytes_v2()?)?
            .checked_add(Self::delete_port_control_bytes_v2()?)
    }

    /// Prices the same fixed recipe and staged comparison controls.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn fixed_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        Self::fixed_kind_demand_v1(self.kind)
    }

    /// Prices construction and the same fixed recipe before an inert target exists.
    ///
    /// # Errors
    /// Retains fixed native geometry, checked overflow or accounting refusal.
    pub fn fixed_construction_demand_v1(kind: RootFinalityReadKindV1)
        -> Result<ResourceVector, ReadError>
    {
        let controls = Self::construction_control_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ReadError::JournalTooLarge)?;
        Self::fixed_kind_demand_v1(kind)?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, controls),
        ).map_err(ReadError::ReceivingAccounting)
    }

    fn fixed_kind_demand_v1(kind: RootFinalityReadKindV1)
        -> Result<ResourceVector, ReadError>
    {
        let bytes = size_of::<Reader>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(Self::stage_control_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ReadError::JournalTooLarge)?;
        kind.fixed_demand()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, bytes),
        ).map_err(ReadError::ReceivingAccounting)
    }

    // Reached only after the containing genuine purpose's fixed admission.
    // The old first clock check follows this inert Reader allocation.
    /// Constructs the real fixed reader after the containing purpose admits its demand.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn construct_reader_once_v1(&mut self) -> Result<(), ReadError> {
        if self.reader.is_some() || self.completed.is_some() || self.model.is_some()
            || self.replay.is_some() || self.posts.is_some()
        {
            return Err(ReadError::ProtectedBoundary);
        }
        self.reader = Some(Box::new(self.kind.reader()));
        Ok(())
    }

    // The actual purpose checks its first clock immediately before this call.
    /// Captures that same reader at the containing purpose's actual UID.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn capture_once_v1(&mut self, controller_uid: u32)
        -> Result<(), ReadError>
    {
        let reader = self.reader_mut()?;
        reader.capture_once(controller_uid);
        reader.require_captured_v1()
    }

    /// Prices native replay from the same actual captured extent.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn native_receiving_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        self.reader()?.replay_demand_v1()
    }

    // Session's actual schema supplier remains on its concrete purpose. This
    // returns the same captured bound for that supplier, with no new probe.
    /// Returns the same captured prefix width for its actual Session schema quote.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn captured_prefix_bytes_v1(&self) -> Result<usize, ReadError> {
        usize::try_from(self.reader()?.captured_extent_v1()?.native_bytes)
            .map_err(|_| ReadError::JournalTooLarge)
    }

    // The containing purpose checks its second clock before this old audit.
    /// Audits the same full Controller or Source prefix and prices its actual model.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn full_semantic_receiving_demand_v1(&mut self)
        -> Result<ResourceVector, ReadError>
    {
        if !self.kind.uses_model() {
            return Err(ReadError::ProtectedBoundary);
        }
        let reader = self.reader_mut()?;
        reader.audit_once();
        reader.additional_semantic_demand_v1()?.checked_add(
            Model::receiving_demand_v1(reader)?,
        ).map_err(ReadError::ReceivingAccounting)
    }

    // The containing purpose checks its third clock after semantic admission.
    /// Replays the same reader and transfers only its actual completed model inputs.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn replay_and_adopt_once_v1(&mut self) -> Result<(), ReadError> {
        if self.replay.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }
        self.replay = Some(self.replay_and_adopt_inner());
        if matches!(self.replay, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    fn replay_and_adopt_inner(&mut self) -> Result<(), ReadError> {
        self.replay_reader_inner_v2(None)?;
        if self.kind.uses_model() {
            let reader = self.reader_mut()?;
            reader.finish_post_once();
            reader.terminal_native_v1()?;
            self.adopt_posted_model_inner_v2()?;
        }
        Ok(())
    }

    // Both ordinary finality and the staged provisioning/Delete programmes
    // use this one replay body. No native post or model transfer moves here.
    fn replay_reader_inner_v2(&mut self, mark: Option<(u64, u64)>) -> Result<(), ReadError> {
        let reader = self.reader.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        match mark {
            Some(position) => reader.replay_marked_once_v1(position),
            None => reader.replay_once(),
        }
        let data = reader.replay_native_v1()?;
        self.cut = Some(RootFinalityNativeCutDataV1 {
            names: data.names,
            next: data.next,
            end: data.end,
        });
        Ok(())
    }

    // The real enclosing programme checks the posted reader at its original
    // frontier. In particular no extra terminal check precedes this allocation.
    fn adopt_posted_model_inner_v2(&mut self) -> Result<(), ReadError> {
        let reader = self.reader.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        self.model = Some(Box::new(Model::new()));
        self.model.as_mut().ok_or(ReadError::ProtectedBoundary)?.adopt_once(reader);
        self.model.as_ref().ok_or(ReadError::ProtectedBoundary)?.require_complete_v1()?;
        Ok(())
    }

    // Every reached reader still receives its owed posts after an earlier
    // funding or clock refusal. The real purpose keeps that earlier cause.
    /// Runs independently owed reader and model posts after every reached refusal.
    pub fn finish_posts_once_v1(&mut self) {
        if self.posts.is_some() {
            return;
        }
        if let Some(reader) = self.reader.as_mut() {
            reader.finish_post_once();
        }
        if let Some(model) = self.model.as_mut() {
            model.finish_parent_post_once_v1();
        }
        self.posts = Some(self.require_posts_inner());
    }

    fn require_posts_inner(&self) -> Result<(), ReadError> {
        if !matches!(self.replay, Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        if let Some(model) = self.model.as_ref() {
            model.require_parent_post_v1()?;
        } else {
            self.reader()?.terminal_native_v1()?;
        }
        Ok(())
    }

    /// Requires this target's positive replay before its late post phase.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn require_body_complete_v1(&self) -> Result<(), ReadError> {
        if matches!(self.replay, Some(Ok(()))) && self.posts.is_none() {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    /// Requires this same target's positive replay and independently owed posts.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn require_complete_v1(&self) -> Result<(), ReadError> {
        if matches!(self.posts, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    /// Returns saved historical cut DATA before late posts.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn native_cut_v1(&self) -> Result<RootFinalityNativeCutDataV1, ReadError> {
        self.require_body_complete_v1()?;
        self.cut.ok_or(ReadError::ProtectedBoundary)
    }

    // The actual NoApply owner first checks its whole private three-target
    // selection/primaries/posts. This adds no observation and cannot make a
    // refused post or replay successful.
    /// Returns the same saved historical cut DATA after positive late posts.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn completed_native_cut_v1(&self)
        -> Result<RootFinalityNativeCutDataV1, ReadError>
    {
        self.require_complete_v1()?;
        self.cut.ok_or(ReadError::ProtectedBoundary)
    }

    /// Borrows historical DATA from this same real replayed reader.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn readback_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, ReadError> {
        if !matches!(self.replay, Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        self.reader()?.replay_native_v1()
    }

    /// Borrows only this same actual completed readonly model.
    ///
    /// # Errors
    /// Retains the reached native or checked representation failure, or refuses
    /// an incomplete, repeated or mismatched mechanical stage.
    pub fn model_v1(&self) -> Result<&Model, ReadError> {
        if self.reader.is_none() || !matches!(self.replay, Some(Ok(()))) {
            return Err(ReadError::ProtectedBoundary);
        }
        let model = self.model.as_deref().ok_or(ReadError::ProtectedBoundary)?;
        model.require_complete_v1()?;
        Ok(model)
    }

    /// Borrows the actual reader's first retained native failure.
    pub fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.reader.as_ref().and_then(|reader| reader.failure())
    }

    /// Borrows the actual same-model adoption or parent-post failure.
    pub fn model_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.model.as_ref().and_then(|model| model.failure())
    }

    /// Borrows the reached native, model, replay or post failure.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_failure_v1()
            .or_else(|| self.model_failure_v1())
            .or_else(|| self.replay.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.posts.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    fn reader(&self) -> Result<&Reader, ReadError> {
        self.reader.as_deref().ok_or(ReadError::ProtectedBoundary)
    }

    fn reader_mut(&mut self) -> Result<&mut Reader, ReadError> {
        self.reader.as_deref_mut().ok_or(ReadError::ProtectedBoundary)
    }
}
