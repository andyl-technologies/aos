//! Debits genuine normal Boot Source before actual journal representations.
//!
//! Every frame retains its own paid metadata sample and actual lower quote.
//! Native replay uses that captured extent; separately reserved name/witness
//! posts never acquire a fresh Source debit or healthy-writer gate.

use std::cell::RefCell;
use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{FileIdentity, WriterWitnessOriginalsV1};

use super::runtime_deployment_post::RuntimeDeploymentJournalPostOriginalV1;
use super::{
    Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalPreopenReplayExtentV1,
};
use crate::runtime_deployment::{
    MAIN_DIRECTORY_V1, MAIN_NAME, SIDECAR_NAME, VerifiedDeploymentGenesisV1,
};

pub(crate) struct BootJournalReceivingArchiveV1 {
    frames: Vec<Arc<BootJournalReceivingFrameV1>>,
    construction: Option<Arc<BootJournalReceivingFrameV1>>,
    pending: Option<usize>,
}

impl BootJournalReceivingArchiveV1 {
    pub(crate) const fn new() -> Self {
        Self {
            frames: Vec::new(),
            construction: None,
            pending: None,
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Allocation,
    Metadata,
    Extent,
    Quote,
    Forecast,
    Source,
    BeforeNames,
    BeforeWitness,
    BeforeIdentity,
    Body,
    Names(usize),
    Witness,
    Identity,
    Interrupted,
}

struct BootJournalReceivingFrameV1 {
    name: &'static str,
    replay: bool,
    allocation: Option<Result<(), TryReserveError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    quote: Option<Result<ResourceVector, JournalError>>,
    forecast_metadata: Option<std::io::Result<std::fs::Metadata>>,
    forecast: Option<Result<ResourceVector, super::JournalAppendReceivingDemandErrorV1>>,
    source: Option<Result<(), crate::runtime_deployment::RuntimeBootPreparationStartupClosedV1>>,
    before_names: Option<Result<(), JournalError>>,
    before_witness: WriterWitnessOriginalsV1<JournalError>,
    before_witness_result: Option<Result<(), JournalError>>,
    before_identity: Option<Result<FileIdentity, JournalError>>,
    body: Option<JournalError>,
    rooted_post: RuntimeDeploymentJournalPostOriginalV1,
    names: [ProtectedJournalCurrentnessOriginalsV1; 2],
    names_result: [Option<Result<(), JournalError>>; 2],
    witness: WriterWitnessOriginalsV1<JournalError>,
    witness_result: Option<Result<(), JournalError>>,
    identity: Option<Result<FileIdentity, JournalError>>,
    identity_binding: Option<Result<(), JournalError>>,
    entered: [bool; 4],
    first: Option<First>,
    complete: bool,
}

impl BootJournalReceivingFrameV1 {
    fn new(name: &'static str, replay: bool) -> Self {
        Self {
            name,
            replay,
            allocation: None,
            metadata: None,
            extent: None,
            quote: None,
            forecast_metadata: None,
            forecast: None,
            source: None,
            before_names: None,
            before_witness: WriterWitnessOriginalsV1::new(),
            before_witness_result: None,
            before_identity: None,
            body: None,
            rooted_post: if name == MAIN_NAME {
                RuntimeDeploymentJournalPostOriginalV1::main_v1()
            } else {
                RuntimeDeploymentJournalPostOriginalV1::floor_v1()
            },
            names: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            names_result: [None, None],
            witness: WriterWitnessOriginalsV1::new(),
            witness_result: None,
            identity: None,
            identity_binding: None,
            entered: [false; 4],
            first: None,
            complete: false,
        }
    }

    fn construction_demand(entries: usize) -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                std::mem::size_of::<Arc<Self>>()
                    .checked_mul(entries.checked_add(1)?)?
                    .checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<usize>().checked_mul(8)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    fn replay_demand(&self) -> Result<ResourceVector, JournalError> {
        let extent = self
            .extent
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let before = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            std::path::Path::new(MAIN_DIRECTORY_V1),
            self.name,
        )?;
        let rooted_after = self.rooted_post.receiving_demand_v1()?;
        let after = ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(self.name)?;
        let witness = WriterWitnessOriginalsV1::<JournalError>::receiving_footprint_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let witness_bytes = witness
            .memory_bytes
            .checked_mul(2)
            .ok_or(JournalError::JournalTooLarge)?;
        let controls = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(witness_bytes).map_err(|_| JournalError::JournalTooLarge)?,
        );
        let demand = extent
            .dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(before)?
            .checked_add(rooted_after)?
            .checked_add(after)?
            .checked_add(controls)
            .map_err(JournalError::from)?;
        Ok(demand.with(
            D::OutputBytes,
            extent
                .native_bytes
                .checked_add(1)
                .ok_or(JournalError::JournalTooLarge)?,
        ))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Allocation => error(&self.allocation),
            First::Metadata => error(&self.metadata),
            First::Extent => error(&self.extent),
            First::Quote => error(&self.quote),
            First::Forecast => error(&self.forecast_metadata).or_else(|| error(&self.forecast)),
            First::Source => error(&self.source),
            First::BeforeNames => error(&self.before_names),
            First::BeforeWitness => self
                .before_witness
                .failure()
                .or_else(|| error(&self.before_witness_result)),
            First::BeforeIdentity => error(&self.before_identity),
            First::Body => self.body.as_ref().map(|cause| cause as _),
            First::Names(0) => self
                .rooted_post
                .failure()
                .or_else(|| error(&self.names_result[0])),
            First::Names(index) => self.names[index]
                .failure()
                .or_else(|| error(&self.names_result[index])),
            First::Witness => self
                .witness
                .failure()
                .or_else(|| error(&self.witness_result)),
            First::Identity => error(&self.identity).or_else(|| error(&self.identity_binding)),
            First::Interrupted => None,
        }
    }
}

/// Borrows the exact retained receiving/native-post cause from the normal owner.
pub struct BootJournalReceivingFailureOriginalV1 {
    original: Arc<BootJournalReceivingFrameV1>,
}

impl fmt::Debug for BootJournalReceivingFailureOriginalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootJournalReceivingFailureOriginalV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Display for BootJournalReceivingFailureOriginalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.original.failure() {
            Some(cause) => fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("normal Boot journal observation was interrupted"),
        }
    }
}

impl Error for BootJournalReceivingFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

pub(crate) struct BootJournalReceivingPassV1<'owner> {
    archive: &'owner RefCell<BootJournalReceivingArchiveV1>,
    index: usize,
    finished: bool,
}

impl Journal {
    pub(crate) fn admit_boot_file_identity_receiving_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        samples: usize,
    ) -> Result<(), JournalError> {
        if owner.boot_purpose().is_none() {
            return Ok(());
        }
        let sample = aos_sandbox_journal::protected_storage::FileIdentityOriginalsV1::<JournalError>::receiving_footprint_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = sample
            .memory_bytes
            .checked_mul(samples)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        owner
            .admit_boot_journal_representation_v1(Some(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            ))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn admit_boot_model_receiving_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<(), JournalError> {
        if owner.boot_purpose().is_none() {
            return Ok(());
        }
        let encoded = usize::try_from(self.held_materialized_encoding_bytes_v1()?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let demand = super::semantic_receiving::semantic_representation_demand_v1(
            encoded,
            self.native.state().len(),
        )?;
        owner
            .admit_boot_journal_representation_v1(Some(demand))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn admit_boot_named_guard_receiving_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        rooted: bool,
    ) -> Result<(), JournalError> {
        if owner.boot_purpose().is_none() {
            return Ok(());
        }
        let location = self
            .native
            .protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        let demand = if rooted {
            ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                std::path::Path::new(MAIN_DIRECTORY_V1),
                location.name(),
            )?
        } else {
            self.held_names_receiving_demand_v2()?
        };
        let witness = WriterWitnessOriginalsV1::<JournalError>::receiving_footprint_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let demand = demand.checked_add(ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(witness.memory_bytes).map_err(|_| JournalError::JournalTooLarge)?,
        ))?;
        owner
            .admit_boot_journal_representation_v1(Some(demand))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn admit_boot_lock_loan_receiving_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<(), JournalError> {
        if owner.boot_purpose().is_none() {
            return Ok(());
        }
        let names = self.held_names_receiving_demand_v2()?;
        let bytes = std::mem::size_of::<super::ProtectedJournalLockCustodyV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<std::io::Result<std::fs::Metadata>>().checked_mul(2)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let demand = names.checked_add(names)?.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, 1),
        )?;
        owner
            .admit_boot_journal_representation_v1(Some(demand))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn admit_boot_append_receiving_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        transaction: &super::JournalTransaction,
    ) -> Result<(), JournalError> {
        let shapes =
            transaction
                .records()
                .iter()
                .map(|record| aos_sandbox_journal::geometry::RecordShape {
                    key_bytes: record.key().len(),
                    value_bytes: record.value().map(<[u8]>::len),
                });
        self.admit_boot_append_shapes_receiving_v1(owner, std::iter::once(Ok(shapes)))
    }

    pub(crate) fn admit_boot_append_shapes_receiving_v1<I, T>(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
        transactions: I,
    ) -> Result<(), JournalError>
    where
        I: IntoIterator<Item = Result<T, JournalError>>,
        T: ExactSizeIterator<Item = aos_sandbox_journal::geometry::RecordShape>,
    {
        if owner.boot_purpose().is_none() {
            return Ok(());
        }
        let name = match self.native.protected_view().map(|location| location.name()) {
            Some(MAIN_NAME) => MAIN_NAME,
            Some(SIDECAR_NAME) => SIDECAR_NAME,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let Some(mut pass) = self.begin_boot_receiving_frame_v1(owner, name, false)? else {
            return Err(JournalError::ProtectedBoundary);
        };
        let mut bank = pass
            .archive
            .try_borrow_mut()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let frame =
            Arc::get_mut(&mut bank.frames[pass.index]).ok_or(JournalError::ProtectedBoundary)?;
        // The common forecast's real fstat is parked in the paid frame, rather
        // than being misclassified as a pure static quote.
        frame.forecast = Some(self.append_sequence_receiving_demand_retaining_metadata_v7(
            transactions,
            &mut frame.forecast_metadata,
        ));
        if !matches!(frame.forecast, Some(Ok(_))) {
            frame.first.get_or_insert(First::Forecast);
        }
        if let Some(Ok(demand)) = frame.forecast {
            frame.source = Some(owner.admit_boot_journal_representation_v1(Some(demand)));
            if !matches!(frame.source, Some(Ok(()))) {
                frame.first.get_or_insert(First::Source);
            }
        }
        // Only the scalar forecast was entered. The caller has not yet begun
        // an append, so its separate captured append engine owns later posts.
        frame.complete = true;
        let failed = frame.first.is_some();
        bank.pending = None;
        pass.finished = true;
        if failed {
            Err(diagnostic(&bank.frames[pass.index]))
        } else {
            Ok(())
        }
    }

    pub(crate) fn drain_boot_history_after_unwind_once_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<(), JournalError> {
        let Some(archive) = owner.boot_journal_receiving_v1() else {
            return Ok(());
        };
        let index = {
            let bank = archive
                .try_borrow()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let Some(index) = bank.pending else {
                return Ok(());
            };
            let frame = &bank.frames[index];
            if self.native.path().parent() != Some(std::path::Path::new(MAIN_DIRECTORY_V1))
                || self.native.path().file_name() != Some(std::ffi::OsStr::new(frame.name))
            {
                return Ok(());
            }
            index
        };
        finish_posts(archive, index, self)?;
        let bank = archive
            .try_borrow()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if bank.frames[index].first.is_some() {
            return Err(diagnostic(&bank.frames[index]));
        }
        Ok(())
    }

    pub(crate) fn begin_boot_history_receiving_v1<'owner>(
        &self,
        owner: &'owner VerifiedDeploymentGenesisV1<'_>,
        name: &'static str,
    ) -> Result<Option<BootJournalReceivingPassV1<'owner>>, JournalError> {
        self.begin_boot_receiving_frame_v1(owner, name, true)
    }

    fn begin_boot_receiving_frame_v1<'owner>(
        &self,
        owner: &'owner VerifiedDeploymentGenesisV1<'_>,
        name: &'static str,
        replay: bool,
    ) -> Result<Option<BootJournalReceivingPassV1<'owner>>, JournalError> {
        let Some(archive) = owner.boot_journal_receiving_v1() else {
            return Ok(None);
        };
        if name != MAIN_NAME && name != SIDECAR_NAME {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut bank = archive
            .try_borrow_mut()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if bank.pending.is_some() || bank.construction.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        owner
            .admit_boot_journal_representation_v1(BootJournalReceivingFrameV1::construction_demand(
                bank.frames.len(),
            ))
            .map_err(|_| JournalError::ProtectedBoundary)?;
        bank.construction = Some(Arc::new(BootJournalReceivingFrameV1::new(name, replay)));
        let allocation = bank.frames.try_reserve_exact(1);
        let frame = bank
            .construction
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or(JournalError::ProtectedBoundary)?;
        frame.allocation = Some(allocation);
        if matches!(frame.allocation, Some(Err(_))) {
            frame.first = Some(First::Allocation);
            return Err(diagnostic(
                bank.construction
                    .as_ref()
                    .ok_or(JournalError::ProtectedBoundary)?,
            ));
        }
        let index = bank.frames.len();
        let frame = bank
            .construction
            .take()
            .ok_or(JournalError::ProtectedBoundary)?;
        bank.frames.push(frame);
        let frame = Arc::get_mut(&mut bank.frames[index]).ok_or(JournalError::ProtectedBoundary)?;
        // This native scalar metadata entry has already been paid above. Its
        // whole Result remains in the same permanent frame before projection.
        if replay {
            frame.extent = Some(self.held_session_receiving_extent_v1(&mut frame.metadata));
            if matches!(frame.metadata, Some(Err(_))) {
                frame.first = Some(First::Metadata);
            }
            if !matches!(frame.extent, Some(Ok(_))) {
                frame.first.get_or_insert(First::Extent);
            }
            if frame.first.is_none() {
                frame.quote = Some(frame.replay_demand());
                if !matches!(frame.quote, Some(Ok(_))) {
                    frame.first = Some(First::Quote);
                }
            }
            if let Some(Ok(demand)) = frame.quote {
                frame.source = Some(owner.admit_boot_journal_representation_v1(Some(demand)));
                if !matches!(frame.source, Some(Ok(()))) {
                    frame.first.get_or_insert(First::Source);
                }
            }
        }
        if frame.first.is_some() {
            frame.complete = true;
            return Err(diagnostic(&bank.frames[index]));
        }
        bank.pending = Some(index);
        Ok(Some(BootJournalReceivingPassV1 {
            archive,
            index,
            finished: false,
        }))
    }
}

impl BootJournalReceivingPassV1<'_> {
    pub(crate) fn before(&mut self, journal: &Journal) -> Result<FileIdentity, JournalError> {
        let mut bank = self
            .archive
            .try_borrow_mut()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let frame =
            Arc::get_mut(&mut bank.frames[self.index]).ok_or(JournalError::ProtectedBoundary)?;
        frame.before_names = Some(journal.require_protected_named_location(
            std::path::Path::new(MAIN_DIRECTORY_V1),
            frame.name,
            0,
            journal.native.limits(),
        ));
        if !matches!(frame.before_names, Some(Ok(()))) {
            frame.first.get_or_insert(First::BeforeNames);
            return Err(JournalError::ProtectedBoundary);
        }
        frame.before_witness_result = Some(
            journal
                .native
                .read_view()
                .writer_witness_retaining_v1(&mut frame.before_witness),
        );
        if !matches!(frame.before_witness_result, Some(Ok(()))) {
            frame.first.get_or_insert(First::BeforeWitness);
            return Err(JournalError::ProtectedBoundary);
        }
        frame.before_identity = Some(journal.native.file_identity::<JournalError>());
        let physical = match frame.before_identity.as_ref() {
            Some(Ok(physical)) => *physical,
            _ => {
                frame.first.get_or_insert(First::BeforeIdentity);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        if frame
            .metadata
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|value| value.len())
            != Some(physical.byte_len())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(physical)
    }

    pub(crate) fn finish<T>(
        mut self,
        journal: &Journal,
        _owner: &VerifiedDeploymentGenesisV1<'_>,
        result: Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let value = match result {
            Ok(value) => Some(value),
            Err(cause) => {
                let mut bank = self
                    .archive
                    .try_borrow_mut()
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                let frame = Arc::get_mut(&mut bank.frames[self.index])
                    .ok_or(JournalError::ProtectedBoundary)?;
                frame.body = Some(cause);
                frame.first.get_or_insert(First::Body);
                None
            }
        };
        finish_posts(self.archive, self.index, journal)?;
        self.finished = true;
        let bank = self
            .archive
            .try_borrow()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if bank.frames[self.index].first.is_some() {
            return Err(diagnostic(&bank.frames[self.index]));
        }
        value.ok_or(JournalError::ProtectedBoundary)
    }
}

impl Drop for BootJournalReceivingPassV1<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut bank) = self.archive.try_borrow_mut() {
            if let Some(frame) = bank.frames.get_mut(self.index).and_then(Arc::get_mut) {
                if !frame.complete {
                    frame.first.get_or_insert(First::Interrupted);
                }
            }
        }
    }
}

fn finish_posts(
    archive: &RefCell<BootJournalReceivingArchiveV1>,
    index: usize,
    journal: &Journal,
) -> Result<(), JournalError> {
    let mut bank = archive
        .try_borrow_mut()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let frame = Arc::get_mut(&mut bank.frames[index]).ok_or(JournalError::ProtectedBoundary)?;
    if !frame.replay {
        // A scalar append forecast does not enter a replay bracket. Its paid
        // metadata Result stays archived, but it owes no root/name/read posts.
        frame.complete = true;
        bank.pending = None;
        return Ok(());
    }
    for lane in 0..2 {
        if !frame.entered[lane] {
            frame.entered[lane] = true;
            frame.names_result[lane] = Some(if lane == 0 {
                frame.rooted_post.observe_owed_once_v1(journal)
            } else {
                journal.observe_held_names_post_retaining_v1(&mut frame.names[lane])
            });
            if !matches!(frame.names_result[lane], Some(Ok(()))) {
                frame.first.get_or_insert(First::Names(lane));
            }
        } else if frame.names_result[lane].is_none() {
            frame.first.get_or_insert(First::Interrupted);
            if lane == 0 {
                // Resume only unused independent root/name lanes. The lower
                // original skips any native entry interrupted by the unwind.
                frame.names_result[0] = Some(frame.rooted_post.observe_owed_once_v1(journal));
            }
        }
    }
    if !frame.entered[2] {
        frame.entered[2] = true;
        frame.witness_result = Some(
            journal
                .native
                .read_view()
                .writer_witness_retaining_v1(&mut frame.witness)
                .and_then(|()| {
                    match (
                        frame.before_witness.completed_witness(),
                        frame.witness.completed_witness(),
                    ) {
                        (Some(before), Some(after))
                            if before.directory() == after.directory()
                                && before.file() == after.file()
                                && before.lock() == after.lock() =>
                        {
                            Ok(())
                        }
                        _ => Err(JournalError::StaleAuthoritySnapshot),
                    }
                }),
        );
        if !matches!(frame.witness_result, Some(Ok(()))) {
            frame.first.get_or_insert(First::Witness);
        }
    } else if frame.witness_result.is_none() {
        frame.first.get_or_insert(First::Interrupted);
    }
    if !frame.entered[3] {
        frame.entered[3] = true;
        frame.identity = Some(journal.native.file_identity::<JournalError>());
        frame.identity_binding = Some(match (&frame.before_identity, &frame.identity) {
            (Some(Ok(before)), Some(Ok(after))) if before == after => Ok(()),
            _ => Err(JournalError::StaleAuthoritySnapshot),
        });
        if !matches!(frame.identity, Some(Ok(_))) || !matches!(frame.identity_binding, Some(Ok(())))
        {
            frame.first.get_or_insert(First::Identity);
        }
    } else if frame.identity.is_none() {
        frame.first.get_or_insert(First::Interrupted);
    }
    // The genuine outer credential/startup frame independently bookends the
    // complete normal journal body. Owed native posts never fresh-debit or
    // consult the healthy Source latch, including on this unwind path.
    frame.complete = true;
    bank.pending = None;
    Ok(())
}

fn diagnostic(original: &Arc<BootJournalReceivingFrameV1>) -> JournalError {
    JournalError::BootReceivingOriginal(BootJournalReceivingFailureOriginalV1 {
        original: Arc::clone(original),
    })
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

pub(crate) fn boot_history_model_demand_v1(
    history: &[super::runtime_deployment_sidecar_history::RuntimeDeploymentNativeTransactionDataV1],
) -> Result<ResourceVector, JournalError> {
    let mut bytes = 0_u64;
    let mut rows = 0_usize;
    for native in history {
        let transaction = native.transaction();
        let encoded = aos_sandbox_journal::geometry::encoded_transaction_append_bytes(
            transaction
                .records()
                .iter()
                .map(|record| aos_sandbox_journal::geometry::RecordShape {
                    key_bytes: record.key().len(),
                    value_bytes: record.value().map(<[u8]>::len),
                }),
        )?;
        bytes = bytes
            .checked_add(encoded)
            .ok_or(JournalError::JournalTooLarge)?;
        rows = rows
            .checked_add(transaction.records().len())
            .ok_or(JournalError::JournalTooLarge)?;
    }
    super::semantic_receiving::semantic_representation_demand_v1(
        usize::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?,
        rows,
    )
}

pub(crate) fn boot_transaction_model_demand_v1(
    transaction: &super::JournalTransaction,
) -> Result<ResourceVector, JournalError> {
    let encoded =
        aos_sandbox_journal::geometry::encoded_prepared_bytes(transaction.records().iter().map(
            |record| aos_sandbox_journal::geometry::RecordShape {
                key_bytes: record.key().len(),
                value_bytes: record.value().map(<[u8]>::len),
            },
        ))?;
    super::semantic_receiving::semantic_representation_demand_v1(
        encoded,
        transaction.records().len(),
    )
}
