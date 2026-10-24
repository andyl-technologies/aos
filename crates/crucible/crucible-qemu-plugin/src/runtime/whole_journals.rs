//! Constructor-preallocated immutable stage and compute body ownership.
//!
//! Every native allocation pointer names an actual stable original journal slot.
//! Lookup compares that pointer with the preowned slot before any use; it never
//! dereferences caller-provided allocation memory. No retirement recycles a slot
//! or clears request, result, receipt, consumed ACK or partial failed storage.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use crucible_qemu_protocol::whole_control::{
    body::{WholeAcknowledgement, WholeRequest, WholeResult},
    staged::{
        StagedControlProfile,
        body::{StageCommit, StageInventory, StageReceipt},
    },
};
use crucible_qemu_shmem::SelectedRingCompletion;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WholeJournalError {
    Profile,
    Allocation,
    Capacity,
    Ownership,
    Process,
    Correlation,
    Missing,
}

/// Retains all preallocated bytes before publishing their immutable original body.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
struct OriginalBody {
    private: Mutex<Option<Box<[u8]>>>,
    retained: OnceLock<Box<[u8]>>,
    extent: AtomicUsize,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
impl OriginalBody {
    fn new(capacity: usize) -> Result<Self, WholeJournalError> {
        let mut body = Vec::new();
        body.try_reserve_exact(capacity)
            .map_err(|_| WholeJournalError::Allocation)?;
        body.resize(capacity, 0);
        Ok(Self {
            private: Mutex::new(Some(body.into_boxed_slice())),
            retained: OnceLock::new(),
            extent: AtomicUsize::new(0),
        })
    }

    fn retain(&self, original: &[u8]) -> Result<(), WholeJournalError> {
        if let Some(body) = self.retained.get() {
            return if self.extent.load(Ordering::Acquire) == original.len()
                && &body[..original.len()] == original
            {
                Ok(())
            } else {
                Err(WholeJournalError::Correlation)
            };
        }
        let mut private = self
            .private
            .try_lock()
            .map_err(|_| WholeJournalError::Ownership)?;
        let backing = private.as_mut().ok_or(WholeJournalError::Ownership)?;
        if original.len() > backing.len() {
            return Err(WholeJournalError::Capacity);
        }
        backing[..original.len()].copy_from_slice(original);
        let backing = private.take().ok_or(WholeJournalError::Ownership)?;
        self.extent.store(original.len(), Ordering::Release);
        if let Err(backing) = self.retained.set(backing) {
            // A single original slot has only one publisher. Retain a refused
            // competing backing in the same slot rather than dropping bytes.
            *private = Some(backing);
            return Err(WholeJournalError::Ownership);
        }
        Ok(())
    }

    fn body(&self) -> Result<&[u8], WholeJournalError> {
        let body = self.retained.get().ok_or(WholeJournalError::Missing)?;
        Ok(&body[..self.extent.load(Ordering::Acquire)])
    }
}

/// Owns the same stage body, original native receipt and both commit bodies.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(crate) struct OriginalStageJournal {
    body: OriginalBody,
    receipt: OriginalBody,
    commit: OriginalBody,
    consumed_commit: OriginalBody,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
impl OriginalStageJournal {
    pub(crate) fn retain_body(&self, body: &[u8]) -> Result<(), WholeJournalError> {
        StageInventory::decode(body).map_err(|_| WholeJournalError::Correlation)?;
        self.body.retain(body)
    }

    pub(crate) fn body(&self) -> Result<StageInventory<'_>, WholeJournalError> {
        StageInventory::decode(self.body.body()?).map_err(|_| WholeJournalError::Correlation)
    }

    pub(crate) fn retain_receipt(
        &self,
        body: &[u8],
        plan_digest: [u8; 32],
    ) -> Result<(), WholeJournalError> {
        let receipt = StageReceipt::decode(body).map_err(|_| WholeJournalError::Correlation)?;
        receipt
            .validate_against(&self.body()?, plan_digest)
            .map_err(|_| WholeJournalError::Correlation)?;
        self.receipt.retain(body)
    }

    pub(crate) fn receipt_body(&self) -> Result<&[u8], WholeJournalError> {
        self.receipt.body()
    }

    pub(crate) fn retain_commit(
        &self,
        body: &[u8],
        plan_digest: [u8; 32],
    ) -> Result<(), WholeJournalError> {
        let stage = self.body()?;
        let receipt = StageReceipt::decode(self.receipt.body()?)
            .map_err(|_| WholeJournalError::Correlation)?;
        let expected = StageCommit::for_receipt(&stage, &receipt, plan_digest)
            .map_err(|_| WholeJournalError::Correlation)?;
        if StageCommit::decode(body).map_err(|_| WholeJournalError::Correlation)? != expected {
            return Err(WholeJournalError::Correlation);
        }
        self.commit.retain(body)
    }

    pub(crate) fn commit_body(&self) -> Result<&[u8], WholeJournalError> {
        self.commit.body()
    }

    pub(crate) fn retain_consumed_commit(&self, body: &[u8]) -> Result<(), WholeJournalError> {
        if body != self.commit.body()? {
            return Err(WholeJournalError::Correlation);
        }
        self.consumed_commit.retain(body)
    }

    pub(crate) fn consumed_commit_body(&self) -> Result<&[u8], WholeJournalError> {
        self.consumed_commit.body()
    }
}

/// Owns the complete original native compute bodies and local ring completion.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
pub(crate) struct OriginalComputeJournal {
    request: OriginalBody,
    result: OriginalBody,
    acknowledgement: OriginalBody,
    consumed_acknowledgement: OriginalBody,
    pub(crate) ring_completion: Mutex<Option<SelectedRingCompletion>>,
    uncertain: AtomicBool,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )
)]
impl OriginalComputeJournal {
    pub(crate) fn refuse(&self) {
        self.uncertain.store(true, Ordering::Release);
    }

    pub(crate) fn is_uncertain(&self) -> bool {
        self.uncertain.load(Ordering::Acquire)
    }

    pub(crate) fn retain_request(&self, body: &[u8]) -> Result<(), WholeJournalError> {
        WholeRequest::decode_staged(body).map_err(|_| WholeJournalError::Correlation)?;
        self.request.retain(body)
    }

    pub(crate) fn request_body(&self) -> Result<&[u8], WholeJournalError> {
        self.request.body()
    }

    pub(crate) fn retain_result(&self, body: &[u8]) -> Result<(), WholeJournalError> {
        let result = WholeResult::decode(body).map_err(|_| WholeJournalError::Correlation)?;
        result
            .validate_against_staged(self.request.body()?)
            .map_err(|_| WholeJournalError::Correlation)?;
        self.result.retain(body)
    }

    pub(crate) fn result_body(&self) -> Result<&[u8], WholeJournalError> {
        self.result.body()
    }

    pub(crate) fn retain_acknowledgement(&self, body: &[u8]) -> Result<(), WholeJournalError> {
        if self.is_uncertain() {
            return Err(WholeJournalError::Correlation);
        }
        let ack = WholeAcknowledgement::decode(body).map_err(|_| WholeJournalError::Correlation)?;
        ack.validate_against_staged(self.request.body()?, self.result.body()?)
            .map_err(|_| WholeJournalError::Correlation)?;
        self.acknowledgement.retain(body)
    }

    pub(crate) fn acknowledgement_body(&self) -> Result<&[u8], WholeJournalError> {
        self.acknowledgement.body()
    }

    pub(crate) fn retain_consumed_acknowledgement(
        &self,
        body: &[u8],
    ) -> Result<(), WholeJournalError> {
        if self.is_uncertain() || body != self.acknowledgement.body()? {
            return Err(WholeJournalError::Correlation);
        }
        self.consumed_acknowledgement.retain(body)
    }

    /// Matches all complete original bodies before separate native retirement.
    pub(crate) fn validate_native_retirement(
        &self,
        request: &[u8],
        result: &[u8],
        consumed: &[u8],
    ) -> Result<(), WholeJournalError> {
        if self.is_uncertain()
            || request != self.request.body()?
            || result != self.result.body()?
            || consumed != self.consumed_acknowledgement.body()?
        {
            return Err(WholeJournalError::Correlation);
        }
        WholeAcknowledgement::decode(consumed)
            .map_err(|_| WholeJournalError::Correlation)?
            .validate_against_staged(request, result)
            .map_err(|_| WholeJournalError::Correlation)
    }
}

/// Retains independently indexed stable stage and compute allocations forever.
pub(crate) struct WholeJournals {
    stages: Box<[OriginalStageJournal]>,
    computes: Box<[OriginalComputeJournal]>,
    process: u32,
    retained_byte_count: u64,
}

impl WholeJournals {
    pub(crate) fn new(
        profile: &StagedControlProfile,
        other_owned_bytes: u64,
    ) -> Result<Self, WholeJournalError> {
        profile.validate().map_err(|_| WholeJournalError::Profile)?;
        let compute_bytes = (std::mem::size_of::<OriginalComputeJournal>() as u64)
            .checked_add(2 * u64::from(profile.compute.body_byte_limit) + 2 * 128)
            .ok_or(WholeJournalError::Capacity)?;
        let stage_bytes = (std::mem::size_of::<OriginalStageJournal>() as u64)
            .checked_add(u64::from(profile.stage_body_byte_limit) + 256 + 2 * 128)
            .ok_or(WholeJournalError::Capacity)?;
        let total = compute_bytes
            .checked_mul(u64::from(profile.compute.operation_capacity))
            .and_then(|bytes| {
                stage_bytes
                    .checked_mul(u64::from(profile.input_stage_limit))
                    .and_then(|stages| bytes.checked_add(stages))
            })
            .and_then(|bytes| bytes.checked_add(other_owned_bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .ok_or(WholeJournalError::Capacity)?;
        if total > profile.compute.provider_history_byte_limit {
            return Err(WholeJournalError::Capacity);
        }

        let mut stages = Vec::new();
        stages
            .try_reserve_exact(profile.input_stage_limit as usize)
            .map_err(|_| WholeJournalError::Allocation)?;
        for _ in 0..profile.input_stage_limit {
            stages.push(OriginalStageJournal {
                body: OriginalBody::new(profile.stage_body_byte_limit as usize)?,
                receipt: OriginalBody::new(256)?,
                commit: OriginalBody::new(128)?,
                consumed_commit: OriginalBody::new(128)?,
            });
        }
        let mut computes = Vec::new();
        computes
            .try_reserve_exact(profile.compute.operation_capacity as usize)
            .map_err(|_| WholeJournalError::Allocation)?;
        for _ in 0..profile.compute.operation_capacity {
            computes.push(OriginalComputeJournal {
                request: OriginalBody::new(profile.compute.body_byte_limit as usize)?,
                result: OriginalBody::new(profile.compute.body_byte_limit as usize)?,
                acknowledgement: OriginalBody::new(128)?,
                consumed_acknowledgement: OriginalBody::new(128)?,
                ring_completion: Mutex::new(None),
                uncertain: AtomicBool::new(false),
            });
        }
        Ok(Self {
            stages: stages.into_boxed_slice(),
            computes: computes.into_boxed_slice(),
            process: std::process::id(),
            retained_byte_count: total,
        })
    }

    pub(crate) fn stage(&self, sequence: u64) -> Result<&OriginalStageJournal, WholeJournalError> {
        self.current_process()?;
        let index = sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(WholeJournalError::Missing)?;
        self.stages.get(index).ok_or(WholeJournalError::Missing)
    }

    pub(crate) fn compute(
        &self,
        sequence: u64,
    ) -> Result<&OriginalComputeJournal, WholeJournalError> {
        self.current_process()?;
        let index = sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(WholeJournalError::Missing)?;
        self.computes.get(index).ok_or(WholeJournalError::Missing)
    }

    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn stage_allocation(
        &self,
        sequence: u64,
        allocation: *mut c_void,
    ) -> Result<&OriginalStageJournal, WholeJournalError> {
        let original = self.stage(sequence)?;
        if std::ptr::from_ref(original).cast_mut().cast::<c_void>() != allocation {
            return Err(WholeJournalError::Ownership);
        }
        Ok(original)
    }

    pub(crate) fn compute_allocation(
        &self,
        sequence: u64,
        allocation: *mut c_void,
    ) -> Result<&OriginalComputeJournal, WholeJournalError> {
        let original = self.compute(sequence)?;
        if std::ptr::from_ref(original).cast_mut().cast::<c_void>() != allocation {
            return Err(WholeJournalError::Ownership);
        }
        Ok(original)
    }

    pub(crate) fn retained_byte_count(&self) -> u64 {
        self.retained_byte_count
    }

    fn current_process(&self) -> Result<(), WholeJournalError> {
        if std::process::id() != self.process {
            return Err(WholeJournalError::Process);
        }
        Ok(())
    }
}
