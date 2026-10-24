//! Retains original edition-two stage and compute exchanges on one Unix stream.
//!
//! The actor keeps every complete and partial byte until authenticated world
//! retirement. Its codec checks correlate native records; they grant no Ready
//! capability. The owning facade authenticates the original process, mapping,
//! native preparation, producer lineage and runtime grants independently.
//!
//! ```text
//! StageInventory -> StageReceipt -> StageCommit -> ConsumedStageCommit
//! ExecutionRequest -> ExecutionResult -> ExecutionAcknowledgement -> consumed ACK
//! ```

#[path = "native_staged_control/storage.rs"]
mod storage;

use std::io;
use std::os::fd::AsFd;

use crucible_qemu_protocol::bounded_setup::{read_once, write_once};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_qemu_protocol::whole_control::body::{
    WholeAcknowledgement, WholeOperationQuota, WholeRequest, WholeResult,
};
use crucible_qemu_protocol::whole_control::staged::administrative::AdministrativeIoBudget;
use crucible_qemu_protocol::whole_control::staged::plan_ack::QueuePlanAcknowledgement;
use crucible_qemu_protocol::whole_control::staged::queue_plan::QueuePlan;

use crucible_qemu_protocol::whole_control::staged::body::{
    StageCommit, StageInventory, StageReceipt, StageReferences,
};
use crucible_qemu_protocol::whole_control::staged::{
    STAGE_RECEIPT_BYTES, StagedControlProfile, StagedFrameKind,
    decode_frame_header as decode_staged_frame_header,
    encode_frame_header as encode_staged_frame_header,
};
use crucible_qemu_protocol::whole_control::{WHOLE_ACK_BYTES, WHOLE_FRAME_HEADER_BYTES};

use crate::native_whole_control::NativeWholeControlError;

#[path = "native_staged_control/initial_io.rs"]
mod initial_io;
use initial_io::InitialIoJournal;
pub(crate) use initial_io::InitialWholeControlSocket;

const QUARANTINE_LIMIT: usize = 4096;
static CUSTODY_OWNERS: AtomicUsize = AtomicUsize::new(0);

struct Exchange {
    original: Vec<u8>,
    original_extent: usize,
    sent: usize,
    response: Vec<u8>,
    response_extent: usize,
    offered_commit: [u8; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
    commit_offered: bool,
    commit_sent: usize,
    consumed_commit: [u8; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
    committed: bool,
}

struct StageHistory {
    exchange: Exchange,
    // Record ownership is spent before the compute original can be transmitted.
    // Failure cannot refund records or admit another operation using them.
    selected: Vec<bool>,
}

#[derive(Clone, Copy)]
enum ActiveExchange {
    Stage(usize),
    Compute(usize),
}

struct Custody {
    socket: UnixStream,
    plan: Exchange,
    source_ready: Exchange,
    stages: Vec<StageHistory>,
    computes: Vec<Exchange>,
    // Scratch retains an incomplete or conflicting peer frame independently of
    // the immutable complete historical slot it would otherwise overwrite.
    scratch: Vec<u8>,
    received: usize,
    incoming_extent: usize,
    incoming_kind: Option<StagedFrameKind>,
    active: Option<ActiveExchange>,
    stage_count: usize,
    compute_count: usize,
    charged: WholeOperationQuota,
    administrative: AdministrativeIoBudget,
    initial: Option<InitialIoJournal>,
}

/// Owns independently indexed stage and compute journals on the original socket.
///
/// Construction reserves finite historical storage and a passive quarantine
/// owner before adopting the socket. No stage or compute callback allocates
/// backing, renews credits or replaces an original allocation.
pub struct NativeStagedControlTransport {
    custody: Option<Box<Custody>>,
    profile: StagedControlProfile,
    process: u32,
    epoch: Option<u64>,
    queue_plan_digest: [u8; 32],
    refused: bool,
    used: bool,
}

impl NativeStagedControlTransport {
    /// Checks complete original initial-and-staged backing before allocation.
    ///
    /// # Errors
    /// Refuses invalid profile geometry or overflow in retained actor storage.
    pub(crate) fn required_setup_backing_bytes(
        profile: &StagedControlProfile,
    ) -> Result<usize, NativeWholeControlError> {
        profile.validate()?;
        storage::required_bytes(profile, true)
    }

    /// Reserves complete histories before reading the original source queue plan.
    ///
    /// The whole plan and its acknowledgement remain on this same original
    /// socket. Their correlation does not qualify source readiness.
    ///
    /// # Errors
    /// Rejects invalid geometry, expired deadline, exhausted quarantine capacity,
    /// inadequate historical storage or unavailable socket configuration.
    pub fn new(
        socket: UnixStream,
        profile: StagedControlProfile,
    ) -> Result<Self, NativeWholeControlError> {
        Self::new_inner(socket, profile, false)
    }

    /// Reserves one original initial-and-staged actor before child execution.
    ///
    /// # Errors
    /// Rejects invalid geometry or insufficient combined initial/staged backing.
    /// No bytes are read and no source readiness is established here.
    pub(crate) fn new_for_setup(
        socket: UnixStream,
        profile: StagedControlProfile,
    ) -> Result<InitialWholeControlSocket, NativeWholeControlError> {
        Self::new_inner(socket, profile, true).map(InitialWholeControlSocket::from_actor)
    }

    fn new_inner(
        socket: UnixStream,
        profile: StagedControlProfile,
        initial_protocol: bool,
    ) -> Result<Self, NativeWholeControlError> {
        profile.validate()?;
        if monotonic_ns()? >= profile.compute.deadline_monotonic_ns {
            return Err(NativeWholeControlError::Custody);
        }
        let compute_extent = WHOLE_FRAME_HEADER_BYTES + profile.compute.body_byte_limit as usize;
        let stage_extent = WHOLE_FRAME_HEADER_BYTES + profile.stage_body_byte_limit as usize;
        let record_capacity = profile.stage_body_byte_limit as usize / 216;
        let total = storage::required_bytes(&profile, initial_protocol)?;
        if total as u64 > profile.compute.provider_history_byte_limit {
            return Err(NativeWholeControlError::Allocation);
        }

        let mut stages = Vec::new();
        stages
            .try_reserve_exact(profile.input_stage_limit as usize)
            .map_err(|_| NativeWholeControlError::Allocation)?;
        for _ in 0..profile.input_stage_limit {
            let mut selected = Vec::new();
            selected
                .try_reserve_exact(record_capacity)
                .map_err(|_| NativeWholeControlError::Allocation)?;
            selected.resize(record_capacity, false);
            stages.push(StageHistory {
                exchange: Exchange::new(
                    stage_extent,
                    WHOLE_FRAME_HEADER_BYTES + STAGE_RECEIPT_BYTES,
                )?,
                selected,
            });
        }
        let mut computes = Vec::new();
        computes
            .try_reserve_exact(profile.compute.operation_capacity as usize)
            .map_err(|_| NativeWholeControlError::Allocation)?;
        for _ in 0..profile.compute.operation_capacity {
            computes.push(Exchange::new(compute_extent, compute_extent)?);
        }
        let scratch = allocated(stage_extent.max(compute_extent))?;
        let plan = Exchange::new(compute_extent, 0)?;
        let source_ready = Exchange::new(compute_extent, 0)?;
        let initial = if initial_protocol {
            Some(InitialIoJournal::new(&profile)?)
        } else {
            None
        };
        socket.set_nonblocking(true)?;

        CUSTODY_OWNERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < QUARANTINE_LIMIT).then_some(count + 1)
            })
            .map_err(|_| NativeWholeControlError::Allocation)?;
        Ok(Self {
            custody: Some(Box::new(Custody {
                socket,
                plan,
                source_ready,
                stages,
                computes,
                scratch,
                received: 0,
                incoming_extent: 0,
                incoming_kind: None,
                active: None,
                stage_count: 0,
                compute_count: 0,
                charged: WholeOperationQuota {
                    input_bytes: 0,
                    input_records: 0,
                    output_bytes: 0,
                    output_records: 0,
                    cpu_retirements: 0,
                    event_steps: 0,
                },
                administrative: AdministrativeIoBudget::new(&profile)
                    .map_err(|_| NativeWholeControlError::Exhausted)?,
                initial,
            })),
            profile,
            process: std::process::id(),
            epoch: None,
            queue_plan_digest: [0; 32],
            refused: false,
            used: false,
        })
    }

    /// Returns preowned source-readiness backing without granting readiness.
    ///
    /// The complete body ceiling and both acknowledgement frames were reserved
    /// in the original constructor. No source-issued receipt is implied by this
    /// capacity, and no later schema transition can renew or resize it.
    ///
    /// # Errors
    /// Refuses missing original socket custody.
    pub fn source_ready_backing_bytes(&self) -> Result<usize, NativeWholeControlError> {
        let custody = self
            .custody
            .as_ref()
            .ok_or(NativeWholeControlError::Custody)?;
        let ready = &custody.source_ready;
        ready
            .original
            .len()
            .checked_add(ready.offered_commit.len())
            .and_then(|bytes| bytes.checked_add(ready.consumed_commit.len()))
            .ok_or(NativeWholeControlError::Allocation)
    }

    /// Retains the complete original stage without delivering any modeled input.
    ///
    /// # Errors
    /// Rejects changed retries, foreign scope or epoch, overlapping exchanges,
    /// exhausted stage slots or aggregate original input credit.
    pub fn retain_stage(&mut self, body: &[u8]) -> Result<(), NativeWholeControlError> {
        let result = self.retain_stage_inner(body);
        if let Err(error) = result {
            return self.refuse(error);
        }
        Ok(())
    }

    fn retain_stage_inner(&mut self, body: &[u8]) -> Result<(), NativeWholeControlError> {
        self.live()?;
        let limits = self.profile.compute.clone();
        let stage = StageInventory::decode(body)?;
        let index = usize::try_from(stage.stage_sequence - 1)
            .map_err(|_| NativeWholeControlError::Custody)?;
        self.validate_scope(stage.scope, stage.native_epoch)?;
        let custody = self.custody_mut()?;
        if let Some(original) = custody.stages.get(index)
            && index < custody.stage_count
        {
            return if original.exchange.body() == body {
                Ok(())
            } else {
                self.refuse(NativeWholeControlError::Custody)
            };
        }
        if index != custody.stage_count
            || index >= custody.stages.len()
            || custody.active.is_some()
            || custody.plan.original_extent == 0
            || custody.plan.commit_sent != custody.plan.offered_commit.len()
        {
            return self.refuse(NativeWholeControlError::Custody);
        }
        let plan = QueuePlan::decode(custody.plan.body())?;
        for record in stage.queue_inventory.records() {
            record.validate_region_spans(plan.region_byte_length)?;
            if !plan.roles().any(|role| {
                role.role == record.role
                    && role.ring_index == record.ring_index
                    && role.node == record.node
                    && role.port == record.port
                    && role.lane == record.lane
                    && role.source_slot == record.source_slot
                    && role.target_slot == record.target_slot
                    && role.generation == record.ring_generation
                    && role.capacity == record.capacity
                    && role.header_offset == record.ring_offset
                    && role.entries_offset == record.entries_offset
                    && role.transport_epoch == record.transport_epoch
            }) {
                return self.refuse(NativeWholeControlError::Custody);
            }
        }
        if stage.queue_inventory.record_count() as usize > custody.stages[index].selected.len() {
            return self.refuse(NativeWholeControlError::Allocation);
        }
        let input_bytes = charged(
            custody.charged.input_bytes,
            stage.payload_byte_count()?,
            limits.input_byte_limit,
        )?;
        let input_records = charged(
            custody.charged.input_records,
            u64::from(stage.queue_inventory.record_count()),
            limits.input_record_limit,
        )?;
        let header =
            encode_staged_frame_header(StagedFrameKind::StageInventory, body.len(), &self.profile)?;
        let custody = self.custody_mut()?;
        custody.stages[index].exchange.retain(&header, body)?;
        custody.charged.input_bytes = input_bytes;
        custody.charged.input_records = input_records;
        custody.stage_count += 1;
        custody.active = Some(ActiveExchange::Stage(index));
        self.used = true;
        Ok(())
    }

    /// Retains compute permission only after every referenced stage commit was consumed.
    ///
    /// # Errors
    /// Rejects uncommitted or foreign originals, reused or overlapping record
    /// ranges, changed retries, invalid sequencing or exhausted compute credit.
    pub fn retain_compute(&mut self, body: &[u8]) -> Result<(), NativeWholeControlError> {
        let result = self.retain_compute_inner(body);
        if let Err(error) = result {
            return self.refuse(error);
        }
        Ok(())
    }

    fn retain_compute_inner(&mut self, body: &[u8]) -> Result<(), NativeWholeControlError> {
        self.live()?;
        let limits = self.profile.compute.clone();
        let request = WholeRequest::decode_staged(body)?;
        self.validate_scope(request.scope, request.epoch)?;
        let index =
            usize::try_from(request.sequence - 1).map_err(|_| NativeWholeControlError::Custody)?;
        let custody = self.custody_mut()?;
        if let Some(original) = custody.computes.get(index)
            && index < custody.compute_count
        {
            return if original.body() == body {
                Ok(())
            } else {
                self.refuse(NativeWholeControlError::Custody)
            };
        }
        if index != custody.compute_count
            || index >= custody.computes.len()
            || custody.active.is_some()
        {
            return self.refuse(NativeWholeControlError::Custody);
        }
        let references = StageReferences::decode(request.input_inventory)?;
        for reference in references.records() {
            let stage_index = usize::try_from(reference.stage_sequence - 1)
                .map_err(|_| NativeWholeControlError::Custody)?;
            if stage_index >= custody.stage_count {
                return self.refuse(NativeWholeControlError::Custody);
            }
            let original = custody
                .stages
                .get(stage_index)
                .ok_or(NativeWholeControlError::Custody)?;
            let stage = StageInventory::decode(original.exchange.body())?;
            let end = reference.first_record + reference.record_count;
            if stage
                .queue_inventory
                .records()
                .skip(reference.first_record as usize)
                .take(reference.record_count as usize)
                .any(|record| {
                    record.time_ps < request.start_ps || record.time_ps >= request.limit_ps
                })
            {
                return self.refuse(NativeWholeControlError::Custody);
            }
            if !original.exchange.committed
                || stage.digest() != reference.stage_body_digest
                || end > stage.queue_inventory.record_count()
                || original.selected[reference.first_record as usize..end as usize]
                    .iter()
                    .any(|used| *used)
                || references
                    .records()
                    .filter(|other| {
                        other.stage_sequence == reference.stage_sequence
                            && other.first_record < end
                            && reference.first_record < other.first_record + other.record_count
                    })
                    .count()
                    != 1
            {
                return self.refuse(NativeWholeControlError::Custody);
            }
        }
        let offered = request.quota;
        let charged_quota = WholeOperationQuota {
            input_bytes: custody.charged.input_bytes,
            input_records: custody.charged.input_records,
            output_bytes: charged(
                custody.charged.output_bytes,
                offered.output_bytes,
                limits.output_byte_limit,
            )?,
            output_records: charged(
                custody.charged.output_records,
                offered.output_records,
                limits.output_record_limit,
            )?,
            cpu_retirements: charged(
                custody.charged.cpu_retirements,
                offered.cpu_retirements,
                limits.cpu_retirement_limit,
            )?,
            event_steps: charged(
                custody.charged.event_steps,
                offered.event_steps,
                limits.event_step_limit,
            )?,
        };
        let header = encode_staged_frame_header(
            StagedFrameKind::ExecutionRequest,
            body.len(),
            &self.profile,
        )?;
        let custody = self.custody_mut()?;
        custody.computes[index].retain(&header, body)?;
        for reference in references.records() {
            let stage_index = usize::try_from(reference.stage_sequence - 1)
                .map_err(|_| NativeWholeControlError::Custody)?;
            let end = reference.first_record + reference.record_count;
            custody.stages[stage_index].selected[reference.first_record as usize..end as usize]
                .fill(true);
        }
        custody.charged = charged_quota;
        custody.compute_count += 1;
        custody.active = Some(ActiveExchange::Compute(index));
        self.used = true;
        Ok(())
    }

    /// Offers one physical prefix from the immutable active original.
    ///
    /// # Errors
    /// Refuses absent exchange, changed process, socket failures or exhausted
    /// lifetime administrative attempts, offered bytes or deadline.
    pub fn transmit_original(&mut self) -> Result<bool, NativeWholeControlError> {
        self.transmit(false)
    }

    /// Offers the exact stage commit or execution ACK for a retained native reply.
    ///
    /// # Errors
    /// Refuses missing native replies or exhausted physical transport credit.
    /// Sending alone never marks native custody consumed.
    pub fn transmit_commit(&mut self) -> Result<bool, NativeWholeControlError> {
        match self.transmit_commit_inner() {
            Ok(complete) => Ok(complete),
            Err(error) => self.refuse(error),
        }
    }

    fn transmit_commit_inner(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let plan_digest = self.queue_plan_digest;
        let custody = self.custody_mut()?;
        let active = custody.active.ok_or(NativeWholeControlError::Custody)?;
        let exchange = custody.exchange_mut(active);
        if exchange.response_extent == 0 {
            return Err(NativeWholeControlError::Custody);
        }
        if !exchange.commit_offered {
            let (kind, body) = match active {
                ActiveExchange::Stage(_) => {
                    let stage = StageInventory::decode(exchange.body())?;
                    let receipt = StageReceipt::decode(exchange.response_body())?;
                    (
                        StagedFrameKind::StageCommit,
                        StageCommit::for_receipt(&stage, &receipt, plan_digest)?.encode()?,
                    )
                }
                ActiveExchange::Compute(_) => (
                    StagedFrameKind::ExecutionAcknowledgement,
                    WholeAcknowledgement::for_complete_staged(
                        exchange.body(),
                        exchange.response_body(),
                    )?
                    .encode()?,
                ),
            };
            let header = encode_staged_frame_header(kind, WHOLE_ACK_BYTES, &self.profile)?;
            let exchange = self.custody_mut()?.exchange_mut(active);
            exchange.offered_commit[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            exchange.offered_commit[WHOLE_FRAME_HEADER_BYTES..].copy_from_slice(&body);
            exchange.commit_offered = true;
        }
        self.transmit(true)
    }

    /// Reads one physical prefix without overwriting complete historical records.
    ///
    /// # Errors
    /// Refuses unsolicited, malformed or changed replies, early consumed commits,
    /// foreign processes or exhausted physical credit. All partial bytes remain
    /// owned even when the actor refuses further work.
    pub fn poll_original(&mut self) -> Result<bool, NativeWholeControlError> {
        match self.poll_original_inner() {
            Ok(complete) => Ok(complete),
            Err(error) => self.refuse(error),
        }
    }

    fn poll_original_inner(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let custody = self
            .custody
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        if let Some(active) = custody.active {
            let exchange = custody.exchange(active);
            if exchange.sent != exchange.original_extent {
                return self.refuse(NativeWholeControlError::Custody);
            }
        } else if custody.plan.original_extent != 0 {
            return Err(NativeWholeControlError::Custody);
        }
        self.used = true;
        let extent = if custody.received < WHOLE_FRAME_HEADER_BYTES {
            WHOLE_FRAME_HEADER_BYTES
        } else {
            custody.incoming_extent
        };
        let progress = read_once(
            custody.socket.as_fd(),
            &mut custody.scratch[custody.received..extent],
            &mut custody.administrative,
            monotonic_ns()?,
        )
        .map_err(io::Error::other)?;
        if progress.peer_closed {
            return self.refuse(
                io::Error::new(io::ErrorKind::UnexpectedEof, "original staged peer closed").into(),
            );
        }
        if progress.retryable {
            return Ok(false);
        }
        custody.received += progress.actual_bytes;
        if custody.incoming_kind.is_none() && custody.received == WHOLE_FRAME_HEADER_BYTES {
            let (kind, body_extent) = decode_staged_frame_header(
                &custody.scratch[..WHOLE_FRAME_HEADER_BYTES],
                &self.profile,
            )?;
            custody.incoming_extent = WHOLE_FRAME_HEADER_BYTES + body_extent;
            custody.incoming_kind = Some(kind);
            return Ok(false);
        }
        if custody.received != custody.incoming_extent {
            return Ok(false);
        }
        let result = if let Some(active) = custody.active {
            self.accept_complete(active)
        } else {
            self.accept_plan()
        };
        if let Err(error) = result {
            return self.refuse(error);
        }
        let custody = self.custody_mut()?;
        custody.received = 0;
        custody.incoming_extent = 0;
        custody.incoming_kind = None;
        Ok(true)
    }

    /// Borrows the entire original native queue plan retained on this socket.
    pub fn original_queue_plan(&self) -> Option<&[u8]> {
        let plan = &self.custody.as_ref()?.plan;
        (plan.original_extent != 0).then(|| plan.body())
    }

    /// Offers one prefix of the exact original plan acknowledgement.
    ///
    /// # Errors
    /// Refuses a missing plan, exhausted physical credits or a socket failure.
    /// Completing this write permits staging and conveys no Ready capability.
    pub fn transmit_plan_acknowledgement(&mut self) -> Result<bool, NativeWholeControlError> {
        match self.transmit_plan_acknowledgement_inner() {
            Ok(complete) => Ok(complete),
            Err(error) => self.refuse(error),
        }
    }

    fn transmit_plan_acknowledgement_inner(&mut self) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let custody = self
            .custody
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        if custody.plan.original_extent == 0 || custody.active.is_some() {
            return Err(NativeWholeControlError::Custody);
        }
        let plan = QueuePlan::decode(custody.plan.body())?;
        if !custody.plan.commit_offered {
            let body = QueuePlanAcknowledgement::for_plan(&plan, &self.profile)?.encode()?;
            let header = encode_staged_frame_header(
                StagedFrameKind::QueuePlanAcknowledgement,
                WHOLE_ACK_BYTES,
                &self.profile,
            )?;
            custody.plan.offered_commit[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            custody.plan.offered_commit[WHOLE_FRAME_HEADER_BYTES..].copy_from_slice(&body);
            custody.plan.commit_offered = true;
        }
        let extent = custody.plan.offered_commit.len();
        let sent = custody.plan.commit_sent;
        if sent == extent {
            return Ok(true);
        }
        let progress = write_once(
            custody.socket.as_fd(),
            &custody.plan.offered_commit[sent..extent],
            &mut custody.administrative,
            monotonic_ns()?,
        )
        .map_err(io::Error::other)?;
        if progress.peer_closed {
            return self.refuse(
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original plan ACK write returned zero",
                )
                .into(),
            );
        }
        if progress.retryable {
            return Ok(false);
        }
        let count = progress.actual_bytes;
        custody.plan.commit_sent += count;
        Ok(custody.plan.commit_sent == extent)
    }

    fn accept_plan(&mut self) -> Result<(), NativeWholeControlError> {
        let custody = self
            .custody
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        if custody.incoming_kind != Some(StagedFrameKind::QueuePlan) {
            return Err(NativeWholeControlError::Custody);
        }
        let extent = custody.incoming_extent;
        let plan = QueuePlan::decode(&custody.scratch[WHOLE_FRAME_HEADER_BYTES..extent])?;
        if plan.scope != self.profile.compute.scope {
            return Err(NativeWholeControlError::Custody);
        }
        self.epoch = Some(plan.native_epoch);
        self.queue_plan_digest = plan.digest();
        custody.plan.original[..extent].copy_from_slice(&custody.scratch[..extent]);
        custody.plan.original_extent = extent;
        Ok(())
    }

    /// Borrows the complete unchanged source receipt for an original stage.
    pub fn original_stage_receipt(&self, sequence: u64) -> Option<&[u8]> {
        let index = usize::try_from(sequence.checked_sub(1)?).ok()?;
        let exchange = &self.custody.as_ref()?.stages.get(index)?.exchange;
        (exchange.response_extent != 0).then(|| exchange.response_body())
    }

    /// Reports exact consumed stage commit retention, without releasing the world.
    pub fn stage_committed(&self, sequence: u64) -> bool {
        sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.custody.as_ref()?.stages.get(index))
            .is_some_and(|stage| stage.exchange.committed)
    }

    /// Borrows the complete original source result for an admitted compute.
    pub fn original_result(&self, sequence: u64) -> Option<&[u8]> {
        let index = usize::try_from(sequence.checked_sub(1)?).ok()?;
        let exchange = self.custody.as_ref()?.computes.get(index)?;
        (exchange.response_extent != 0).then(|| exchange.response_body())
    }

    fn accept_complete(&mut self, active: ActiveExchange) -> Result<(), NativeWholeControlError> {
        let plan_digest = self.queue_plan_digest;
        let custody = self.custody_mut()?;
        let incoming_kind = custody
            .incoming_kind
            .ok_or(NativeWholeControlError::Custody)?;
        let extent = custody.incoming_extent;
        let exchange = custody.exchange(active);
        let body = &custody.scratch[WHOLE_FRAME_HEADER_BYTES..extent];
        let response_kind = match active {
            ActiveExchange::Stage(_) => StagedFrameKind::StageReceipt,
            ActiveExchange::Compute(_) => StagedFrameKind::ExecutionResult,
        };
        if incoming_kind == response_kind {
            if exchange.response_extent != 0 {
                return if exchange.response[..exchange.response_extent] == custody.scratch[..extent]
                {
                    Ok(())
                } else {
                    Err(NativeWholeControlError::Custody)
                };
            }
            match active {
                ActiveExchange::Stage(_) => StageReceipt::decode(body)?
                    .validate_against(&StageInventory::decode(exchange.body())?, plan_digest)?,
                ActiveExchange::Compute(_) => {
                    let result = WholeResult::decode(body)?;
                    result.validate_against_staged(exchange.body())?;
                    if result.disposition
                        == crucible_qemu_protocol::whole_control::body::WholeResultDisposition::Complete
                    {
                        let request = WholeRequest::decode_staged(exchange.body())?;
                        let (records, bytes) = original_input_geometry(custody, &request)?;
                        // A smaller native prefix remains unresolved. Counts
                        // never guess which original records were consumed.
                        if result.input_records != records || result.input_bytes != bytes {
                            return Err(NativeWholeControlError::Custody);
                        }
                    }
                }
            }
            match active {
                ActiveExchange::Stage(index) => {
                    let exchange = &mut custody.stages[index].exchange;
                    exchange.response[..extent].copy_from_slice(&custody.scratch[..extent]);
                    exchange.response_extent = extent;
                }
                ActiveExchange::Compute(index) => {
                    let exchange = &mut custody.computes[index];
                    exchange.response[..extent].copy_from_slice(&custody.scratch[..extent]);
                    exchange.response_extent = extent;
                }
            }
            return Ok(());
        }
        let consumed_kind = match active {
            ActiveExchange::Stage(_) => StagedFrameKind::StageCommitAcknowledgement,
            ActiveExchange::Compute(_) => StagedFrameKind::ExecutionAcknowledgement,
        };
        // Consumed StageCommit uses another envelope kind but the exact original
        // body; a parser-accepted equivalent encoding is insufficient.
        if incoming_kind != consumed_kind
            || !exchange.commit_offered
            || exchange.commit_sent != exchange.offered_commit.len()
            || body != &exchange.offered_commit[WHOLE_FRAME_HEADER_BYTES..]
        {
            return Err(NativeWholeControlError::Custody);
        }
        match active {
            ActiveExchange::Stage(index) => {
                custody.stages[index]
                    .exchange
                    .consumed_commit
                    .copy_from_slice(&custody.scratch[..extent]);
                custody.stages[index].exchange.committed = true;
            }
            ActiveExchange::Compute(index) => {
                custody.computes[index]
                    .consumed_commit
                    .copy_from_slice(&custody.scratch[..extent]);
                custody.computes[index].committed = true;
            }
        }
        custody.active = None;
        Ok(())
    }

    fn transmit(&mut self, commit: bool) -> Result<bool, NativeWholeControlError> {
        self.live()?;
        let custody = self
            .custody
            .as_mut()
            .ok_or(NativeWholeControlError::Custody)?;
        let active = custody.active.ok_or(NativeWholeControlError::Custody)?;
        let exchange = custody.exchange(active);
        let (sent, extent) = if commit {
            (exchange.commit_sent, exchange.offered_commit.len())
        } else {
            (exchange.sent, exchange.original_extent)
        };
        if sent == extent {
            return Ok(true);
        }
        let exchange = match active {
            ActiveExchange::Stage(index) => &custody.stages[index].exchange,
            ActiveExchange::Compute(index) => &custody.computes[index],
        };
        let bytes = if commit {
            &exchange.offered_commit[sent..extent]
        } else {
            &exchange.original[sent..extent]
        };
        let progress = write_once(
            custody.socket.as_fd(),
            bytes,
            &mut custody.administrative,
            monotonic_ns()?,
        )
        .map_err(io::Error::other)?;
        if progress.peer_closed {
            return self.refuse(
                io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original staged write returned zero",
                )
                .into(),
            );
        }
        if progress.retryable {
            return Ok(false);
        }
        let count = progress.actual_bytes;
        let exchange = custody.exchange_mut(active);
        if commit {
            exchange.commit_sent += count;
        } else {
            exchange.sent += count;
        }
        Ok(sent + count == extent)
    }

    fn validate_scope(
        &mut self,
        scope: [u8; 32],
        epoch: u64,
    ) -> Result<(), NativeWholeControlError> {
        if scope != self.profile.compute.scope
            || self.epoch.is_some_and(|original| original != epoch)
        {
            return self.refuse(NativeWholeControlError::Custody);
        }
        self.epoch = Some(epoch);
        Ok(())
    }

    fn custody_mut(&mut self) -> Result<&mut Custody, NativeWholeControlError> {
        self.custody
            .as_deref_mut()
            .ok_or(NativeWholeControlError::Custody)
    }

    fn live(&mut self) -> Result<(), NativeWholeControlError> {
        if self.refused || self.process != std::process::id() {
            return Err(NativeWholeControlError::Custody);
        }
        if monotonic_ns()? >= self.profile.compute.deadline_monotonic_ns {
            return self.refuse(NativeWholeControlError::Exhausted);
        }
        Ok(())
    }

    fn refuse<T>(&mut self, error: NativeWholeControlError) -> Result<T, NativeWholeControlError> {
        self.refused = true;
        Err(error)
    }
}

impl Custody {
    fn exchange(&self, active: ActiveExchange) -> &Exchange {
        match active {
            ActiveExchange::Stage(index) => &self.stages[index].exchange,
            ActiveExchange::Compute(index) => &self.computes[index],
        }
    }

    fn exchange_mut(&mut self, active: ActiveExchange) -> &mut Exchange {
        match active {
            ActiveExchange::Stage(index) => &mut self.stages[index].exchange,
            ActiveExchange::Compute(index) => &mut self.computes[index],
        }
    }
}

impl Exchange {
    fn new(original: usize, response: usize) -> Result<Self, NativeWholeControlError> {
        Ok(Self {
            original: allocated(original)?,
            original_extent: 0,
            sent: 0,
            response: allocated(response)?,
            response_extent: 0,
            offered_commit: [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
            commit_offered: false,
            commit_sent: 0,
            consumed_commit: [0; WHOLE_FRAME_HEADER_BYTES + WHOLE_ACK_BYTES],
            committed: false,
        })
    }

    fn retain(
        &mut self,
        header: &[u8; WHOLE_FRAME_HEADER_BYTES],
        body: &[u8],
    ) -> Result<(), NativeWholeControlError> {
        let extent = WHOLE_FRAME_HEADER_BYTES + body.len();
        if extent > self.original.len() {
            return Err(NativeWholeControlError::Allocation);
        }
        self.original[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(header);
        self.original[WHOLE_FRAME_HEADER_BYTES..extent].copy_from_slice(body);
        self.original_extent = extent;
        Ok(())
    }

    fn body(&self) -> &[u8] {
        &self.original[WHOLE_FRAME_HEADER_BYTES..self.original_extent]
    }

    fn response_body(&self) -> &[u8] {
        &self.response[WHOLE_FRAME_HEADER_BYTES..self.response_extent]
    }
}

impl Drop for NativeStagedControlTransport {
    fn drop(&mut self) {
        if self.used || self.refused {
            // The preallocated capsule survives without allocating or locking
            // in Drop. Its bounded constructor permit is never recycled. No
            // public terminal native-world release capability exists yet.
            if let Some(custody) = self.custody.take() {
                std::mem::forget(custody);
            }
        } else {
            CUSTODY_OWNERS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn allocated(extent: usize) -> Result<Vec<u8>, NativeWholeControlError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(extent)
        .map_err(|_| NativeWholeControlError::Allocation)?;
    bytes.resize(extent, 0);
    Ok(bytes)
}

fn original_input_geometry(
    custody: &Custody,
    request: &WholeRequest<'_>,
) -> Result<(u64, u64), NativeWholeControlError> {
    let references = StageReferences::decode(request.input_inventory)?;
    let mut records = 0u64;
    let mut bytes = 0u64;
    for reference in references.records() {
        let stage_index = usize::try_from(reference.stage_sequence - 1)
            .map_err(|_| NativeWholeControlError::Custody)?;
        let stage = custody
            .stages
            .get(stage_index)
            .ok_or(NativeWholeControlError::Custody)?;
        let stage = StageInventory::decode(stage.exchange.body())?;
        for record in stage
            .queue_inventory
            .records()
            .skip(reference.first_record as usize)
            .take(reference.record_count as usize)
        {
            records = records
                .checked_add(1)
                .ok_or(NativeWholeControlError::Custody)?;
            bytes = bytes
                .checked_add(record.payload.len() as u64)
                .ok_or(NativeWholeControlError::Custody)?;
        }
    }
    Ok((records, bytes))
}

fn charged(used: u64, offered: u64, ceiling: u64) -> Result<u64, NativeWholeControlError> {
    used.checked_add(offered)
        .filter(|sum| *sum <= ceiling)
        .ok_or(NativeWholeControlError::Exhausted)
}

fn monotonic_ns() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The writable timespec lives throughout this synchronous call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos))
        })
        .ok_or_else(|| io::Error::other("monotonic clock extent overflow"))
}

#[cfg(test)]
#[path = "native_staged_control/tests.rs"]
mod tests;
