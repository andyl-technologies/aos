//! Original-cutoff parent exchanges and the closed v3 reader branch.
//!
//! The resident parent owns the actual connect outcome, every consumed record,
//! all nominated subjects and the original mount table before later checks.
//! One durable launch marker spans preprobe, reader and postprobe. Cleanup
//! observations remain separate from the first cause; only exact pidfd death
//! and complete retained population proof permit retirement of that marker.

use aos_sandbox_linux::cgroup::CgroupPopulationMonitor;
use aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1;

use crate::process::original_cutoff::{
    MAXIMUM_ORIGINAL_BODY_BYTES, OriginalWorkerIntroductionV3, OriginalWorkerPurposeV3,
    encode_acknowledgement, encode_body,
};
use crate::runtime::original_held_measurement::{
    OriginalHeldMeasurementErrorV3, OriginalWorkerLoanV3,
};

use super::super::{
    RetainedWorkerDescriptorSlot, RetainedWorkerRecordSlot, SystemdZfsExecutor,
    WorkerCleanupReport, capture_worker_cleanup, held_snapshot, verify_worker_peer,
    worker_is_quiescent,
};
use super::*;

const MAXIMUM_RECEIVE_CALLS_PER_STAGE: usize = 16;
const ORIGINAL_STAGES: usize = 3;

pub(in crate::process) fn validate_selected<'a>(
    cutoff: &crate::process::original_cutoff::DecodedOriginalWorkerCutoffV3,
    selected: &'a [u8],
) -> Result<(&'a str, u64, u64), ZfsWorkerError> {
    let (name, pool, guid, _, mode) = decode_request(selected)?;
    let claims = cutoff.request.request().claims();
    let catalog = claims.catalog();
    let (_, snapshot) = catalog
        .select_under_head(
            catalog.generation(),
            catalog.digest(),
            catalog.namespace_digest(),
            claims.selection().0,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    if mode != ReaderReplyMode::WithMount
        || guid != snapshot.snapshot_guid()
        || pool != snapshot.pool_guid()
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok((name, pool, guid))
}

#[derive(Default)]
struct OriginalStage {
    introduction: Option<[u8; 92]>,
    body: Vec<u8>,
    digest: Option<ObjectDigest>,
    connection: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    records: Vec<RetainedWorkerRecordSlot>,
    descriptors: Vec<RetainedWorkerDescriptorSlot>,
    receive_calls: usize,
    ready: Option<usize>,
    result: Option<usize>,
    cgroup: Option<RetainedCgroupAnchor>,
    population: Option<CgroupPopulationMonitor>,
    setup_cancellation: Option<Result<(), aos_sandbox_linux::Error>>,
    cleanup: WorkerCleanupReport,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    first_failure: Option<OriginalHeldMeasurementErrorV3>,
    secondary_postcheck_failure: Option<OriginalHeldMeasurementErrorV3>,
    cleanup_failure: Option<ZfsWorkerError>,
    measured: Option<HeldSnapshotReaderObservationV1>,
    probe: Option<super::super::HeldSnapshotPhysicalObservationV1>,
    quiescent: bool,
}

/// Move-only actual progress, not a caller-supplied custody projection.
pub(crate) struct OriginalHeldWorkerProgressV3 {
    stages: [OriginalStage; ORIGINAL_STAGES],
    next_stage: usize,
    launch: HeldReaderLaunchCapture,
    begun: bool,
    retired: bool,
    measured_mount: Option<OwnedFd>,
    measured_record: Option<(Vec<u8>, KernelAuthorizedRecordSubject)>,
    sequence: OriginalSequence,
}

#[derive(Clone, Copy)]
enum OriginalSequence {
    Measurement,
    Probe,
}

impl Default for OriginalHeldWorkerProgressV3 {
    fn default() -> Self {
        Self {
            stages: std::array::from_fn(|_| OriginalStage::default()),
            next_stage: 0,
            launch: HeldReaderLaunchCapture::default(),
            begun: false,
            retired: false,
            measured_mount: None,
            measured_record: None,
            sequence: OriginalSequence::Measurement,
        }
    }
}

impl OriginalHeldWorkerProgressV3 {
    pub(crate) fn for_probe() -> Self {
        Self {
            sequence: OriginalSequence::Probe,
            ..Self::default()
        }
    }

    fn expected_stages(&self) -> usize {
        match self.sequence {
            OriginalSequence::Measurement => ORIGINAL_STAGES,
            OriginalSequence::Probe => 1,
        }
    }

    pub(crate) fn take_measured_mount(
        &mut self,
    ) -> Result<OwnedFd, OriginalHeldMeasurementErrorV3> {
        if !matches!(self.sequence, OriginalSequence::Measurement)
            || !self.retired
            || !self.stages.iter().all(|stage| stage.quiescent)
        {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        self.measured_mount
            .take()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)
    }

    fn stage(
        &mut self,
        purpose: OriginalWorkerPurposeV3,
        body: Vec<u8>,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    ) -> Result<&mut OriginalStage, OriginalHeldMeasurementErrorV3> {
        if !self.begun || self.retired || body.len() > MAXIMUM_ORIGINAL_BODY_BYTES {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        let expected = match (self.sequence, self.next_stage) {
            (OriginalSequence::Measurement, 0 | 2) | (OriginalSequence::Probe, 0) => {
                OriginalWorkerPurposeV3::Observer
            }
            (OriginalSequence::Measurement, 1) => OriginalWorkerPurposeV3::Reader,
            _ => return Err(OriginalHeldMeasurementErrorV3::Closed),
        };
        if expected != purpose {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        let stage = &mut self.stages[self.next_stage];
        self.next_stage += 1;

        // The count and worst-case payload reservation were admitted by the
        // runtime before begin. Each concrete slot is reserved before connect.
        stage
            .records
            .try_reserve_exact(MAXIMUM_RECEIVE_CALLS_PER_STAGE)?;
        stage
            .descriptors
            .try_reserve_exact(MAXIMUM_RECEIVE_CALLS_PER_STAGE)?;
        stage.body = body;
        let (first, cutoff) = loan.clock_scope();
        let digest = purpose.digest(&stage.body);
        stage.digest = Some(digest);
        stage.introduction = Some(
            OriginalWorkerIntroductionV3 {
                first,
                cutoff,
                body_length: stage.body.len(),
                digest,
            }
            .encode(purpose)?,
        );
        Ok(stage)
    }
}

impl SystemdHeldSnapshotReaderV1 {
    pub(crate) fn begin_original(
        &mut self,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut OriginalHeldWorkerProgressV3,
    ) -> Result<(), OriginalHeldMeasurementErrorV3> {
        if self.fail_stopped || progress.begun {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        progress.begun = true;
        loan.check()?;
        self.prove_prior_readers_empty()?;
        loan.check()?;
        self.launch_fence
            .capture_claim_with_sync(&mut progress.launch, &mut |fd| fsync(fd))?;
        if !matches!(&progress.launch.claim, Some(Ok(()))) {
            self.fail_stopped = true;
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        loan.check()?;
        Ok(())
    }

    pub(crate) fn finish_original(
        &mut self,
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut OriginalHeldWorkerProgressV3,
    ) -> Result<(), OriginalHeldMeasurementErrorV3> {
        if progress.retired
            || progress.next_stage != progress.expected_stages()
            || !progress.stages[..progress.next_stage]
                .iter()
                .all(|stage| stage.quiescent && stage.first_failure.is_none())
        {
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        loan.check()?;
        self.launch_fence
            .capture_retirement(&mut progress.launch)?;
        if !matches!(&progress.launch.retirement, Some(Ok(()))) {
            self.fail_stopped = true;
            return Err(OriginalHeldMeasurementErrorV3::Closed);
        }
        progress.retired = true;
        loan.check()?;
        Ok(())
    }

    pub(crate) fn measure_original_with_mount(
        &mut self,
        snapshot: &ResolvedSnapshot,
        pool_guid: u64,
        cut_digest: ObjectDigest,
        nonce: [u8; 16],
        loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
        progress: &mut OriginalHeldWorkerProgressV3,
    ) -> Result<HeldSnapshotReaderObservationV1, OriginalHeldMeasurementErrorV3> {
        let selected = encode_request_for(
            snapshot,
            pool_guid,
            cut_digest,
            nonce,
            ReaderReplyMode::WithMount,
        )?;
        let body = encode_body(OriginalWorkerPurposeV3::Reader, loan.cutoff_bytes(), &selected)?;
        let stage = progress.stage(OriginalWorkerPurposeV3::Reader, body, loan)?;
        let result = exchange_stage(
            Endpoint::Reader(self),
            stage,
            loan,
            StageResult::Reader {
                snapshot_guid: snapshot.guid(),
                pool_guid,
            },
        );
        finish_stage(Endpoint::Reader(self), stage, result)?;
        let index = stage.result.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        let measured = stage.measured.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        let mount = descriptor(stage, index)?
            .descriptors()
            .first()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        verify_received_mount_fd(mount.as_fd(), &measured, pool_guid)?;
        loan.check()?;
        // Full validation is borrowed. Only after quiescence and the postcheck
        // do the same mount, payload and subject move into resident progress.
        let response = match stage.descriptors[index].outcome.take() {
            Some(Ok(response)) => response,
            retained => {
                stage.descriptors[index].outcome = retained;
                return Err(OriginalHeldMeasurementErrorV3::RetainedReceive);
            }
        };
        let (payload, subject, descriptors) = response.into_parts();
        let [mount]: [OwnedFd; 1] = descriptors.try_into()
            .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?;
        progress.measured_mount = Some(mount);
        progress.measured_record = Some((payload, subject));
        Ok(measured)
    }
}

pub(crate) fn observe_original(
    executor: &mut SystemdZfsExecutor,
    contract: &crate::ZfsHelperContract,
    snapshot: &ResolvedSnapshot,
    hold_id: crate::HoldId,
    binding: super::super::HeldSnapshotWorkerBindingV1,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    progress: &mut OriginalHeldWorkerProgressV3,
) -> Result<super::super::HeldSnapshotPhysicalObservationV1, OriginalHeldMeasurementErrorV3> {
    if executor.fail_stopped {
        return Err(OriginalHeldMeasurementErrorV3::Closed);
    }
    let selected = held_snapshot::encode_request(contract, snapshot, hold_id, binding)?;
    let body = encode_body(OriginalWorkerPurposeV3::Observer, loan.cutoff_bytes(), &selected)?;
    let stage = progress.stage(OriginalWorkerPurposeV3::Observer, body, loan)?;
    let result = exchange_stage(
        Endpoint::Observer(executor),
        stage,
        loan,
        StageResult::Observer,
    );
    if let Err(error) = finish_stage(Endpoint::Observer(executor), stage, result) {
        executor.fail_stopped = true;
        return Err(error);
    }
    let observed = stage.probe.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    loan.check()?;
    Ok(observed)
}

/// Closed selection of existing concrete owners, never an injected endpoint.
#[derive(Clone, Copy)]
enum Endpoint<'a> {
    Reader(&'a SystemdHeldSnapshotReaderV1),
    Observer(&'a SystemdZfsExecutor),
}

impl<'a> Endpoint<'a> {
    fn maximum_ready_bytes(self) -> usize {
        match self {
            Self::Reader(_) => MAXIMUM_READY_BYTES,
            Self::Observer(_) => super::super::MAXIMUM_READY_BYTES,
        }
    }

    fn path(self) -> &'a Path {
        match self {
            Self::Reader(_) => Path::new(SOCKET_PATH),
            Self::Observer(executor) => &executor.socket_path,
        }
    }

    fn manager(self) -> &'a RetainedCgroupAnchor {
        match self {
            Self::Reader(reader) => &reader.manager,
            Self::Observer(executor) => &executor.systemd_manager_cgroup,
        }
    }

    fn admit_subject(
        self,
        ready: &aos_sandbox_linux::seqpacket::ReceivedRecord,
    ) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
        match self {
            Self::Reader(reader) => {
                reader.verify_reader(ready.subject(), decode_ready(ready.payload())?)
            }
            Self::Observer(executor) => {
                let path = super::super::decode_ready(ready.payload())?;
                verify_worker_peer(ready.subject(), &executor.worker_parent_cgroup, Path::new(path))
            }
        }
    }
}

enum StageResult {
    Reader {
        snapshot_guid: u64,
        pool_guid: u64,
    },
    Observer,
}

fn exchange_stage(
    endpoint: Endpoint<'_>,
    stage: &mut OriginalStage,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    expected: StageResult,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    loan.check()?;
    stage.connection = Some(SeqpacketSocket::connect_retaining(endpoint.path()));
    let checked = loan.check();
    if matches!(&stage.connection, Some(Err(_))) {
        stage.secondary_postcheck_failure = checked.err();
        return Err(OriginalHeldMeasurementErrorV3::RetainedAdmission);
    }
    checked?;
    {
        let socket = socket(stage)?;
        socket
            .peer()
            .require_peer_filesystem_path(
                socket.as_fd().map_err(ZfsWorkerError::from)?,
                endpoint.path(),
            )
            .map_err(ZfsWorkerError::from)?;
        verify_systemd_activation_peer(socket.peer(), endpoint.manager())?;
    }
    let ready = receive_record(stage, loan, endpoint.maximum_ready_bytes())?;
    stage.ready = Some(ready);
    stage.cgroup = Some(endpoint.admit_subject(record(stage, ready)?)?);
    let cgroup = stage
        .cgroup
        .as_ref()
        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    match cgroup.population_monitor() {
        Ok(population) => stage.population = Some(population),
        Err(cause) => {
            stage.setup_cancellation = Some(cgroup.kill_all());
            return Err(ZfsWorkerError::Linux(cause).into());
        }
    }
    loan.check()?;
    let introduction = stage.introduction.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    send_original(stage, loan, OriginalSend::Bytes(&introduction))?;
    send_original(stage, loan, OriginalSend::Body)?;
    let with_mount = matches!(&expected, StageResult::Reader { .. });
    let response = if with_mount {
        receive_descriptor(stage, loan, RESULT_BYTES)?
    } else {
        receive_record(stage, loan, held_snapshot::RESPONSE_BYTES)?
    };
    stage.result = Some(response);
    {
        let ready = record(stage, ready)?;
        let subject = if with_mount {
            descriptor(stage, response)?.subject()
        } else {
            record(stage, response)?.subject()
        };
        verify_same_live_subject(ready.subject(), subject)?;
        stage
            .cgroup
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?
            .verify_exact_membership(subject.pidfd())
            .map_err(ZfsWorkerError::from)?;
        verify_systemd_activation_peer(socket(stage)?.peer(), endpoint.manager())?;
    }
    loan.check()?;
    let digest = stage.digest.ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    match expected {
        StageResult::Reader {
            snapshot_guid,
            pool_guid,
        } => {
            let response = descriptor(stage, response)?;
            stage.measured = Some(validate_result_with_mount_for(
                response.payload(),
                digest,
                snapshot_guid,
                pool_guid,
                response.descriptors(),
                ReaderReplyMode::OriginalWithMount,
            )?);
        }
        StageResult::Observer => {
            stage.probe = Some(held_snapshot::decode_original_response(
                record(stage, response)?.payload(),
                digest,
            )?);
        }
    }
    loan.check()?;
    let acknowledgement =
        encode_acknowledgement(stage.digest.ok_or(OriginalHeldMeasurementErrorV3::Closed)?);
    send_original(stage, loan, OriginalSend::Bytes(&acknowledgement))?;
    let later = loan.check()?;
    let remaining = loan
        .clock_scope()
        .1
        .checked_sub(later.boottime_nanoseconds())
        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    wait_for_worker_quiescence(
        record(stage, ready)?.subject(),
        stage
            .population
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
        Duration::from_nanos(remaining).min(Duration::from_secs(1)),
    )?;
    loan.check()?;
    stage.quiescent = worker_is_quiescent(
        record(stage, ready)?.subject(),
        stage
            .population
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?,
    )?;
    if !stage.quiescent {
        return Err(OriginalHeldMeasurementErrorV3::Closed);
    }
    Ok(())
}

fn finish_stage(
    _endpoint: Endpoint<'_>,
    stage: &mut OriginalStage,
    result: Result<(), OriginalHeldMeasurementErrorV3>,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    if let Err(cause) = result {
        stage.first_failure = Some(cause);
        // The exact first cause remains resident before shutdown/cancellation.
        if let Some(Ok(socket)) = stage.connection.as_ref() {
            if let Ok(fd) = socket.as_fd() {
                stage.shutdown = Some(rustix::net::shutdown(fd, rustix::net::Shutdown::Both));
            }
        }
        if let (Some(index), Some(cgroup), Some(population)) =
            (stage.ready, &stage.cgroup, &stage.population)
        {
            if let Some(Some(Ok(ready))) =
                stage.records.get(index).map(RetainedWorkerRecordSlot::outcome)
            {
                stage.cleanup_failure =
                    capture_worker_cleanup(&mut stage.cleanup, ready.subject(), cgroup, population)
                        .err();
            }
        }
        return Err(OriginalHeldMeasurementErrorV3::Closed);
    }
    Ok(())
}

fn socket(stage: &OriginalStage) -> Result<&SeqpacketSocket, OriginalHeldMeasurementErrorV3> {
    match stage.connection.as_ref() {
        Some(Ok(socket)) => Ok(socket),
        Some(Err(_)) => Err(OriginalHeldMeasurementErrorV3::RetainedAdmission),
        None => Err(OriginalHeldMeasurementErrorV3::Closed),
    }
}

fn record(
    stage: &OriginalStage,
    index: usize,
) -> Result<&aos_sandbox_linux::seqpacket::ReceivedRecord, OriginalHeldMeasurementErrorV3> {
    match stage
        .records
        .get(index)
        .and_then(RetainedWorkerRecordSlot::outcome)
    {
        Some(Ok(record)) => Ok(record),
        Some(Err(_)) => Err(OriginalHeldMeasurementErrorV3::RetainedReceive),
        None => Err(OriginalHeldMeasurementErrorV3::Closed),
    }
}

fn descriptor(
    stage: &OriginalStage,
    index: usize,
) -> Result<
    &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    OriginalHeldMeasurementErrorV3,
> {
    match stage
        .descriptors
        .get(index)
        .and_then(RetainedWorkerDescriptorSlot::outcome)
    {
        Some(Ok(record)) => Ok(record),
        Some(Err(_)) => Err(OriginalHeldMeasurementErrorV3::RetainedReceive),
        None => Err(OriginalHeldMeasurementErrorV3::Closed),
    }
}

fn receive_record(
    stage: &mut OriginalStage,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    maximum: usize,
) -> Result<usize, OriginalHeldMeasurementErrorV3> {
    loop {
        loan.check()?;
        require_receive_budget(stage, maximum)?;
        let index = stage.records.len();
        stage.records.push(RetainedWorkerRecordSlot::default());
        let Some(Ok(socket)) = stage.connection.as_mut() else {
            return Err(OriginalHeldMeasurementErrorV3::RetainedAdmission);
        };
        stage.records[index].capture_once(socket, maximum)?;
        let checked = loan.check();
        match stage.records[index].outcome() {
            Some(Ok(_)) => {
                checked?;
                return Ok(index);
            }
            Some(Err(cause)) if receive_is_transient(cause) => {
                checked?;
                wait_original(stage, loan, rustix::event::PollFlags::IN)?;
            }
            _ => {
                stage.secondary_postcheck_failure = checked.err();
                return Err(OriginalHeldMeasurementErrorV3::RetainedReceive);
            }
        }
    }
}

fn receive_descriptor(
    stage: &mut OriginalStage,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    maximum: usize,
) -> Result<usize, OriginalHeldMeasurementErrorV3> {
    loop {
        loan.check()?;
        require_receive_budget(stage, maximum)?;
        let index = stage.descriptors.len();
        stage.descriptors.push(RetainedWorkerDescriptorSlot::default());
        let Some(Ok(socket)) = stage.connection.as_mut() else {
            return Err(OriginalHeldMeasurementErrorV3::RetainedAdmission);
        };
        stage.descriptors[index].capture_once(socket, maximum)?;
        let checked = loan.check();
        match stage.descriptors[index].outcome() {
            Some(Ok(_)) => {
                checked?;
                return Ok(index);
            }
            Some(Err(cause)) if receive_is_transient(cause) => {
                checked?;
                wait_original(stage, loan, rustix::event::PollFlags::IN)?;
            }
            _ => {
                stage.secondary_postcheck_failure = checked.err();
                return Err(OriginalHeldMeasurementErrorV3::RetainedReceive);
            }
        }
    }
}

fn require_receive_budget(
    stage: &mut OriginalStage,
    maximum: usize,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    if maximum == 0
        || maximum > MAXIMUM_ORIGINAL_BODY_BYTES
        || stage.receive_calls >= MAXIMUM_RECEIVE_CALLS_PER_STAGE
    {
        return Err(OriginalHeldMeasurementErrorV3::Bound);
    }
    stage.receive_calls += 1;
    Ok(())
}

/// Avoids borrowing the resident body outside its exclusive stage loan.
enum OriginalSend<'bytes> {
    Body,
    Bytes(&'bytes [u8]),
}

fn send_original(
    stage: &mut OriginalStage,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    payload: OriginalSend<'_>,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    loop {
        loan.check()?;
        let bytes = match &payload {
            OriginalSend::Body => stage.body.as_slice(),
            OriginalSend::Bytes(bytes) => *bytes,
        };
        let result = match stage.connection.as_mut() {
            Some(Ok(socket)) => socket.send(bytes),
            _ => return Err(OriginalHeldMeasurementErrorV3::RetainedAdmission),
        };
        let checked = loan.check();
        match result {
            Ok(()) => {
                checked?;
                return Ok(());
            }
            Err(
                aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock
                | aos_sandbox_linux::seqpacket::SeqpacketError::Interrupted,
            ) => {
                checked?;
                wait_original(stage, loan, rustix::event::PollFlags::OUT)?;
            }
            Err(cause) => {
                stage.secondary_postcheck_failure = checked.err();
                return Err(ZfsWorkerError::from(cause).into());
            }
        }
    }
}

fn wait_original(
    stage: &OriginalStage,
    loan: &mut OriginalWorkerLoanV3<'_, '_, '_>,
    events: rustix::event::PollFlags,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    let later = loan.check()?;
    let remaining = loan
        .clock_scope()
        .1
        .checked_sub(later.boottime_nanoseconds())
        .filter(|remaining| *remaining != 0)
        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    let timeout = rustix::event::Timespec::try_from(Duration::from_nanos(remaining))
        .map_err(|_| OriginalHeldMeasurementErrorV3::Closed)?;
    let fd = socket(stage)?.as_fd().map_err(ZfsWorkerError::from)?;
    let mut descriptors = [rustix::event::PollFd::new(&fd, events)];
    let polled = rustix::event::poll(&mut descriptors, Some(&timeout)).map_err(ZfsWorkerError::from);
    let checked = loan.check();
    if polled? == 0 {
        return Err(OriginalHeldMeasurementErrorV3::Closed);
    }
    checked?;
    Ok(())
}

/// Holds the actual new-version worker originals on every returned failure.
///
/// The inherited-socket and first-record prefix still uses the legacy entry
/// point. This custody begins at its explicit version dispatch, not before
/// every fallible operation in the process. Lower mount/spawn calls can also
/// fail before handing an object back; neither case establishes quiescence.
pub(in crate::process) struct WorkerOriginalChildCustodyV3 {
    socket: SeqpacketSocket,
    introduction_record: aos_sandbox_linux::seqpacket::ReceivedRecord,
    storaged: RetainedCgroupAnchor,
    body_receives: Vec<RetainedWorkerRecordSlot>,
    acknowledgements: Vec<RetainedWorkerRecordSlot>,
    introduction: Option<OriginalWorkerIntroductionV3>,
    decoded: Option<crate::process::original_cutoff::DecodedOriginalWorkerCutoffV3>,
    mount: Option<aos_sandbox_linux::mount::DetachedMount>,
    probe: held_snapshot::OriginalProbeProgressV3,
    configured: Option<crate::ZfsHelperContract>,
    executable: Option<super::super::PinnedExecutable>,
    response: Option<OriginalChildResponse>,
    secondary_tree_failure: Option<crate::held_snapshot_tree::HeldSnapshotTreeErrorV1>,
    secondary_postcheck_failure: Option<OriginalHeldMeasurementErrorV3>,
}

pub(super) fn run_original_reader(
    socket: SeqpacketSocket,
    introduction_record: aos_sandbox_linux::seqpacket::ReceivedRecord,
    storaged: RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    run_original_child(
        OriginalWorkerPurposeV3::Reader,
        socket,
        introduction_record,
        storaged,
        None,
    )
}

pub(in crate::process) fn run_original_observer(
    socket: SeqpacketSocket,
    introduction_record: aos_sandbox_linux::seqpacket::ReceivedRecord,
    storaged: RetainedCgroupAnchor,
    configured: crate::ZfsHelperContract,
    executable: super::super::PinnedExecutable,
) -> Result<(), ZfsWorkerError> {
    run_original_child(
        OriginalWorkerPurposeV3::Observer,
        socket,
        introduction_record,
        storaged,
        Some((configured, executable)),
    )
}

fn run_original_child(
    purpose: OriginalWorkerPurposeV3,
    socket: SeqpacketSocket,
    introduction_record: aos_sandbox_linux::seqpacket::ReceivedRecord,
    storaged: RetainedCgroupAnchor,
    configured: Option<(crate::ZfsHelperContract, super::super::PinnedExecutable)>,
) -> Result<(), ZfsWorkerError> {
    let (configured, executable) = match configured {
        Some((configured, executable)) => (Some(configured), Some(executable)),
        None => (None, None),
    };
    // The actual inputs enter owning custody before decoding or allocation.
    let mut custody = Box::new(WorkerOriginalChildCustodyV3 {
        socket,
        introduction_record,
        storaged,
        body_receives: Vec::new(),
        acknowledgements: Vec::new(),
        introduction: None,
        decoded: None,
        mount: None,
        probe: held_snapshot::OriginalProbeProgressV3::default(),
        configured,
        executable,
        response: None,
        secondary_tree_failure: None,
        secondary_postcheck_failure: None,
    });
    match run_original_child_into(purpose, &mut custody) {
        Ok(()) => Ok(()),
        Err(cause) => Err(Box::new(super::super::OriginalWorkerFailureV3 { cause, custody }).into()),
    }
}

fn run_original_child_into(
    purpose: OriginalWorkerPurposeV3,
    custody: &mut WorkerOriginalChildCustodyV3,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    custody
        .body_receives
        .try_reserve_exact(MAXIMUM_RECEIVE_CALLS_PER_STAGE)?;
    custody
        .acknowledgements
        .try_reserve_exact(MAXIMUM_RECEIVE_CALLS_PER_STAGE)?;
    custody.introduction = Some(OriginalWorkerIntroductionV3::decode(
        purpose,
        custody.introduction_record.payload(),
    )?);
    let body_index = receive_original_body(custody)?;

    // Split the one owner, never move or clone its socket, records or mount.
    // The view retains exclusive socket access through measurement and ACK.
    let WorkerOriginalChildCustodyV3 {
        socket,
        introduction_record,
        storaged,
        body_receives,
        acknowledgements,
        decoded,
        mount,
        probe,
        configured,
        executable,
        response,
        secondary_tree_failure,
        secondary_postcheck_failure,
        ..
    } = custody;
    let body = match body_receives[body_index].outcome() {
        Some(Ok(body)) => body,
        _ => return Err(OriginalHeldMeasurementErrorV3::RetainedReceive),
    };
    let (mut view, selection) = crate::process::original_cutoff::WorkerOriginalCheckedViewV3::admit(
        purpose,
        socket,
        introduction_record,
        body,
        storaged,
    )?;
    let result = (|| {
        *response = Some(match selection {
            crate::process::original_cutoff::OriginalWorkerSelectionV3::Reader {
                name,
                pool_guid,
                snapshot_guid,
            } => {
                let measured = crate::held_snapshot_tree::measure_bound_original_snapshot_with_mount(
                    name,
                    pool_guid,
                    snapshot_guid,
                    &mut view,
                    mount,
                );
                let measured = match measured {
                    Ok(measured) => measured,
                    Err(tree_cause) => {
                        if let Some(cause) = view.take_first_failure() {
                            *secondary_tree_failure = Some(tree_cause);
                            return Err(cause.into());
                        }
                        return Err(tree_cause.into());
                    }
                };
                let observation = HeldSnapshotReaderObservationV1 {
                    content_digest: measured.content_digest,
                    tree_digest: measured.tree.digest(),
                    tree_size: measured.tree.encoded_size(),
                    mount_id: measured.mount_id.get(),
                    root_device: measured.root_device,
                    root_inode: measured.root_inode,
                    nodes: u32::try_from(measured.nodes)
                        .map_err(|_| OriginalHeldMeasurementErrorV3::Bound)?,
                    file_bytes: u64::try_from(measured.file_bytes)
                        .map_err(|_| OriginalHeldMeasurementErrorV3::Bound)?,
                    mounted_snapshot_guid: snapshot_guid,
                    identity: measured.identity,
                };
                OriginalChildResponse::Reader(encode_result_for(
                    view.digest(),
                    observation,
                    ReaderReplyMode::OriginalWithMount,
                ))
            }
            crate::process::original_cutoff::OriginalWorkerSelectionV3::Observer(request) => {
                let configured = configured
                    .as_ref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
                let executable = executable
                    .as_ref()
                    .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
                if request.executable != *configured {
                    return Err(ZfsWorkerError::Executable(
                        "broker and worker executable contracts differ".to_owned(),
                    )
                    .into());
                }
                executable.validate_current(configured)?;
                let observed = held_snapshot::execute_original_request(&request, &mut view, probe)?;
                executable.validate_current(configured)?;
                OriginalChildResponse::Observer(held_snapshot::encode_original_response(
                    view.digest(),
                    observed,
                ))
            }
        });
        view.check()?;
        // The exact response remains owned even if send or ACK fails later.
        let response = response
            .as_ref()
            .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
        send_original_child(
            &mut view,
            response.bytes(),
            mount.as_ref().map(|mount| mount.as_fd()),
        )?;
        receive_original_acknowledgement(
            &mut view,
            acknowledgements,
            secondary_postcheck_failure,
        )?;
        view.check()?;
        Ok::<_, OriginalHeldMeasurementErrorV3>(())
    })();
    // Preserve decoded signed DATA on returned errors without promoting it
    // into a checked token or permitting a new loan/deadline from this owner.
    *decoded = Some(view.into_data());
    result
}

enum OriginalChildResponse {
    Reader([u8; RESULT_BYTES]),
    Observer([u8; held_snapshot::RESPONSE_BYTES]),
}

impl OriginalChildResponse {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Reader(bytes) => bytes,
            Self::Observer(bytes) => bytes,
        }
    }
}

fn receive_original_body(
    custody: &mut WorkerOriginalChildCustodyV3,
) -> Result<usize, OriginalHeldMeasurementErrorV3> {
    let introduction = custody
        .introduction
        .ok_or(OriginalHeldMeasurementErrorV3::Closed)?;
    loop {
        check_introduction_peer(custody, introduction)?;
        if custody.body_receives.len() >= MAXIMUM_RECEIVE_CALLS_PER_STAGE {
            return Err(OriginalHeldMeasurementErrorV3::Bound);
        }
        let index = custody.body_receives.len();
        custody.body_receives.push(RetainedWorkerRecordSlot::default());
        custody.body_receives[index]
            .capture_once(&mut custody.socket, introduction.body_length)?;
        let checked = check_introduction_peer(custody, introduction);
        match custody.body_receives[index].outcome() {
            Some(Ok(_)) => {
                checked?;
                return Ok(index);
            }
            Some(Err(cause)) if receive_is_transient(cause) => {
                checked?;
                wait_introduction(custody, introduction)?;
            }
            _ => {
                custody.secondary_postcheck_failure = checked.err();
                return Err(OriginalHeldMeasurementErrorV3::RetainedReceive);
            }
        }
    }
}

fn check_introduction_peer(
    custody: &WorkerOriginalChildCustodyV3,
    introduction: OriginalWorkerIntroductionV3,
) -> Result<Duration, OriginalHeldMeasurementErrorV3> {
    super::super::verify_storaged_peer(custody.socket.peer(), &custody.storaged)?;
    super::super::verify_same_subject(custody.socket.peer(), custody.introduction_record.subject())?;
    custody
        .storaged
        .verify_exact_membership(custody.introduction_record.subject().pidfd())
        .map_err(ZfsWorkerError::from)?;
    Ok(introduction.remaining_kernel_time()?)
}

fn wait_introduction(
    custody: &WorkerOriginalChildCustodyV3,
    introduction: OriginalWorkerIntroductionV3,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    let remaining = check_introduction_peer(custody, introduction)?;
    let timeout = rustix::event::Timespec::try_from(remaining)
        .map_err(|_| OriginalHeldMeasurementErrorV3::Bound)?;
    let descriptor = custody.socket.as_fd().map_err(ZfsWorkerError::from)?;
    let mut descriptors = [rustix::event::PollFd::new(&descriptor, rustix::event::PollFlags::IN)];
    let polled = rustix::event::poll(&mut descriptors, Some(&timeout)).map_err(ZfsWorkerError::from);
    let checked = check_introduction_peer(custody, introduction);
    if polled? == 0 {
        return Err(OriginalHeldMeasurementErrorV3::Closed);
    }
    checked?;
    Ok(())
}

fn send_original_child(
    view: &mut crate::process::original_cutoff::WorkerOriginalCheckedViewV3<'_>,
    bytes: &[u8],
    mount: Option<BorrowedFd<'_>>,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    loop {
        match view.send_once(bytes, mount) {
            Ok(()) => return Ok(()),
            Err(cause) if send_is_transient(&cause) => view.wait(rustix::event::PollFlags::OUT)?,
            Err(cause) => return Err(cause.into()),
        }
    }
}

fn receive_original_acknowledgement(
    view: &mut crate::process::original_cutoff::WorkerOriginalCheckedViewV3<'_>,
    slots: &mut Vec<RetainedWorkerRecordSlot>,
    secondary_postcheck_failure: &mut Option<OriginalHeldMeasurementErrorV3>,
) -> Result<(), OriginalHeldMeasurementErrorV3> {
    loop {
        if slots.len() >= MAXIMUM_RECEIVE_CALLS_PER_STAGE {
            return Err(OriginalHeldMeasurementErrorV3::Bound);
        }
        let index = slots.len();
        slots.push(RetainedWorkerRecordSlot::default());
        let checked = view.receive_once(&mut slots[index], 42);
        match slots[index].outcome() {
            Some(Ok(record)) => {
                checked?;
                view.require_acknowledgement(record)?;
                return Ok(());
            }
            Some(Err(cause)) if receive_is_transient(cause) => {
                checked?;
                view.wait(rustix::event::PollFlags::IN)?;
            }
            Some(Err(_)) => {
                *secondary_postcheck_failure = checked.err().map(OriginalHeldMeasurementErrorV3::from);
                return Err(OriginalHeldMeasurementErrorV3::RetainedReceive);
            }
            None => {
                checked?;
                return Err(OriginalHeldMeasurementErrorV3::Closed);
            }
        }
    }
}

fn receive_is_transient(
    cause: &aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1,
) -> bool {
    matches!(
        cause.cause(),
        aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock
            | aos_sandbox_linux::seqpacket::SeqpacketError::Interrupted,
    )
}

fn send_is_transient(cause: &crate::process::original_cutoff::OriginalWorkerCutoffErrorV3) -> bool {
    matches!(
        cause,
        crate::process::original_cutoff::OriginalWorkerCutoffErrorV3::Worker(cause)
            if matches!(
                cause.as_ref(),
                ZfsWorkerError::Transport(
                    aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock
                        | aos_sandbox_linux::seqpacket::SeqpacketError::Interrupted,
                ),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_partial_receive_consumes_the_same_nonrenewable_stage_budget() {
        let mut stage = OriginalStage::default();
        for _ in 0..MAXIMUM_RECEIVE_CALLS_PER_STAGE {
            require_receive_budget(&mut stage, 4096).unwrap();
        }

        assert_eq!(stage.receive_calls, MAXIMUM_RECEIVE_CALLS_PER_STAGE);
        assert!(matches!(
            require_receive_budget(&mut stage, 4096),
            Err(OriginalHeldMeasurementErrorV3::Bound),
        ));
        assert_eq!(stage.receive_calls, MAXIMUM_RECEIVE_CALLS_PER_STAGE);

        let mut invalid = OriginalStage::default();
        assert!(require_receive_budget(&mut invalid, 0).is_err());
        assert!(require_receive_budget(&mut invalid, MAXIMUM_ORIGINAL_BODY_BYTES + 1).is_err());
        assert_eq!(invalid.receive_calls, 0);
    }

    #[test]
    fn measurement_and_readback_keep_distinct_complete_stage_counts() {
        // These are empty progress DATA, not constructed physical owners.
        let measurement = OriginalHeldWorkerProgressV3::default();
        let readback = OriginalHeldWorkerProgressV3::for_probe();

        assert_eq!(measurement.expected_stages(), 3);
        assert_eq!(readback.expected_stages(), 1);
        assert!(!measurement.begun && !measurement.retired);
        assert!(!readback.begun && !readback.retired);
    }

    #[test]
    fn original_mount_result_preserves_all_fields_and_rejects_legacy_headers() {
        let digest = ObjectDigest::from_bytes([1; 32]);
        let observation = HeldSnapshotReaderObservationV1 {
            content_digest: ObjectDigest::from_bytes([2; 32]),
            tree_digest: ObjectDigest::from_bytes([3; 32]),
            tree_size: 42,
            mount_id: 19,
            root_device: 21,
            root_inode: 23,
            nodes: 2,
            file_bytes: 29,
            mounted_snapshot_guid: 31,
            identity: HeldSnapshotIdentityObservationV1 {
                root_attributes: PortableRootAttributesV1::new(7, 8, 0o755).unwrap(),
                maximum_portable_uid: 9,
                maximum_portable_gid: 10,
                distinct_inode_count: 2,
                directory_entry_count: 1,
                identity_tree_digest: ObjectDigest::from_bytes([4; 32]),
            },
        };
        let legacy = encode_result_for(digest, observation, ReaderReplyMode::WithMount);
        let original = encode_result_for(digest, observation, ReaderReplyMode::OriginalWithMount);

        assert_eq!(&legacy[10..], &original[10..]);
        assert_eq!(&original[..10], b"AOSHSM04\0\x04");
        assert_eq!(
            decode_result_for(&original, digest, 31, ReaderReplyMode::OriginalWithMount).unwrap(),
            observation,
        );
        assert!(decode_result_for(&legacy, digest, 31, ReaderReplyMode::OriginalWithMount).is_err());
        assert!(decode_result_for(&original, digest, 31, ReaderReplyMode::WithMount).is_err());
        assert!(
            decode_result_for(
                &original[..RESULT_BYTES - 1],
                digest,
                31,
                ReaderReplyMode::OriginalWithMount,
            )
            .is_err(),
        );
        assert!(
            decode_result_for(&original, digest, 32, ReaderReplyMode::OriginalWithMount).is_err(),
        );
    }
}
