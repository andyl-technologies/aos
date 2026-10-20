//! Drives the actual private Capture worker on its existing inherited channel.
//!
//! A failure after native entry keeps the entire reached phase and all pipe
//! ends resident behind the original absolute kernel timer. It performs no
//! more drain reads and never converts Abort, exhaustion or expiry into EOF.
//! The process exits through the existing selected fail-stop fence at expiry.

use super::*;
use aos_sandbox_linux::seqpacket::bounded::{ZfsWorkerRecordKindV1, ZfsWorkerSendKindV1,
    ZfsWorkerSendAttemptV1, ZfsWorkerReceiveErrorV1, send_zfs_worker_record_v1,
    receive_zfs_worker_record_v1};

struct NegativeWaitOriginalV3 {
    timer: original_cutoff::OriginalBoottimeTimerV3,
    armed: Option<Result<(), original_cutoff::OriginalWorkerCutoffErrorV3>>,
    polled: Option<Result<usize, rustix::io::Errno>>,
}

impl NegativeWaitOriginalV3 {
    fn new() -> Self { Self { timer: original_cutoff::OriginalBoottimeTimerV3::default(), armed: None, polled: None } }

    fn arm_once_v3(&mut self, context: &AuthenticatedCaptureWorkerContextV3<'_>) -> Result<(), ZfsWorkerError> {
        if self.armed.is_some() { return Err(ZfsWorkerError::Authority); }
        let (_, _, _, _, _, _, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)
            .map_err(|_| ZfsWorkerError::Authority)?;
        self.armed = Some(self.timer.arm(cutoff));
        if matches!(self.armed, Some(Ok(()))) { Ok(()) } else { Err(worker_entry::retained()) }
    }

    fn retain_until_original_expiry_v3(&mut self) -> ! {
        if !matches!(self.armed, Some(Ok(()))) { std::process::abort(); }
        loop {
            let descriptor = match self.timer.descriptor() {
                Ok(descriptor) => descriptor, Err(_) => std::process::abort(),
            };
            let mut timer = [rustix::event::PollFd::new(&descriptor, rustix::event::PollFlags::IN)];
            self.polled = Some(rustix::event::poll(&mut timer, None));
            match self.polled.as_ref() {
                Some(Ok(count)) if *count > 0 => std::process::abort(),
                Some(Err(rustix::io::Errno::INTR)) | Some(Ok(0)) => {
                    // This nonacquiring wait has no owning prefix. The first
                    // actual Capture failure remains in its enclosing phase.
                    self.polled = None;
                }
                _ => std::process::abort(),
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FinalFailureV3 { Before, Encoding, Send, Receive, Subject, Membership, Expected, Compare, After }

struct FinalOriginalV3 {
    first: Option<FinalFailureV3>,
    encoded: Option<Result<[u8; wire::COMPLETED_BYTES_V3], ZfsWorkerError>>,
    sent: Option<ZfsWorkerSendAttemptV1>,
    ack: Option<Result<ReceivedRecord, ZfsWorkerReceiveErrorV1>>,
    subject: Option<Result<(), ZfsWorkerError>>,
    membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1,
    membership_status: Option<Result<(), aos_sandbox_linux::cgroup::ExactCgroupMembershipRefusalV1>>,
    expected: Option<Result<[u8; wire::FINAL_ACK_BYTES_V3], ZfsWorkerError>>,
    comparison: Option<Result<(), ZfsWorkerError>>,
    clocks: Option<crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3<2>>,
    clock_status: [Option<Result<(), ()>>; 2],
}

impl FinalOriginalV3 {
    fn new() -> Self {
        Self { first: None, encoded: None, sent: None, ack: None, subject: None,
            membership: aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::new(),
            membership_status: None, expected: None, comparison: None, clocks: None, clock_status: [None, None] }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)> { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            FinalFailureV3::Before => self.clocks.as_ref()?.failure_at_v3(0),
            FinalFailureV3::After => self.clocks.as_ref()?.failure_at_v3(1),
            FinalFailureV3::Encoding => error(&self.encoded),
            FinalFailureV3::Send => self.sent.as_ref()?.failure(),
            FinalFailureV3::Receive => error(&self.ack),
            FinalFailureV3::Subject => error(&self.subject),
            FinalFailureV3::Membership => self.membership.failure().map(|cause| cause as _),
            FinalFailureV3::Expected => error(&self.expected),
            FinalFailureV3::Compare => error(&self.comparison),
        }
    }

    fn send_and_wait_once_v3(
        &mut self, socket: &mut SeqpacketSocket, context: &AuthenticatedCaptureWorkerContextV3<'_>,
        completed: &crate::execution_capture_zfs_worker::CaptureWriterCompletionOriginalV3,
    ) -> Result<(), ZfsWorkerError> {
        if self.encoded.is_some() { return Err(ZfsWorkerError::Authority); }
        let (_, _, _, _, _, boot, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)
            .map_err(|_| ZfsWorkerError::Authority)?;
        self.clocks = Some(crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::from_worker_v3(context, boot, cutoff));
        let Some(clocks) = self.clocks.as_mut() else { std::process::abort(); };
        let body = (|| {
            self.first = Some(FinalFailureV3::Before);
            self.clock_status[0] = Some(clocks.observe_once_v3(0));
            if !matches!(self.clock_status[0], Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(FinalFailureV3::Encoding);
            self.encoded = Some(wire::encode_completed_v3(context, completed));
            let Some(Ok(bytes)) = self.encoded.as_ref() else { return Err(worker_entry::retained()); };
            self.first = Some(FinalFailureV3::Send);
            self.sent = Some(send_zfs_worker_record_v1(socket, bytes, ZfsWorkerSendKindV1::Request, cutoff));
            if self.sent.as_ref().is_none_or(|sent| !sent.is_sent()) { return Err(worker_entry::retained()); }
            self.first = Some(FinalFailureV3::Receive);
            self.ack = Some(receive_zfs_worker_record_v1(socket, ZfsWorkerRecordKindV1::Request, cutoff));
            let Some(Ok(ack)) = self.ack.as_ref() else { return Err(worker_entry::retained()); };
            self.first = Some(FinalFailureV3::Subject);
            self.subject = Some(verify_same_live_subject(context._parent.request_v3().subject(), ack.subject()));
            if !matches!(self.subject, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(FinalFailureV3::Membership);
            self.membership_status = Some(self.membership.capture_once(context._parent.parent_v3(), ack.subject().pidfd()));
            if !matches!(self.membership_status, Some(Ok(()))) { return Err(worker_entry::retained()); }
            self.first = Some(FinalFailureV3::Expected);
            self.expected = Some(wire::final_ack_data_v3(context.request_digest_v3(), context.source_v3().source_digest_v2(), bytes));
            self.first = Some(FinalFailureV3::Compare);
            self.comparison = Some(match self.expected.as_ref() {
                Some(Ok(expected)) if ack.payload() == expected => Ok(()),
                _ => Err(ZfsWorkerError::Authority),
            });
            if !matches!(self.comparison, Some(Ok(()))) { return Err(worker_entry::retained()); }
            Ok(())
        })();
        self.clock_status[1] = Some(clocks.observe_once_v3(1));
        if body.is_err() { return body; }
        if !matches!(self.clock_status[1], Some(Ok(()))) {
            self.first = Some(FinalFailureV3::After); return Err(worker_entry::retained());
        }
        self.first = None;
        Ok(())
    }
}

pub(in crate::process) fn run_authenticated_capture_v3(
    entry: &mut worker_entry::WorkerEntryOriginalV3,
    aggregate: &mut worker_aggregate::WorkerAggregateV1,
) -> Result<(), ZfsWorkerError> {
    let Some(worker_entry::CaptureEntryLoansV3 { parent, socket, contract, path }) = entry.borrow_capture_entry_v3()
        else { return Err(worker_entry::retained()); };
    // All actual destinations precede the selected scope. Its failure fence
    // cannot unwind through a reached pipe/file/mount/native original.
    let mut created = CaptureWorkerCreateOriginalV3::new();
    let mut negative = NegativeWaitOriginalV3::new();
    let mut created_send = None;
    let mut catalog = CaptureWorkerCatalogOriginalV3::new();
    let mut pipes: Option<Result<drain::CaptureDrainOriginalV3, ZfsWorkerError>> = None;
    let mut mounted: Option<Result<mounted::CaptureMountedSendOriginalV3, ZfsWorkerError>> = None;
    let mut completion = None;
    let mut final_turn = FinalOriginalV3::new();
    let mut execution = aggregate.borrow_capture_execution_scope_v3(path)?;
    created.prepare_parent_once_v3(parent, &execution)?;
    let Some(Ok(context)) = created.parent.as_ref() else { std::process::abort(); };
    negative.arm_once_v3(context)?;
    // Bind while the parent is borrowed, then end that borrow before entering
    // the mutable creation engine. A refused bind follows the same fail-stop
    // and diagnostic path as a refused first command.
    created.first = Some(CaptureWorkerFailureV3::Create);
    let bound = execution.bind_capture_process_cut_v3(context);
    let result = (|| {
        bound?;
        created.enter_once_v3(&mut execution, contract)?;
        let Some(Ok(context)) = created.parent.as_ref() else { return Err(worker_entry::retained()); };
        let Some(Ok(observed)) = created.created.as_ref() else { return Err(worker_entry::retained()); };
        let (_, _, _, _, _, _, cutoff) = crate::execution_output::capture_worker_inputs_v3(context)
            .map_err(|_| ZfsWorkerError::Authority)?;
        let bytes = wire::encode_created_v3(context, observed);
        created_send = Some(send_zfs_worker_record_v1(socket, &bytes, ZfsWorkerSendKindV1::Request, cutoff));
        if created_send.as_ref().is_none_or(|sent| !sent.is_sent()) { return Err(worker_entry::retained()); }
        catalog.receive_and_prepare_once_v3(socket, &created, &mut execution, contract)?;
        pipes = Some(drain::CaptureDrainOriginalV3::from_worker_v3(context));
        let Some(Ok(pipes)) = pipes.as_mut() else { return Err(worker_entry::retained()); };
        pipes.prepare_pipes_once_v3()?;
        mounted = Some(mounted::CaptureMountedSendOriginalV3::from_worker_v3(context));
        let Some(Ok(mounted)) = mounted.as_mut() else { return Err(worker_entry::retained()); };
        let Some(Ok(writer)) = catalog.writer.as_ref() else { return Err(worker_entry::retained()); };
        mounted.send_once_v3(socket, context, &catalog, writer, pipes, cutoff)?;
        pipes.release_child_writers_after_parent_ack_v3(socket, context)?;
        let Some(Ok(writer)) = catalog.writer.as_mut() else { return Err(worker_entry::retained()); };
        pipes.drain_to_eof_v3(writer)?;
        let Some(Ok(writer)) = catalog.writer.take() else { std::process::abort(); };
        completion = Some(crate::execution_capture_zfs_worker::CaptureWriterCompletionOriginalV3::from_prepared_v3(writer));
        let Some(completed) = completion.as_mut() else { std::process::abort(); };
        completed.run_once_v3(contract, Some((&mut execution, context)));
        if completed.result_v3().is_none() { return Err(worker_entry::retained()); }
        final_turn.send_and_wait_once_v3(socket, context, completed)?;
        Ok(())
    })();
    if result.is_err() {
        // Keep every reached native error and owner above alive. In particular,
        // budget exhaustion leaves both read ends open and performs no more IO.
        if let Some(cause) = execution.failure_v3().or_else(|| created.failure(&execution))
            .or_else(|| catalog.failure(&execution))
            .or_else(|| catalog.writer.as_ref()?.as_ref().ok()?.native_io_failure_v3())
            .or_else(|| pipes.as_ref()?.as_ref().ok()?.failure())
            .or_else(|| mounted.as_ref()?.as_ref().ok()?.failure())
            .or_else(|| completion.as_ref()?.failure()).or_else(|| final_turn.failure())
        { eprintln!("Capture worker retained failure: {cause}"); }
        negative.retain_until_original_expiry_v3();
    }
    // Only the parent's exact final report-bound ACK reaches this point. The
    // parent still owes whole-worker death/population and its armed F posts.
    execution.complete_after_ack_v1();
    Ok(())
}


pub(in crate::process) fn receiving_bytes_v3() -> Option<usize> {
    use crate::execution_capture_zfs_worker::{CaptureCreateExecutionOriginalV3,
        CaptureWriterPreparationFailureV2, CaptureWriterCompletionOriginalV3, PreparedDetachedCaptureWriterV1};
    let carriers = std::mem::size_of::<CaptureWorkerCreateOriginalV3<'static>>()
        .checked_add(std::mem::size_of::<CaptureCreateExecutionOriginalV3>())?
        .checked_add(std::mem::size_of::<CaptureWorkerCatalogOriginalV3>())?
        .checked_add(std::mem::size_of::<CaptureWriterPreparationFailureV2>())?
        .checked_add(std::mem::size_of::<PreparedDetachedCaptureWriterV1>())?
        .checked_add(std::mem::size_of::<CaptureWriterCompletionOriginalV3>())?
        .checked_add(std::mem::size_of::<drain::CaptureDrainOriginalV3>())?
        .checked_add(std::mem::size_of::<mounted::CaptureMountedSendOriginalV3>())?
        .checked_add(std::mem::size_of::<NegativeWaitOriginalV3>())?
        .checked_add(std::mem::size_of::<FinalOriginalV3>())?;
    // Actual fixed reservoirs: create3 + mount5 + mounted-send2 + pipe-ACK2
    // + EOF-completion2 + final-report/ACK2. Positive BOOT EOFs close serially;
    // all actual byte/native Results stay on these distinct owners.
    carriers.checked_mul(3)?
        .checked_add(crate::execution_capture_zfs_worker::CaptureWorkerClockOriginalV3::<37>::receiving_bytes_v3()?)?
        .checked_add(crate::execution_capture_files::capture_file_receiving_bytes_v2()?)?
        // Request DATA/root clones and the bounded codec model coexist with
        // the original actual packet. Both remain below the fixed24KiB wire
        // recipe; machine command argv plans are a separate plane below.
        .checked_add(3 * MAXIMUM_REQUEST_BYTES)?
        .checked_add(worker_aggregate::WorkerAggregateV1::capture_planner_requested_bytes_v3()?)
}
