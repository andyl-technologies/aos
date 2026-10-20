//! Retains the same one-shot create/preflight recipe before native refusal.
//!
//! The ordinary adapter and authenticated worker share this exact sequence.
//! The destination keeps the actual source owner, preflight outputs, checked
//! command, entered effect and chronological error. A zero exit still returns
//! only an attempted-effect record; catalog/readback and mount remain separate.

use super::*;
use crate::catalog_transition::execution_capture::readback::CaptureZfsPreflightV1;

use super::clock::CaptureWorkerClockOriginalV3;

#[derive(Clone, Copy)]
enum Failure { Before, Outputs, Preflight, Pool, Command, Entry }

pub(crate) struct CaptureCreateExecutionOriginalV3 {
    authority: AuthorizedCaptureCreateAttemptV1,
    before: Option<Result<(), CaptureCreateWorkerErrorV1>>,
    outputs: Option<Result<[Vec<u8>; 2], ZfsWorkerError>>,
    preflight: Option<Result<CaptureZfsPreflightV1, CaptureZfsReadbackErrorV1>>,
    pool: Option<Result<(), CaptureZfsReadbackErrorV1>>,
    command: Option<Result<CaptureZfsCreateCommandV1, CaptureZfsReadbackErrorV1>>,
    entry: Option<Result<(), CaptureCreateWorkerErrorV1>>,
    attempted: Option<CaptureCreateAttemptedV1>,
    first: Option<Failure>,
    entered: bool,
    native_clock: Option<CaptureWorkerClockOriginalV3<3>>,
    owed_clock: Option<Result<(), CaptureCreateWorkerErrorV1>>,
}

impl CaptureCreateExecutionOriginalV3 {
    pub(super) fn new(authority: AuthorizedCaptureCreateAttemptV1) -> Self {
        Self { authority, before: None, outputs: None, preflight: None, pool: None,
            command: None, entry: None, attempted: None, first: None, entered: false,
            native_clock: None, owed_clock: None }
    }

    pub(crate) fn prepare_authenticated_worker_v3(
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
    ) -> Result<Self, CaptureCreateWorkerErrorV1> {
        let (retained, attempt, controller, host, durable, boot, deadline) =
            crate::execution_output::capture_worker_inputs_v3(context)
                .map_err(CaptureCreateWorkerErrorV1::Source)?;
        let preflight = CaptureZfsPreflightPlanV1::new(context.requirement_v3(), &retained,
            context.metadata_headroom_v3(), context.remaining_floor_v3())?;
        let authority = AuthorizedCaptureCreateAttemptV1 {
            attempt, controller_grant_digest: controller, host_receipt_digest: host,
            durable_attempt_digest: durable, kernel_boot_id: boot,
            deadline_boottime_nanoseconds: deadline, retained,
            requirement: context.requirement_v3().clone(), preflight,
            expected_pool_guid: context.pool_guid_v3(),
        };
        Ok(Self::from_authenticated_parent_v3(authority, context))
    }

    pub(super) fn from_authenticated_parent_v3(
        authority: AuthorizedCaptureCreateAttemptV1,
        context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
    ) -> Self {
        let mut original = Self::new(authority);
        original.native_clock = Some(CaptureWorkerClockOriginalV3::from_worker_v3(
            context, original.authority.kernel_boot_id, original.authority.deadline_boottime_nanoseconds,
        ));
        original
    }

    fn observe_live_v3(&mut self, index: usize) -> Result<(), CaptureCreateWorkerErrorV1> {
        let Some(clock) = self.native_clock.as_mut() else { return self.authority.check_live(); };
        clock.observe_once_v3(index).map_err(|()| CaptureCreateWorkerErrorV1::InvalidAttempt)
    }

    pub(crate) fn run_once_v3<B: CaptureCreateBackendV1>(&mut self, backend: &mut B) {
        if self.entered { return; }
        self.entered = true;
        self.run_body_v3(backend);
        if self.native_clock.is_some() {
            // Its distinct actual native reservoir is prepaid before create.
            // This source post is owed even after preflight or effect failure.
            self.owed_clock = Some(self.observe_live_v3(2));
        }
    }

    fn run_body_v3<B: CaptureCreateBackendV1>(&mut self, backend: &mut B) {
        self.first = Some(Failure::Before);
        self.before = Some(self.observe_live_v3(0));
        if !matches!(self.before, Some(Ok(()))) { return; }
        self.first = Some(Failure::Outputs);
        self.outputs = Some(backend.observe_preflight(&self.authority, &self.authority.preflight));
        let Some(Ok(outputs)) = self.outputs.as_ref() else { return; };
        self.first = Some(Failure::Preflight);
        self.preflight = Some(self.authority.preflight.evaluate([&outputs[0], &outputs[1]]));
        let Some(Ok(observed)) = self.preflight.as_ref() else { return; };
        self.first = Some(Failure::Pool);
        self.pool = Some(if observed.pool_guid == self.authority.expected_pool_guid {
            Ok(())
        } else { Err(CaptureZfsReadbackErrorV1::DatasetMismatch) });
        if !matches!(self.pool, Some(Ok(()))) { return; }
        self.first = Some(Failure::Command);
        self.command = Some(CaptureZfsCreateCommandV1::new(
            &self.authority.requirement, &self.authority.retained, observed,
        ));
        if !matches!(self.command, Some(Ok(_))) { return; }
        self.first = Some(Failure::Entry);
        self.entry = Some(self.observe_live_v3(1));
        if !matches!(self.entry, Some(Ok(()))) { return; }
        let Some(Ok(command)) = self.command.as_ref() else { std::process::abort(); };
        let effect_result = backend.create(&self.authority, command);
        let reported_zero_exit = matches!(effect_result, Ok(true));
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_DOMAIN);
        digest.update(self.authority.attempt);
        digest.update(self.authority.controller_grant_digest.as_bytes());
        digest.update(self.authority.host_receipt_digest.as_bytes());
        digest.update(self.authority.durable_attempt_digest.as_bytes());
        digest.update(self.authority.kernel_boot_id);
        digest.update(self.authority.deadline_boottime_nanoseconds.to_be_bytes());
        digest.update(command.record_digest.as_bytes());
        digest.update(command.storage_create_operation.as_bytes());
        digest.update(command.preflight_digest.as_bytes());
        digest.update(command.command_digest.as_bytes());
        digest.update([u8::from(reported_zero_exit)]);
        self.attempted = Some(CaptureCreateAttemptedV1 {
            attempt: self.authority.attempt,
            record_digest: command.record_digest,
            storage_create_operation: command.storage_create_operation,
            controller_grant_digest: self.authority.controller_grant_digest,
            host_receipt_digest: self.authority.host_receipt_digest,
            durable_attempt_digest: self.authority.durable_attempt_digest,
            kernel_boot_id: self.authority.kernel_boot_id,
            deadline_boottime_nanoseconds: self.authority.deadline_boottime_nanoseconds,
            preflight_digest: command.preflight_digest,
            command_digest: command.command_digest,
            reported_zero_exit, effect_result,
            attempt_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        });
        self.first = None;
    }

    pub(crate) fn attempted_v3(&self) -> Option<&CaptureCreateAttemptedV1> {
        self.attempted.as_ref()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first {
            Some(Failure::Before) => self.native_clock.as_ref().and_then(|clock| clock.failure_at_v3(0))
                .or_else(|| error(&self.before)),
            Some(Failure::Outputs) => error(&self.outputs),
            Some(Failure::Preflight) => error(&self.preflight),
            Some(Failure::Pool) => error(&self.pool),
            Some(Failure::Command) => error(&self.command),
            Some(Failure::Entry) => self.native_clock.as_ref().and_then(|clock| clock.failure_at_v3(1))
                .or_else(|| error(&self.entry)),
            None => self.attempted.as_ref().and_then(|attempt| attempt.effect_failure_v2().map(|cause| cause as _))
                .or_else(|| self.owed_clock_failure_v3()),
        }
    }

    pub(crate) fn owed_clock_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native_clock.as_ref().and_then(|clock| clock.failure_at_v3(2))
            .or_else(|| self.owed_clock.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(crate) fn can_continue_after_create_v3(&self) -> bool {
        self.first.is_none() && self.owed_clock_failure_v3().is_none()
            && self.attempted.as_ref().is_some_and(|attempt|
                attempt.reported_zero_exit && attempt.effect_failure_v2().is_none())
    }

    pub(super) fn into_ordinary_result_v3(mut self)
        -> Result<CaptureCreateAttemptedV1, CaptureCreateWorkerErrorV1>
    {
        if let Some(attempted) = self.attempted.take() { return Ok(attempted); }
        let cause = match self.first {
            Some(Failure::Before) => self.before.take().and_then(Result::err),
            Some(Failure::Outputs) => self.outputs.take().and_then(Result::err).map(Into::into),
            Some(Failure::Preflight) => self.preflight.take().and_then(Result::err).map(Into::into),
            Some(Failure::Pool) => self.pool.take().and_then(Result::err).map(Into::into),
            Some(Failure::Command) => self.command.take().and_then(Result::err).map(Into::into),
            Some(Failure::Entry) => self.entry.take().and_then(Result::err),
            None => None,
        };
        Err(cause.unwrap_or(CaptureCreateWorkerErrorV1::InvalidAttempt))
    }
}
