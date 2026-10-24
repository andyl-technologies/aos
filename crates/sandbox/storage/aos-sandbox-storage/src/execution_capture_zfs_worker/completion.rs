//! Retains the actual EOF, sync/readback, mount and final ZFS completion phase.
//!
//! A successful file prefix is disposed only after its existing full readback.
//! Failed file/mount/native originals remain resident; neither parsing a result
//! nor completing this child alone admits a protected terminal record.

use super::*;
use crate::execution_capture_writer::CaptureWriterFinishFailureV2;
use crate::catalog_transition::execution_capture::readback::CaptureZfsReadbackV1;
use crate::process::{capture_worker, worker_aggregate};

#[derive(Clone, Copy)]
enum Failure { Before, Files, Directory, Plan, Observation, After }

pub(crate) struct CaptureWriterCompletionOriginalV3 {
    authority: AuthorizedCaptureWriterAttemptV1,
    writer: Option<DetachedCaptureWriterV1>,
    files: Option<Result<UnboundCaptureWriteResultV1, CaptureWriterFinishFailureV2>>,
    guard: Option<CaptureWriterDirectoryGuardV1>,
    directory_sync: Option<Result<(), CaptureFileCustodyErrorV1>>,
    detached: Option<DetachedMount>,
    mount_id: Option<u64>,
    before_digest: ObjectDigest,
    mounted_digest: ObjectDigest,
    plan: Option<Result<CaptureZfsReadbackPlanV1, CaptureZfsReadbackErrorV1>>,
    observation: crate::process::CaptureZfsObservationOriginalV3,
    observed: Option<Result<CaptureZfsReadbackV1, ()>>,
    clocks: Option<CaptureWorkerClockOriginalV3<2>>,
    clock_status: [Option<Result<(), ()>>; 2],
    ordinary_clock: [Option<Result<(), CaptureWriterWorkerErrorV1>>; 2],
    result: Option<UnboundCaptureWorkerResultV1>,
    first: Option<Failure>,
    entered: bool,
}

impl CaptureWriterCompletionOriginalV3 {
    pub(crate) fn from_prepared_v3(prepared: PreparedDetachedCaptureWriterV1) -> Self {
        let PreparedDetachedCaptureWriterV1 { authority, detached, writer, guard,
            before_observation_digest, mounted_observation_digest } = prepared;
        Self { authority, writer: Some(writer), files: None, guard: Some(guard),
            directory_sync: None, detached: Some(detached), mount_id: None,
            before_digest: before_observation_digest, mounted_digest: mounted_observation_digest,
            plan: None, observation: crate::process::CaptureZfsObservationOriginalV3::new(),
            observed: None, clocks: None, clock_status: [None, None], ordinary_clock: [None, None],
            result: None, first: None, entered: false }
    }

    pub(crate) fn run_once_v3(
        &mut self,
        zfs: &ZfsHelperContract,
        mut selected: Option<(&mut worker_aggregate::WorkerExecutionScopeV1<'_>,
            &capture_worker::AuthenticatedCaptureWorkerContextV3<'_>)>,
    ) {
        if self.entered { return; }
        self.entered = true;
        if let Some((_, context)) = selected.as_ref() {
            if self.authority.ongoing_source != Some(context.source_v3().source_digest_v2()) {
                self.ordinary_clock[0] = Some(Err(CaptureWriterWorkerErrorV1::InvalidAttempt));
                self.first = Some(Failure::Before);
                return;
            }
            self.clocks = Some(CaptureWorkerClockOriginalV3::from_worker_v3(
                context, self.authority.kernel_boot_id, self.authority.deadline_boottime_nanoseconds,
            ));
        }
        let body = (|| -> Result<(), ()> {
            self.first = Some(Failure::Before);
            if let Some(clocks) = self.clocks.as_mut() {
                self.clock_status[0] = Some(clocks.observe_once_v3(0));
                if !matches!(self.clock_status[0], Some(Ok(()))) { return Err(()); }
            } else {
                self.ordinary_clock[0] = Some(self.authority.check_live());
                if !matches!(self.ordinary_clock[0], Some(Ok(()))) { return Err(()); }
            }
            self.first = Some(Failure::Files);
            let Some(writer) = self.writer.take() else { std::process::abort(); };
            self.files = Some(writer.finish_retaining_v2());
            if !matches!(self.files, Some(Ok(_))) { return Err(()); }
            self.first = Some(Failure::Directory);
            let Some(guard) = self.guard.as_mut() else { std::process::abort(); };
            self.directory_sync = Some(guard.sync_after_write_selected_v3());
            if !matches!(self.directory_sync, Some(Ok(()))) { return Err(()); }
            let Some(detached) = self.detached.as_ref() else { std::process::abort(); };
            self.mount_id = Some(detached.mount_id().get());
            // Both streams and the directory are synced/read back. The old
            // engine closes these exact successful mount anchors before ZFS.
            drop(self.guard.take());
            drop(self.detached.take());
            self.first = Some(Failure::Plan);
            let Some(Ok(written)) = self.files.as_ref() else { std::process::abort(); };
            self.plan = Some(CaptureZfsReadbackPlanV1::after_write(
                &self.authority.verified, &self.authority.retained, written,
                self.authority.metadata_headroom_bytes, self.authority.minimum_remaining_bytes,
            ));
            let Some(Ok(plan)) = self.plan.as_ref() else { return Err(()); };
            self.first = Some(Failure::Observation);
            self.observed = Some(match selected.as_mut() {
                Some((scope, _)) => crate::process::observe_capture_zfs_in_scope_v3(
                    zfs, plan, &mut self.observation, scope, self.authority.deadline_boottime_nanoseconds,
                ),
                None => crate::process::observe_capture_zfs_retaining_v3(zfs, plan, &mut self.observation),
            });
            if !matches!(self.observed, Some(Ok(_))) { return Err(()); }
            self.first = None;
            Ok(())
        })();
        // The selected post is independently owed even after EOF, file sync,
        // directory or ZFS refusal. It never replaces an earlier actual cause.
        if let Some(clocks) = self.clocks.as_mut() {
            self.clock_status[1] = Some(clocks.observe_once_v3(1));
            if body.is_ok() && !matches!(self.clock_status[1], Some(Ok(()))) {
                self.first = Some(Failure::After);
            }
        } else if body.is_ok() {
            self.ordinary_clock[1] = Some(self.authority.check_live());
            if !matches!(self.ordinary_clock[1], Some(Ok(()))) { self.first = Some(Failure::After); }
        }
        if body.is_err() || self.first.is_some() { return; }
        let Some(Ok(written)) = self.files.take() else { std::process::abort(); };
        let Some(Ok(after)) = self.observed.as_ref() else { std::process::abort(); };
        let Some(mount_id) = self.mount_id else { std::process::abort(); };
        let mut result = UnboundCaptureWorkerResultV1 {
            attempt: self.authority.attempt, record_digest: self.authority.retained.record_digest(),
            dataset_binding: self.authority.verified.binding(), mount_id,
            before_observation_digest: self.before_digest, mounted_observation_digest: self.mounted_digest,
            after_observation_digest: after.observation_digest, written,
            result_digest: ObjectDigest::from_bytes([0; 32]),
        };
        result.result_digest = result.result_digest_data_v3(&CaptureWorkerResultIdentityDataV3 {
            attempt: self.authority.attempt, controller: self.authority.controller_grant_digest,
            host: self.authority.host_receipt_digest, durable: self.authority.durable_attempt_digest,
        });
        self.result = Some(result);
    }

    pub(crate) fn result_v3(&self) -> Option<&UnboundCaptureWorkerResultV1> {
        if !self.entered || self.first.is_some() { return None; }
        self.result.as_ref()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Before | Failure::After => {
                let index = usize::from(matches!(self.first, Some(Failure::After)));
                self.clocks.as_ref().and_then(|clock| clock.failure_at_v3(index))
                    .or_else(|| self.ordinary_clock[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            Failure::Files => self.files.as_ref()?.as_ref().err().and_then(|cause| {
                cause.native_io_failure_v3().or(Some(cause as _))
            }),
            Failure::Directory => self.guard.as_ref().and_then(|guard| guard.native_io_failure_v3())
                .or_else(|| self.directory_sync.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Failure::Plan => self.plan.as_ref()?.as_ref().err().map(|cause| cause as _),
            Failure::Observation => self.observation.failure(),
        }
    }

    #[cfg(test)]
    pub(super) fn into_ordinary_result_v3(mut self) -> Result<UnboundCaptureWorkerResultV1, CaptureWriterWorkerErrorV1> {
        if self.first.is_none() {
            return self.result.take().ok_or(CaptureWriterWorkerErrorV1::InvalidAttempt);
        }
        match self.first {
            Some(Failure::Before | Failure::After) => {
                let index = usize::from(matches!(self.first, Some(Failure::After)));
                match self.ordinary_clock[index].take() {
                    Some(Err(cause)) => Err(cause),
                    _ => Err(CaptureWriterWorkerErrorV1::InvalidAttempt),
                }
            }
            Some(Failure::Files) => match self.files.take() {
                Some(Err(cause)) => Err(CaptureWriterWorkerErrorV1::Writer(cause.into_ordinary_error())),
                _ => Err(CaptureWriterWorkerErrorV1::InvalidAttempt),
            },
            Some(Failure::Directory) => match self.directory_sync.take() {
                Some(Err(cause)) => Err(cause.into()), _ => Err(CaptureWriterWorkerErrorV1::InvalidAttempt),
            },
            Some(Failure::Plan) => match self.plan.take() {
                Some(Err(cause)) => Err(cause.into()), _ => Err(CaptureWriterWorkerErrorV1::InvalidAttempt),
            },
            Some(Failure::Observation) => Err(CaptureWriterWorkerErrorV1::Zfs(self.observation.take_ordinary_error_v3())),
            None => Err(CaptureWriterWorkerErrorV1::InvalidAttempt),
        }
    }
}
