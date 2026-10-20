//! Runs exact Stop and post-unref observation on the same paid Launch roster.
//!
//! The kernel proof is parked before the SDK acquires its unit reference. Both
//! callbacks borrow that original only during their synchronous native recipe;
//! no Stage mutex is held while an SDK effect write invokes its clock callback.

use super::*;

impl HostLaunchWorkerReceivingV2<'_, '_> {
    pub(crate) async fn observe_post_unref_v3(
        &mut self,
        worker: &super::super::RetainedPayloadWorkerV1<'_>,
        identity: &super::super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
    ) -> Result<super::super::GuardianObservation> {
        self.observe_exact_kind_v3(worker.worker, identity, role, None, true, None).await
    }

    pub(crate) async fn stop_exact_unit_v3(
        &mut self,
        worker: &super::super::RetainedPayloadWorkerV1<'_>,
        identity: &super::super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        binding: [u8; 32],
        invocation_id: [u8; 16],
    ) -> Result<super::super::ExactWorkerStopOutcome> {
        self.stop_exact_unit_engine_v1(worker, identity, role, binding, invocation_id,
            CallObligationV2::Primary).await
    }

    pub(super) async fn stop_exact_unit_engine_v1(
        &mut self,
        worker: &super::super::RetainedPayloadWorkerV1<'_>,
        identity: &super::super::HostRuntimeIdentity,
        role: aos_systemd_client::ExactUnitRole,
        binding: [u8; 32],
        invocation_id: [u8; 16],
        obligation: CallObligationV2,
    ) -> Result<super::super::ExactWorkerStopOutcome> {
        let compensation = match &obligation {
            CallObligationV2::Compensation(permit) => Some(*permit),
            _ => None,
        };
        let target = aos_systemd_client::ExactUnitTarget::new(binding, invocation_id)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let receiver = self.prepare_call(HostSystemdCallV2::ExactStop, obligation).await?;
        {
            let mut row = receiver.lock().await;
            let primary = async {
                row.stop_native = Some(Arc::new(std::sync::Mutex::new(
                    super::super::systemd::StopQuiescenceOriginalV3::new(),
                )));
                row.connect(self.deadline).await?;
                let client = match row.native.take_exact_client_once_v2() {
                    Ok(client) => client,
                    Err(error) => {
                        row.operation = Some(error);
                        row.first.get_or_insert(CallFailureV2::Operation);
                        return Err(closed("Stop exact client transfer failed; original retained"));
                    }
                };
                let original = row.stop_native.as_ref().cloned()
                    .ok_or_else(|| closed("Stop native original is absent"))?;
                let mut prepare = |observation: &aos_systemd_client::ExactUnitObservation| {
                    original.lock().map_err(|_| closed("Stop preparation lock is poisoned"))?
                        .prepare_once_v3(&worker.worker.cgroup_root, observation)
                };
                let mut confirm = |observation: &aos_systemd_client::ExactUnitObservation| {
                    original.lock().map_err(|_| closed("Stop confirmation lock is poisoned"))?
                        .confirm_once_v3(&worker.worker.cgroup_root, observation)
                };
                let name = aos_systemd_client::SandboxUnitName::from_incarnation(*identity.incarnation_id());
                let outcome = client.stop_exact_unit_prepared(&name, role, target, &mut prepare, &mut confirm).await;
                match outcome {
                    Ok(outcome) => {
                        if let aos_systemd_client::ExactStopOutcome::JobFailed(result) = &outcome {
                            row.record_job_result_v3(result.clone());
                        } else {
                            row.primary = Some(Ok(()));
                        }
                        row.stop_result = Some(outcome);
                        Ok(())
                    }
                    Err(aos_systemd_client::ExactStopError::Systemd(error)) => {
                        row.operation = Some(error);
                        row.first.get_or_insert(CallFailureV2::Operation);
                        Err(closed("Stop SDK failed; actual error retained"))
                    }
                    Err(aos_systemd_client::ExactStopError::Quiescence(error)) => {
                        row.readback = Some(error);
                        row.first.get_or_insert(CallFailureV2::NativeReadback);
                        Err(closed("Stop quiescence failed; actual originals retained"))
                    }
                }
            }.await;
            if let Err(error) = primary {
                row.readback.get_or_insert(error);
                row.first.get_or_insert(CallFailureV2::NativeReadback);
                row.primary = Some(Err(closed("Stop primary failed; original retained")));
            }
            // Connection disposition is independently owed after every reached
            // constructor/primary result, including either native callback.
            row.finish().await;
            if row.first.is_none() {
                match self.receiving.require_launch_readonly_post_request_v2(self.request) {
                    Ok(()) => { let _ = row.dispose_positive().await; }
                    Err(error) => {
                        row.guard = Some(error);
                        row.first.get_or_insert(CallFailureV2::Guard);
                    }
                }
            }
        }
        self.record_failure(&receiver).await;
        let projected = {
            let row = receiver.lock().await;
            if !matches!(row.first, None | Some(CallFailureV2::JobResult))
                || !matches!(row.disposition, Some(Ok(())))
            {
                drop(row);
                return Err(self.retained_failure().await);
            }
            match row.stop_result.as_ref().ok_or_else(|| closed("Stop result is absent"))? {
                aos_systemd_client::ExactStopOutcome::MissingManagerObject => Some(super::super::ExactWorkerStopOutcome::Missing),
                aos_systemd_client::ExactStopOutcome::Foreign(observation) => Some(super::super::ExactWorkerStopOutcome::Foreign(
                    super::super::systemd::project_exact_observation_ref_v3(observation),
                )),
                aos_systemd_client::ExactStopOutcome::Residual(observation) => Some(super::super::ExactWorkerStopOutcome::Residual(
                    super::super::systemd::project_exact_observation_ref_v3(observation),
                )),
                aos_systemd_client::ExactStopOutcome::AwaitingAbsence(observation) => Some(super::super::ExactWorkerStopOutcome::AwaitingAbsence(
                    super::super::systemd::project_exact_observation_ref_v3(observation),
                )),
                aos_systemd_client::ExactStopOutcome::JobFailed(_) => None,
            }
        };
        // Preserve the old additional observation only for the actual typed
        // failed job. It is a fresh paid read, never an effect or healthy reset.
        match projected {
            Some(outcome) => Ok(outcome),
            None => Ok(super::super::ExactWorkerStopOutcome::Residual(
                self.observe_exact_kind_v3(worker.worker, identity, role, None, false, compensation).await?,
            )),
        }
    }
}
