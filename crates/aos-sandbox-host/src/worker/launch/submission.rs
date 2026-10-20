//! Submits Guardian and payload through one retained SDK disposition recipe.
//!
//! A prearmed same-flight read-only post always runs after the actual primary,
//! including refused construction/property/guard/start. Only complete local
//! bookends and native disposal/compaction can retire the matching SDK row.
//! The whole Launch and actual input pins remain resident for global posts.

use super::*;

pub(in crate::worker) struct PayloadSubmissionV3 {
    pub(in crate::worker) result: aos_systemd::JobResult,
}

enum Submission<'spec> {
    Guardian(&'spec aos_systemd::GuardianUnitSpec),
    Payload(&'spec aos_systemd::SandboxUnitSpec, aos_systemd::ExactUnitTarget),
}

impl Submission<'_> {
    fn role(&self) -> aos_systemd::ExactUnitRole {
        match self {
            Self::Guardian(_) => aos_systemd::ExactUnitRole::Guardian,
            Self::Payload(..) => aos_systemd::ExactUnitRole::Payload,
        }
    }

    fn call(&self) -> HostSystemdCallV2 {
        match self {
            Self::Guardian(_) => HostSystemdCallV2::GuardianStart,
            Self::Payload(..) => HostSystemdCallV2::PayloadStart,
        }
    }
}

enum SubmissionError {
    Guard(HostError),
    Systemd(aos_systemd::Error),
}

impl HostLaunchWorkerReceivingV2<'_, '_> {
    pub(super) async fn start_guardian(
        &mut self,
        worker: &super::super::SystemdOneShotWorker,
        spec: &aos_systemd::GuardianUnitSpec,
        identity: &super::super::HostRuntimeIdentity,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<super::super::GuardianStartObservation> {
        let (result, observation) = self.submit_unit_v3(
            worker, Submission::Guardian(spec), identity, before_effect,
        ).await?;
        Ok(super::super::GuardianStartObservation {
            job_done: result == aos_systemd::JobResult::Done,
            observation,
        })
    }

    pub(in crate::worker) async fn submit_payload_v3(
        &mut self,
        worker: &super::super::SystemdOneShotWorker,
        spec: &aos_systemd::SandboxUnitSpec,
        identity: &super::super::HostRuntimeIdentity,
        guardian: aos_systemd::ExactUnitTarget,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<PayloadSubmissionV3> {
        if self.payload_entry.is_some() {
            return Err(closed("payload start has an unconsumed exact entry observation"));
        }
        let (result, observation) = self.submit_unit_v3(
            worker, Submission::Payload(spec, guardian), identity, before_effect,
        ).await?;
        // This is the actual prearmed exact-before-verification row, retained
        // also after a failed submission. It is neither recreated nor counted
        // as a second healthy observation by the verification recipe.
        self.payload_entry = Some(observation);
        Ok(PayloadSubmissionV3 { result })
    }

    pub(in crate::worker) async fn observe_payload_entry_v3(
        &mut self,
        worker: &super::super::SystemdOneShotWorker,
        identity: &super::super::HostRuntimeIdentity,
    ) -> Result<super::super::GuardianObservation> {
        self.require_current()?;
        match self.payload_entry.take() {
            Some(observed) => Ok(observed),
            None => self.observe_exact(worker, identity, aos_systemd::ExactUnitRole::Payload, None).await,
        }
    }

    async fn submit_unit_v3(
        &mut self,
        worker: &super::super::SystemdOneShotWorker,
        submission: Submission<'_>,
        identity: &super::super::HostRuntimeIdentity,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<(aos_systemd::JobResult, super::super::GuardianObservation)> {
        self.require_current()?;
        {
            let mut original = self.original.lock().await;
            let binding = match &submission {
                Submission::Guardian(spec) => {
                    if spec.name() != aos_systemd::SandboxUnitName::from_incarnation(
                        *identity.incarnation_id()).guardian()
                    {
                        return Err(closed("Guardian submission names another scope"));
                    }
                    spec.binding()
                }
                Submission::Payload(spec, _) => spec.launch_binding()
                    .ok_or_else(|| closed("payload submission has no original binding"))?,
            };
            match (original.compensation_scope, &submission) {
                (None, Submission::Guardian(_)) => original.compensation_scope = Some((*identity, binding)),
                (Some(scope), _) if scope == (*identity, binding) => {}
                _ => return Err(closed("submission differs from its original Guardian scope")),
            }
        }
        let role = submission.role();
        let receiver = self.prepare_call(submission.call(), CallObligationV2::Primary).await?;
        let post = self.prearm_readonly_post(&receiver, HostSystemdCallV2::ExactObserve).await?;
        {
            let mut row = receiver.lock().await;
            let primary = async {
                row.connect(self.deadline).await?;
                let result = row.submit_once_v3(submission, before_effect).await?;
                row.record_job_result_v3(result);
                Ok(())
            }.await;
            match primary {
                Ok(()) => {}
                Err(error) => {
                    row.readback = Some(error);
                    row.first.get_or_insert(CallFailureV2::NativeReadback);
                    row.primary = Some(Err(closed("unit start primary failed; original retained")));
                }
            }
        }
        self.record_failure(&receiver).await;

        // The same actual post is entered even after primary poison; the
        // private Owed loan cannot perform another effect or healthy reentry.
        let observation = self.observe_exact(worker, identity, role, Some(post)).await;
        {
            let mut row = receiver.lock().await;
            if let Err(error) = observation.as_ref() {
                row.readback.get_or_insert_with(|| HostError::Worker(error.to_string()));
                row.first.get_or_insert(CallFailureV2::NativeReadback);
            }
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
        let result = {
            let row = receiver.lock().await;
            if !matches!(row.first, None | Some(CallFailureV2::JobResult)) || observation.is_err()
                || !matches!(row.disposition, Some(Ok(())))
            {
                drop(row);
                return Err(self.retained_failure().await);
            }
            row.job_result.clone().ok_or_else(|| closed("unit job result is absent"))?
        };
        // Failed jobs stay resident without a disposal/compaction proof or
        // peak credit, while the old semantic reducer receives its same result.
        Ok((result, observation?))
    }
}

impl SystemdCallOriginalV2 {
    pub(super) fn record_job_result_v3(&mut self, result: aos_systemd::JobResult) {
        self.job_result = Some(result);
        if matches!(self.job_result, Some(aos_systemd::JobResult::Done)) {
            self.primary = Some(Ok(()));
        } else {
            self.primary = Some(Err(closed("unit job failed; actual typed result retained")));
            self.first.get_or_insert(CallFailureV2::JobResult);
        }
    }

    async fn submit_once_v3(
        &mut self,
        submission: Submission<'_>,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<aos_systemd::JobResult> {
        let role = submission.role();
        let outcome = match submission {
            Submission::Guardian(spec) => {
                self.guardian = Some(GuardianUnitPropertyOriginalV2::new());
                let Self { native, guardian, .. } = self;
                let client = native.client_v2()
                    .ok_or_else(|| closed("Guardian start lost its same connected client"))?;
                let properties = guardian.as_mut()
                    .ok_or_else(|| closed("Guardian start lost its property original"))?;
                client.start_guardian_unit_guarded_retaining_v2(spec, properties, before_effect).await
                    .map_err(|error| match error {
                        aos_systemd::GuardianStartError::Guard(error) => SubmissionError::Guard(error),
                        aos_systemd::GuardianStartError::Systemd(error) => SubmissionError::Systemd(error),
                    })
            }
            Submission::Payload(spec, guardian) => {
                self.payload = Some(PayloadUnitPropertyOriginalV2::new());
                let client = match self.native.take_exact_client_once_v2() {
                    Ok(client) => client,
                    Err(error) => {
                        self.operation = Some(error);
                        self.first.get_or_insert(CallFailureV2::Operation);
                        return Err(closed("payload exact-client transfer failed; original retained"));
                    }
                };
                let properties = self.payload.as_mut()
                    .ok_or_else(|| closed("payload start lost its property original"))?;
                client.start_payload_guarded_retaining_v2(spec, properties, guardian, before_effect).await
                    .map_err(|error| match error {
                        aos_systemd::ExactStartError::Guard(error) => SubmissionError::Guard(error),
                        aos_systemd::ExactStartError::Systemd(error) => SubmissionError::Systemd(error),
                    })
            }
        };
        match outcome {
            Ok(outcome) => Ok(outcome.result),
            Err(SubmissionError::Guard(error)) => {
                self.guard = Some(error);
                self.first.get_or_insert(CallFailureV2::Guard);
                Err(closed("unit effect guard failed; original retained"))
            }
            Err(SubmissionError::Systemd(error)) => {
                let properties = match role {
                    aos_systemd::ExactUnitRole::Guardian => self.guardian.as_ref().and_then(|owner| owner.failure()).is_some(),
                    aos_systemd::ExactUnitRole::Payload => self.payload.as_ref().and_then(|owner| owner.failure()).is_some(),
                };
                self.operation = Some(error);
                self.first.get_or_insert(match (role, properties) {
                    (aos_systemd::ExactUnitRole::Guardian, true) => CallFailureV2::GuardianProperties,
                    (aos_systemd::ExactUnitRole::Payload, true) => CallFailureV2::PayloadProperties,
                    _ => CallFailureV2::Operation,
                });
                Err(closed("unit submission failed; original retained"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_job_keeps_the_same_typed_result_and_cannot_dispose_its_row() {
        let schedule = HostSystemdCallV2::GuardianStart.receiving_schedule_v2(16, 16, 16, 0).unwrap();
        let mut original = SystemdCallOriginalV2::new(
            0, HostSystemdCallV2::GuardianStart, schedule, None, Weak::new(), None, None,
        );
        original.record_job_result_v3(aos_systemd::JobResult::Failed);
        let actual = original.job_result.as_ref().unwrap() as *const _;
        original.disposition = Some(Ok(()));

        assert!(original.dispose_positive().await.is_err());

        assert_eq!(original.job_result, Some(aos_systemd::JobResult::Failed));
        assert_eq!(original.job_result.as_ref().unwrap() as *const _, actual);
        assert!(matches!(original.first, Some(CallFailureV2::JobResult)));
        assert!(!original.storage_is_physically_compacted());
        assert!(original.disposal.is_none());
        assert!(original.compaction.is_none());
        assert!(CallFailureViewV2(&original).to_string().contains("Failed"));
    }
}
