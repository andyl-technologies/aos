//! Scopes native fixture aliases beneath their actual prepared Main role.
//!
//! This helper issues no Main, Source, queue or Original. Its only input is the
//! real role returned by the SAME production factory before Service startup.
//! The standalone native test ELF still needs a genuine deployed Main provider.

use super::*;
use crate::lifecycle_cleanup::{
    PreparedSourceRefusal, PreparedSourceRetirement, ServiceMainHandle, ServiceMainPreclaimError,
    ServiceMainReceiverHandle,
};
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateServiceFactory;

/// Keeps one real transport receiver around its exact local Context alias.
pub(in crate::packaged_qemu_executor::tests) struct NativeServiceScope {
    role: ServiceMainHandle,
    context: Option<AttemptExecutionContext>,
    receiver: Option<ServiceMainReceiverHandle>,
    destruction_started: bool,
}

/// Preserves failed status independently from actual physical terminal return.
#[derive(Debug)]
pub(in crate::packaged_qemu_executor::tests) enum NativeServiceReturnError {
    Pending(NativeServiceReturnRefusal),
    Terminal(NativeServiceTerminal),
}

impl std::fmt::Display for NativeServiceReturnError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending(refusal) => std::fmt::Display::fmt(refusal, output),
            Self::Terminal(terminal) => std::fmt::Display::fmt(terminal, output),
        }
    }
}

/// Retains actual pending custody and independent receiver/retry observations.
#[derive(Debug)]
pub(in crate::packaged_qemu_executor::tests) struct NativeServiceReturnRefusal {
    retirement: PreparedSourceRetirement,
    acknowledgment: Option<ServiceMainPreclaimError>,
    retry: Option<PreparedSourceRefusal>,
}

impl std::fmt::Display for NativeServiceReturnRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "native fixture return: acknowledgment={:?}; retry={:?}",
            self.acknowledgment, self.retry
        )?;
        let mut result = Ok(());
        self.retirement.with_history(|phase, first| {
            if result.is_ok() {
                result = write!(output, "; {phase}: {first}");
            }
        });
        result
    }
}

/// Retains terminal native history and the independent retry observation.
#[derive(Debug)]
pub(in crate::packaged_qemu_executor::tests) struct NativeServiceTerminal {
    body: crate::ProductionVmConstructionPostBody,
    retry: Option<PreparedSourceRefusal>,
}

impl std::fmt::Display for NativeServiceTerminal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "retry={:?}; {}", self.retry, self.body)
    }
}

impl NativeServiceScope {
    pub(in crate::packaged_qemu_executor::tests) fn comparison(
        role: ServiceMainHandle,
        services: &RetainedTemplateServiceFactory,
        source: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Self {
        match role
            .with_start(|start| services.start_comparison_child_for_test(start, source, original))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("{}", role.failure("native comparison Service startup")),
            Err(raw) => panic!(
                "{}",
                role.failure_with_refusal("borrow native comparison Service", raw)
            ),
        }
        Self::from_ready(role)
    }

    /// Acknowledges only this fixture's actual Context alias destruction.
    pub(in crate::packaged_qemu_executor::tests) fn release_context_aliases(&mut self) {
        drop(self.context.take());
        if let Some(receiver) = self.receiver.take() {
            receiver
                .return_after_alias_destruction()
                .expect("same receiver observes actual comparison Context destruction");
        }
        self.destruction_started = true;
    }

    /// Checks the original role's journal after runtime-owned terminal disposal.
    pub(in crate::packaged_qemu_executor::tests) fn assert_released(self) {
        assert!(self.context.is_none() && self.receiver.is_none());
        assert!(
            self.role
                .prepared_selector()
                .is_released()
                .expect("same original comparison role completion journal")
        );
    }

    pub(in crate::packaged_qemu_executor::tests) fn resume(
        role: ServiceMainHandle,
        services: &RetainedTemplateServiceFactory,
        source: &ScenarioDefForm,
        checkpoint: crucible_campaign::ExactCheckpointId,
        original: &AttemptExecutionContext,
    ) -> Self {
        match role
            .with_start(|start| services.start_for_resume(start, source, checkpoint, original))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("{}", role.failure("native resume Service startup")),
            Err(raw) => panic!(
                "{}",
                role.failure_with_refusal("borrow native resume Service", raw)
            ),
        }
        assert!(
            original
                .try_take_selected_checkpoint()
                .expect("same checked original selection slot")
                .is_none(),
            "source Service consumes the linear root only on success"
        );
        Self::from_ready(role)
    }

    pub(in crate::packaged_qemu_executor::tests) fn causal(
        role: ServiceMainHandle,
        services: &RetainedTemplateServiceFactory,
        source: &ScenarioDefForm,
        original: &AttemptExecutionContext,
    ) -> Self {
        match role
            .with_start(|start| services.start_causal_source_for_test(start, source, original))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("{}", role.failure("native causal Service startup")),
            Err(raw) => panic!(
                "{}",
                role.failure_with_refusal("borrow native causal Service", raw)
            ),
        }
        Self::from_ready(role)
    }

    fn from_ready(role: ServiceMainHandle) -> Self {
        let receiver = match role.retain_receiver_in_main() {
            Ok(receiver) => receiver,
            Err(raw) => panic!(
                "{}",
                role.failure_with_refusal("retain native context receiver", raw)
            ),
        };
        let mut scope = Self {
            role,
            context: None,
            receiver: Some(receiver),
            destruction_started: false,
        };
        scope.context = Some(
            match scope.role.with_ready(|ready| ready.context().clone()) {
                Ok(context) => context,
                Err(raw) => panic!(
                    "{}",
                    scope
                        .role
                        .failure_with_refusal("project native Context", raw)
                ),
            },
        );
        scope
    }

    pub(in crate::packaged_qemu_executor::tests) fn context(&self) -> &AttemptExecutionContext {
        self.context
            .as_ref()
            .expect("local fixture alias remains live")
    }

    pub(in crate::packaged_qemu_executor::tests) fn try_body_retirement(
        &self,
    ) -> Result<bool, ServiceMainPreclaimError> {
        self.role.retry_prepared_body()
    }

    /// Leaves unknown cleanup in the same actual Main role without a new owner.
    pub(in crate::packaged_qemu_executor::tests) fn retain_in_main(self) {
        self.role.prepared_selector().request_retirement();
        // Drop acknowledges only this local alias. Actual body/World return
        // remains an independent Main journal and cannot follow from that ACK.
    }

    /// Returns actual terminal custody only after local aliases are destroyed.
    ///
    /// The returned typed payload may contain historical errors; callers report
    /// those independently before destroying it and checking released credit.
    pub(in crate::packaged_qemu_executor::tests) fn into_retirement(
        mut self,
    ) -> Result<NativeServiceTerminal, NativeServiceReturnError> {
        self.destruction_started = true;
        drop(self.context.take());
        let acknowledgment = self
            .receiver
            .take()
            .and_then(|receiver| receiver.return_after_alias_destruction().err());
        let mut retirement = self.role.clone().into_retirement();
        if acknowledgment.is_some() {
            return Err(NativeServiceReturnError::Pending(
                NativeServiceReturnRefusal {
                    retirement,
                    acknowledgment,
                    retry: None,
                },
            ));
        }
        let retry = retirement.retry().err();
        match retirement.finish() {
            Ok(body) => {
                let failed = retry.is_some() || body.first_failure().is_some();
                let terminal = NativeServiceTerminal { body, retry };
                if failed {
                    Err(NativeServiceReturnError::Terminal(terminal))
                } else {
                    Ok(terminal)
                }
            }
            Err(retirement) => Err(NativeServiceReturnError::Pending(
                NativeServiceReturnRefusal {
                    retirement,
                    acknowledgment: None,
                    retry,
                },
            )),
        }
    }
}

impl Drop for NativeServiceScope {
    fn drop(&mut self) {
        if self.destruction_started {
            return;
        }
        self.role.prepared_selector().request_retirement();
        self.destruction_started = true;
        drop(self.context.take());
        if let Some(receiver) = self.receiver.take() {
            // The actual Main token journals alias destruction before its
            // fallible observation; refusal cannot free the native World.
            let _observation = receiver.return_after_alias_destruction();
        }
    }
}
