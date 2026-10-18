//! Scopes retained-source capture under its actual Main-owned Service.
//!
//! A transport receiver precedes the only local context alias. The Service
//! mutex is released before native capture, and alias destruction precedes
//! acknowledgment. Operation and acknowledgment failures stay independent.

use super::*;
use crate::lifecycle_cleanup::{
    PreparedSourceFailure, ServiceMainHandle, ServiceMainPreclaimError, ServiceMainReceiverHandle,
};

/// Retains independent capture, receiver-return and terminal failure evidence.
#[derive(Debug)]
pub struct RetainedSourceCaptureFailure<E> {
    first: Option<E>,
    receiver_return: Option<PreparedSourceFailure>,
    retirement: Option<crate::lifecycle_cleanup::PreparedSourceRetirement>,
    retirement_refusal: Option<crate::lifecycle_cleanup::PreparedSourceRefusal>,
    terminal: Option<std::sync::Mutex<crate::ProductionVmConstructionPostBody>>,
}

impl<E> RetainedSourceCaptureFailure<E> {
    pub(super) fn operation(first: E) -> Self {
        Self {
            first: Some(first),
            receiver_return: None,
            retirement: None,
            retirement_refusal: None,
            terminal: None,
        }
    }

    /// Borrows the original capture cause, independently of return failures.
    #[must_use]
    pub fn first_error(&self) -> Option<&E> {
        self.first.as_ref()
    }

    /// Visits retirement history while retaining its original owner or payload.
    ///
    /// Returns `false` when this report contains no observable retirement history. The
    /// callback must not reenter this report's history projection.
    pub fn with_retirement_history(
        &self,
        apply: impl FnMut(&'static str, crate::LifecycleHistoryRef<'_>),
    ) -> bool {
        if let Some(retirement) = &self.retirement {
            return retirement.with_history(apply);
        }
        let Some(terminal) = &self.terminal else {
            return false;
        };
        let body = match terminal.lock() {
            Ok(body) => body,
            Err(poisoned) => poisoned.into_inner(),
        };
        body.visit_history(apply);
        true
    }
}

impl<E: std::fmt::Display> std::fmt::Display for RetainedSourceCaptureFailure<E> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("retained-source capture refused")?;
        if let Some(first) = &self.first {
            write!(output, ": {first}")?;
        }
        if let Some(first) = &self.receiver_return {
            write!(output, "; context return: {first}")?;
        }
        if let Some(first) = &self.retirement_refusal {
            write!(output, "; retirement observation: {first}")?;
        }
        if let Some(retirement) = &self.retirement {
            let mut result = Ok(());
            retirement.with_history(|phase, first| {
                if result.is_ok() {
                    result = write!(output, "; {phase}: {first}");
                }
            });
            result?;
        }
        if let Some(terminal) = &self.terminal {
            let body = match terminal.lock() {
                Ok(body) => body,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(first) = body.first_failure() {
                write!(output, "; terminal history: {first}")?;
            }
        }
        Ok(())
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RetainedSourceCaptureFailure<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(first) = &self.first {
            return Some(first);
        }
        if let Some(first) = &self.receiver_return {
            return Some(first);
        }
        match &self.retirement_refusal {
            Some(first) => Some(first),
            None => None,
        }
    }
}

/// Retains the receiver before projection, including unwinding during capture.
struct SourceContextProjection<'a> {
    service: &'a ServiceMainHandle,
    context: Option<AttemptExecutionContext>,
    receiver: Option<ServiceMainReceiverHandle>,
    destruction_started: bool,
}

impl SourceContextProjection<'_> {
    fn finish(mut self) -> Result<(), ServiceMainPreclaimError> {
        self.destruction_started = true;
        drop(self.context.take());
        match self.receiver.take() {
            Some(receiver) => receiver.return_after_alias_destruction(),
            None => Ok(()),
        }
    }
}

impl Drop for SourceContextProjection<'_> {
    fn drop(&mut self) {
        if self.destruction_started {
            // A context destructor that unwound has not proved destruction.
            // The original Main-held token remains unacknowledged in that case.
            return;
        }
        self.service.prepared_selector().request_retirement();
        self.destruction_started = true;
        drop(self.context.take());
        if let Some(receiver) = self.receiver.take() {
            // The actual token and the completed-destruction journal stay in
            // Main even when its immediate metadata projection refuses.
            let _return_observation = receiver.return_after_alias_destruction();
        }
    }
}

pub(super) fn capture_with_service<E, T>(
    service: &ServiceMainHandle,
    start: impl FnOnce(
        &mut retained_service::RetainedServiceStart,
    ) -> Result<(), retained_service::RetainedServiceStartRefusal>,
    prepared_error: impl Fn(PreparedSourceFailure) -> E,
    capture: impl FnOnce(&AttemptExecutionContext) -> Result<T, E>,
) -> Result<T, RetainedSourceCaptureFailure<E>> {
    match service.with_start(start) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            return Err(RetainedSourceCaptureFailure::operation(prepared_error(
                service.failure("start retained-source Service"),
            )));
        }
        Err(first) => {
            return Err(RetainedSourceCaptureFailure::operation(prepared_error(
                service.failure_with_refusal("borrow retained-source Service", first),
            )));
        }
    }
    let receiver = service.retain_receiver_in_main().map_err(|first| {
        RetainedSourceCaptureFailure::operation(prepared_error(
            service.failure_with_refusal("retain source-capture context", first),
        ))
    })?;
    let mut projection = SourceContextProjection {
        service,
        context: None,
        receiver: Some(receiver),
        destruction_started: false,
    };
    let result = match service.with_ready(|ready| {
        projection.context = Some(ready.context().clone());
    }) {
        Ok(()) => match projection.context.as_ref() {
            Some(context) => capture(context),
            None => Err(prepared_error(
                service.failure("source-capture context is absent"),
            )),
        },
        Err(first) => Err(prepared_error(
            service.failure_with_refusal("project source-capture context", first),
        )),
    };
    match (result, projection.finish()) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(first), Ok(())) => Err(RetainedSourceCaptureFailure::operation(first)),
        (result, Err(access)) => {
            // A successful native output already carries its own return
            // destination. Destroying it returns that same body before this
            // independent receiver refusal is exposed.
            let first = match result {
                Ok(output) => {
                    drop(output);
                    None
                }
                Err(first) => Some(first),
            };
            Err(RetainedSourceCaptureFailure {
                first,
                receiver_return: Some(
                    service.failure_with_refusal("return source-capture context", access),
                ),
                retirement: None,
                retirement_refusal: None,
                terminal: None,
            })
        }
    }
}

/// Closes a capture that authenticated a different configuration before World.
pub(super) fn retire_unused_source<E>(
    service: ServiceMainHandle,
) -> Result<(), RetainedSourceCaptureFailure<E>> {
    let mut retirement = service.into_retirement();
    let refusal = retirement.retry().err();
    let terminal = match retirement.finish() {
        Ok(terminal) => terminal,
        Err(retirement) => {
            return Err(RetainedSourceCaptureFailure {
                first: None,
                receiver_return: None,
                retirement: Some(retirement),
                retirement_refusal: refusal,
                terminal: None,
            });
        }
    };
    if terminal.first_failure().is_some() || refusal.is_some() {
        return Err(RetainedSourceCaptureFailure {
            first: None,
            receiver_return: None,
            retirement: None,
            retirement_refusal: refusal,
            terminal: Some(std::sync::Mutex::new(terminal)),
        });
    }
    drop(terminal);
    Ok(())
}
