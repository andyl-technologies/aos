//! Drives actual fixed Controller Runtime receiving under the same C/profile.
//!
//! The public entry accepts only the genuine original/profile and passive
//! concrete layout. The profile callback is private within this lower owner;
//! caller success DATA cannot replace actual PID1, pids or independent posts.

use super::ControllerReceivingErrorV1;
use super::shapes::{ControllerRuntimeStartupShapeV1, ControllerRuntimeCredentialShapeV1};

static RUNTIME_CLOSED: ControllerReceivingErrorV1 = ControllerReceivingErrorV1::EnrollmentUnavailable;

/// Parks the original receiving action between independent producer bookends.
pub struct ControllerRuntimeStartupAdmissionV1 {
    task_envelope: Option<super::shapes::ControllerRuntimeTaskEnvelopeV1>,
    before: Option<Result<([u8; 16], [u8; 16]), super::profile::ControllerProfileErrorV1>>,
    tasks: Option<Result<(), super::profile::ControllerProfileErrorV1>>,
    pids: aos_sandbox_linux::cgroup::PidsLimitReadbackV1,
    pids_capture: Option<Result<(), aos_sandbox_linux::cgroup::PidsLimitReadbackRefusalV1>>,
    initial_pids_policy: Option<Result<(), ControllerReceivingErrorV1>>,
    funding: Option<Result<(), ControllerReceivingErrorV1>>,
    pids_post: Option<Result<(), aos_sandbox_linux::cgroup::PidsLimitReadbackRefusalV1>>,
    final_pids_policy: Option<Result<(), ControllerReceivingErrorV1>>,
    pids_settlement: Option<Result<(), aos_sandbox_linux::cgroup::PidsLimitReadbackRefusalV1>>,
    after: Option<Result<([u8; 16], [u8; 16]), super::profile::ControllerProfileErrorV1>>,
    binding: Option<Result<(), ControllerReceivingErrorV1>>,
    completion: Option<Result<(), super::profile::ControllerProfileErrorV1>>,
}

impl ControllerRuntimeStartupAdmissionV1 {
    /// Creates an empty destination without entering the original or observing PID1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_envelope: None,
            before: None,
            tasks: None,
            pids: aos_sandbox_linux::cgroup::PidsLimitReadbackV1::new(),
            pids_capture: None,
            initial_pids_policy: None,
            funding: None,
            pids_post: None,
            final_pids_policy: None,
            pids_settlement: None,
            after: None,
            binding: None,
            completion: None,
        }
    }

    /// Runs the fixed Runtime admission once under the same admitted profile.
    ///
    /// Actual PID1, original pids policy and independent posts remain owned on
    /// refusal. Reentry performs no work and preserves the first observation.
    pub fn observe(
        &mut self,
        original: &std::sync::Arc<super::original::ControllerReceivingOriginalV1>,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
        shape: ControllerRuntimeStartupShapeV1,
        credentials: ControllerRuntimeCredentialShapeV1,
    ) {
        if self.completion.is_some() {
            return;
        }
        self.task_envelope = Some(super::shapes::ControllerRuntimeTaskEnvelopeV1::from_profile_v1(profile));
        self.completion = Some(profile.observe_original_runtime_startup(original, || {
            self.before = Some(profile.require_resource_producer());
            self.tasks = Some(profile.require_runtime_tasks_max());
            // The actual native observation is independent of a refused PID1
            // scalar, and uses this SAME admitted profile's retained anchor.
            self.pids_capture = Some(profile.capture_runtime_pids(&mut self.pids));
            self.initial_pids_policy = Some(require_eight_pids(self.pids.initial_bytes()));
            self.funding = Some(match (
                self.before.as_ref(), self.tasks.as_ref(), self.pids_capture.as_ref(),
                self.initial_pids_policy.as_ref(), self.task_envelope,
            ) {
                (Some(Ok(recipient)), Some(Ok(())), Some(Ok(())), Some(Ok(())), Some(envelope)) => {
                    original.reserve_runtime_startup_once(profile, shape, credentials, *recipient,
                        envelope)
                }
                _ => Err(ControllerReceivingErrorV1::EnrollmentUnavailable),
            });
            // An earlier comparison, shape, or Core refusal cannot suppress
            // the independently available original recipient/currentness post.
            self.after = Some(profile.require_resource_producer());
            self.pids_post = Some(profile.recheck_runtime_pids(&mut self.pids));
            self.final_pids_policy = Some(require_eight_pids(self.pids.final_bytes()));
            self.binding = Some(match (self.before.as_ref(), self.after.as_ref()) {
                (Some(Ok(before)), Some(Ok(after))) if before == after =>
                    original.require_runtime_recipient(after.0, after.1),
                _ => Err(ControllerReceivingErrorV1::Conflict),
            });
            if self.failure().is_some() {
                Err(super::profile::ControllerProfileErrorV1::Service)
            } else {
                Ok(())
            }
        }));
        // Only the complete same-original scope/control/semantic/Ended join
        // permits actual native disposal before a later scope reuses its peak.
        if matches!(self.completion, Some(Ok(()))) {
            self.pids_settlement = Some(self.pids.settle_positive_once());
        }
    }

    /// Requires the actual observation and its native disposal to have completed.
    ///
    /// # Errors
    /// Borrows the earliest retained cause, or refuses an incomplete observation.
    pub fn require_success(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.failure() {
            return Err(cause);
        }
        if matches!(self.completion, Some(Ok(())))
            && matches!(self.pids_settlement, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(&RUNTIME_CLOSED)
        }
    }

    /// Copies the same measured task mode only after complete native admission.
    ///
    /// This is readonly scheduling DATA; it grants no physical/helper entry.
    #[doc(hidden)]
    #[must_use]
    pub fn admitted_task_envelope_v1(&self) -> Option<super::shapes::ControllerRuntimeTaskEnvelopeV1> {
        self.require_success().ok()?;
        self.task_envelope
    }

    /// Borrows the first actual retained refusal in execution order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(
            result: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
        }
        error(&self.before).or_else(|| error(&self.tasks))
            .or_else(|| self.pids.initial_failure().map(|cause| cause as _))
            .or_else(|| error(&self.pids_capture))
            .or_else(|| error(&self.initial_pids_policy)).or_else(|| error(&self.funding))
            .or_else(|| error(&self.after))
            .or_else(|| self.pids.final_failure().map(|cause| cause as _))
            .or_else(|| error(&self.pids_post))
            .or_else(|| error(&self.final_pids_policy)).or_else(|| error(&self.binding))
            .or_else(|| error(&self.completion)).or_else(|| error(&self.pids_settlement))
    }
}

// The actual Controller product owns this finite installed policy. Linux
// supplies only borrowed original record DATA and native currentness outcomes.
fn require_eight_pids(bytes: Option<&[u8]>) -> Result<(), ControllerReceivingErrorV1> {
    if bytes == Some(b"8\n".as_slice()) {
        Ok(())
    } else {
        Err(ControllerReceivingErrorV1::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_policy_requires_its_exact_borrowed_initial_and_final_record() {
        assert!(require_eight_pids(Some(b"8\n")).is_ok());
        for other in [None, Some(b"max\n".as_slice()), Some(b"16\n".as_slice()),
            Some(b"08\n".as_slice()), Some(b"8".as_slice()), Some(b"8\n0".as_slice())]
        {
            assert!(require_eight_pids(other).is_err());
        }
    }

}
