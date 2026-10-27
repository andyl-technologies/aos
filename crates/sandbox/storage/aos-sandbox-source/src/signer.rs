//! Owns Source policy over the same retained fixed-service receiving engine.

use std::error::Error;
use aos_sandbox_broker::receiving::{FixedServiceReceivingCaptureV1, RepresentationDemandDebitV1};

use aos_sandbox_ledger_replay::source_signer_data::*;
use readonly_view::{SourceReadonlyAttemptV1, SourceReadonlyRequestV1};

const SIGNER_SOURCE_VIEW: &str = "/run/aos/sandbox-source-signer-journal";


mod credential_receiving;
mod currentness;
mod listener;
mod readonly;
mod root_peer;
mod serving;
mod root_observation;
mod readonly_view;
mod readonly_native;
mod clock;
mod signing_posts;
mod readback_error;
mod comparison;
use readback_error::SourceSignerReadbackErrorV1;
use readonly_native::SourceReadonlyNativeOriginalV1 as ReadOnlyProtectedJournal;
use signing_posts::SourceReadonlySigningPostsV1;
use aos_sandbox_model::{ObjectDigest, ProjectId};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_broker::source_receiving::{SOURCE_DOMAIN_JOURNAL_V1 as PROTECTED_SOURCE_DOMAIN_JOURNAL,
    SOURCE_DOMAIN_DIRECTORY_V1 as PROTECTED_SOURCE_DOMAIN_ROOT,
    source_journal_limits_v1 as source_domain_journal_limits};
use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback::sign_fields;
use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback_v2::sign_source_hold_readback_with_names_v2;
use ed25519_dalek::SigningKey;


use geometry_error::SourceReceivingGeometryErrorV1;
mod geometry_error;

pub(crate) use readonly::SourceReadonlyReceivingContextV1;
pub(crate) use root_peer::SourceRootPeerInputsLoanV1;

const CLOSED: SourceReceivingClosedV1 = SourceReceivingClosedV1;

/// Reports a permanently closed Source startup while its actual cause is retained.
#[derive(Clone, Copy, Debug, Default, thiserror::Error)]
#[error("the original Source signer receiving interval is unavailable")]
pub struct SourceReceivingClosedV1;

#[derive(Clone, Copy)]
enum Failure { Common, Credential, Accounting, Listener, ListenerPost, RootInputs, Serving, Closed }

/// Retains Source's actual original and private credential/listener policy.
#[must_use]
pub struct SourceSignerServiceOriginalV1 {
    common: FixedServiceReceivingCaptureV1<SourceReceivingClosedV1>,
    first: Option<Failure>,
    credential_receiving: credential_receiving::SourceCredentialReceivingV1,
    readonly_peak: readonly::SourceReadonlyPeakV1,
    listener: listener::SourceInheritedListenerV1,
    listener_post: currentness::SourceCurrentnessSampleV1,
    listener_post_result: Option<Result<(), SourceReceivingClosedV1>>,
    root_inputs: crate::signer::root_observation::SourceRootPeerInputsV1,
    root_inputs_receiving: root_peer::SourceRootInputsReceivingV1,
    serving: serving::SourceServingV1,
    serving_resident_geometry: Option<Result<u64, serving::SourceServingResidentErrorV1>>,
}

impl SourceSignerServiceOriginalV1 {
    /// Creates empty fixed storage without observing a descriptor or process.
    pub fn new() -> Self {
        let upper_inline = std::mem::size_of::<Self>()
            .saturating_sub(std::mem::size_of::<FixedServiceReceivingCaptureV1<SourceReceivingClosedV1>>());
        Self {
            common: FixedServiceReceivingCaptureV1::new_source_component_v1(upper_inline),
            first: None,
            credential_receiving: Default::default(),
            readonly_peak: readonly::SourceReadonlyPeakV1::new(),
            listener: Default::default(),
            listener_post: Default::default(),
            listener_post_result: None,
            root_inputs: crate::signer::root_observation::SourceRootPeerInputsV1::new(),
            root_inputs_receiving: Default::default(),
            serving: Default::default(),
            serving_resident_geometry: None,
        }
    }

    /// Captures only the real Source PID1 original and paid fixed observations.
    ///
    /// # Errors
    /// Retains every actual failure; no entry can be repeated or replaced.
    pub fn capture_once(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.first.is_some() {
            return Err(CLOSED);
        }
        if self.common.capture_once().is_err() {
            return Err(self.fail(Failure::Common));
        }
        self.capture_inherited_listener_once()
    }

    fn capture_inherited_listener_once(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.listener.observe_once().is_err() {
            self.fail(Failure::Listener);
        }

        // The independent Source bookend runs after either listener outcome;
        // its later refusal cannot erase the original duplicate/option cause.
        let cgroup = self.common.cgroup.as_ref().ok_or(CLOSED)?;
        let initial_info = self.common.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        let initial_identity = self.common.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
        self.listener_post_result = Some(self.listener_post.observe_once(
            &mut self.common.process, cgroup, &self.common.limits, initial_info, initial_identity,
        ));
        if !matches!(self.listener_post_result, Some(Ok(()))) {
            self.fail(Failure::ListenerPost);
        }
        if self.first.is_some() { Err(CLOSED) } else { Ok(()) }
    }


    fn fail(&mut self, site: Failure) -> SourceReceivingClosedV1 {
        self.first.get_or_insert(site);
        CLOSED
    }

    fn require_permanent_fd_coverage_v1(&self) -> Result<(), SourceReceivingClosedV1> {
        self.common.require_permanent_fd_coverage_v1()?;
        if self.first.is_some() || !self.listener.complete()
            || !matches!(self.listener_post_result, Some(Ok(())))
            || self.listener_post.failure().is_some() {
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Borrows the earliest retained actual native, policy or accounting cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Common => self.common.failure(),
            Failure::Credential => self.credential_receiving.failure(),
            Failure::Accounting => self.common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|error| error as _),
            Failure::Listener => self.listener.failure(),
            Failure::ListenerPost => self.listener_post.failure().or_else(|| failure(&self.listener_post_result)),
            Failure::RootInputs => self.root_inputs_receiving.before_failure()
                .or_else(|| if self.root_inputs_receiving.debit_refused() {
                    self.common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|error| error as _)
                } else { None })
                .or_else(|| self.root_inputs.failure())
                .or_else(|| self.root_inputs_receiving.after_failure()),
            Failure::Serving => failure(&self.serving_resident_geometry).or_else(||
                self.serving.failure(&self.root_inputs, self.common.representation.as_ref().map(|value| value as &dyn RepresentationDemandDebitV1), &self.readonly_peak)),
            Failure::Closed => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED as &(dyn Error + 'static)))
    }
}

impl Default for SourceSignerServiceOriginalV1 {
    fn default() -> Self { Self::new() }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod first_refusal_tests {
    use super::*;

    #[test]
    fn refused_credential_order_cannot_enter_the_initial_descriptor_table_later() {
        // Even an unobserved original arms the production initial-table Drop fence.
        // Keep this inert destination resident; no descriptor was captured.
        let mut original = std::mem::ManuallyDrop::new(SourceSignerServiceOriginalV1::new());
        assert!(original.reserve_source_credential_capture_once_v1(0).is_err());
        let initial_cause = original.failure().unwrap()
            .downcast_ref::<SourceReceivingClosedV1>().unwrap() as *const SourceReceivingClosedV1;

        assert!(original.capture_once().is_err());

        assert!(!original.common.entered);
        let final_cause = original.failure().unwrap()
            .downcast_ref::<SourceReceivingClosedV1>().unwrap() as *const SourceReceivingClosedV1;
        assert!(std::ptr::eq(initial_cause, final_cause));
    }
}

// Financial FD projection never substitutes for checking the known live shape.
// The actual permanent F transfer and fresh hard-limit bookends remain required.
fn require_descriptor_shape(attempted: u64, limit: u64) -> Result<(), aos_sandbox_model::AccountingError> {
    use aos_sandbox_model::{AccountingError, ResourceDimension};

    if attempted > limit {
        return Err(AccountingError::LimitExceeded {
            dimension: ResourceDimension::OpenFiles, limit, attempted,
        });
    }
    Ok(())
}

#[cfg(test)]
mod descriptor_shape_tests {
    use super::require_descriptor_shape;
    use aos_sandbox_model::{AccountingError, ResourceDimension};

    #[test]
    fn permanent_fd_coverage_requires_the_complete_known_shape_to_fit() {
        assert!(require_descriptor_shape(128, 128).is_ok());
        assert!(matches!(require_descriptor_shape(129, 128),
            Err(AccountingError::LimitExceeded {
                dimension: ResourceDimension::OpenFiles, limit: 128, attempted: 129,
            })));
    }
}
