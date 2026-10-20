//! Drives fixed Source/TLS native intervals on the same Controller startup C.
//!
//! Actual credential parsers and outputs stay in the trusted Native owner.
//! This opaque receiver consumes its existing fixed operation, retains native
//! bookends and never accepts a body callback, semantic flag or caller vector.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_core::ResourceVector;

use crate::receiving::ComponentReceivingOwnedOperationV1;
use super::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1};
use super::startup_envelope::CredentialPurposeV1;
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

type RecipientV1 = Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>;

/// Retains one fixed credential interval without exporting capacity or a payer.
///
/// Only the trusted actual Native coordinator pairs this mechanism with its
/// fixed producer. Mechanical success establishes no Source/TLS output; its
/// private producer owner separately requires typed success before progression.
#[must_use = "retain the same failed interval with its actual credential producer"]
pub struct ControllerStartupCredentialReceivingV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    purpose: CredentialPurposeV1,
    preparation: Option<Result<(), ControllerReceivingErrorV1>>,
    begin: Option<Result<(ResourceVector, ResourceVector), ControllerReceivingErrorV1>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    entry: Option<Result<(), ControllerProfileErrorV1>>,
    before: Option<RecipientV1>,
    before_binding: Option<Result<(), ControllerReceivingErrorV1>>,
    after: Option<RecipientV1>,
    binding: Option<Result<(), ControllerReceivingErrorV1>>,
    completion: Option<Result<(), ControllerProfileErrorV1>>,
    finish: Option<Result<(), ControllerReceivingErrorV1>>,
    entered: bool,
    mechanical_complete: bool,
    disposed: bool,
}

impl ControllerStartupCredentialReceivingV1 {
    fn new(original: Arc<ControllerReceivingOriginalV1>, purpose: CredentialPurposeV1) -> Self {
        Self { original, purpose, preparation: None, begin: None, operation: None,
            entry: None, before: None, before_binding: None, after: None, binding: None,
            completion: None, finish: None, entered: false, mechanical_complete: false, disposed: false }
    }

    /// Creates inert destinations for the actual fixed Source producer.
    #[doc(hidden)]
    #[must_use]
    pub fn source(original: Arc<ControllerReceivingOriginalV1>) -> Self {
        Self::new(original, CredentialPurposeV1::SourceGenesis)
    }

    /// Creates inert destinations for the actual fixed public TLS producer.
    #[doc(hidden)]
    #[must_use]
    pub fn public_tls(original: Arc<ControllerReceivingOriginalV1>) -> Self {
        Self::new(original, CredentialPurposeV1::PublicTls)
    }

    /// Claims its existing fixed startup stage against the same actual profile.
    ///
    /// # Errors
    /// Retains foreign, closed, repeated, unadmitted or out-of-order refusal.
    #[doc(hidden)]
    pub fn prepare_once(&mut self, profile: &ControllerSelfProfileOriginalV1) -> Result<(), ControllerReceivingErrorV1> {
        if self.preparation.is_some() { return Err(ControllerReceivingErrorV1::Conflict); }
        self.preparation = Some(self.original.claim_startup_credential(profile, self.purpose));
        if self.is_prepared_v1() { Ok(()) } else { Err(ControllerReceivingErrorV1::Conflict) }
    }

    /// Reports the actual untouched preparation state as comparison DATA.
    #[must_use]
    pub fn is_prepared_v1(&self) -> bool { matches!(self.preparation, Some(Ok(()))) && !self.entered }

    /// Begins the same consumed full-shape operation and fixed profile interval.
    ///
    /// # Errors
    /// Retains original startup/operation/profile/native/recipient refusal.
    /// Capacity and required vectors never leave this actual owner.
    #[doc(hidden)]
    pub fn begin_native_once(&mut self, profile: &ControllerSelfProfileOriginalV1) -> Result<(), ControllerReceivingErrorV1> {
        if self.entered || !matches!(self.preparation, Some(Ok(()))) { return Err(ControllerReceivingErrorV1::Conflict); }
        self.entered = true;
        self.begin = Some(self.original.begin_startup_credential(self.purpose));
        let Some(Ok((capacity, required))) = self.begin.as_ref() else { return Err(ControllerReceivingErrorV1::Conflict); };
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(*capacity, *required));
        self.operation.as_mut().ok_or(ControllerReceivingErrorV1::Conflict)?
            .consume_once().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        self.entry = Some(profile.begin_startup_credential_receiving_v1(&self.original, self.purpose));
        if !matches!(self.entry, Some(Ok(()))) { return Err(ControllerReceivingErrorV1::Conflict); }
        self.before = Some(profile.require_resource_producer());
        self.before_binding = Some(match self.before.as_ref() {
            Some(Ok(before)) => self.original.require_runtime_recipient(before.0, before.1),
            _ => Err(ControllerReceivingErrorV1::Conflict),
        });
        if self.entry_failure_v1().is_none() { Ok(()) } else { Err(ControllerReceivingErrorV1::Conflict) }
    }

    /// Performs the independently owed actual native after/control/Ended post.
    ///
    /// No upper credential Result or success flag is accepted. Even a failed
    /// primary producer still calls this same fixed mechanical continuation.
    ///
    /// # Errors
    /// Retains incomplete entry, changed native/recipient or disposal refusal.
    #[doc(hidden)]
    pub fn finish_native_once(&mut self, profile: &ControllerSelfProfileOriginalV1) -> Result<(), ControllerReceivingErrorV1> {
        if self.completion.is_some() || self.mechanical_complete || !matches!(self.entry, Some(Ok(()))) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.after = Some(profile.require_resource_producer());
        self.binding = Some(match (self.before.as_ref(), self.after.as_ref()) {
            (Some(Ok(before)), Some(Ok(after))) if before == after => self.original.require_runtime_recipient(after.0, after.1),
            _ => Err(ControllerReceivingErrorV1::Conflict),
        });
        let comparison = if self.entry_failure_v1().is_none() && matches!(self.binding, Some(Ok(()))) {
            Ok(())
        } else { Err(ControllerProfileErrorV1::Service) };
        self.completion = Some(profile.finish_startup_credential_receiving_v1(&self.original, self.purpose, comparison));
        if self.entry_failure_v1().is_none() && self.post_failure_v1().is_none()
            && matches!(self.completion, Some(Ok(()))) {
            self.mechanical_complete = true;
            Ok(())
        } else { Err(ControllerReceivingErrorV1::Conflict) }
    }

    /// Records disposal at the actual trusted Native producer's success boundary.
    ///
    /// Native calls only after its real typed output is resident and its native
    /// proof temporaries have disposed. This fixed continuation accepts no bool,
    /// result, account, amount, output DTO or completion callback. Actual Bank
    /// progression still separately requires that producer's positive take.
    ///
    /// # Errors
    /// Retains repeated, mechanically incomplete or out-of-order disposal.
    #[doc(hidden)]
    pub fn complete_after_producer_disposal_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.disposed || !self.mechanical_complete || self.entry_failure_v1().is_some() || self.post_failure_v1().is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.finish = Some(self.original.finish_startup_credential(self.purpose));
        if !matches!(self.finish, Some(Ok(()))) { return Err(ControllerReceivingErrorV1::Conflict); }
        let Some(operation) = self.operation.take() else { return Err(ControllerReceivingErrorV1::Conflict); };
        operation.complete_after_disposal();
        self.disposed = true;
        Ok(())
    }

    /// Borrows failures reached before the actual Native credential body.
    #[must_use]
    pub fn entry_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.preparation).or_else(|| error(&self.begin))
            .or_else(|| self.operation.as_ref().and_then(ComponentReceivingOwnedOperationV1::failure).map(|cause| cause as _))
            .or_else(|| error(&self.entry)).or_else(|| error(&self.before)).or_else(|| error(&self.before_binding))
    }

    /// Borrows the independently owed native post and final disposal cause.
    #[must_use]
    pub fn post_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.after).or_else(|| error(&self.binding)).or_else(|| error(&self.completion)).or_else(|| error(&self.finish))
    }

    /// Borrows only an actual stored Profile error at its selected entry/post.
    ///
    /// The upper producer first selects its own chronological cause, then uses
    /// pointer equality with this borrower before exposing a richer Profile guard.
    #[doc(hidden)]
    #[must_use]
    pub fn profile_failure_marker_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.entry_failure_v1().filter(|cause| cause.is::<ControllerProfileErrorV1>())
            .or_else(|| self.post_failure_v1().filter(|cause| cause.is::<ControllerProfileErrorV1>()))
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
