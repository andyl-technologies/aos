//! Retains the independently provisioned origin beside one original Start.
//!
//! The owner keeps the fixed credential's real descriptors and partial reads.
//! Its decoded family is historical DATA; only the separately held current
//! Start and physical input cut can issue the selected Storage plan. No local
//! snapshot signer, path/FD nomination or replacement Session exists here.

use aos_sandbox_core::{BrokerAuthorizationPlan, RawPairedClockSample};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::nix_generation::VerifiedNixGenerationInputFamilyV2;

use super::*;
use crate::public_api_session::ControllerNixGenerationOriginCredentialCustodyV1;

/// Classifies a refusal while the original owner keeps its actual typed cause.
///
/// [`ControllerNixGenerationOriginalV1::failure`] borrows the original I/O,
/// canonical-family or selector error. Classification never moves that cause
/// or reconstructs custody from historical bytes.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum NixGenerationOriginalErrorV1 {
    /// The fixed credential owner retains its actual first failure.
    #[error("Nix generation origin credential custody failed")]
    Credential,
    /// The resident canonical-family result contains the actual failure.
    #[error("Nix generation origin family verification failed")]
    Family,
    /// The same selector's actual currentness check failed.
    #[error("Nix generation origin selector currentness failed")]
    Selector,
    /// Original recipe, parent, incarnation or occupied slots disagree.
    #[error("Nix generation origin differs from the original Start")]
    Changed,
    /// The owner was already attempted, failed or interrupted.
    #[error("Nix generation origin is permanently closed")]
    Closed,
}

enum OriginalCauseV1 {
    Credential,
    Family,
    Selector(NixStartAdmissionErrorV2),
    Comparison(NixGenerationOriginalErrorV1),
}

/// Owns one genuine selector and its fixed independently signed origin input.
///
/// This is not cloneable, serializable or a Storage authorization. Construction
/// is limited to the named selector capture, and comparison rechecks cannot
/// select a different artifact, parent, name, clock or current Start.
pub struct ControllerNixGenerationOriginalV1 {
    selector: Arc<ControllerNixStartRecipeSelectorV2>,
    credential: ControllerNixGenerationOriginCredentialCustodyV1,
    family: Option<Result<VerifiedNixGenerationInputFamilyV2, aos_sandbox_protocol::ProtocolValidationError>>,
    first: Option<OriginalCauseV1>,
    debt: Option<OriginalCauseV1>,
    failed: bool,
    ready: bool,
}

impl std::fmt::Debug for ControllerNixGenerationOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ControllerNixGenerationOriginalV1(<resident fixed origin>)")
    }
}

impl ControllerNixStartRecipeSelectorV2 {
    /// Parks and captures the fixed generation family for a retained recipe.
    ///
    /// The original output is installed before opening credentials. The recipe
    /// must be the exact artifact already retained by this genuine selector.
    /// These local comparison bytes do not authorize an effect or Start.
    ///
    /// # Errors
    /// Rejects an occupied slot, changed selector/recipe, unsafe original file,
    /// invalid independent family or failed final original recheck. The owner
    /// retains the actual cause and all completed/partial observations.
    pub fn retain_storage_generation_origin_into(
        self: &Arc<Self>,
        recipe: &VerifiedNixRecipeArtifactV2,
        target: &mut Option<ControllerNixGenerationOriginalV1>,
    ) -> Result<(), NixGenerationOriginalErrorV1> {
        if target.is_some() {
            return Err(NixGenerationOriginalErrorV1::Changed);
        }
        *target = Some(ControllerNixGenerationOriginalV1 {
            selector: Arc::clone(self),
            credential: ControllerNixGenerationOriginCredentialCustodyV1::new(),
            family: None,
            first: None,
            debt: None,
            failed: true,
            ready: false,
        });
        let original = target.as_mut().ok_or(NixGenerationOriginalErrorV1::Closed)?;
        original.capture(recipe)
    }
}

impl ControllerNixGenerationOriginalV1 {
    /// Borrows the first real cause without moving the retained original.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first.as_ref()? {
            OriginalCauseV1::Credential => self.credential.failure()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            OriginalCauseV1::Family => self.family.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            OriginalCauseV1::Selector(error) => Some(error),
            OriginalCauseV1::Comparison(error) => Some(error),
        }
    }

    /// Borrows later original readback debt without replacing the first cause.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.debt.as_ref()? {
            OriginalCauseV1::Credential => self.credential.failure()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            OriginalCauseV1::Family => self.family.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            OriginalCauseV1::Selector(error) => Some(error),
            OriginalCauseV1::Comparison(error) => Some(error),
        }
    }

    fn capture(&mut self, recipe: &VerifiedNixRecipeArtifactV2) -> Result<(), NixGenerationOriginalErrorV1> {
        self.require_recipe(recipe)?;
        if self.credential.capture().is_err() {
            self.first.get_or_insert(OriginalCauseV1::Credential);
            return Err(NixGenerationOriginalErrorV1::Credential);
        }
        let decoded = (|| -> Result<_, NixStartAdmissionErrorV2> {
            let loan = self.selector.recheck_and_borrow_publics()
                ?;
            let credentials = loan.publics()
                .ok_or(NixStartAdmissionErrorV2::CredentialCustodyClosed)?;
            let issuer = array::<32>(credentials[0].bytes())?;
            let bytes = self.credential.bytes()
                .ok_or(NixStartAdmissionErrorV2::CredentialCustodyClosed)?;
            Ok(VerifiedNixGenerationInputFamilyV2::decode(bytes, issuer, recipe))
        })();
        let decoded = decoded.map_err(|error| self.retain_selector(error))?;
        // Own the real decode/signature result before any later original check.
        self.family = Some(decoded);
        if self.family.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(OriginalCauseV1::Family);
        }

        // Both independent original observations follow the parked decode
        // Result, including an invalid signature/canonical family.
        let selector_after = self.selector.recheck()
            .and_then(|()| self.selector.require_recipe_pins(recipe));
        if let Err(error) = selector_after {
            if self.first.is_some() {
                self.debt.get_or_insert(OriginalCauseV1::Selector(error));
            } else {
                self.first = Some(OriginalCauseV1::Selector(error));
            }
        }
        if self.credential.recheck().is_err() {
            if self.first.is_some() {
                self.debt.get_or_insert(OriginalCauseV1::Credential);
            } else {
                self.first = Some(OriginalCauseV1::Credential);
            }
        }
        if self.first.is_some() || self.debt.is_some() {
            return Err(NixGenerationOriginalErrorV1::Closed);
        }
        self.ready = true;
        self.failed = false;
        Ok(())
    }

    fn retain_selector(&mut self, error: NixStartAdmissionErrorV2) -> NixGenerationOriginalErrorV1 {
        self.first.get_or_insert(OriginalCauseV1::Selector(error));
        NixGenerationOriginalErrorV1::Selector
    }

    fn require_recipe(&mut self, recipe: &VerifiedNixRecipeArtifactV2) -> Result<(), NixGenerationOriginalErrorV1> {
        self.selector.recheck().map_err(|error| self.retain_selector(error))?;
        if !self.selector.recipes.iter().any(|original| {
            original.digest() == recipe.digest() && original.canonical_bytes() == recipe.canonical_bytes()
        }) {
            self.first.get_or_insert(OriginalCauseV1::Comparison(NixGenerationOriginalErrorV1::Changed));
            return Err(NixGenerationOriginalErrorV1::Changed);
        }
        self.selector.require_recipe_pins(recipe)
            .map_err(|error| self.retain_selector(error))
    }

    pub(super) fn recheck_original(
        &mut self,
        selector: &ControllerNixStartRecipeSelectorV2,
        recipe: &VerifiedNixRecipeArtifactV2,
    ) -> Result<(), NixGenerationOriginalErrorV1> {
        if self.failed || !self.ready || self.first.is_some() || self.debt.is_some() {
            return Err(NixGenerationOriginalErrorV1::Closed);
        }
        self.failed = true;
        if !std::ptr::eq(Arc::as_ptr(&self.selector), selector) {
            self.first.get_or_insert(OriginalCauseV1::Comparison(NixGenerationOriginalErrorV1::Changed));
            return Err(NixGenerationOriginalErrorV1::Changed);
        }
        self.require_recipe(recipe)?;
        if self.credential.recheck().is_err() {
            self.first.get_or_insert(OriginalCauseV1::Credential);
            return Err(NixGenerationOriginalErrorV1::Credential);
        }
        self.require_recipe(recipe)?;
        self.failed = false;
        Ok(())
    }

    pub(super) fn family(&self) -> Result<&VerifiedNixGenerationInputFamilyV2, NixGenerationOriginalErrorV1> {
        if self.failed || !self.ready || self.first.is_some() || self.debt.is_some() {
            return Err(NixGenerationOriginalErrorV1::Closed);
        }
        self.family.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(NixGenerationOriginalErrorV1::Closed)
    }
}

/// Retains the actual unsigned selected plan, original lease and complete body.
///
/// A signed and independently admitted Session request is still mandatory.
/// No catalog, Prepare receipt, physical effect or completed Start is implied.
pub struct StorageGenerationPreparationDraftV1 {
    pub(super) plan: BrokerAuthorizationPlan,
    pub(super) lease: SignedOwnershipLease,
    pub(super) request: Vec<u8>,
    pub(super) observed: RawPairedClockSample,
}

impl StorageGenerationPreparationDraftV1 {
    /// Checks the actual signer return using the existing grant matcher.
    ///
    /// # Errors
    /// Rejects any altered plan, whole-wrapper commitment or byte bound.
    pub fn validate_signed_plan(
        &self,
        signed: &aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan,
    ) -> Result<(), crate::BrokerDispatchTemplateError> {
        crate::dispatch::validate_nix_generation_plan_v1(signed, &self.plan, &self.request)
    }

    /// Borrows the actual whole-wrapper unsigned Storage plan.
    #[must_use]
    pub fn plan(&self) -> &BrokerAuthorizationPlan { &self.plan }

    /// Borrows the same independently signed current assignment lease.
    #[must_use]
    pub fn lease(&self) -> &SignedOwnershipLease { &self.lease }

    /// Borrows the complete exact canonical selected method body.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] { &self.request }

    /// Returns the genuine fresh pair used to derive this draft, not a new D.
    #[must_use]
    pub const fn observed(&self) -> RawPairedClockSample { self.observed }
}
