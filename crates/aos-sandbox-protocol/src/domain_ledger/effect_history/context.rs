//! Decodes complete plain/FUSE/Nix historical Effect context through the canonical selector.

use aos_sandbox_core::{PrincipalId, ProjectId};
use crate::public_api::public_mutation_context::{InvalidPublicMutationContext, PublicMutationContextV1};
use super::EffectHistoryDataError;

/// Carries authenticated admission identity with one exact public mutation.
///
/// The public envelope does not contain the mutually authenticated caller or
/// its project authority. Production lowering therefore persists those facts
/// beside the exact envelope instead of attempting to reconstruct them from a
/// target resource after admission.
/// Protocol owns its plain historical DATA and codec; this native wrapper
/// retains the original FUSE/Nix carrier selection and admission recipes.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicMutationEffectHistoryV1 {
    plain: PublicMutationContextV1,
    #[cfg(target_os = "linux")]
    fuse_admission: Option<crate::public_api::mutation_history::ControllerFuseAdmissionCarrierV1>,
    #[cfg(target_os = "linux")]
    nix_start: Option<crate::public_api::mutation_history::NixStartAdmissionCarrierV2>,
}

impl std::fmt::Debug for PublicMutationEffectHistoryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the original flat diagnostic fields despite nested DATA storage.
        let mut fields = formatter.debug_struct("PublicMutationEffectV1");
        fields.field("caller", &self.plain.caller());
        fields.field("project", &self.plain.project());
        fields.field("accepted_wall_seconds", &self.plain.accepted_wall_seconds());
        fields.field("canonical_request", &self.plain.canonical_request());
        #[cfg(target_os = "linux")]
        fields.field("fuse_admission", &self.fuse_admission);
        #[cfg(target_os = "linux")]
        fields.field("nix_start", &self.nix_start);
        fields.finish()
    }
}

fn invalid_public_mutation_context(error: InvalidPublicMutationContext) -> EffectHistoryDataError {
    EffectHistoryDataError::InvalidPlan(error.reason())
}

impl PublicMutationEffectHistoryV1 {
    /// Returns the authenticated caller fixed at admission.
    #[must_use]
    pub const fn caller(&self) -> PrincipalId {
        self.plain.caller()
    }

    /// Returns the authenticated project fixed at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.plain.project()
    }

    /// Returns the protected admission clock in Unix seconds.
    #[must_use]
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.plain.accepted_wall_seconds()
    }

    /// Returns the exact canonical public mutation envelope.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        self.plain.canonical_request()
    }

    /// Decodes the exact public request through the established mutation validator.
    ///
    /// This preserves the authenticated caller and project carried by this
    /// effect while reusing the same canonical protobuf and field validation as
    /// initial public admission. Lowering code must not decode the retained body
    /// through a second, weaker request path.
    ///
    /// # Errors
    ///
    /// Returns [`EffectHistoryDataError::InvalidPlan`] when the retained envelope or
    /// method-selected protobuf is malformed, noncanonical, or semantically
    /// invalid.
    pub fn validated_request(
        &self,
    ) -> Result<crate::public_api::request::DormantSandboxRequestKindV1, EffectHistoryDataError> {
        self.plain
            .validated_request()
            .map_err(invalid_public_mutation_context)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, EffectHistoryDataError> {
        #[cfg(target_os = "linux")]
        return crate::public_api::mutation_history::decode_history(bytes)
            .map(|parts| parts.map(|(plain, fuse_admission, nix_start)| Self {
                plain,
                fuse_admission,
                nix_start,
            }))
            .map_err(|error| EffectHistoryDataError::InvalidPlan(error.reason()));
        #[cfg(not(target_os = "linux"))]
        Self::decode_plain(bytes)
    }

    /// Returns retained FUSE history without constructing Native admission.
    #[cfg(target_os = "linux")]
    pub fn fuse_admission(&self) -> Option<&crate::public_api::mutation_history::ControllerFuseAdmissionCarrierV1> {
        self.fuse_admission.as_ref()
    }

    /// Returns retained Start history without current build or floor readiness.
    #[cfg(target_os = "linux")]
    pub fn nix_start(&self) -> Option<&crate::public_api::mutation_history::NixStartAdmissionCarrierV2> {
        self.nix_start.as_ref()
    }

    /// Reports retained Nix continuation DATA without a readiness claim.
    #[cfg(target_os = "linux")]
    pub fn has_retained_nix_start(&self) -> bool {
        self.nix_start.is_some()
    }

    pub fn decode_plain(bytes: &[u8]) -> Result<Option<Self>, EffectHistoryDataError> {
        PublicMutationContextV1::decode(bytes)
            .map(|context| {
                context.map(|plain| Self {
                    plain,
                    #[cfg(target_os = "linux")]
                    fuse_admission: None,
                    #[cfg(target_os = "linux")]
                    nix_start: None,
                })
            })
            .map_err(invalid_public_mutation_context)
    }
}


impl PublicMutationEffectHistoryV1 {
    /// Assembles already checked plain history without decoding or issuing authority.
    #[must_use]
    pub fn from_plain(plain: PublicMutationContextV1) -> Self {
        Self {
            plain,
            #[cfg(target_os = "linux")]
            fuse_admission: None,
            #[cfg(target_os = "linux")]
            nix_start: None,
        }
    }

    /// Borrows the complete retained plain context for the original binding checks.
    #[must_use]
    pub const fn plain(&self) -> &PublicMutationContextV1 {
        &self.plain
    }

    /// Encodes the complete selected history without an authority claim.
    ///
    /// # Errors
    /// Returns the original mixed-carrier, Nix encoding or plain context refusal.
    pub fn encode(&self) -> Result<Vec<u8>, EffectHistoryDataError> {
        #[cfg(target_os = "linux")]
        return crate::public_api::mutation_history::encode_history(
            &self.plain,
            self.fuse_admission.as_ref(),
            self.nix_start.as_ref(),
        ).map_err(|error| EffectHistoryDataError::InvalidPlan(error.reason()));
        #[cfg(not(target_os = "linux"))]
        self.encode_plain()
    }

    /// Encodes only the original plain context for ordinary-effect joins.
    ///
    /// # Errors
    /// Returns the original plain context encoding refusal.
    pub fn encode_plain(&self) -> Result<Vec<u8>, EffectHistoryDataError> {
        self.plain.encode().map_err(invalid_public_mutation_context)
    }

    /// Binds a complete historical FUSE carrier through the original context checks.
    ///
    /// # Errors
    /// Returns the original mixed-carrier, identity or ordinary-effect refusal.
    #[cfg(target_os = "linux")]
    pub fn with_fuse_admission(
        mut self,
        carrier: crate::public_api::mutation_history::ControllerFuseAdmissionCarrierV1,
    ) -> Result<Self, EffectHistoryDataError> {
        crate::public_api::mutation_history::require_fuse_context(
            &self.plain,
            self.nix_start.as_ref(),
            &carrier,
        )
        .map_err(|error| EffectHistoryDataError::InvalidPlan(error.reason()))?;
        self.fuse_admission = Some(carrier);
        Ok(self)
    }

    /// Replaces only passive FUSE history after the caller's original checks.
    #[cfg(target_os = "linux")]
    pub fn set_fuse_admission(&mut self, carrier: crate::public_api::mutation_history::ControllerFuseAdmissionCarrierV1) {
        self.fuse_admission = Some(carrier);
    }

    /// Binds a complete historical Nix carrier at the original join frontier.
    ///
    /// # Errors
    /// Returns the original mixed-carrier, context, request or preflight refusal.
    #[cfg(target_os = "linux")]
    pub fn with_nix_start(
        mut self,
        carrier: crate::public_api::mutation_history::NixStartAdmissionCarrierV2,
    ) -> Result<Self, EffectHistoryDataError> {
        crate::public_api::mutation_history::require_nix_context(
            &self.plain, self.fuse_admission.as_ref(), &carrier,
        ).map_err(|error| EffectHistoryDataError::InvalidPlan(error.reason()))?;
        self.nix_start = Some(carrier);
        Ok(self)
    }

    /// Replaces only passive Nix history after the caller's original checks.
    #[cfg(target_os = "linux")]
    pub fn set_nix_start(&mut self, carrier: crate::public_api::mutation_history::NixStartAdmissionCarrierV2) {
        self.nix_start = Some(carrier);
    }

}
