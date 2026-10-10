//! Couples exact version1 peer negotiation to original authenticated Hello custody.

use std::rc::Rc;
use std::sync::Arc;

use crucible_node_contract::{
    ContentRef, ExtensionSelection, Id, IdSet, ProviderManifest, SchemaRef, Validate,
};

use super::extension_contract::{decode_bounded, exact_intersection};
use super::{
    ConnectionAuthority, EXTENSION_NEGOTIATION_V1, ExtensionOfferV1, ExtensionSelectionV1,
    Handshake, HelloRequest, HelloResult, InstalledExtensionNegotiationVerifier, ResumedOperation,
    TrustedHandshakeVerifier, TrustedInstallation,
};
use crate::ProviderError;
use crate::envelope::Envelope;

/// Owns an opt-in installed contract and the same revocable Hello registration gate.
///
/// The transport policy must explicitly map the version1 envelope key to its
/// matching feature. This wrapper cannot unwrap or downgrade its surviving
/// handshake; resumption preserves every exact selected definition.
pub struct ExtensionHandshake {
    handshake: Handshake,
    installed: Rc<dyn InstalledExtensionNegotiationVerifier>,
    selected: Option<Arc<[ExtensionSelection]>>,
}

impl ExtensionHandshake {
    /// Retains independently installed peer contracts before any exchange.
    ///
    /// # Errors
    /// Refuses malformed or oversized installed rosters and unsupported local
    /// requirements. Installation grants no native or graph admission authority.
    pub fn new(
        handshake: Handshake,
        installed: Rc<dyn InstalledExtensionNegotiationVerifier>,
    ) -> Result<Self, ProviderError> {
        super::extension_contract::validate_roster(installed.supported())?;
        super::extension_contract::validate_roster(installed.required())?;
        if installed
            .required()
            .iter()
            .any(|required| !installed.supported().contains(required))
        {
            return Err(ProviderError::Correlation(
                "local extension requirement is not installed",
            ));
        }
        Ok(Self {
            handshake,
            installed,
            selected: None,
        })
    }

    /// Admits a correlated original Hello with an exact installed version1 roster.
    ///
    /// Required and optional tuples are compared before host callbacks. Installed
    /// contract verification then follows actual peer authentication and precedes
    /// journal custody, stream fencing and lease rotation. Failure preserves the
    /// previous typed selection and original registration lease.
    ///
    /// # Errors
    /// Refuses missing/unsupported editions, oversized or ambiguous rosters,
    /// changed required versions/schemas, invented selections, changed resume
    /// selection, untrusted contracts, or any ordinary Hello authentication failure.
    pub fn admit_envelopes(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        request.validate()?;
        response.validate()?;
        let offer: ExtensionOfferV1 =
            decode_bounded(request.extensions.get(EXTENSION_NEGOTIATION_V1).ok_or(
                ProviderError::Correlation("version1 extension offer missing"),
            )?)?;
        let selected: ExtensionSelectionV1 =
            decode_bounded(response.extensions.get(EXTENSION_NEGOTIATION_V1).ok_or(
                ProviderError::Correlation("version1 extension selection missing"),
            )?)?;
        selected.validate()?;
        let expected = exact_intersection(&offer, self.installed.as_ref())?;
        if selected != expected {
            return Err(ProviderError::Correlation(
                "peer changed exact installed extension intersection",
            ));
        }
        if self
            .selected
            .as_deref()
            .is_some_and(|original| original != selected.selected.as_slice())
        {
            return Err(ProviderError::Correlation(
                "resume changed exact original extension contracts",
            ));
        }

        // Retain the bounded immutable roster before any gate or secret rotates.
        let retained: Arc<[ExtensionSelection]> = selected.selected.into();
        let mut bridge = SelectionVerifier {
            original: verifier,
            installed: self.installed.as_ref(),
            selected: &retained,
        };
        let mut authority = self.handshake.admit_envelopes_versioned(
            request,
            response,
            connection,
            &mut bridge,
            true,
        )?;
        authority.extensions = Some(Arc::clone(&retained));
        self.selected = Some(retained);
        Ok(authority)
    }

    /// Revokes every original registration lease while retaining native custody.
    pub fn contain(&mut self) {
        self.handshake.contain();
    }
}

struct SelectionVerifier<'a, V> {
    original: &'a mut V,
    installed: &'a dyn InstalledExtensionNegotiationVerifier,
    selected: &'a [ExtensionSelection],
}

impl<V: TrustedHandshakeVerifier> TrustedHandshakeVerifier for SelectionVerifier<'_, V> {
    fn authenticate_exchange(
        &mut self,
        connection: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if !request
            .required_features
            .iter()
            .any(|feature| feature.as_str() == EXTENSION_NEGOTIATION_V1)
            || !result
                .selected_features
                .iter()
                .any(|feature| feature.as_str() == EXTENSION_NEGOTIATION_V1)
        {
            return Err(ProviderError::Correlation(
                "typed negotiation feature must be explicitly required and selected",
            ));
        }
        self.original
            .authenticate_exchange(connection, installation, request, result)
    }

    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.original
            .verify_contract_selection(manifest, features, schemas, guarantees)?;
        self.installed.verify_selection(self.selected, features)
    }

    fn resume_custody(
        &mut self,
        session: &Id,
        incarnation: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        self.original
            .resume_custody(session, incarnation, operations)
    }

    fn fence_connection(&mut self, connection: &Id) -> Result<(), ProviderError> {
        self.original.fence_connection(connection)
    }
}
