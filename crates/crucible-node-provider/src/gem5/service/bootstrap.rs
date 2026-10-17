//! Private installation authorization for the measured gem5 discovery service.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Id, Validate};

use crate::{
    ProviderError,
    handshake::{Handshake, Limits, NegotiationPolicy, TrustedInstallation},
};

use super::super::{Gem5Launch, Gem5LaunchArtifact};
use super::Gem5Catalog;

/// Authenticates installed gem5 artifacts and private launch custody.
///
/// Implementations belong to the trusted host launcher. They must consult actual
/// installation and admission records; a provider-supplied content reference or
/// native observer's `complete` field cannot implement this authority.
pub trait Gem5InstallationVerifier {
    /// Authenticates complete measurements, launch identity and resource custody.
    ///
    /// # Errors
    /// Rejects unsupported source or host ABI, changed installed model/device
    /// selection, foreign launch receipts or missing native supervision.
    fn authenticate_installation(
        &self,
        launch: &Gem5Launch,
        catalog: &Gem5Catalog,
        launch_receipt: &ContentRef,
        session: &Id,
    ) -> Result<(), ProviderError>;
}

/// Retains a privately authenticated gem5 service installation and launch secret.
///
/// No wire deserializer exists for this value. Creating it requires actual file
/// measurements and a trusted installation verifier. It authorizes negotiation,
/// not execution, node admission, capture, or activation.
pub struct Gem5ServiceBootstrap {
    pub(super) launch: Gem5Launch,
    pub(super) catalog: Gem5Catalog,
    session: Id,
    receipt: ContentRef,
    token: [u8; 32],
    limits: Limits,
}

impl Gem5ServiceBootstrap {
    /// Measures and authenticates private installation before opening an endpoint.
    ///
    /// The caller obtains the unpredictable token and receipt from its private
    /// launch channel. The token is never logged or returned by discovery.
    ///
    /// # Errors
    /// Rejects malformed limits or receipts, changed artifact bytes, invalid
    /// owner generation, unbounded native deadlines, or failed host authorization.
    pub fn authenticate(
        provider: &Gem5LaunchArtifact,
        launch: Gem5Launch,
        session: Id,
        receipt: ContentRef,
        token: [u8; 32],
        limits: Limits,
        verifier: &dyn Gem5InstallationVerifier,
    ) -> Result<Self, ProviderError> {
        limits.validate()?;
        receipt.validate()?;
        if launch.generation.get() == 0
            || launch.timeout.is_zero()
            || launch.timeout > std::time::Duration::from_secs(300)
        {
            return Err(ProviderError::Frame("invalid gem5 private launch bounds"));
        }
        let catalog = Gem5Catalog::measure(provider, &launch)?;
        verifier.authenticate_installation(&launch, &catalog, &receipt, &session)?;

        Ok(Self {
            launch,
            catalog,
            session,
            receipt,
            token,
            limits,
        })
    }

    /// Returns immutable discovery content without exposing private paths or secrets.
    pub fn catalog(&self) -> &Gem5Catalog {
        &self.catalog
    }

    /// Returns the host-admitted surviving world session.
    pub fn session_id(&self) -> &Id {
        &self.session
    }

    /// Returns the native incarnation fenced by the private launch authority.
    pub fn incarnation_id(&self) -> &Id {
        &self.launch.incarnation
    }

    /// Creates standard revocable CNP negotiation under the measured installation.
    ///
    /// The normal trusted exchange verifier must still authenticate actual peer
    /// credentials and private challenge/token custody on every connection.
    /// Resumption is not advertised until the complete original control ledger
    /// has a qualified native continuation implementation.
    ///
    /// # Errors
    /// Rejects invalid installed identity or bounded negotiation policy.
    pub fn handshake(&self) -> Result<Handshake, ProviderError> {
        let core = Id::new("cnp.core/1")?;
        Handshake::new(
            TrustedInstallation {
                session_id: self.session.clone(),
                incarnation_id: self.launch.incarnation.clone(),
                measured_implementation: self.catalog.manifest().implementation.clone(),
                launch_receipt: self.receipt.clone(),
                admission_token: self.token,
            },
            NegotiationPolicy {
                supported_features: vec![core.clone()],
                required_features: vec![core],
                provider_limits: self.limits,
                required_schemas: Vec::new(),
                required_guarantees: self.catalog.guarantee_reference().clone(),
                envelope_extension_features: BTreeMap::new(),
            },
        )
    }
}
