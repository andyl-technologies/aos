//! Exact authenticated identity custody for pre-publication metadata controls.
//!
//! A bearer is proved by the server before its first mutation. Token renewal
//! reuses the original provider, proves the same immutable actor/deployment and
//! sends the exact owned bearer that was proved, without a shared-token reread.

use aos_net::direct_upload::DirectClientError;
use aos_proto_types::direct_upload::{
    DirectAdvertisedTransferMode, valid_direct_digest, valid_direct_identity,
};
use aos_proto_types::{WhoAmIRequest, WhoAmIResponse};
use serde::{Serialize, de::DeserializeOwned};

use super::{
    super::{HubClient, HubTopologyMethod},
    DirectHubControl, DirectUploadOptions,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) deployment: String,
    pub(super) principal: String,
}

/// Retains one successful authenticated publication transport discovery.
///
/// Successful older empty replies preserve the existing standalone publication
/// compatibility path. Errors and unknown nonempty modes never authorize bodies.
pub struct PublicationTransferDiscovery {
    identity: Option<Identity>,
    legacy_identity: Option<LegacyIdentity>,
    hub: HubClient,
}

impl std::fmt::Debug for PublicationTransferDiscovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicationTransferDiscovery([authenticated policy])")
    }
}

impl PublicationTransferDiscovery {
    /// Returns the positively admitted transport or older standalone compatibility.
    pub fn transfer_mode(&self) -> DirectAdvertisedTransferMode {
        if self.identity.is_some() {
            DirectAdvertisedTransferMode::DirectRequired
        } else {
            DirectAdvertisedTransferMode::Legacy
        }
    }

    /// Returns the exact owned client whose server policy reply was proved.
    ///
    /// This clone owns its bearer; a mutable shared authentication cache cannot
    /// replace the credential between proof and a subsequent request.
    pub fn authenticated_hub(&self) -> HubClient {
        self.hub.clone()
    }

    /// Reconciles direct target discovery with the preceding actor/policy proof.
    ///
    /// # Errors
    /// Refuses a legacy proof or changed deployment/principal before direct work.
    pub fn validate_actor(
        &self,
        capabilities: &aos_proto_types::direct_upload::DirectUploadCapabilities,
    ) -> Result<(), DirectClientError> {
        let identity = self.identity.as_ref().ok_or(DirectClientError::Invalid)?;
        capabilities
            .validate_actor_for(&identity.deployment, &identity.principal)
            .map_err(|_| DirectClientError::Invalid)
    }

    /// Captures legacy credentials without allowing a shared-cache substitution.
    ///
    /// # Errors
    /// Refuses direct policy, anonymous proof or an invalid canonical origin.
    pub fn legacy_bearer(&self) -> Result<PinnedLegacyBearer, DirectClientError> {
        if self.identity.is_some() {
            return Err(DirectClientError::Invalid);
        }
        let token = self.hub.token.clone().ok_or(DirectClientError::Denied)?;
        let origin = url::Url::parse(&self.hub.base)
            .map_err(|_| DirectClientError::Invalid)?
            .origin()
            .ascii_serialization();
        Ok(PinnedLegacyBearer {
            origin,
            token,
            identity: self.legacy_identity.clone(),
        })
    }

    pub(super) fn matches(&self, identity: &Identity) -> bool {
        self.identity.as_ref() == Some(identity)
    }
}

/// Discovers publication body policy through the original authenticated provider.
///
/// Provider readiness remains a later target-specific GetCapabilities check.
/// Direct-required discovery retains the genuine server identity before any
/// first manifest mutation, never a locally decoded JWT or email.
///
/// # Errors
/// Refuses failed/unknown discovery, missing direct identity or another origin.
pub async fn discover_publication_transport(
    hub: &HubClient,
    options: &DirectUploadOptions,
) -> Result<PublicationTransferDiscovery, DirectClientError> {
    let hub = authenticate(hub, options).await?;
    let control = DirectHubControl::new(&hub)?.with_metrics(options.metrics.clone());
    let reply: WhoAmIResponse = control
        .publication_call(
            HubTopologyMethod::WhoAmI,
            &WhoAmIRequest {},
            aos_proto_types::direct_upload::MAX_DIRECT_CONTROL_BYTES,
        )
        .await?;
    match reply.transfer_mode.as_str() {
        "" | "legacy" => Ok(PublicationTransferDiscovery {
            identity: None,
            legacy_identity: legacy_identity(&reply)?,
            hub,
        }),
        "direct_required" => Ok(PublicationTransferDiscovery {
            identity: Some(identity(reply)?),
            legacy_identity: None,
            hub,
        }),
        _ => Err(DirectClientError::Invalid),
    }
}

/// An origin-pinned owned bearer from a successful legacy policy proof.
///
/// This value has redacted Debug and no serialization. Each request captures an
/// immutable proved bearer; renewal changes custody only after server proof:
/// a shared authentication-cache refresh cannot substitute a different bearer.
/// A new bearer requires a new successful authenticated policy proof. Older
/// servers provide only their historical kind/reference continuity guarantee;
/// this does not prove immutable continuity across recycled accounts.
pub struct PinnedLegacyBearer {
    origin: String,
    token: String,
    identity: Option<LegacyIdentity>,
}

#[derive(Clone)]
struct LegacyIdentity {
    kind: String,
    reference: String,
    modern: Option<Identity>,
}

fn legacy_identity(reply: &WhoAmIResponse) -> Result<Option<LegacyIdentity>, DirectClientError> {
    if reply.principal_kind.is_empty() && reply.principal_ref.is_empty() {
        return Ok(None);
    }
    if !matches!(reply.principal_kind.as_str(), "user" | "service_account")
        || reply.principal_ref.is_empty()
        || reply.principal_ref.len() > 1024
        || reply.principal_ref.chars().any(char::is_control)
    {
        return Err(DirectClientError::Invalid);
    }
    let modern = if reply.deployment_id.is_empty() && reply.principal_id.is_empty() {
        None
    } else {
        Some(identity(reply.clone())?)
    };
    Ok(Some(LegacyIdentity {
        kind: reply.principal_kind.clone(),
        reference: reply.principal_ref.clone(),
        modern,
    }))
}

impl std::fmt::Debug for PinnedLegacyBearer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedLegacyBearer([private])")
    }
}

impl PinnedLegacyBearer {
    /// Renews credentials after a successful original-origin legacy identity proof.
    ///
    /// Modern identity pins remain exact when originally present. Older servers
    /// must preserve their historical principal kind/reference and legacy mode;
    /// this compatibility rule does not establish immutable account continuity.
    /// An initial response without either historical identity cannot renew.
    ///
    /// # Errors
    /// Refuses changed origin, actor, modern identity, mode or failed proof.
    pub async fn refresh(
        &mut self,
        candidate: &HubClient,
        options: &DirectUploadOptions,
    ) -> Result<(), DirectClientError> {
        let owned = authenticate(candidate, options).await?;
        let origin = url::Url::parse(&owned.base)
            .map_err(|_| DirectClientError::Invalid)?
            .origin()
            .ascii_serialization();
        if origin != self.origin {
            return Err(DirectClientError::Invalid);
        }
        if owned.token.as_ref() == Some(&self.token) {
            return Ok(());
        }
        let original = self.identity.as_ref().ok_or(DirectClientError::Invalid)?;
        // This proof owns its bearer. No later mutable auth-store lookup can
        // choose a different credential for the dispatched legacy request.
        let proof = discover_publication_transport(
            &owned,
            &DirectUploadOptions {
                authentication: None,
                ..options.clone()
            },
        )
        .await?;
        if proof.transfer_mode() != DirectAdvertisedTransferMode::Legacy {
            return Err(DirectClientError::Invalid);
        }
        let renewed = proof
            .legacy_identity
            .as_ref()
            .ok_or(DirectClientError::Invalid)?;
        if original.kind != renewed.kind
            || original.reference != renewed.reference
            || original
                .modern
                .as_ref()
                .is_some_and(|id| renewed.modern.as_ref() != Some(id))
        {
            return Err(DirectClientError::Invalid);
        }
        self.token = proof.hub.token.ok_or(DirectClientError::Denied)?;
        Ok(())
    }

    /// Applies one exact proved credential to an existing-origin request.
    ///
    /// # Errors
    /// Refuses malformed URLs or a different origin before attaching credentials.
    pub fn apply(&self, request: &mut aos_net::TransferRequest) -> Result<(), DirectClientError> {
        let url = url::Url::parse(&request.url).map_err(|_| DirectClientError::Invalid)?;
        let origin = url.origin().ascii_serialization();
        if origin != self.origin
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(DirectClientError::Invalid);
        }
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
        request
            .headers
            .push(("Authorization".into(), format!("Bearer {}", self.token)));
        Ok(())
    }
}

pub(super) struct PublicationControl {
    original: HubClient,
    options: DirectUploadOptions,
    pub(super) identity: Identity,
    state: tokio::sync::Mutex<DirectHubControl>,
}

impl PublicationControl {
    pub(super) async fn new(
        original: &HubClient,
        options: &DirectUploadOptions,
    ) -> Result<Self, DirectClientError> {
        let hub = authenticate(original, options).await?;
        let control = DirectHubControl::new(&hub)?.with_metrics(options.metrics.clone());
        let identity = prove(&control).await?;
        Ok(Self {
            original: original.clone(),
            options: options.clone(),
            identity,
            state: tokio::sync::Mutex::new(control),
        })
    }

    pub(super) async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: HubTopologyMethod,
        request: &T,
        maximum_reply: usize,
    ) -> Result<R, DirectClientError> {
        let mut state = self.state.lock().await;
        for attempt in 0..3 {
            let hub = authenticate(&self.original, &self.options).await?;
            if hub.token != state.token {
                let renewed =
                    DirectHubControl::new(&hub)?.with_metrics(self.options.metrics.clone());
                if prove(&renewed).await? != self.identity {
                    return Err(DirectClientError::Invalid);
                }
                *state = renewed;
            }
            // This pool owns the bearer whose identity was proved. Neither
            // ordinary auth caches nor provider callbacks can mutate it here.
            match state.publication_call(method, request, maximum_reply).await {
                Err(DirectClientError::ControlUnavailable | DirectClientError::Blocked)
                    if attempt < 2 =>
                {
                    // Only original request bytes replay, under Native metadata
                    // generation/manifest/chunk CAS; no provider control occurs.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                result => return result,
            }
        }
        Err(DirectClientError::ControlUnavailable)
    }
}

async fn authenticate(
    original: &HubClient,
    options: &DirectUploadOptions,
) -> Result<HubClient, DirectClientError> {
    let hub = match &options.authentication {
        Some(provider) => provider.authenticate(&original.base).await?,
        None => original.clone(),
    };
    if hub.base != original.base {
        return Err(DirectClientError::Invalid);
    }
    Ok(hub)
}

async fn prove(control: &DirectHubControl) -> Result<Identity, DirectClientError> {
    let reply: WhoAmIResponse = control
        .publication_call(
            HubTopologyMethod::WhoAmI,
            &WhoAmIRequest {},
            aos_proto_types::direct_upload::MAX_DIRECT_CONTROL_BYTES,
        )
        .await?;
    if reply.transfer_mode != "direct_required" {
        return Err(DirectClientError::Invalid);
    }
    identity(reply)
}

fn identity(reply: WhoAmIResponse) -> Result<Identity, DirectClientError> {
    if !valid_direct_identity(&reply.deployment_id) || !valid_direct_digest(&reply.principal_id) {
        return Err(DirectClientError::Invalid);
    }
    Ok(Identity {
        deployment: reply.deployment_id,
        principal: reply.principal_id,
    })
}

#[cfg(test)]
mod tests;
