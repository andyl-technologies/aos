//! Bounded authenticated direct-upload control, separate from provider bodies.
//!
//! The authenticated Hub receives closed controls only. Its response bytes are
//! bounded before decoding and errors never expose raw provider capability URLs
//! or envelope messages. Legacy transport is selected only by valid discovery.

#[cfg(unix)]
mod authentication;
#[cfg(unix)]
pub use authentication::DirectProvisioningAuthentication;

#[cfg(unix)]
mod coordinator;
#[cfg(unix)]
mod local;
#[cfg(unix)]
mod publication;
#[cfg(unix)]
mod publication_identity;
#[cfg(unix)]
pub use publication::{
    PreparedDirectPublication, commit_direct_publication, prepare_direct_publication,
    publication_inventory_digest,
};
#[cfg(unix)]
pub use publication_identity::{
    PinnedLegacyBearer, PublicationTransferDiscovery, discover_publication_transport,
};
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod refresh;
#[cfg(unix)]
pub use coordinator::{DirectStageFile, DirectUploadCoordinator, checkpoint_namespace};
#[cfg(unix)]
pub use local::DirectStagePath;
#[cfg(unix)]
pub use options::DirectUploadOptions;
#[cfg(unix)]
pub use refresh::DirectHubAuthentication;

use std::fmt;
use std::time::Duration;

use aos_net::direct_upload::{DirectClientError, DirectUploadControl};
use aos_proto_types::direct_upload::*;
use aos_proto_types::{CONNECT_PROTOCOL_VERSION, CONNECT_PROTOCOL_VERSION_HEADER};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

use super::HubClient;

/// Authenticated bounded Hub controls that never send application file bytes.
#[derive(Clone)]
pub struct DirectHubControl {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
    maximum_control_bytes: usize,
    metrics: std::sync::Arc<aos_net::direct_upload::DirectTransferMetrics>,
}

impl fmt::Debug for DirectHubControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectHubControl")
            .field("authenticated", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

impl DirectHubControl {
    /// Admits historical body transport through authenticated server policy.
    ///
    /// Platforms without private-journal custody use this metadata-only check
    /// before sending a positively identified Hub any legacy upload body.
    /// Successful old empty replies retain standalone compatibility. Direct
    /// policy requires a supported direct adapter even when providers are unready.
    ///
    /// # Errors
    /// Refuses direct-required, unknown or failed policy discovery without
    /// exposing the response or credential.
    pub async fn require_legacy_transport(&self) -> Result<(), DirectClientError> {
        let reply: aos_proto_types::WhoAmIResponse = self
            .publication_call(
                super::HubTopologyMethod::WhoAmI,
                &aos_proto_types::WhoAmIRequest {},
                MAX_DIRECT_CONTROL_BYTES,
            )
            .await?;
        match reply.transfer_mode.as_str() {
            "" | "legacy" => Ok(()),
            _ => Err(DirectClientError::Invalid),
        }
    }

    /// Builds a credential-confined control pool from an existing Hub client.
    ///
    /// Hub credentials remain on its configured origin; provider grants use a
    /// different transport. Environment proxies and HTTP redirects are disabled.
    /// The configured Hub may use HTTP for existing explicit local deployments;
    /// this never authorizes an HTTP provider URL.
    ///
    /// # Errors
    /// Returns a value-free failure if the pool cannot be initialized.
    pub fn new(hub: &HubClient) -> Result<Self, DirectClientError> {
        let base = url::Url::parse(&hub.base).map_err(|_| DirectClientError::Invalid)?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(DirectClientError::Invalid);
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| DirectClientError::ControlUnavailable)?;
        Ok(Self {
            http,
            base: hub.base.clone(),
            token: hub.token.clone(),
            maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES,
            metrics: std::sync::Arc::new(aos_net::direct_upload::DirectTransferMetrics::default()),
        })
    }

    /// Shares value-free attempted-call counters across owned bearer renewal.
    pub fn with_metrics(
        mut self,
        metrics: std::sync::Arc<aos_net::direct_upload::DirectTransferMetrics>,
    ) -> Self {
        self.metrics = metrics;
        self
    }

    /// Applies a smaller independently authenticated whole-control byte limit.
    ///
    /// # Errors
    /// Refuses zero or a limit above the fixed protocol maximum.
    pub fn with_control_limit(&self, maximum: usize) -> Result<Self, DirectClientError> {
        if maximum == 0 || maximum > MAX_DIRECT_CONTROL_BYTES {
            return Err(DirectClientError::Invalid);
        }
        let mut result = self.clone();
        result.maximum_control_bytes = maximum;
        Ok(result)
    }

    /// Resolves explicit transport policy for the exact authenticated owner.
    ///
    /// Only a valid `Legacy` response permits a standalone old-API adapter. An
    /// unavailable, unknown or malformed reply is an error, never fallback.
    ///
    /// # Errors
    /// Returns a value-free authorization, transport or closed protocol failure.
    pub async fn capabilities(
        &self,
        target: &DirectCapabilitiesTarget,
    ) -> Result<DirectUploadCapabilities, DirectClientError> {
        target.validate().map_err(|_| DirectClientError::Invalid)?;
        let request = DirectGetCapabilities {
            target: target.clone(),
        };
        let response: DirectUploadCapabilities = self.call("GetCapabilities", &request).await?;
        response
            .validate_for(target)
            .map_err(|_| DirectClientError::Invalid)?;
        Ok(response)
    }

    async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        request: &T,
    ) -> Result<R, DirectClientError> {
        let bytes = self
            .post_bytes(
                &format!("aos.hub.v1.DirectUploadService/{method}"),
                request,
                self.maximum_control_bytes,
            )
            .await?;
        decode_direct_control(&bytes).map_err(|_| DirectClientError::Invalid)
    }

    pub(super) async fn publication_call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: super::HubTopologyMethod,
        request: &T,
        maximum_reply: usize,
    ) -> Result<R, DirectClientError> {
        use super::HubTopologyMethod::*;
        if !matches!(
            method,
            GetRegistry
                | ListRegistryPublications
                | GetRegistryPublication
                | BeginRegistryPublicationManifest
                | AppendRegistryPublicationManifest
                | SealRegistryPublicationManifest
                | CommitRegistryPublication
                | WhoAmI
        ) {
            return Err(DirectClientError::Invalid);
        }
        let bytes = self
            .post_bytes(method.path(), request, maximum_reply)
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| DirectClientError::Invalid)
    }

    async fn post_bytes<T: Serialize>(
        &self,
        path: &str,
        request: &T,
        maximum_reply: usize,
    ) -> Result<Vec<u8>, DirectClientError> {
        if maximum_reply == 0 || maximum_reply > 64 * 1024 * 1024 {
            return Err(DirectClientError::Invalid);
        }
        let body = encode_direct_control(request).map_err(|_| DirectClientError::Invalid)?;
        if body.len() > self.maximum_control_bytes {
            return Err(DirectClientError::Invalid);
        }
        let mut request = self
            .http
            .post(format!("{}{path}", self.base))
            .header(CONNECT_PROTOCOL_VERSION_HEADER, CONNECT_PROTOCOL_VERSION)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        use aos_net::direct_upload::DirectControlKind as Kind;
        let kind = match path.rsplit('/').next() {
            Some("GetCapabilities") => Kind::Capabilities,
            Some("BeginBatch") => Kind::Begin,
            Some("StatusBatch") => Kind::Status,
            Some("GrantPartsBatch") => Kind::Grant,
            Some("ReportPartsBatch") => Kind::Report,
            Some("CompleteBatch") => Kind::Complete,
            Some("Abort") => Kind::Abort,
            Some("WhoAmI") => Kind::Identity,
            Some("BeginRegistryPublicationManifest") => Kind::ManifestBegin,
            Some("AppendRegistryPublicationManifest") => Kind::ManifestAppend,
            Some("SealRegistryPublicationManifest") => Kind::ManifestSeal,
            Some("CommitRegistryPublication") => Kind::PublicationCommit,
            _ => Kind::MetadataRead,
        };
        self.metrics.record_control_attempt(kind);
        let mut response = request
            .send()
            .await
            .map_err(|_| DirectClientError::ControlUnavailable)?;
        // Error envelopes may contain upstream URLs or provider bodies. Do not
        // parse, log or attach their text to a public error chain.
        match response.status().as_u16() {
            200 => {}
            401 | 403 => return Err(DirectClientError::Denied),
            409 | 412 => return Err(DirectClientError::Blocked),
            429 | 500..=599 => return Err(DirectClientError::ControlUnavailable),
            _ => return Err(DirectClientError::Invalid),
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum_reply as u64)
        {
            return Err(DirectClientError::Invalid);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DirectClientError::ControlUnavailable)?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > maximum_reply)
            {
                return Err(DirectClientError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;

#[async_trait]
impl DirectUploadControl for DirectHubControl {
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError> {
        request.validate().map_err(|_| DirectClientError::Invalid)?;
        let (response, expected_operation): (DirectUploadResponse, &str) = match request {
            DirectUploadRequest::BeginBatch(batch) => {
                (self.call("BeginBatch", batch).await?, &batch.operation_id)
            }
            DirectUploadRequest::StatusBatch(batch) => {
                (self.call("StatusBatch", batch).await?, &batch.operation_id)
            }
            DirectUploadRequest::GrantPartsBatch(batch) => (
                self.call("GrantPartsBatch", batch).await?,
                &batch.operation_id,
            ),
            DirectUploadRequest::ReportPartsBatch(batch) => (
                self.call("ReportPartsBatch", batch).await?,
                &batch.operation_id,
            ),
            DirectUploadRequest::CompleteBatch(batch) => (
                self.call("CompleteBatch", batch).await?,
                &batch.operation_id,
            ),
            DirectUploadRequest::Abort(batch) => {
                (self.call("Abort", batch).await?, &batch.operation_id)
            }
        };
        response
            .validate()
            .map_err(|_| DirectClientError::Invalid)?;
        if response.operation_id != expected_operation {
            return Err(DirectClientError::Invalid);
        }
        Ok(response)
    }
}
