//! Bounded batched direct staging with explicit durable retry custody.
//!
//! The engine moves parts only. Storage-side completion and final publication
//! are bounded control operations whose returned states remain authoritative.
//! A staged batch may precede other batches needed by a publication barrier.

mod helpers;
mod status;
mod transfer;

use std::fmt;

use aos_proto_types::direct_upload::*;
use async_trait::async_trait;

use super::{AdmittedSource, PartSource, ProviderContext, ProviderError, ProviderTransport};

pub use transfer::upload_direct_batch;

/// Closed failures without provider URLs, body content or raw RPC responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectClientError {
    /// A declaration, response or persisted identity changed.
    Invalid,
    /// A local retained source no longer has the admitted bytes.
    SourceChanged,
    /// Durable checkpoint ownership or persistence failed.
    Checkpoint,
    /// A bounded control request is unavailable.
    ControlUnavailable,
    /// An authorization or provider policy refused the operation.
    Denied,
    /// A provider-control outcome remains unknown or needs reconciliation.
    Blocked,
    /// A checksum-bound part exhausted its bounded transport retries.
    PartUnavailable,
}

impl fmt::Display for DirectClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "direct upload identity or protocol response changed",
            Self::SourceChanged => "direct upload source changed",
            Self::Checkpoint => "direct upload checkpoint is unavailable",
            Self::ControlUnavailable => "direct upload control is unavailable",
            Self::Denied => "direct upload was refused",
            Self::Blocked => "direct upload requires control reconciliation",
            Self::PartUnavailable => "direct upload part retries were exhausted",
        })
    }
}

impl std::error::Error for DirectClientError {}

/// One file whose original full and part hashes were checked before effects.
#[derive(Debug, Clone)]
pub struct DirectUploadObject {
    /// Exact immutable logical admission, including retained client operation.
    pub intent: DirectUploadIntent,
    /// Retained regular descriptor and original part checksum catalogue.
    pub source: AdmittedSource,
    /// Sorted exact required placements from authenticated public discovery.
    pub placements: Vec<DirectPlacementRef>,
    /// Independently authenticated reusable owner discovery and exclusive expiry.
    pub discovery: DirectUploadCapabilities,
}

/// An observed exact provider part, retained before reporting its outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectPartReceipt {
    /// Original admitted session.
    pub session: DirectSessionRef,
    /// Original required placement.
    pub placement: DirectPlacementRef,
    /// Original issuing grant identity, excluding its bearer URL.
    pub grant_id: String,
    /// Original issuing grant revision.
    pub grant_revision: WireInteger,
    /// Exact original part commitment and provider ETag.
    pub observed: DirectManifestPart,
}

/// One original part's durable grant-attempt reservation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DirectGrantAttempt {
    /// Original session and immutable admission fingerprint.
    pub session: DirectSessionRef,
    /// Original destination and checksum policy.
    pub placement: DirectPlacementRef,
    /// Original one-based part number.
    pub part_number: u32,
    /// Advances an expired/refused grant instead of replaying its last ordinal.
    pub refresh: bool,
}

/// One bounded authenticated server-observation persistence item.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DirectObservedPart {
    /// Original session and admission fingerprint.
    pub session: DirectSessionRef,
    /// Original required destination.
    pub placement: DirectPlacementRef,
    /// Exact original part bytes/checksum and strong provider ETag.
    pub observed: DirectManifestPart,
}

/// Durable custody used before every operation that can issue a new capability.
///
/// Implementations scope keys to the authenticated Hub/deployment/principal and
/// logical operation, refuse changed source/owner/geometry, and use private
/// atomic storage. Neither bearer URLs nor provider UploadIds belong here.
#[async_trait]
pub trait DirectCheckpointStore: Send + Sync {
    /// Durably admits one bounded intent wave before any Begin dispatch.
    ///
    /// # Errors
    /// Refuses excessive waves, changed declarations or failed durable storage.
    async fn admit_intents(&self, intents: &[DirectUploadIntent]) -> Result<(), DirectClientError> {
        if intents.is_empty() || intents.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Invalid);
        }
        for intent in intents {
            self.admit_intent(intent).await?;
        }
        Ok(())
    }

    /// Retains a bounded original session wave before delegation.
    ///
    /// # Errors
    /// Refuses excessive waves, replacement identities or durable storage failure.
    async fn admit_sessions(
        &self,
        statuses: &[DirectSessionStatus],
    ) -> Result<(), DirectClientError> {
        if statuses.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Invalid);
        }
        for status in statuses {
            self.admit_session(status).await?;
        }
        Ok(())
    }

    /// Durably reserves bounded grant ordinals before a whole delegation wave.
    ///
    /// # Errors
    /// Refuses excessive waves, changed scope, overflow or failed persistence.
    async fn grant_attempts(
        &self,
        attempts: &[DirectGrantAttempt],
    ) -> Result<Vec<u64>, DirectClientError> {
        if attempts.is_empty() || attempts.len() > MAX_DIRECT_BATCH_PARTS {
            return Err(DirectClientError::Invalid);
        }
        let mut result = Vec::with_capacity(attempts.len());
        for attempt in attempts {
            result.push(
                self.grant_attempt(
                    &attempt.session,
                    &attempt.placement,
                    attempt.part_number,
                    attempt.refresh,
                )
                .await?,
            );
        }
        Ok(result)
    }

    /// Persists a bounded exact receipt wave before any Report dispatch.
    ///
    /// # Errors
    /// Refuses excessive waves, changed receipts or failed durable storage.
    async fn record_receipts(
        &self,
        receipts: &[DirectPartReceipt],
    ) -> Result<(), DirectClientError> {
        if receipts.len() > MAX_DIRECT_BATCH_PARTS {
            return Err(DirectClientError::Invalid);
        }
        for receipt in receipts {
            self.record_receipt(receipt).await?;
        }
        Ok(())
    }

    /// Persists bounded acknowledged observations in one durable wave.
    ///
    /// # Errors
    /// Refuses excessive waves, changed identities or failed durable storage.
    async fn record_server_parts(
        &self,
        parts: &[DirectObservedPart],
    ) -> Result<(), DirectClientError> {
        if parts.len() > MAX_DIRECT_BATCH_PARTS {
            return Err(DirectClientError::Invalid);
        }
        for part in parts {
            self.record_server_part(&part.session, &part.placement, &part.observed)
                .await?;
        }
        Ok(())
    }

    /// Retains a bounded original completion wave before control dispatch.
    ///
    /// # Errors
    /// Refuses excessive waves, changed completion commitments or persistence.
    async fn admit_completes(
        &self,
        requests: &[DirectCompleteRequest],
    ) -> Result<Vec<DirectCompleteRequest>, DirectClientError> {
        if requests.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Invalid);
        }
        let mut result = Vec::with_capacity(requests.len());
        for request in requests {
            result.push(self.admit_complete(request).await?);
        }
        Ok(result)
    }
    /// Retains an intent before Begin and refuses a different exact declaration.
    ///
    /// # Errors
    /// Fails before remote effects if custody or durable persistence fails.
    async fn admit_intent(&self, intent: &DirectUploadIntent) -> Result<(), DirectClientError>;

    /// Retains the original session and complete required placement set.
    ///
    /// # Errors
    /// Refuses replacement session/fingerprint/placement or persistence failure.
    async fn admit_session(&self, status: &DirectSessionStatus) -> Result<(), DirectClientError>;

    /// Advances or replays a durable grant-attempt ordinal before grant RPC.
    ///
    /// `refresh=false` reuses the last ordinal, including after a lost reply.
    /// `refresh=true` advances it only for an expired/refused capability. The
    /// returned ordinal must already be durable; it never changes source bytes.
    ///
    /// # Errors
    /// Refuses changed custody, ordinal overflow or persistence failure.
    async fn grant_attempt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
        refresh: bool,
    ) -> Result<u64, DirectClientError>;

    /// Reads an exact local provider observation whose report may need replay.
    ///
    /// # Errors
    /// Refuses malformed/oversized checkpoint or changed admission identity.
    async fn receipt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
    ) -> Result<Option<DirectPartReceipt>, DirectClientError>;

    /// Durably retains an observation before its report request can be lost.
    ///
    /// # Errors
    /// Refuses changed receipt identity or durable persistence failure.
    async fn record_receipt(&self, receipt: &DirectPartReceipt) -> Result<(), DirectClientError>;

    /// Retains an exact authenticated server observation in bounded sparse storage.
    ///
    /// # Errors
    /// Refuses changed scope/part descriptor or durable persistence failure.
    async fn record_server_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        observed: &DirectManifestPart,
    ) -> Result<(), DirectClientError>;

    /// Reads one exact observed part for bounded manifest assembly.
    ///
    /// # Errors
    /// Refuses malformed storage or changed scope/part descriptor.
    async fn observed_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
    ) -> Result<Option<DirectManifestPart>, DirectClientError>;

    /// Retains original compact completion before its first provider-control RPC.
    ///
    /// Exact replay returns its original expected resource version even after
    /// the server advances a phase. Changed session/manifest/operation rejects.
    /// This never authorizes an alternative close after an unknown outcome.
    ///
    /// # Errors
    /// Refuses changed completion identity or durable persistence failure.
    async fn admit_complete(
        &self,
        request: &DirectCompleteRequest,
    ) -> Result<DirectCompleteRequest, DirectClientError>;

    /// Reads an original completion before accepting server-side pending work.
    ///
    /// Stores without a verified retained read refuse pending resume by default.
    ///
    /// # Errors
    /// Refuses missing custody, malformed records or storage failures.
    async fn retained_complete(
        &self,
        _session: &DirectSessionRef,
    ) -> Result<Option<DirectCompleteRequest>, DirectClientError> {
        Err(DirectClientError::Checkpoint)
    }
}

/// Small authenticated Hub controls, without an application-body upload method.
#[async_trait]
pub trait DirectUploadControl: Send + Sync {
    /// Executes one closed bounded request and returns its bounded reply.
    ///
    /// # Errors
    /// Returns a value-free failure, never raw Hub/provider response content.
    async fn execute(
        &self,
        request: &DirectUploadRequest,
    ) -> Result<DirectUploadResponse, DirectClientError>;
}

/// Exact provider part transport, independent from Hub control credentials.
#[async_trait]
pub trait DirectPartTransport: Send + Sync {
    /// Sends a position-independent part under its original checksum-bound grant.
    ///
    /// # Errors
    /// Refuses unsafe grants/transport or reports a bounded retry classification.
    async fn send_part(
        &self,
        context: &ProviderContext,
        source: &PartSource,
        grant: &DirectPartGrant,
    ) -> Result<DirectManifestPart, ProviderError>;
}

#[async_trait]
impl DirectPartTransport for ProviderTransport {
    async fn send_part(
        &self,
        context: &ProviderContext,
        source: &PartSource,
        grant: &DirectPartGrant,
    ) -> Result<DirectManifestPart, ProviderError> {
        self.upload_part(context, source, grant).await
    }
}

#[cfg(test)]
mod tests;
