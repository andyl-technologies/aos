//! Typed control and complete evidence custody for the installed public checksum profile.

use std::time::Duration;

use crucible_node_contract::{ContentRef, Extensions, Id, Validate, canonical};
use serde_json::Value;

use crate::ProviderError;
use crate::bodies::{MethodResult, ResponseBody, ResponseShape, decode_request, decode_response};
use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use crate::reference_service::{ReferenceProfile, ReferenceServiceBootstrap};

use super::session::object;
use super::{ClientCustody, ClientSession};

#[path = "reference/evidence.rs"]
mod evidence;

pub use evidence::{
    ObservationHandle, ObservationLimits, ObservationScope, ObservedContent, ObservedRequest,
    ObservedRequestKey, RecordedReferenceObservation, ReferenceObservationSnapshot,
};

#[path = "reference/original_response_loss.rs"]
pub(crate) mod original_response_loss;
pub use original_response_loss::{
    OriginalResponseLossObservation, OriginalResponseLossObservationHandle,
    OriginalResponseLossQualification,
};

#[path = "reference/resend.rs"]
mod resend;

#[path = "reference/conflict_transmissions.rs"]
pub(crate) mod conflict_transmissions;
#[path = "reference/lifecycle_resend.rs"]
mod lifecycle_resend;
#[path = "reference/original_conflict.rs"]
mod original_conflict;
#[path = "reference/transmissions.rs"]
pub(crate) mod transmissions;
pub use conflict_transmissions::{
    OriginalConflictLimits, OriginalConflictObservation, OriginalConflictObservationHandle,
};
pub use transmissions::{
    TransmissionLimits, TransmissionObservation, TransmissionObservationHandle,
};

/// Owns original public control and receipt bytes beneath a separately retained native peer.
///
/// The enclosing installed adapter retains the actual provider Child, private
/// bootstrap and mandatory supervision slot. This controller neither grants
/// execution authority nor authenticates receipt semantics from their shape.
pub struct ReferenceController {
    /// Retains independently measured immutable model and schema content.
    pub profile: ReferenceProfile,
    /// Retains private installation scope; credentials must not enter diagnostics.
    pub bootstrap: ReferenceServiceBootstrap,
    session: ClientSession,
    custody: ClientCustody,
    budget: Duration,
    qualifications: Vec<ContentRef>,
    observer: Option<evidence::ObservationRecorder>,
    transmissions: Option<transmissions::TransmissionRecorder>,
    conflicts: Option<conflict_transmissions::OriginalConflictRecorder>,
}

impl ReferenceController {
    /// Returns the actual kernel peer checked against the original private launch.
    pub fn peer_pid(&self) -> u32 {
        self.session.peer_pid()
    }

    /// Borrows the original authenticated typed Hello selection, when opted in.
    ///
    /// The roster supplies metadata, not source qualification or lease liveness.
    pub fn selected_extensions(&self) -> Option<&[crucible_node_contract::ExtensionSelection]> {
        self.session.authority().selected_extensions()
    }

    /// Checks this actual session against its original retained typed registrar.
    ///
    /// # Errors
    /// Refuses a foreign, superseded or contained registrar, or changed selection.
    pub fn verify_extension_registrar(
        &self,
        registrar: &crate::handshake::ExtensionHandshake,
    ) -> Result<(), ProviderError> {
        registrar.verify_authority(self.session.authority())
    }

    /// Returns the measured public endpoint executable without conferring authority.
    pub fn peer_executable(&self) -> &ContentRef {
        self.session.peer_executable()
    }
    /// Takes the original authenticated connection and finite request/content ledgers.
    ///
    /// # Errors
    /// Refuses wrong live scope, missing negotiated evidence delivery, invalid
    /// private bootstrap or an unavailable immutable profile definition.
    pub fn new(
        profile: ReferenceProfile,
        bootstrap: ReferenceServiceBootstrap,
        session: ClientSession,
        custody: ClientCustody,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        Self::new_qualified(profile, bootstrap, session, custody, budget, Vec::new())
    }

    /// Retains exact host-selected qualification references in a private installed binding.
    ///
    /// This constructor validates custody and immutable bytes only. The host
    /// registry independently authenticates every qualification and native owner.
    /// Empty references preserve the original public controller behavior.
    ///
    /// # Errors
    /// Refuses invalid original scope, missing evidence negotiation, noncanonical
    /// references, absent private evidence bytes or exhausted finite custody.
    pub fn new_qualified(
        profile: ReferenceProfile,
        bootstrap: ReferenceServiceBootstrap,
        session: ClientSession,
        mut custody: ClientCustody,
        budget: Duration,
        qualifications: Vec<ContentRef>,
    ) -> Result<Self, ProviderError> {
        bootstrap.validate()?;
        profile.bind_qualified(bootstrap.authority.clone(), &qualifications)?;
        for reference in &qualifications {
            let installed = bootstrap
                .installed_content
                .iter()
                .find(|content| content.reference == *reference)
                .ok_or(ProviderError::Correlation(
                    "private installed qualification bytes unavailable",
                ))?;
            reference.verify(installed.bytes.as_slice())?;
        }
        if budget.is_zero()
            || session.authority().session_id() != &bootstrap.authority.session_id
            || session.authority().incarnation_id() != &bootstrap.authority.incarnation_id
            || !session
                .authority()
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1")
        {
            return Err(ProviderError::Correlation(
                "reference controller lacks original admitted evidence scope",
            ));
        }
        for content in profile.content_objects() {
            custody
                .content_mut()
                .install(content.reference.clone(), content.bytes.clone())?;
        }
        for content in &bootstrap.installed_content {
            custody
                .content_mut()
                .install(content.reference.clone(), content.bytes.as_slice().to_vec())?;
        }
        Ok(Self {
            profile,
            bootstrap,
            session,
            custody,
            budget,
            qualifications,
            observer: None,
            transmissions: None,
            conflicts: None,
        })
    }

    /// Returns the exact privately installed durable binding and owner roster.
    ///
    /// # Errors
    /// Refuses invalid original authority or qualification reference data.
    pub fn binding(
        &self,
    ) -> Result<
        (
            crucible_node_contract::NodeBinding,
            crucible_node_contract::OwnerBinding,
        ),
        ProviderError,
    > {
        self.profile
            .bind_qualified(self.bootstrap.authority.clone(), &self.qualifications)
    }

    /// Sends an immutable original control request and retains its complete promised evidence.
    ///
    /// The caller supplies the original request and operation IDs from host
    /// admission. This function only maps and correlates protocol data. Refusal
    /// and uncertainty remain in the returned typed ResponseBody and custody.
    ///
    /// # Errors
    /// Rejects invalid body schemas, changed originals, exhausted native control
    /// budgets, transport loss or incomplete dynamic receipt closure.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owned: bool,
        body: impl serde::Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        let attempt = self.observer.as_ref().map(|observer| observer.attempt());
        let result = self.call_original(request_id, operation_id, method, owned, body);
        if let Some(observer) = &self.observer {
            observer.record(self, &result);
        }
        if let Some(attempt) = attempt {
            attempt.finish();
        }
        result
    }

    fn call_original(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owned: bool,
        body: impl serde::Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        let body = object(body)?;
        let original = decode_request(method, &body)?;
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.bootstrap.authority.session_id.clone())),
            incarnation_id: Nullable(Some(self.bootstrap.authority.incarnation_id.clone())),
            node_id: Nullable(owned.then(|| self.bootstrap.node_id.clone())),
            execution_owner_id: Nullable(owned.then(|| self.bootstrap.owner_id.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(operation_id),
            sequence: 2.into(),
            method,
            body,
            extensions: Extensions::new(),
        };
        let reply = self
            .session
            .exchange(&mut self.custody, request, self.budget)?;
        let response = decode_response(&original, &reply.body)?;
        if matches!(response.shape, ResponseShape::Completed { .. }) {
            let mut roots = Vec::new();
            references(&Value::Object(reply.body), &mut roots)?;
            roots.retain(|reference| {
                !self
                    .profile
                    .implementation
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.content == *reference)
            });
            self.session
                .receive_content(&mut self.custody, &roots, self.budget)?;
        }
        Ok(response)
    }

    /// Returns exact transferred bytes for independent installed native verification.
    ///
    /// # Errors
    /// Refuses unavailable bytes or changed original reference metadata.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.custody.content().get(reference)
    }

    /// Decodes a complete hash-verified record without conferring native authority.
    ///
    /// # Errors
    /// Refuses missing bytes, malformed closed records or violated schema bounds.
    pub fn record<T: serde::de::DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        Ok(canonical::decode(
            self.content(reference)?,
            16 * 1024 * 1024,
        )?)
    }

    /// Uploads exact immutable bytes through original baseline transfer identities.
    ///
    /// # Errors
    /// Refuses changed bytes, incomplete acknowledgements, exhausted original
    /// request credit or an uncertain transport. Upload grants no model effects.
    pub fn upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
        use crucible_node_contract::{Bytes, U64};

        reference.verify(bytes)?;
        self.custody
            .content_mut()
            .install(reference.clone(), bytes.to_vec())?;
        let transfer = Id::new(format!("controller-content-{}", reference.hash.digest))?;
        let begun = self.call(
            Id::new(format!("controller-begin-{}", reference.hash.digest))?,
            None,
            Method::BlobBegin,
            false,
            BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::BlobBegin(progress)) = begun.result else {
            return Err(ProviderError::Correlation(
                "original content reservation refused",
            ));
        };
        if progress.transfer_id != transfer || progress.next_offset > reference.length {
            return Err(ProviderError::Correlation(
                "original content reservation changed",
            ));
        }
        let frame_room = self
            .session
            .authority()
            .limits()
            .frame_bytes
            .get()
            .saturating_sub(2048)
            .saturating_mul(3)
            / 4;
        let maximum = progress
            .maximum_chunk_bytes
            .min(self.session.authority().limits().blob_chunk_bytes)
            .get()
            .min(frame_room);
        let maximum = usize::try_from(maximum)
            .ok()
            .filter(|size| *size != 0)
            .ok_or(ProviderError::ResourceExhausted(
                "content chunk frame allowance",
            ))?;
        let mut offset = 0usize;
        for chunk in bytes.chunks(maximum) {
            let response = self.call(
                Id::new(format!(
                    "controller-chunk-{}-{offset}",
                    reference.hash.digest
                ))?,
                None,
                Method::BlobChunk,
                false,
                BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new(offset as u64),
                    bytes: Bytes::new(chunk.to_vec()),
                    extensions: Extensions::new(),
                },
            )?;
            offset = offset
                .checked_add(chunk.len())
                .ok_or(ProviderError::ResourceExhausted("content offset"))?;
            if !matches!(response.result, Some(MethodResult::BlobChunk(ref progress))
                if progress.transfer_id == transfer && progress.next_offset == U64::new(offset as u64))
            {
                return Err(ProviderError::Correlation(
                    "original content chunk acknowledgment changed",
                ));
            }
        }
        let response = self.call(
            Id::new(format!("controller-finish-{}", reference.hash.digest))?,
            None,
            Method::BlobFinish,
            false,
            BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            },
        )?;
        if !matches!(response.result, Some(MethodResult::BlobFinish(ref progress)) if progress.content == *reference)
        {
            return Err(ProviderError::Correlation(
                "original content completion changed",
            ));
        }
        Ok(())
    }

    /// Fences transport while retaining every original request and immutable object.
    pub fn fence(&mut self) {
        self.session.close();
    }
}

fn references(value: &Value, output: &mut Vec<ContentRef>) -> Result<(), ProviderError> {
    match value {
        Value::Object(object)
            if object.contains_key("hash")
                && object.contains_key("length")
                && object.contains_key("media_type") =>
        {
            let reference: ContentRef = serde_json::from_value(value.clone())
                .map_err(crucible_node_contract::ContractError::from)?;
            reference.validate()?;
            if !output.contains(&reference) {
                if output.len() >= 4096 {
                    return Err(ProviderError::ResourceExhausted(
                        "control evidence root count",
                    ));
                }
                output.push(reference);
            }
        }
        Value::Object(object) => {
            for child in object.values() {
                references(child, output)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                references(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[path = "reference/lineage.rs"]
mod lineage;

pub use lineage::{
    LineageWindowRequests, OriginalLineageAcknowledgement, OriginalLineageEvidence,
    OriginalLineageObject, OriginalLineageRealization, OriginalLineageWindow,
};
