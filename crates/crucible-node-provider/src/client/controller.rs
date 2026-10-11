//! Generic CNP/1 control calls and original evidence custody.
//!
//! This controller translates baseline method bodies without selecting a role,
//! device model or receipt oracle. The installed common adapter must separately
//! authenticate native realization, behavioral acceptance and every returned
//! semantic fact. A completed transport response is never native authority.

use std::io::{self, Write};
use std::time::Duration;

use crucible_node_contract::{Bytes, ContentRef, Extensions, Id, U64, Validate, canonical};
use serde::Serialize;
use serde_json::Value;

use crate::ProviderError;
use crate::bodies::*;
use crate::envelope::{Envelope, MessageKind, Method, Nullable, RequestOrigin};

use super::{ClientCustody, ClientOriginal, ClientSession};

#[path = "controller/registration_read.rs"]
mod registration_read;
pub use registration_read::CnpRegistrarRead;

/// Names one node and its indivisible execution owner on an actual connection.
///
/// These labels are routing data. Construction does not authenticate their
/// native meaning or establish an admitted common world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerRoute {
    /// Identifies the logical node whose source semantics are independently installed.
    pub node: Id,
    /// Identifies its original authoritative execution owner.
    pub execution_owner: Id,
}

/// Retains a generic authenticated stream and its finite original journals.
///
/// The caller retains actual native resources and the handshake registrar for
/// the entire lifetime. Neither this controller nor its decoded results select
/// a native profile or manufacture preparation, execution or cleanup evidence.
pub struct CnpController {
    session: ClientSession,
    custody: ClientCustody,
    route: ControllerRoute,
    budget: Duration,
    fenced: bool,
}

impl CnpController {
    /// Installs the immutable packet codec before any original control request.
    ///
    /// This selects source-owned no-extension transport validation only. It
    /// grants no profile, native, readiness, behavioral or operation authority.
    /// Existing generic controllers retain their independently supplied verifier.
    ///
    /// # Errors
    /// Refuses a fenced controller, a used original journal or any prior control
    /// frame. A failed installation does not dispatch native work.
    pub fn install_packet_transport_schema(&mut self) -> Result<(), ProviderError> {
        if self.fenced || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "packet schema requires original unused controller",
            ));
        }
        self.session.install_packet_schema()
    }

    /// Reports the actual connection's immutable packet codec selection as data.
    ///
    /// This source fact cannot be set by a vendor verifier or portable record.
    /// It is only a necessary conjunction for an installed packet source policy.
    pub fn has_packet_transport_schema(&self) -> bool {
        self.session.has_packet_schema()
    }

    /// Checks complete source-selected reply and blob custody before dispatch.
    ///
    /// This pure capacity check grants no operation or receipt authority. The
    /// caller must hold this same controller exclusively through the subsequent
    /// exchange and authenticate the source's complete response population. It
    /// checks both original endpoint journals and all immutable transfer/content
    /// slots; a response extent alone is not a complete blob-transfer allowance.
    /// Existing call and wire behavior is unchanged for callers not using it.
    ///
    /// # Errors
    /// Refuses a fenced lease, nonfinite allowances, exhausted negotiated or
    /// local journals, and insufficient complete object/transfer byte custody.
    pub fn preflight_source_reply(
        &self,
        controller_requests: usize,
        provider_requests: usize,
        journal_bytes: usize,
        content_objects: usize,
        content_bytes: usize,
    ) -> Result<(), ProviderError> {
        if self.fenced
            || controller_requests > 4096
            || provider_requests > 4096
            || content_objects > 4096
            || journal_bytes > 256 * 1024 * 1024
            || content_bytes > 256 * 1024 * 1024
        {
            return Err(ProviderError::ResourceExhausted(
                "source response allowance",
            ));
        }
        self.session.authority().ensure_live()?;
        let negotiated_entries =
            usize::try_from(self.session.authority().limits().journal_entries.get())
                .map_err(|_| ProviderError::ResourceExhausted("source journal platform bound"))?;
        self.custody.preflight_response(
            controller_requests,
            provider_requests,
            journal_bytes,
            negotiated_entries,
        )?;
        self.custody
            .content()
            .preflight_capacity(content_objects, content_bytes)
    }

    /// Takes the original negotiated stream and finite immutable byte custody.
    ///
    /// # Errors
    /// Refuses expired registration, missing evidence delivery, or zero or
    /// greater-than-one-minute operational exchange budgets.
    pub fn new(
        session: ClientSession,
        custody: ClientCustody,
        route: ControllerRoute,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        session.authority().ensure_live()?;
        if budget.is_zero()
            || budget > Duration::from_secs(60)
            || !session
                .authority()
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1")
        {
            return Err(ProviderError::Correlation(
                "generic controller lacks bounded original evidence scope",
            ));
        }
        Ok(Self {
            session,
            custody,
            route,
            budget,
            fenced: false,
        })
    }

    /// Validates caller-owned originals before taking the negotiated session.
    ///
    /// The caller retains these slots outside any unwind boundary. Refusal
    /// leaves every slot unchanged; success moves the same session, complete
    /// journals and route into this controller without another allocation.
    /// The slots and route can be prepared before Child, while the actual
    /// session is installed immediately after the original Hello completes.
    /// The ordinary `new` API and its validation remain unchanged.
    ///
    /// # Errors
    /// Refuses missing original slots, expired registration, unsupported evidence
    /// delivery or zero/greater-than-one-minute exchange budget. Every refusal
    /// leaves the original session, custody and route in the caller's slots.
    pub fn new_retained(
        session: &mut Option<ClientSession>,
        custody: &mut Option<ClientCustody>,
        route: &mut Option<ControllerRoute>,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        let original = session.as_ref().ok_or(ProviderError::Correlation(
            "generic controller original session absent",
        ))?;
        if custody.is_none() || route.is_none() {
            return Err(ProviderError::Correlation(
                "generic controller original custody or route absent",
            ));
        }
        original.authority().ensure_live()?;
        if budget.is_zero()
            || budget > Duration::from_secs(60)
            || !original
                .authority()
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1")
        {
            return Err(ProviderError::Correlation(
                "generic controller lacks bounded original evidence scope",
            ));
        }

        // No callback or allocation separates validation from these moves.
        // Even an inconsistent slot set is returned to its original holder.
        match (session.take(), custody.take(), route.take()) {
            (Some(session), Some(custody), Some(route)) => Ok(Self {
                session,
                custody,
                route,
                budget,
                fenced: false,
            }),
            (original_session, original_custody, original_route) => {
                *session = original_session;
                *custody = original_custody;
                *route = original_route;
                Err(ProviderError::Correlation(
                    "generic controller original slots changed",
                ))
            }
        }
    }

    /// Returns the actual kernel peer checked during the original negotiation.
    pub fn peer_pid(&self) -> u32 {
        self.session.peer_pid()
    }

    /// Borrows the independently measured actual endpoint executable reference.
    pub fn peer_executable(&self) -> &ContentRef {
        self.session.peer_executable()
    }

    /// Borrows the original host-authenticated transport registration.
    pub fn authority(&self) -> &crate::handshake::ConnectionAuthority {
        self.session.authority()
    }

    /// Borrows the fixed public route without granting owner authority.
    pub fn route(&self) -> &ControllerRoute {
        &self.route
    }

    /// Borrows one retained original request and its authentic last response.
    ///
    /// Missing or unresolved originals are never reconstructed from later
    /// observations. Reading does not retry or retire an original operation.
    pub fn original(&self, request: &Id) -> Option<&ClientOriginal> {
        self.custody.original(RequestOrigin::Controller, request)
    }

    /// Enumerates both endpoint namespaces under the original finite custody.
    pub fn originals(&self) -> impl Iterator<Item = &ClientOriginal> {
        self.custody.originals()
    }

    /// Borrows complete hash-verified bytes for an independent source oracle.
    ///
    /// # Errors
    /// Refuses unavailable original bytes or changed reference metadata.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.custody.content().get(reference)
    }

    /// Decodes a bounded closed receipt as data without authenticating its meaning.
    ///
    /// # Errors
    /// Refuses missing original bytes, exceeded frame bounds or an invalid record.
    pub fn record<T: serde::de::DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        Ok(canonical::decode(
            self.content(reference)?,
            self.maximum_frame()?,
        )?)
    }

    /// Sends one original closed baseline method and retains promised evidence.
    ///
    /// Direct Rust bodies pass a nonretaining whole-envelope sizing pass before
    /// allocating a JSON value or dispatching a native request. Immutable request
    /// identity includes the complete original body and scope; only transport
    /// sequence changes on an identical retry. Refusals remain typed responses.
    ///
    /// # Errors
    /// Refuses oversized or invalid bodies, changed originals, unavailable
    /// registration, exhausted journals, transport loss or missing receipt bytes.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: impl Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller is fenced",
            ));
        }
        let session_id = self.session.authority().session_id().clone();
        let incarnation_id = self.session.authority().incarnation_id().clone();
        let node_id = owner_scoped.then(|| self.route.node.clone());
        let execution_owner_id = owner_scoped.then(|| self.route.execution_owner.clone());
        let wire = BorrowedEnvelope {
            protocol: "CNP/1",
            message: MessageKind::Request,
            session_id: &session_id,
            incarnation_id: &incarnation_id,
            node_id: &node_id,
            execution_owner_id: &execution_owner_id,
            capture_owner_id: None,
            request_id: &request_id,
            operation_id: &operation_id,
            sequence: U64::new(u64::MAX),
            method,
            body: &body,
            extensions: Extensions::new(),
        };
        count_serialized(&wire, self.maximum_frame()?)?;

        let body =
            serde_json::to_value(body).map_err(crucible_node_contract::ContractError::from)?;
        let Value::Object(body) = body else {
            return Err(ProviderError::Frame("generic method body is not an object"));
        };
        let original = decode_request(method, &body)?;
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session_id)),
            incarnation_id: Nullable(Some(incarnation_id)),
            node_id: Nullable(node_id),
            execution_owner_id: Nullable(execution_owner_id),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(operation_id),
            sequence: U64::new(2),
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
            self.session
                .receive_content(&mut self.custody, &roots, self.budget)?;
        }
        Ok(response)
    }

    /// Transfers exact original immutable content through baseline blob methods.
    ///
    /// Uploading bytes grants no modeled input or receipt authority. Identical
    /// transfers keep their original IDs; partial or uncertain transfer failures
    /// retain every original request and owned byte buffer.
    ///
    /// # Errors
    /// Refuses changed content, insufficient finite custody, invalid progress,
    /// exhausted journals, overlong identities or uncertain transport effects.
    pub fn upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller is fenced",
            ));
        }
        reference.verify(bytes)?;
        // Reuse the current borrowed installation preflight before any body copy.
        self.custody
            .content_mut()
            .install_borrowed(std::iter::once((reference, bytes)))?;
        let transfer = Id::new(format!("cnp-content-{}", reference.hash.digest))?;
        let begun = self.call(
            Id::new(format!("cnp-blob-begin-{}", reference.hash.digest))?,
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
                "original blob reservation refused",
            ));
        };
        if progress.transfer_id != transfer || progress.next_offset > reference.length {
            return Err(ProviderError::Correlation(
                "original blob reservation changed",
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
            .filter(|value| *value != 0)
            .ok_or(ProviderError::ResourceExhausted("blob frame allowance"))?;
        let mut offset = 0usize;
        for chunk in bytes.chunks(maximum) {
            let response =
                self.call(
                    Id::new(format!("cnp-blob-chunk-{}-{offset}", reference.hash.digest))?,
                    None,
                    Method::BlobChunk,
                    false,
                    BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new(u64::try_from(offset).map_err(|_| {
                            ProviderError::ResourceExhausted("blob platform offset")
                        })?),
                        bytes: Bytes::new(chunk.to_vec()),
                        extensions: Extensions::new(),
                    },
                )?;
            offset = offset
                .checked_add(chunk.len())
                .ok_or(ProviderError::ResourceExhausted("blob offset"))?;
            if !matches!(response.result, Some(MethodResult::BlobChunk(ref progress))
                if progress.transfer_id == transfer && progress.next_offset.get() == offset as u64)
            {
                return Err(ProviderError::Correlation("original blob chunk changed"));
            }
        }
        let response = self.call(
            Id::new(format!("cnp-blob-finish-{}", reference.hash.digest))?,
            None,
            Method::BlobFinish,
            false,
            BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            },
        )?;
        if !matches!(response.result, Some(MethodResult::BlobFinish(ref progress))
            if progress.content == *reference)
        {
            return Err(ProviderError::Correlation(
                "original blob completion changed",
            ));
        }
        Ok(())
    }

    /// Fences the original stream while preserving native and journal obligations.
    pub fn fence(&mut self) {
        self.fenced = true;
        self.session.close();
    }

    fn maximum_frame(&self) -> Result<usize, ProviderError> {
        usize::try_from(self.session.authority().limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("generic platform frame ceiling"))
    }
}

#[derive(Serialize)]
struct BorrowedEnvelope<'a, T> {
    protocol: &'static str,
    message: MessageKind,
    session_id: &'a Id,
    incarnation_id: &'a Id,
    node_id: &'a Option<Id>,
    execution_owner_id: &'a Option<Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: &'a Id,
    operation_id: &'a Option<Id>,
    sequence: U64,
    method: Method,
    body: &'a T,
    extensions: Extensions,
}

fn count_serialized(value: &impl Serialize, maximum: usize) -> Result<(), ProviderError> {
    struct Counter {
        used: usize,
        maximum: usize,
    }

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(next) = self.used.checked_add(bytes.len()) else {
                return Err(io::Error::other("generic body length overflow"));
            };
            if next > self.maximum {
                return Err(io::Error::other("generic frame exceeds original credit"));
            }
            self.used = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(&mut Counter { used: 0, maximum }, value)
        .map_err(|_| ProviderError::ResourceExhausted("generic whole-frame precredit"))
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
                if output.len() == 4096 {
                    return Err(ProviderError::ResourceExhausted("generic evidence roots"));
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

#[cfg(test)]
#[path = "controller/construction_tests.rs"]
mod construction_tests;
