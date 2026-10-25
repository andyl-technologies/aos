//! Restricts packet runtime calls to immutable bodies in the priced method graph.
//!
//! The owner retains the same original compact controller without an extractor
//! or a generic serializer/exchange entry point. Legacy controller request IDs
//! cannot enter its call path; new compact originals still support exact replay.
//! These enforced SDK restrictions establish no Source, native or funding right.

use super::*;

mod identity;

/// Borrows one immutable request from the closed packet runtime method family.
///
/// Every variant uses the defining DTO serializer. Callers cannot supply a
/// serializer callback, override the method or select a different body schema.
/// Begin arguments retain their separately validated kind-specific schema.
/// The caller independently funds its original body and all call construction.
#[derive(Serialize)]
#[serde(untagged)]
pub enum PacketRuntimeRequest<'a> {
    /// Borrows delivered input for its execution owner.
    Input(&'a InputRequest),
    /// Borrows an execution owner's observation query.
    Observe(&'a ObserveRequest),
    /// Borrows one of the seven baseline Begin argument kinds.
    Begin(&'a BeginRequest),
    /// Borrows a retained operation's progress query.
    Poll(&'a PollRequest),
    /// Borrows authenticated retirement or inert abandonment data.
    Retire(&'a RetireRequest),
    /// Borrows an inert content-transfer reservation.
    BlobBegin(&'a BlobBeginRequest),
    /// Borrows one immutable content chunk.
    BlobChunk(&'a BlobChunkRequest),
    /// Borrows an inert content-transfer completion.
    BlobFinish(&'a BlobFinishRequest),
}

impl PacketRuntimeRequest<'_> {
    fn scope(
        &self,
        operation_id: Option<Id>,
        capture_owner: Option<Id>,
    ) -> Result<CallScope, ProviderError> {
        let method = match self {
            Self::Input(_) => Method::Input,
            Self::Observe(_) => Method::Observe,
            Self::Begin(_) => Method::Begin,
            Self::Poll(_) => Method::Poll,
            Self::Retire(_) => Method::Retire,
            Self::BlobBegin(_) => Method::BlobBegin,
            Self::BlobChunk(_) => Method::BlobChunk,
            Self::BlobFinish(_) => Method::BlobFinish,
        };
        let capture = matches!(self, Self::Begin(body) if body.kind == BeginKind::Capture);
        if capture != capture_owner.is_some() {
            return Err(ProviderError::Correlation(
                "packet runtime capture scope disagrees with its body",
            ));
        }

        Ok(CallScope {
            operation_id,
            method,
            owner_scoped: !matches!(
                self,
                Self::BlobBegin(_) | Self::BlobChunk(_) | Self::BlobFinish(_)
            ),
            capture_owner,
        })
    }
}

/// Retains an original controller behind a closed packet runtime call surface.
///
/// The same session, registrar, content, journals, deadline and process witnesses
/// survive construction. No mutable controller, generic Serialize callback or
/// arbitrary envelope exchange is exposed. Outgoing legacy IDs are refused
/// before body construction or cached-response cloning; runtime suffix originals
/// retain exact replay. Incoming provider legacy replay remains independently
/// priced and supervised by the original compact exchange.
///
/// This is an SDK restriction, not a Source18 constructor or grant. The actual
/// Source must authenticate completed Initial ownership and outstanding claims,
/// then fund the complete future R/T/S row before moving the original owner.
pub struct PacketRuntimeController {
    runtime: CompactRuntimeController,
}

impl PacketRuntimeController {
    /// Moves the complete original owner into the closed runtime call surface.
    ///
    /// Every fallible operation precedes the ownership move. An occupied output
    /// or refused original leaves both caller slots intact. Success wraps the
    /// actual compact controller without a later allocation or fallible step.
    /// Quotas, consumed credit and the original content store remain unchanged.
    ///
    /// # Errors
    /// Refuses occupied output, unavailable or changed original ownership,
    /// unresolved originals, future assignments or exhausted compact credit.
    /// Source admission and native lifecycle authentication remain independent.
    pub fn retain_into(
        original: &mut Option<CnpController>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(ProviderError::Conflict("packet runtime output occupied"));
        }
        let runtime = CompactRuntimeController::retain_original(original)?;

        // Only the inline slot move follows successful original retention.
        *output = Some(Self { runtime });
        Ok(())
    }

    /// Sends one closed immutable body through the same original stream.
    ///
    /// The body selects its method and owner scope. Only a Capture Begin accepts
    /// a capture owner, and that kind requires one. Envelope extensions are
    /// ordinary immutable data and remain subject to actual negotiation. No
    /// direct caller serializer or arbitrary method enters the sizing/encode
    /// passes. Caller-owned roots, codec work and all response populations still
    /// require independent funding.
    ///
    /// Outgoing request IDs must belong to the new runtime suffix. Legacy ID
    /// collisions are refused before serialization or cached-response cloning.
    /// Reusing a compact runtime ID retains the existing exact-replay checks.
    /// Any refusal fences the stream while preserving all surviving originals.
    ///
    /// # Errors
    /// Refuses a legacy ID, inconsistent capture scope, invalid or oversized
    /// body, unnegotiated extensions, changed originals, exhausted credit,
    /// unavailable content or uncertain transport. Decoding grants no effects.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        capture_owner: Option<Id>,
        body: PacketRuntimeRequest<'_>,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        let result = self.call_inner(request_id, operation_id, capture_owner, body, extensions);
        if result.is_err() {
            self.runtime.fence();
        }
        result
    }

    fn call_inner(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        capture_owner: Option<Id>,
        body: PacketRuntimeRequest<'_>,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        if self
            .runtime
            .legacy_originals(RequestOrigin::Controller)
            .any(|original| original.request.request_id.0.as_ref() == Some(&request_id))
        {
            return Err(ProviderError::Conflict("packet runtime legacy request ID"));
        }
        let scope = body.scope(operation_id, capture_owner)?;

        self.runtime
            .call_scoped(request_id, scope, body, extensions)
    }

    /// Borrows the same connection authority without renewing registration.
    pub fn authority(&self) -> &crate::handshake::ConnectionAuthority {
        self.runtime.authority()
    }

    /// Borrows the original routing labels without native effect authority.
    pub fn route(&self) -> &ControllerRoute {
        self.runtime.route()
    }

    /// Borrows complete originals from the read-only legacy namespace.
    pub fn legacy_originals(&self, origin: RequestOrigin) -> impl Iterator<Item = &ClientOriginal> {
        self.runtime.legacy_originals(origin)
    }

    /// Borrows complete compact originals from the unchanged runtime namespace.
    pub fn compact_originals(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &crate::client::CompactClientOriginal> {
        self.runtime.compact_originals(origin)
    }

    /// Reports the unchanged ceiling, legacy debit and runtime debit as DATA.
    pub fn journal_byte_reservations_data(&self) -> [usize; 3] {
        self.runtime.journal_byte_reservations_data()
    }

    /// Borrows hash-verified original content without native receipt authority.
    ///
    /// # Errors
    /// Refuses missing bytes or metadata inconsistent with the retained object.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.runtime.content(reference)
    }

    /// Borrows a received original retained after a failed compact operation.
    pub fn pending_envelope(&self) -> Option<(RequestOrigin, &Envelope)> {
        self.runtime.pending_envelope()
    }

    /// Borrows unsupported traffic retained when the original stream was fenced.
    pub fn unexpected_frame(&self) -> Option<&crate::connection::ReceivedFrame> {
        self.runtime.unexpected_frame()
    }

    /// Observes the same original, compact suffix and actual supervisor owners.
    ///
    /// The enclosing inline header and future allocations remain independent.
    /// The caller first admits [`Self::retained_metadata_counter_scratch_data`].
    /// Reading facts after fencing or revocation renews no effect permission.
    ///
    /// # Errors
    /// Refuses foreign creators, changed registrar or codec/supervisor backing,
    /// conflicting loans, metadata exhaustion or arithmetic overflow.
    pub fn retained_metadata_facts_with_retained_supervisor(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.runtime
            .retained_metadata_facts_with_retained_supervisor(owner, witness)
    }

    /// Names the defining observer and additional borrowed owner/result controls.
    pub fn retained_metadata_counter_scratch_data() -> usize {
        CompactRuntimeController::retained_metadata_counter_scratch_data()
            + std::mem::size_of::<&Self>()
    }

    /// Fences the same stream while preserving every retained original owner.
    pub fn fence(&mut self) {
        self.runtime.fence();
    }
}
