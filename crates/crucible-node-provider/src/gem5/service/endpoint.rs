//! Bounded authenticated discovery dispatch beneath original native custody.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use crucible_node_contract::{ContractError, Id, U64, canonical};
use serde_json::{Map, Value, json};

use crate::{
    ProviderError,
    bodies::{DiscoverResult, RequestBody, decode_request},
    connection::{
        BodySchemaVerifier, Connection, ConnectionSupervisor, EndpointRole, ProviderStream,
        ReceivedBody,
    },
    envelope::{Envelope, MessageKind, Nullable, RequestOrigin},
    handshake::{ConnectionAuthority, Handshake, TrustedHandshakeVerifier},
    journal::JournalLimits,
    native_journal::{
        NativeJournal, NativeJournalLimits, NativeJournalSupervisor, NativeRequestRegistration,
    },
};

use super::super::{Gem5CustodySlot, Gem5OwnerResources};
use super::{Gem5Catalog, Gem5ServiceBootstrap};

/// Serves measured gem5 discovery while refusing unqualified native contracts.
///
/// One original journal persists across connections. Unsupported requests are
/// recorded as no-effect refusals without calling a native resource callback.
/// Dropping the service revokes negotiation and transfers the entire journal to
/// its already reserved supervisor. This administrative endpoint is not a
/// qualified native execution, blob-transfer, or preservation provider.
pub struct Gem5DiscoveryService {
    catalog: Gem5Catalog,
    handshake: Handshake,
    journal: NativeJournal<Gem5OwnerResources>,
    admitted_connections: BTreeMap<Id, ConnectionAuthority>,
    used_connections: BTreeSet<Id>,
}

impl Gem5DiscoveryService {
    /// Reserves native supervision before any connection or native realization.
    ///
    /// The supplied native slot and journal supervisor must retain actual handles
    /// and original obligations after failure. Resources are inert at this step.
    ///
    /// # Errors
    /// Rejects invalid journal limits, unavailable reserved supervision or an
    /// invalid privately authenticated negotiation installation.
    pub fn new(
        bootstrap: Gem5ServiceBootstrap,
        native_slot: Box<dyn Gem5CustodySlot>,
        journal_limits: JournalLimits,
        native_limits: NativeJournalLimits,
        supervisor: &dyn NativeJournalSupervisor<Gem5OwnerResources>,
    ) -> Result<Self, ProviderError> {
        let handshake = bootstrap.handshake()?;
        let resources = Gem5OwnerResources::new(bootstrap.launch.clone(), native_slot);
        let journal = NativeJournal::new(
            bootstrap.session_id().clone(),
            bootstrap.incarnation_id().clone(),
            journal_limits,
            native_limits,
            resources,
            supervisor,
        )?;

        Ok(Self {
            catalog: bootstrap.catalog,
            handshake,
            journal,
            admitted_connections: BTreeMap::new(),
            used_connections: BTreeSet::new(),
        })
    }

    /// Returns the measured conservative discovery catalog.
    pub fn catalog(&self) -> &Gem5Catalog {
        &self.catalog
    }

    /// Authenticates an original exchange with this installation's own handshake.
    ///
    /// The trusted verifier checks actual peer credentials and the private
    /// challenge. The acknowledged hello may be sent only after this succeeds.
    /// Issued leases are retained and matched by native registration identity,
    /// rather than accepting another handshake's matching session-ID claims.
    ///
    /// # Errors
    /// Rejects reused or exhausted connection IDs and failed authenticated
    /// negotiation. Failure does not authorize native launch or execution.
    pub fn admit_connection(
        &mut self,
        request: &Envelope,
        response: &Envelope,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        if self.admitted_connections.len() >= 4096
            || self.admitted_connections.contains_key(&connection)
        {
            return Err(ProviderError::Conflict(
                "gem5 negotiation identity cannot be reused",
            ));
        }
        let authority =
            self.handshake
                .admit_envelopes(request, response, connection.clone(), verifier)?;
        self.admitted_connections
            .insert(connection, authority.clone());
        Ok(authority)
    }

    /// Returns the surviving read-only journal for authenticated reconciliation.
    pub fn journal(&self) -> &NativeJournal<Gem5OwnerResources> {
        &self.journal
    }

    /// Dispatches one original request under an actual negotiated connection lease.
    ///
    /// Identical retries return only the original retained bytes. They cannot
    /// create another native effect permit or substitute a discovery result.
    ///
    /// # Errors
    /// Rejects revoked authority, foreign scope, malformed or conflicting original
    /// requests, exhausted finite journal storage or unavailable original outcomes.
    pub fn dispatch(
        &mut self,
        authority: &ConnectionAuthority,
        request: &Envelope,
    ) -> Result<Map<String, Value>, ProviderError> {
        self.check_authority(authority)?;
        let body = decode_request(request.method, &request.body)?;
        let registration =
            self.journal
                .register_request(authority, request, RequestOrigin::Controller)?;
        let permit = match registration {
            NativeRequestRegistration::New(permit) => permit,
            NativeRequestRegistration::Original(original) => {
                let bytes = original.outcome.ok_or(ProviderError::Correlation(
                    "original gem5 request outcome remains unresolved",
                ))?;
                let maximum = usize::try_from(authority.limits().frame_bytes.get())
                    .map_err(|_| ProviderError::ResourceExhausted("gem5 response frame"))?;
                return canonical::parse_json(&bytes, maximum)?
                    .as_object()
                    .cloned()
                    .ok_or(ProviderError::Frame(
                        "retained gem5 outcome is not an object",
                    ));
            }
        };

        let response = match body {
            RequestBody::Discover(discover)
                if request.extensions.is_empty()
                    && discover.extensions.is_empty()
                    && discover.cursor.is_none() =>
            {
                let result = DiscoverResult {
                    provider_manifest: self.catalog.manifest().clone(),
                    profiles: Vec::new(),
                    facet_schemas: Vec::new(),
                    complete: true,
                    next_cursor: Nullable(None),
                };
                object(json!({"status":"completed", "operation_state":"completed",
                    "result":result, "extensions":{}}))?
            }
            _ => {
                let response = object(json!({"status":"error", "operation_state":"not_started",
                    "error":{"code":"UNSUPPORTED_FEATURE", "effect":"not_started",
                        "retryable":false, "message":"gem5 native contract is not qualified",
                        "details":{}}, "extensions":{}}))?;
                self.journal.record_request_refusal(&permit, &response)?;
                return Ok(response);
            }
        };
        self.journal.record_request_terminal(&permit, &response)?;
        Ok(response)
    }

    /// Runs bounded framed discovery on an already authenticated actual stream.
    ///
    /// The launcher supplies deadline-bounded native transport and independently
    /// installed body-schema validation. A connection identity is never reused to
    /// reset correlation sequences. Native custody remains supervised on EOF,
    /// protocol failure or partial writes.
    ///
    /// # Errors
    /// Rejects reused connection identities, exhausted finite connection custody,
    /// failed body/correlation checks, revoked leases or stream I/O failures.
    pub fn serve_connection<S: ProviderStream>(
        &mut self,
        stream: S,
        authority: ConnectionAuthority,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
    ) -> Result<(), ProviderError> {
        if let Err(error) = self.check_authority(&authority) {
            let mut connection = Connection::new(
                stream,
                authority,
                supervisor,
                schemas,
                EndpointRole::Provider,
            )?;
            connection.close();
            return Err(error);
        }
        if self.used_connections.len() >= 4096
            || !self
                .used_connections
                .insert(authority.connection_id().clone())
        {
            // Constructing and closing a Connection fences the actual stream and
            // hands its incident to supervision, even on admission refusal.
            let mut connection = Connection::new(
                stream,
                authority,
                supervisor,
                schemas,
                EndpointRole::Provider,
            )?;
            connection.close();
            return Err(ProviderError::Conflict(
                "gem5 connection identity cannot be reused",
            ));
        }
        let mut connection = Connection::new(
            stream,
            authority.clone(),
            supervisor,
            schemas,
            EndpointRole::Provider,
        )?;
        let result = (|| {
            let mut sequence = U64::new(2);
            while let Some(frame) = connection.receive()? {
                if !matches!(frame.body, ReceivedBody::Request(_)) {
                    return Err(ProviderError::Frame("gem5 endpoint requires a request"));
                }
                let response = self.dispatch(&authority, &frame.envelope)?;
                let mut envelope = frame.envelope;
                envelope.message = MessageKind::Response;
                envelope.sequence = sequence;
                envelope.body = response;
                sequence = sequence.checked_add(U64::new(1))?;
                connection.send(envelope)?;
            }
            Ok(())
        })();
        // No resumption profile is selected. EOF or failure revokes every local
        // registration lease while the original journal remains supervised.
        self.handshake.contain();
        result
    }

    fn check_authority(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        if !self
            .admitted_connections
            .get(authority.connection_id())
            .is_some_and(|original| original.same_registration(authority))
        {
            return Err(ProviderError::Correlation(
                "gem5 connection has another installation's lease",
            ));
        }
        Ok(())
    }
}

fn object(value: Value) -> Result<Map<String, Value>, ProviderError> {
    value.as_object().cloned().ok_or_else(|| {
        ProviderError::Contract(ContractError::Invalid {
            field: "response",
            reason: "expected object".into(),
        })
    })
}
