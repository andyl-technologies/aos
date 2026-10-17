//! Installs closed typed-source schemas and original transport incident custody.
//!
//! Services are prepared independently before Child for one sticky original
//! Hello/Connection attempt. Baseline codecs run in the provider SDK first;
//! this host policy checks the exact installed extension tuple and location.
//! Incident journals retain uncertainty and cannot authorize a native result.

use super::InstalledTypedReaderSourceFixture;
use crucible_node_contract::{ContentRef, Extensions, Id, IdSet, Validate};
use crucible_node_provider::{
    ProviderError,
    bodies::{RequestBody, ResponseShape},
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    envelope::Envelope,
    handshake::{ConnectionAuthority, EXTENSION_NEGOTIATION_V1},
    reference_lineage::INPUT_LINEAGE_FEATURE,
    reference_service::ReferenceNegotiatedLineageReaderLaunchBootstrap,
};
use std::{
    cell::{Cell, OnceCell, Ref, RefCell},
    rc::Rc,
};

/// Retains original incidents beside the same independently installed source scope.
///
/// The host creates a separate instance for each sole original Connection. SDK
/// containment fences that Connection before its one quarantine callback, and
/// constructor refusal cannot coexist with a successfully constructed instance.
/// No journal is replaced. Unexpected scope or repetition remains explicitly
/// unqualified; its records are retained rather than discarded as a clean fence.
pub struct TypedReaderHostIncidents {
    session: Id,
    incarnation: Id,
    connection: Id,
    records: RefCell<Vec<ConnectionIncident>>,
    emergency: OnceCell<ConnectionIncident>,
    overflow: RefCell<Vec<ConnectionIncident>>,
    seen: Cell<bool>,
    differs: Cell<bool>,
}

impl TypedReaderHostIncidents {
    /// Borrows actual retained journals after the owning connection is contained.
    ///
    /// The actor must not hold this borrow across transport or cleanup callbacks.
    /// Portable incident data supplies no independent native custody authority.
    pub fn records(&self) -> Ref<'_, Vec<ConnectionIncident>> {
        self.records.borrow()
    }

    /// Borrows an original moved into independent emergency custody.
    ///
    /// This immutable slot cannot block a later custody move. Its presence
    /// records a host borrow conflict, never a successful containment receipt.
    pub fn emergency_incident(&self) -> Option<&ConnectionIncident> {
        self.emergency.get()
    }

    /// Reports unexpected incident scope without proving transport containment.
    pub fn scope_differs(&self) -> bool {
        self.differs.get()
    }
}

impl ConnectionSupervisor for TypedReaderHostIncidents {
    fn quarantine(&self, incident: ConnectionIncident) {
        if self.seen.replace(true)
            || incident.session != self.session
            || incident.incarnation != self.incarnation
            || incident.connection != self.connection
        {
            self.differs.set(true);
        }
        match self.records.try_borrow_mut() {
            Ok(mut records) => records.push(incident),
            Err(_) => {
                // A caller's live journal borrow cannot discard the incoming
                // original or panic before its custody move. This independent
                // slot has no public mutable borrow and needs no allocation.
                self.differs.set(true);
                if let Err(original) = self.emergency.set(incident) {
                    // A second callback is outside the exact SDK one-fence
                    // source invariant. Keep even that unqualified uncertainty
                    // in storage with no external borrow or result authority.
                    self.overflow.borrow_mut().push(original);
                }
            }
        }
    }
}

/// Checks received bodies against the exact independently installed typed source.
///
/// These checks grant no source launch, operation or behavioral acceptance.
/// All baseline bodies have already passed their method-selected closed codec.
/// The only dynamic extension location here is the original Input inventory;
/// its full uploaded body and producer closure remain separate source checks.
pub struct TypedReaderHostSchemas {
    source: Rc<InstalledTypedReaderSourceFixture>,
    node: Id,
    session: Id,
    incarnation: Id,
    connection: Id,
    features: IdSet,
}

impl BodySchemaVerifier for TypedReaderHostSchemas {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        self.source.current_unit(&self.node)?;
        if authority.session_id() != &self.session
            || authority.incarnation_id() != &self.incarnation
            || authority.connection_id() != &self.connection
            || authority.selected_features() != &self.features
            || authority.selected_extensions()
                != Some(std::slice::from_ref(
                    self.source.package().definition().selection(),
                ))
            || !envelope.extensions.is_empty()
        {
            return Err(refused());
        }
        validate_extensions(self.source.package().definition(), body)?;
        // Scope/lease revalidation follows the entire installed codec decision.
        // This is a host schema fence, not a native physical callback permit.
        self.source.current_unit(&self.node)?;
        authority.ensure_live()
    }
}

/// Owns independently installed schemas and a separate original incident holder.
///
/// Callers pass these exact Rc objects to one prepared typed session before
/// Child. They retain this object through failure and original reclamation.
pub struct TypedReaderHostServices {
    /// Retains original connection uncertainty without an accepted-result oracle.
    pub incidents: Rc<TypedReaderHostIncidents>,
    /// Retains the exact selected typed source schema policy.
    pub schemas: Rc<TypedReaderHostSchemas>,
}

impl TypedReaderHostServices {
    /// Authenticates original private launch scope and prepares both host services.
    ///
    /// No private launch bytes or capabilities are cloned or publicly hashed.
    /// The source installation must already independently authenticate them.
    ///
    /// # Errors
    /// Refuses changed launch/source/node/plan, invalid connection IDs or missing
    /// incident storage before Child or transport creation.
    pub fn prepare(
        source: &Rc<InstalledTypedReaderSourceFixture>,
        plan: &ContentRef,
        launch: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
        connection: Id,
    ) -> Result<Self, ProviderError> {
        connection.validate()?;
        let node = &launch.bootstrap.node_id;
        let original = source.source(node)?;
        source.authenticate_launch(plan, source.package(), &original.profile, launch)?;
        source.current_unit(node)?;
        let features: IdSet = [
            "cnp.control-evidence/1",
            "cnp.core/1",
            EXTENSION_NEGOTIATION_V1,
            INPUT_LINEAGE_FEATURE,
        ]
        .into_iter()
        .map(Id::new)
        .collect::<Result<_, _>>()?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("original typed incident slot"))?;
        let mut overflow = Vec::new();
        overflow.try_reserve_exact(1).map_err(|_| {
            ProviderError::ResourceExhausted("original typed emergency overflow slot")
        })?;
        let session = launch.bootstrap.authority.session_id.clone();
        let incarnation = launch.bootstrap.authority.incarnation_id.clone();
        let incidents = Rc::new(TypedReaderHostIncidents {
            session: session.clone(),
            incarnation: incarnation.clone(),
            connection: connection.clone(),
            records: RefCell::new(records),
            emergency: OnceCell::new(),
            overflow: RefCell::new(overflow),
            seen: Cell::new(false),
            differs: Cell::new(false),
        });
        let schemas = Rc::new(TypedReaderHostSchemas {
            source: Rc::clone(source),
            node: node.clone(),
            session,
            incarnation,
            connection,
            features,
        });
        source.current_unit(node)?;
        Ok(Self { incidents, schemas })
    }
}

fn validate_extensions(
    definition: &crucible_node_provider::reference_lineage::InputLineageDefinition,
    body: &ReceivedBody,
) -> Result<(), ProviderError> {
    let extensions: &Extensions = match body {
        ReceivedBody::Request(request) => match request.as_ref() {
            RequestBody::Input(value) => {
                definition.input_inventory_reference(&value.extensions)?;
                return Ok(());
            }
            RequestBody::Hello(value) => &value.extensions,
            RequestBody::Discover(value) => &value.extensions,
            RequestBody::Realize(value) => &value.extensions,
            RequestBody::Admit(value) => &value.extensions,
            RequestBody::Activate(value) => &value.extensions,
            RequestBody::Observe(value) => &value.extensions,
            RequestBody::Begin(value) => &value.extensions,
            RequestBody::Poll(value) => &value.extensions,
            RequestBody::Cancel(value) => &value.extensions,
            RequestBody::QuantumClose(value) => &value.extensions,
            RequestBody::WorldActivate(value) => &value.extensions,
            RequestBody::Abort(value) => &value.extensions,
            RequestBody::Retire(value) => &value.extensions,
            RequestBody::BlobBegin(value) => &value.extensions,
            RequestBody::BlobChunk(value) => &value.extensions,
            RequestBody::BlobFinish(value) => &value.extensions,
            RequestBody::Release(value) => &value.extensions,
        },
        ReceivedBody::Response(response) => match &response.shape {
            ResponseShape::Accepted { extensions, .. }
            | ResponseShape::Completed { extensions, .. }
            | ResponseShape::Error { extensions, .. } => extensions,
        },
        ReceivedBody::Notification(notification) => &notification.extensions,
    };
    if !extensions.is_empty() {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original typed host schema scope differs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_provider::connection::ConnectionFailure;

    // Source/native eligibility is modeled here. The actual incident type and
    // original custody callback execute with a real outstanding Rust borrow.
    #[test]
    fn held_journal_borrow_retains_original_in_emergency_without_panic() -> Result<(), ProviderError>
    {
        let session = Id::new("modeled-session")?;
        let incarnation = Id::new("modeled-incarnation")?;
        let connection = Id::new("modeled-connection")?;
        let journal = TypedReaderHostIncidents {
            session: session.clone(),
            incarnation: incarnation.clone(),
            connection: connection.clone(),
            records: RefCell::new(Vec::with_capacity(1)),
            emergency: OnceCell::new(),
            overflow: RefCell::new(Vec::with_capacity(1)),
            seen: Cell::new(false),
            differs: Cell::new(false),
        };
        let outgoing: Envelope = serde_json::from_value(serde_json::json!({
            "protocol": "CNP/1", "message": "request", "session_id": session,
            "incarnation_id": incarnation, "node_id": null,
            "execution_owner_id": null, "capture_owner_id": null,
            "request_id": "modeled-pending-request", "operation_id": null,
            "sequence": "2", "method": "discover", "body": {"extensions": {}}, "extensions": {},
        }))
        .map_err(|_| ProviderError::Correlation("modeled original envelope codec"))?;
        let incoming = outgoing.clone();
        let held = journal.records();
        journal.quarantine(ConnectionIncident {
            session,
            incarnation,
            connection: connection.clone(),
            failure: ConnectionFailure::Write,
            transport_fenced: false,
            outgoing: vec![outgoing.clone()],
            incoming: vec![incoming.clone()],
        });
        assert!(held.is_empty());
        assert!(journal.scope_differs());
        let original = journal
            .emergency_incident()
            .ok_or(ProviderError::Correlation("emergency original missing"))?;
        assert_eq!(original.connection, connection);
        assert_eq!(original.failure, ConnectionFailure::Write);
        assert!(!original.transport_fenced);
        assert!(original.outgoing == [outgoing]);
        assert!(original.incoming == [incoming]);
        drop(held);
        assert!(journal.records().is_empty());
        Ok(())
    }
}
