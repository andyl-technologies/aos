//! Host-authenticated negotiation and revocable single-connection registration leases.

use super::*;

/// Binds non-wire host installation facts to one admitted launch.
///
/// This configuration comes from the trusted broker, never from provider JSON.
/// Constructing it grants no authority; the exchange verifier must authenticate
/// actual peer credentials, private launch token custody, and measurements.
pub struct TrustedInstallation {
    /// Identifies the host-authorized session.
    pub session_id: Id,
    /// Identifies the surviving host-bound process incarnation.
    pub incarnation_id: Id,
    /// Contains the host's measured implementation identity.
    pub measured_implementation: ImplementationIdentity,
    /// Identifies authenticated launch and supervision facts in trusted storage.
    pub launch_receipt: ContentRef,
    /// Contains the secret from the private host launch channel.
    pub admission_token: [u8; 32],
}

/// Selects host-required contracts and exact installed receiving advertisements.
#[derive(Clone, Debug)]
pub struct NegotiationPolicy {
    /// Lists locally supported exact feature identifiers in ASCII order.
    pub supported_features: IdSet,
    /// Lists every mandatory host feature, including cnp.core/1.
    pub required_features: IdSet,
    /// Supplies the installed provider receiving advertisement for intersection.
    pub provider_limits: Limits,
    /// Lists complete required schema definitions for trusted verification.
    pub required_schemas: Vec<SchemaRef>,
    /// Binds mandatory host guarantee and qualification requirements.
    pub required_guarantees: ContentRef,
    /// Maps explicit envelope extension keys to their negotiated feature names.
    pub envelope_extension_features: std::collections::BTreeMap<String, Id>,
}

impl Validate for NegotiationPolicy {
    fn validate(&self) -> Result<(), ContractError> {
        self.supported_features.validate()?;
        self.required_features.validate()?;
        self.provider_limits.validate()?;
        self.required_guarantees.validate()?;
        if !self
            .required_features
            .iter()
            .any(|id| id.as_str() == "cnp.core/1")
            || !self
                .supported_features
                .iter()
                .any(|id| id.as_str() == "cnp.core/1")
        {
            return Err(invalid(
                "required_features",
                "both endpoints must offer and require baseline core",
            ));
        }
        if self
            .required_features
            .iter()
            .any(|id| !self.supported_features.contains(id))
        {
            return Err(invalid(
                "required_features",
                "host requires unsupported feature",
            ));
        }
        if self.required_schemas.len() > MAX_ARRAY_ELEMENTS
            || self
                .required_schemas
                .windows(2)
                .any(|pair| (&pair[0].id, pair[0].version) >= (&pair[1].id, pair[1].version))
        {
            return Err(invalid(
                "required_schemas",
                "require bounded strictly sorted schema editions",
            ));
        }
        for schema in &self.required_schemas {
            schema.validate()?;
        }
        for (extension, feature) in &self.envelope_extension_features {
            Id::new(extension.clone())?;
            if !self.supported_features.contains(feature) {
                return Err(invalid(
                    "extensions",
                    "extension registry names unsupported feature",
                ));
            }
        }
        Ok(())
    }
}

/// Authenticates facts unavailable from self-advertised provider messages.
///
/// Implementations are trusted host broker code. They obtain peer credentials
/// from the actual transport, resolve content through admitted local storage,
/// and consult installed measurement and qualification records. A vendor cannot
/// implement this interface across the process protocol to mint authority.
pub trait TrustedHandshakeVerifier {
    /// Authenticates the connection against actual peer and private launch custody.
    ///
    /// # Errors
    /// Rejects a foreign peer, invalid challenge binding, unavailable launch
    /// measurement, or unauthenticated launch-token custody.
    fn authenticate_exchange(
        &mut self,
        connection: &Id,
        installation: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError>;

    /// Verifies complete required schema content and qualified guarantee support.
    ///
    /// # Errors
    /// Rejects missing content, unsupported schemas, unknown mandatory constraints,
    /// and unsupported guarantees. Realized-node admission remains a later check.
    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        selected_features: &IdSet,
        required_schemas: &[SchemaRef],
        required_guarantees: &ContentRef,
    ) -> Result<(), ProviderError>;

    /// Returns actual surviving journal states under proven native owner custody.
    ///
    /// This check snapshots custody without waiting for operation completion or
    /// reentering control registration, which is fenced during the snapshot.
    ///
    /// # Errors
    /// Rejects a restarted incarnation, missing journal entry, changed owner
    /// custody, or uncertainty requiring OUTCOME_UNKNOWN and quarantine.
    fn resume_custody(
        &mut self,
        session: &Id,
        incarnation: &Id,
        operation_ids: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError>;

    /// Physically fences the previous stream before acknowledging replacement.
    ///
    /// # Errors
    /// Rejects inability to revoke previous connection registration authority.
    /// Failure leaves all leases revoked; it does not prove native termination.
    fn fence_connection(&mut self, connection: &Id) -> Result<(), ProviderError>;
}

/// Authorizes control-stream registration while its host epoch remains current.
///
/// This opaque lease cannot be decoded from wire data. It grants neither native
/// execution nor activation. Workers must recheck it immediately before journal
/// registration; already journaled work retains independent operation custody.
#[derive(Clone)]
pub struct ConnectionAuthority {
    shared_epoch: Arc<AtomicU64>,
    registration_gate: Arc<Mutex<()>>,
    epoch: u64,
    connection: Id,
    session: Id,
    incarnation: Id,
    limits: Limits,
    features: IdSet,
    envelope_extensions: BTreeSet<String>,
}

impl ConnectionAuthority {
    /// Compares the original host registration lease without granting authority.
    ///
    /// Matching wire IDs and epochs are insufficient: both leases must originate
    /// from the same native registration gate and revocation counter. Callers
    /// must separately call [`Self::ensure_live`] immediately before admitting
    /// effects; equality does not establish liveness or native execution scope.
    pub fn same_registration(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared_epoch, &other.shared_epoch)
            && Arc::ptr_eq(&self.registration_gate, &other.registration_gate)
            && self.epoch == other.epoch
            && self.connection == other.connection
            && self.session == other.session
            && self.incarnation == other.incarnation
    }

    /// Registers control work atomically with respect to connection fencing.
    ///
    /// The callback must only register bounded work; it must not block on native
    /// execution, socket I/O, or a callback that negotiates another connection.
    /// Already registered operations retain their independent custody afterward.
    ///
    /// # Errors
    /// Rejects a poisoned gate, a revoked lease, or registration failure.
    pub fn with_live<T>(
        &self,
        register: impl FnOnce() -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let _guard = self
            .registration_gate
            .lock()
            .map_err(|_| ProviderError::Correlation("connection registration gate poisoned"))?;
        self.ensure_live()?;
        register()
    }

    /// Verifies that the host still permits registration on this connection.
    ///
    /// # Errors
    /// Rejects a fenced, superseded, contained, or retired connection lease.
    pub fn ensure_live(&self) -> Result<(), ProviderError> {
        if self.registration_gate.is_poisoned()
            || self.shared_epoch.load(Ordering::Acquire) != self.epoch
        {
            return Err(ProviderError::Correlation(
                "control connection authority is fenced",
            ));
        }
        Ok(())
    }

    /// Returns the authenticated session identity.
    pub fn session_id(&self) -> &Id {
        &self.session
    }

    /// Returns the authenticated surviving process incarnation.
    pub fn incarnation_id(&self) -> &Id {
        &self.incarnation
    }

    /// Returns the host-bound physical connection identity.
    pub fn connection_id(&self) -> &Id {
        &self.connection
    }

    /// Returns the negotiated positive receiving ceilings.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns explicitly selected mutual features.
    pub fn selected_features(&self) -> &IdSet {
        &self.features
    }

    /// Returns explicitly registered and negotiated envelope extension names.
    pub fn envelope_extensions(&self) -> &BTreeSet<String> {
        &self.envelope_extensions
    }

    /// Returns the host-local connection generation, never a world identity.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Retains one installed incarnation and its single control connection custody.
pub struct Handshake {
    installation: TrustedInstallation,
    policy: NegotiationPolicy,
    shared_epoch: Arc<AtomicU64>,
    registration_gate: Arc<Mutex<()>>,
    epoch: u64,
    current_connection: Option<Id>,
    selected_features: Option<IdSet>,
    resume_token: Option<[u8; 32]>,
    contained: bool,
    hello_request_ids: BTreeSet<Id>,
}

impl Handshake {
    /// Authenticates the sole correlated initial or resumed hello frame pair.
    ///
    /// # Errors
    /// Rejects non-hello traffic, foreign correlation, noninitial sequences,
    /// owner scope, omitted identities, malformed replies, or any refused
    /// authentication and negotiation requirement of the underlying exchange.
    pub fn admit_envelopes(
        &mut self,
        request: &crate::envelope::Envelope,
        response: &crate::envelope::Envelope,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        use crate::bodies::{MethodResult, RequestBody, ResponseShape};
        use crate::envelope::{MessageKind, Method};

        request.validate()?;
        response.validate()?;
        if request.method != Method::Hello
            || response.method != Method::Hello
            || request.message != MessageKind::Request
            || response.message != MessageKind::Response
            || request.sequence.get() != 1
            || response.sequence.get() != 1
            || request.request_id != response.request_id
            || [
                &request.node_id,
                &response.node_id,
                &request.execution_owner_id,
                &response.execution_owner_id,
                &request.capture_owner_id,
                &response.capture_owner_id,
                &request.operation_id,
                &response.operation_id,
            ]
            .iter()
            .any(|field| field.0.is_some())
        {
            return Err(ProviderError::Correlation(
                "hello frame pair has foreign correlation or scope",
            ));
        }
        let request_id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("hello has no request identity"))?;
        if self.hello_request_ids.contains(request_id) {
            return Err(ProviderError::Conflict(
                "hello request identity was already used",
            ));
        }
        if self.hello_request_ids.len()
            >= usize::try_from(self.policy.provider_limits.journal_entries.get())
                .map_err(|_| ProviderError::ResourceExhausted("hello identity ceiling"))?
        {
            self.contain();
            return Err(ProviderError::ResourceExhausted(
                "hello identity history exhausted",
            ));
        }
        let RequestBody::Hello(hello) =
            crate::bodies::decode_request(Method::Hello, &request.body)?
        else {
            return Err(ProviderError::Frame(
                "hello request did not select hello schema",
            ));
        };
        let decoded =
            crate::bodies::decode_response(&RequestBody::Hello(hello.clone()), &response.body)?;
        if !matches!(decoded.shape, ResponseShape::Completed { .. }) {
            return Err(ProviderError::Correlation(
                "hello did not complete negotiation",
            ));
        }
        let Some(MethodResult::Hello(result)) = decoded.result else {
            return Err(ProviderError::Frame(
                "hello response has no negotiated result",
            ));
        };
        let expected_session = hello.resume_session.as_ref().map(|_| &hello.session_id);
        let expected_incarnation = hello
            .resume_session
            .as_ref()
            .map(|resume| &resume.incarnation_id);
        if request.session_id.0.as_ref() != expected_session
            || response.session_id.0.as_ref() != expected_session
            || request.incarnation_id.0.as_ref() != expected_incarnation
            || response.incarnation_id.0.as_ref() != Some(&result.incarnation_id)
        {
            return Err(ProviderError::Correlation(
                "hello envelope identities disagree with negotiated phase",
            ));
        }
        for extension in request.extensions.keys().chain(response.extensions.keys()) {
            let Some(feature) = self.policy.envelope_extension_features.get(extension) else {
                return Err(ProviderError::Correlation(
                    "unregistered hello envelope extension",
                ));
            };
            if !result.selected_features.contains(feature) {
                return Err(ProviderError::Correlation(
                    "unnegotiated hello envelope extension",
                ));
            }
        }
        let authority = self.admit_exchange(&hello, &result, connection, verifier)?;
        self.hello_request_ids.insert(request_id.clone());
        Ok(authority)
    }

    /// Prepares bounded host policy without admitting any connection.
    ///
    /// # Errors
    /// Rejects invalid installation records, requirements, or hard limits.
    pub fn new(
        installation: TrustedInstallation,
        policy: NegotiationPolicy,
    ) -> Result<Self, ProviderError> {
        installation.measured_implementation.validate()?;
        installation.launch_receipt.validate()?;
        policy.validate()?;
        Ok(Self {
            installation,
            policy,
            shared_epoch: Arc::new(AtomicU64::new(0)),
            registration_gate: Arc::new(Mutex::new(())),
            epoch: 0,
            current_connection: None,
            selected_features: None,
            resume_token: None,
            contained: false,
            hello_request_ids: BTreeSet::new(),
        })
    }

    /// Authenticates an initial exchange or a same-incarnation fenced resumption.
    ///
    /// # Errors
    /// Rejects changed identities/challenges, secret mismatch, downgrade, missing
    /// schemas/qualification, stale journal custody, token reuse, or failure to
    /// fence the previous stream. Fencing failure permanently contains this
    /// incarnation's connection authority until a new controlled recovery.
    pub(crate) fn admit_exchange(
        &mut self,
        request: &HelloRequest,
        result: &HelloResult,
        connection: Id,
        verifier: &mut impl TrustedHandshakeVerifier,
    ) -> Result<ConnectionAuthority, ProviderError> {
        if self.contained {
            return Err(ProviderError::Correlation(
                "incarnation control custody is contained",
            ));
        }
        request.validate()?;
        result.validate()?;
        if request.session_id != self.installation.session_id
            || result.session_id != self.installation.session_id
            || result.incarnation_id != self.installation.incarnation_id
            || request.controller_nonce != result.controller_nonce
        {
            return Err(ProviderError::Correlation(
                "hello identity or controller challenge mismatch",
            ));
        }
        if !constant_equal(
            request.admission_token.as_slice(),
            &self.installation.admission_token,
        ) {
            return Err(ProviderError::Correlation("unauthenticated launch token"));
        }
        if result.provider_identity.implementation != self.installation.measured_implementation {
            return Err(ProviderError::Correlation(
                "advertised implementation differs from installed measurement",
            ));
        }
        let offered: BTreeSet<_> = request
            .required_features
            .iter()
            .chain(&request.optional_features)
            .collect();
        if result.selected_features.iter().any(|feature| {
            !offered.contains(feature) || !self.policy.supported_features.contains(feature)
        }) || request
            .required_features
            .iter()
            .chain(&self.policy.required_features)
            .any(|feature| !result.selected_features.contains(feature))
        {
            return Err(ProviderError::Correlation(
                "required feature missing or selection not mutually offered",
            ));
        }
        if result.limits != request.limits.intersection(self.policy.provider_limits)? {
            return Err(ProviderError::Correlation(
                "receiving limits differ from advertised intersection",
            ));
        }
        // A selected optional behavior becomes part of this admitted session.
        // Refuse changes before any retained journal check, stream fence, or
        // secret/epoch rotation; an invalid proposal cannot revoke old custody.
        if request.resume_session.is_some()
            && self.selected_features.as_ref() != Some(&result.selected_features)
        {
            return Err(ProviderError::Correlation(
                "resume changed original selected semantic features",
            ));
        }
        verifier.authenticate_exchange(&connection, &self.installation, request, result)?;
        verifier.verify_contract_selection(
            &result.provider_identity,
            &result.selected_features,
            &self.policy.required_schemas,
            &self.policy.required_guarantees,
        )?;

        // Serialize the retained custody check and epoch rotation with old
        // connection registration. An atomic load by itself permits a worker
        // to pass its check and register after a simultaneous resume fence.
        let gate = Arc::clone(&self.registration_gate);
        let registration = gate
            .lock()
            .map_err(|_| ProviderError::Correlation("connection registration gate poisoned"))?;

        match &request.resume_session {
            None => {
                if self.current_connection.is_some() || !result.resumed_operations.is_empty() {
                    return Err(ProviderError::Correlation(
                        "fresh hello cannot replace admitted control custody",
                    ));
                }
            }
            Some(resume) => {
                if !result
                    .selected_features
                    .iter()
                    .any(|id| id.as_str() == "cnp.resume/1")
                    || resume.session_id != self.installation.session_id
                    || resume.incarnation_id != self.installation.incarnation_id
                {
                    return Err(ProviderError::Correlation(
                        "resume does not name admitted surviving incarnation",
                    ));
                }
                let old = self
                    .resume_token
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "incarnation has no resume custody",
                    ))?;
                if !constant_equal(resume.resume_token.as_slice(), old) {
                    return Err(ProviderError::Correlation("stale resume token"));
                }
                let new = result
                    .resume_token
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("missing rotated resume token"))?;
                if constant_equal(new.as_slice(), old) {
                    return Err(ProviderError::Correlation("resume token was not rotated"));
                }
                if resume.unresolved_operation_ids.len()
                    > usize::try_from(result.limits.journal_entries.get())
                        .map_err(|_| ProviderError::ResourceExhausted("journal ceiling"))?
                {
                    return Err(ProviderError::ResourceExhausted(
                        "resume inventory exceeds journal ceiling",
                    ));
                }
                let expected_ids: Vec<_> = result
                    .resumed_operations
                    .iter()
                    .map(|operation| operation.operation_id.clone())
                    .collect();
                if expected_ids != resume.unresolved_operation_ids {
                    return Err(ProviderError::Correlation(
                        "resume omits or invents unresolved operation",
                    ));
                }
                let retained = match verifier.resume_custody(
                    &self.installation.session_id,
                    &self.installation.incarnation_id,
                    &resume.unresolved_operation_ids,
                ) {
                    Ok(retained) => retained,
                    Err(error) => {
                        self.contained = true;
                        self.shared_epoch.store(0, Ordering::Release);
                        return Err(error);
                    }
                };
                if retained != result.resumed_operations {
                    self.contained = true;
                    self.shared_epoch.store(0, Ordering::Release);
                    return Err(ProviderError::Correlation(
                        "resume changed original journal state or outcome",
                    ));
                }
            }
        }
        let next = self
            .epoch
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted("connection epochs"))?;
        if let Some(old) = &self.current_connection {
            if old == &connection {
                return Err(ProviderError::Correlation(
                    "resume reused physical connection identity",
                ));
            }
            // Revoke deferred registration before any fallible native fencing.
            // A failure retains custody but never restores the old lease.
            self.shared_epoch.store(0, Ordering::Release);
            // Native fencing may wait for a deferred worker to observe its
            // revoked lease. Release the gate so that worker can refuse.
            drop(registration);
            if let Err(error) = verifier.fence_connection(old) {
                self.contained = true;
                return Err(error);
            }
        } else {
            drop(registration);
        }
        self.resume_token = result.resume_token.0.as_ref().map(|token| {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(token.as_slice());
            bytes
        });
        self.epoch = next;
        self.current_connection = Some(connection.clone());
        self.selected_features = Some(result.selected_features.clone());
        self.shared_epoch.store(next, Ordering::Release);
        let envelope_extensions = self
            .policy
            .envelope_extension_features
            .iter()
            .filter(|(_, feature)| result.selected_features.contains(feature))
            .map(|(name, _)| name.clone())
            .collect();
        Ok(ConnectionAuthority {
            shared_epoch: Arc::clone(&self.shared_epoch),
            registration_gate: Arc::clone(&self.registration_gate),
            epoch: next,
            connection,
            session: self.installation.session_id.clone(),
            incarnation: self.installation.incarnation_id.clone(),
            limits: result.limits,
            features: result.selected_features.clone(),
            envelope_extensions,
        })
    }

    /// Revokes every registration lease without asserting native operation stop.
    pub fn contain(&mut self) {
        let _registration = self.registration_gate.lock();
        self.contained = true;
        self.shared_epoch.store(0, Ordering::Release);
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        let _registration = self.registration_gate.lock();
        self.shared_epoch.store(0, Ordering::Release);
    }
}

fn constant_equal(left: &[u8], right: &[u8; 32]) -> bool {
    if left.len() != 32 {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}
