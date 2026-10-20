//! Owns immutable no-extension and connected packet transport verifiers.
//!
//! Baseline framing and method decoding run in the ordinary Connection decoder.
//! This extra source verifier reads only that decoded envelope; it retains no
//! callback, policy object, mutable state or native authority. The connection
//! records this choice only when its own private installation method runs.

use super::{BodySchemaVerifier, ConnectionAuthority, Envelope, ProviderError, ReceivedBody};

pub(super) struct PacketSchema;

impl BodySchemaVerifier for PacketSchema {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope.body.get("extensions").is_some_and(|extensions| {
                extensions
                    .as_object()
                    .is_none_or(|values| !values.is_empty())
            })
        {
            return Err(ProviderError::Correlation(
                "immutable packet transport extensions unsupported",
            ));
        }
        Ok(())
    }
}

/// Retains source-installed routing facts, never a provider-defined callback.
pub(super) struct ConnectedPacketSchema {
    node: crucible_node_format::Id,
    execution_owner: crucible_node_format::Id,
    owner_generation: crucible_node_format::U64,
    input_epoch: crucible_node_format::Id,
    binding_hash: crucible_node_format::HashRef,
}

impl ConnectedPacketSchema {
    pub(super) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            node,
            execution_owner,
            owner_generation,
            input_epoch,
            binding_hash,
        } = self;
        observer.observe(node)?;
        observer.observe(execution_owner)?;
        observer.observe(owner_generation)?;
        observer.observe(input_epoch)?;
        observer.observe(binding_hash)
    }

    pub(super) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            &self.node,
            &self.execution_owner,
            self.owner_generation,
            &self.input_epoch,
            &self.binding_hash,
        )
    }

    /// Binds a closed input grammar to original negotiated source records.
    ///
    /// # Errors
    /// Refuses unnegotiated features, inconsistent bindings, expired registration,
    /// or source records exceeding the finite packet serialization allowance.
    pub(super) fn new(
        authority: &ConnectionAuthority,
        binding: &crucible_node_format::NodeBinding,
        owner: &crucible_node_format::OwnerBinding,
    ) -> Result<Self, ProviderError> {
        use crate::reference_packet::input::PACKET_INPUT_FEATURE;
        use crucible_node_format::Validate;

        super::serialized_credit(binding, 65_536)?;
        super::serialized_credit(owner, 65_536)?;
        binding.validate()?;
        owner.validate()?;
        authority.ensure_live()?;
        let node = &binding.compatibility.node_id;
        if !authority
            .selected_features()
            .iter()
            .any(|id| id.as_str() == PACKET_INPUT_FEATURE)
            || !authority
                .envelope_extensions()
                .contains(PACKET_INPUT_FEATURE)
            || binding.authority.session_id != *authority.session_id()
            || binding.authority.incarnation_id != *authority.incarnation_id()
            || binding.compatibility.execution_owner != owner.owner
            || !owner
                .owner_roles
                .iter()
                .any(|role| role.as_str() == "execution")
            || owner.node_bindings.len() != 1
            || owner.node_bindings[0].node_id != *node
            || owner.node_bindings[0].binding_hash != binding.identity()?
        {
            return Err(ProviderError::Correlation(
                "connected packet source differs from original negotiated owner",
            ));
        }
        Ok(Self {
            node: node.clone(),
            execution_owner: owner.owner.id.clone(),
            owner_generation: binding.authority.owner_generation,
            input_epoch: binding.authority.input_epoch.clone(),
            binding_hash: owner.identity()?,
        })
    }
}

impl BodySchemaVerifier for ConnectedPacketSchema {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::input::PacketInputContext;
        use crate::{
            bodies::RequestBody,
            envelope::{MessageKind, Method},
        };
        use crucible_node_format::{Extensions, InputBatch};

        if envelope.message != MessageKind::Request || envelope.method != Method::Input {
            return PacketSchema.verify(authority, envelope, body);
        }
        super::serialized_credit(envelope, 65_536)?;
        let ReceivedBody::Request(request) = body else {
            return Err(ProviderError::Correlation(
                "connected packet input body absent",
            ));
        };
        let RequestBody::Input(request) = request.as_ref() else {
            return Err(ProviderError::Correlation(
                "connected packet input method changed",
            ));
        };
        let context = PacketInputContext::decode(&envelope.extensions)?;
        let cut = context.cut();
        if cut.session_id != *authority.session_id()
            || cut.incarnation_id != *authority.incarnation_id()
            || cut.node_id != self.node
            || cut.execution_owner_id != self.execution_owner
            || envelope.node_id.0.as_ref() != Some(&self.node)
            || envelope.execution_owner_id.0.as_ref() != Some(&self.execution_owner)
            || envelope.capture_owner_id.0.is_some()
            || envelope.operation_id.0.is_some()
            || cut.owner_generation != self.owner_generation
            || cut.input_epoch != self.input_epoch
            || request.binding_hash != self.binding_hash
            || request.owner_generation != cut.owner_generation
            || request.input_epoch != cut.input_epoch
            || request.batch_id != cut.batch_id
            || request.batch_sequence != cut.batch_sequence
            || request.batch_hash != cut.batch_hash
            || !request.extensions.is_empty()
            || request
                .events
                .iter()
                .any(|event| !event.extensions.is_empty() || event.destination.node_id != self.node)
            || matches!(&context, PacketInputContext::Commit { input_request_id, .. }
                if envelope.request_id.0.as_ref() == Some(input_request_id))
        {
            return Err(ProviderError::Correlation(
                "connected packet input changed original source correlation",
            ));
        }
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: self.execution_owner.clone(),
            input_epoch: request.input_epoch.clone(),
            batch_id: request.batch_id.clone(),
            batch_sequence: request.batch_sequence,
            events: request.events.clone(),
            extensions: Extensions::new(),
        };
        if batch.identity()? != cut.batch_hash {
            return Err(ProviderError::Correlation(
                "connected packet complete batch changed",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    //! Actual SDK Hello and framed Unix transport; source/native trust is modeled.
    // crucible-lint: allow panic-shortcut -- These transport regressions deliberately panic on invalid model fixtures or failed invariants.
    #![allow(clippy::unwrap_used)]

    use std::{
        cell::RefCell, collections::BTreeMap, os::unix::net::UnixStream, rc::Rc, time::Duration,
    };

    use crucible_node_format::*;
    use serde_json::json;

    use super::*;
    use crate::{
        bodies::*,
        client::{ClientContent, ClientCustody, ClientSession, CnpController, ControllerRoute},
        connection::{Connection, ConnectionIncident, ConnectionSupervisor, EndpointRole},
        envelope::{MessageKind, Method, Nullable},
        handshake::*,
        reference_packet::input::{PACKET_INPUT_FEATURE, PacketInputContext, PacketInputCut},
        transport::{FrameReader, write_frame},
    };

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn reference() -> ContentRef {
        canonical::content_ref(b"inert transport model", "application/json").unwrap()
    }

    fn implementation() -> ImplementationIdentity {
        ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("transport-model/1"),
            artifacts: Vec::new(),
            model_definitions: Vec::new(),
            formats: Vec::new(),
            extensions: Extensions::new(),
        }
    }

    fn binding() -> (NodeBinding, OwnerBinding) {
        let owner_ref = OwnerRef {
            id: id("model-owner"),
            participant_ids: vec![id("model-node")],
            state_domain_ids: vec![id("model-domain")],
        };
        let binding = NodeBinding {
            compatibility: BindingCompatibility {
                schema_version: 1,
                node_id: id("model-node"),
                descriptor_hash: canonical::json_hash(
                    "cnp.node-descriptor.v1",
                    &json!({"model":true}),
                )
                .unwrap(),
                implementation: implementation(),
                profile_ref: reference(),
                configuration_ref: reference(),
                operating_contract: OperatingContract {
                    schema_version: 1,
                    mode: OperatingMode::Exact,
                    scheduling_role: SchedulingRole::Active,
                    ordering_profile: "superdense-v1".into(),
                    policy_ref: reference(),
                    resolution_ps: None,
                    phase_ps: None,
                    facets: Vec::new(),
                    extensions: Extensions::new(),
                },
                execution_owner: owner_ref.clone(),
                capture_owner: owner_ref.clone(),
                capabilities_ref: reference(),
                guarantees_ref: reference(),
                qualification_refs: Vec::new(),
                extensions: Extensions::new(),
            },
            authority: LiveAuthority {
                schema_version: 1,
                session_id: id("model-session"),
                incarnation_id: id("model-incarnation"),
                realization_id: id("model-realization"),
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: U64::new(7),
                input_epoch: id("model-input-epoch"),
                host_receipt: reference(),
                extensions: Extensions::new(),
            },
            extensions: Extensions::new(),
        };
        let owner = OwnerBinding {
            schema_version: 1,
            owner: owner_ref,
            owner_roles: vec![id("execution")],
            node_bindings: vec![NodeBindingRef {
                node_id: binding.compatibility.node_id.clone(),
                binding_hash: binding.identity().unwrap(),
                extensions: Extensions::new(),
            }],
            ownership_ref: reference(),
            extensions: Extensions::new(),
        };
        (binding, owner)
    }

    #[derive(Default)]
    struct ModelTrust {
        authentications: usize,
        contracts: usize,
    }

    impl TrustedHandshakeVerifier for ModelTrust {
        fn authenticate_exchange(
            &mut self,
            _: &Id,
            _: &TrustedInstallation,
            _: &HelloRequest,
            _: &HelloResult,
        ) -> Result<(), ProviderError> {
            self.authentications += 1;
            Ok(())
        }

        fn verify_contract_selection(
            &mut self,
            _: &ProviderManifest,
            _: &IdSet,
            _: &[SchemaRef],
            _: &ContentRef,
        ) -> Result<(), ProviderError> {
            self.contracts += 1;
            Ok(())
        }

        fn resume_custody(
            &mut self,
            _: &Id,
            _: &Id,
            _: &IdSet,
        ) -> Result<Vec<ResumedOperation>, ProviderError> {
            Err(ProviderError::Correlation(
                "model has no resumed native custody",
            ))
        }

        fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
            Err(ProviderError::Correlation(
                "model has no prior native connection",
            ))
        }
    }

    #[derive(Default)]
    struct Supervisor(RefCell<Vec<ConnectionIncident>>);

    impl ConnectionSupervisor for Supervisor {
        fn quarantine(&self, incident: ConnectionIncident) {
            self.0.borrow_mut().push(incident);
        }
    }

    struct UninstalledSchemas;

    impl BodySchemaVerifier for UninstalledSchemas {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    struct Negotiated {
        handshake: Handshake,
        authority: ConnectionAuthority,
        controller: UnixStream,
        provider: UnixStream,
    }

    fn hello_records(feature: bool, mapped: bool) -> (Handshake, Envelope, Envelope) {
        let limits = Limits {
            frame_bytes: U64::new(65_536),
            nesting: U64::new(64),
            requests: U64::new(16),
            journal_entries: U64::new(64),
            blob_chunk_bytes: U64::new(4096),
        };
        let mut features = vec![id("cnp.control-evidence/1"), id("cnp.core/1")];
        if feature {
            features.push(id(PACKET_INPUT_FEATURE));
        }
        let mut mappings = BTreeMap::new();
        if mapped {
            mappings.insert(PACKET_INPUT_FEATURE.into(), id(PACKET_INPUT_FEATURE));
        }
        let handshake = Handshake::new(
            TrustedInstallation {
                session_id: id("model-session"),
                incarnation_id: id("model-incarnation"),
                measured_implementation: implementation(),
                launch_receipt: reference(),
                admission_token: [7; 32],
            },
            NegotiationPolicy {
                supported_features: features.clone(),
                required_features: features.clone(),
                provider_limits: limits,
                required_schemas: Vec::new(),
                required_guarantees: reference(),
                envelope_extension_features: mappings,
            },
        )
        .unwrap();
        let hello = HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: id("model-session"),
            controller_nonce: Bytes::new(vec![3; 32]),
            required_features: features.clone(),
            optional_features: Vec::new(),
            limits,
            admission_token: Bytes::new(vec![7; 32]),
            resume_session: None,
            extensions: Extensions::new(),
        };
        let result = HelloResult {
            version: "CNP/1".into(),
            session_id: id("model-session"),
            incarnation_id: id("model-incarnation"),
            controller_nonce: hello.controller_nonce.clone(),
            provider_nonce: Bytes::new(vec![5; 32]),
            selected_features: features,
            limits,
            resume_token: Nullable(None),
            provider_identity: ProviderManifest {
                schema_version: 1,
                provider_id: id("model-provider"),
                implementation: implementation(),
                protocol_versions: vec![id("CNP/1")],
                supported_profiles: Vec::new(),
                extensions_supported: Vec::new(),
                qualification_refs: Vec::new(),
                extensions: Extensions::new(),
            },
            resumed_operations: Vec::new(),
        };
        let hello = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(id("original-hello"))),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::Hello,
            body: serde_json::to_value(hello)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        };
        let mut response = hello.clone();
        response.message = MessageKind::Response;
        response.incarnation_id = Nullable(Some(id("model-incarnation")));
        response.body = serde_json::to_value(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: serde_json::to_value(result)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
        (handshake, hello, response)
    }

    fn negotiated(feature: bool, mapped: bool) -> Negotiated {
        let (mut controller, mut provider) = UnixStream::pair().unwrap();
        for stream in [&controller, &provider] {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        let (mut handshake, hello, response) = hello_records(feature, mapped);
        write_frame(
            &mut controller,
            &serde_json::to_value(&hello).unwrap(),
            65_536,
        )
        .unwrap();
        let received: Envelope = serde_json::from_value(
            FrameReader::with_limits(&mut provider, 65_536, 64)
                .unwrap()
                .read()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(received, hello);
        write_frame(
            &mut provider,
            &serde_json::to_value(&response).unwrap(),
            65_536,
        )
        .unwrap();
        let returned: Envelope = serde_json::from_value(
            FrameReader::with_limits(&mut controller, 65_536, 64)
                .unwrap()
                .read()
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let mut trust = ModelTrust::default();
        let authority = handshake
            .admit_envelopes(&received, &returned, id("original-connection"), &mut trust)
            .unwrap();
        assert_eq!(trust.authentications, 1);
        assert_eq!(trust.contracts, 1);
        Negotiated {
            handshake,
            authority,
            controller,
            provider,
        }
    }

    fn input(owner: &OwnerBinding, sequence: u64, commit: bool) -> Envelope {
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: owner.owner.id.clone(),
            input_epoch: id("model-input-epoch"),
            batch_id: id("original-batch"),
            batch_sequence: U64::new(1),
            events: vec![Event {
                schema_version: 1,
                id: id("original-event"),
                source: Endpoint {
                    node_id: id("model-producer"),
                    port_id: id("output"),
                    lane_id: id("packet"),
                },
                destination: Endpoint {
                    node_id: id("model-node"),
                    port_id: id("input"),
                    lane_id: id("packet"),
                },
                position: Position::new(U64::new(12), U64::new(2), Phase::Delivery),
                stage: EventStage::Delivery,
                publication_position: Position::new(U64::new(11), U64::new(0), Phase::Publication),
                delivery_position: Some(Position::new(U64::new(12), U64::new(2), Phase::Delivery)),
                source_sequence: U64::new(1),
                causal_parent_ids: Vec::new(),
                payload: reference(),
                provenance_ref: reference(),
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let request = InputRequest {
            binding_hash: owner.identity().unwrap(),
            owner_generation: U64::new(7),
            batch_id: batch.batch_id.clone(),
            batch_sequence: batch.batch_sequence,
            input_epoch: batch.input_epoch.clone(),
            events: batch.events.clone(),
            batch_hash: batch.identity().unwrap(),
            extensions: Extensions::new(),
        };
        let cut = PacketInputCut {
            schema_version: 4,
            session_id: id("model-session"),
            incarnation_id: id("model-incarnation"),
            node_id: id("model-node"),
            execution_owner_id: owner.owner.id.clone(),
            owner_generation: request.owner_generation,
            activation_id: id("model-activation"),
            world_generation: U64::new(9),
            world_binding_hash: canonical::json_hash(
                "cnp.world-binding.v1",
                &json!({"model":true}),
            )
            .unwrap(),
            stage_operation_id: id("model-stage-operation"),
            batch_id: request.batch_id.clone(),
            batch_sequence: request.batch_sequence,
            input_epoch: request.input_epoch.clone(),
            batch_hash: request.batch_hash.clone(),
            delivery_inventory: canonical::content_ref(
                b"[]",
                "application/vnd.crucible.input-inventory+json",
            )
            .unwrap(),
            cutoff: Position::new(U64::new(12), U64::new(3), Phase::Reaction),
        };
        let context = if commit {
            PacketInputContext::Commit {
                cut,
                input_request_id: id("original-stage-request"),
                staging_receipt: reference(),
            }
        } else {
            PacketInputContext::Stage { cut }
        };
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(id("model-session"))),
            incarnation_id: Nullable(Some(id("model-incarnation"))),
            node_id: Nullable(Some(id("model-node"))),
            execution_owner_id: Nullable(Some(owner.owner.id.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(id(if commit {
                "original-commit-request"
            } else {
                "original-stage-request"
            }))),
            operation_id: Nullable(None),
            sequence: U64::new(sequence),
            method: Method::Input,
            body: serde_json::to_value(request)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::from([(
                PACKET_INPUT_FEATURE.into(),
                serde_json::to_value(context).unwrap(),
            )]),
        }
    }

    fn refusal(original: &Envelope, sequence: u64) -> Envelope {
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(sequence);
        response.extensions.clear();
        response.body = serde_json::to_value(ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            error: ErrorRecord {
                code: "UNSUPPORTED_FEATURE".into(),
                message: "inert transport model dispatches no source effects".into(),
                effect: EffectCertainty::NotStarted,
                retryable: false,
                details: serde_json::Map::new(),
            },
            extensions: Extensions::new(),
        })
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
        response
    }

    #[test]
    fn native5_original_connected_archive_preserves_actual_stage_commit_frames() {
        let original = negotiated(true, true);
        let (binding, owner) = binding();
        let mut controller = Connection::new(
            original.controller,
            original.authority.clone(),
            Rc::new(Supervisor::default()),
            Rc::new(UninstalledSchemas),
            EndpointRole::Controller,
        )
        .unwrap();
        let mut provider = Connection::new(
            original.provider,
            original.authority,
            Rc::new(Supervisor::default()),
            Rc::new(UninstalledSchemas),
            EndpointRole::Provider,
        )
        .unwrap();
        let mut host_bank = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 8)
                .unwrap(),
        );
        let mut native_bank = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 8)
                .unwrap(),
        );
        controller
            .install_native5_connected_frame_bank(&mut host_bank, &binding, &owner)
            .unwrap();
        provider
            .install_native5_connected_frame_bank(&mut native_bank, &binding, &owner)
            .unwrap();
        assert!(host_bank.is_none() && native_bank.is_none());
        assert!(controller.has_connected_packet_schema() && provider.has_connected_packet_schema());
        assert!(!controller.has_packet_schema() && !provider.has_packet_schema());

        for commit in [false, true] {
            let sequence = if commit { 3 } else { 2 };
            let request = input(&owner, sequence, commit);
            controller.send(request.clone()).unwrap();
            assert_eq!(provider.receive().unwrap().unwrap().envelope, request);
            provider.send(refusal(&request, sequence)).unwrap();
            controller.receive().unwrap().unwrap();
        }
        let host = controller.original_frames.as_ref().unwrap().borrow();
        let native = provider.original_frames.as_ref().unwrap().borrow();
        assert_eq!(host.frames().count(), 4);
        assert_eq!(native.frames().count(), 4);
        for (sent, received) in host.frames().zip(native.frames()) {
            assert_eq!(sent.bytes, received.bytes);
            assert!(sent.complete && received.complete);
            assert_eq!(sent.transferred, sent.bytes.len());
            assert_eq!(received.transferred, received.bytes.len());
            assert_ne!(sent.direction, received.direction);
        }
        drop(host);
        drop(native);
        assert!(
            controller
                .protocol_capture_preflight(
                    crate::protocol_snapshot::ProtocolCaptureCut::HostSettled
                )
                .is_err()
        );
        let mut replacement = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 8)
                .unwrap(),
        );
        assert!(
            controller
                .install_native5_connected_frame_bank(&mut replacement, &binding, &owner)
                .is_err()
        );
        assert_eq!(replacement.as_ref().unwrap().frames().count(), 0);
        drop(original.handshake);
    }

    #[test]
    fn native5_original_connected_archive_refusal_preserves_same_reserved_bank() {
        let (binding, owner) = binding();
        for (feature, mapped) in [(false, false), (true, false)] {
            let original = negotiated(feature, mapped);
            let mut connection = Connection::new(
                original.provider,
                original.authority,
                Rc::new(Supervisor::default()),
                Rc::new(UninstalledSchemas),
                EndpointRole::Provider,
            )
            .unwrap();
            let mut bank = Some(
                crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 8)
                    .unwrap(),
            );
            let original_allocation = bank.as_ref().unwrap().allocated_bytes();
            assert!(
                connection
                    .install_native5_connected_frame_bank(&mut bank, &binding, &owner)
                    .is_err()
            );
            assert_eq!(
                bank.as_ref().unwrap().allocated_bytes(),
                original_allocation
            );
            assert_eq!(bank.as_ref().unwrap().frames().count(), 0);
            assert!(connection.original_frames.is_none());
            assert!(!connection.has_connected_packet_schema());
            assert!(connection.guard.unused());
        }
    }

    #[test]
    fn connected_packet_stage_and_commit_keep_full_cuts_on_actual_unix_frames() {
        let original = negotiated(true, true);
        let (binding, owner) = binding();
        let controller_supervisor = Rc::new(Supervisor::default());
        let provider_supervisor = Rc::new(Supervisor::default());
        let mut controller = Connection::new(
            original.controller,
            original.authority.clone(),
            controller_supervisor.clone(),
            Rc::new(UninstalledSchemas),
            EndpointRole::Controller,
        )
        .unwrap();
        let mut provider = Connection::new(
            original.provider,
            original.authority,
            provider_supervisor.clone(),
            Rc::new(UninstalledSchemas),
            EndpointRole::Provider,
        )
        .unwrap();
        controller
            .install_connected_packet_schema(&binding, &owner)
            .unwrap();
        provider
            .install_connected_packet_schema(&binding, &owner)
            .unwrap();
        assert!(controller.has_connected_packet_schema() && provider.has_connected_packet_schema());
        assert!(!controller.has_packet_schema() && !provider.has_packet_schema());

        for commit in [false, true] {
            let sequence = if commit { 3 } else { 2 };
            let request = input(&owner, sequence, commit);
            controller.send(request.clone()).unwrap();
            let received = provider.receive().unwrap().unwrap();
            assert_eq!(received.envelope, request);
            let context = PacketInputContext::decode(&received.envelope.extensions).unwrap();
            assert_eq!(
                context.cut().cutoff,
                Position::new(U64::new(12), U64::new(3), Phase::Reaction)
            );
            assert!(
                matches!(received.body, ReceivedBody::Request(ref body) if matches!(body.as_ref(), RequestBody::Input(_)))
            );

            provider.send(refusal(&request, sequence)).unwrap();
            assert!(matches!(
                controller.receive().unwrap().unwrap().body,
                ReceivedBody::Response(_)
            ));
            assert_eq!(controller.guard.pending_requests().count(), 0);
            assert_eq!(provider.guard.incoming_requests().count(), 0);
        }
        assert!(controller_supervisor.0.borrow().is_empty());
        assert!(provider_supervisor.0.borrow().is_empty());
        drop(original.handshake);
    }

    #[test]
    fn connected_packet_install_requires_negotiated_feature_and_registered_key() {
        let (binding, owner) = binding();
        for (feature, mapped) in [(false, false), (true, false)] {
            let original = negotiated(feature, mapped);
            let supervisor = Rc::new(Supervisor::default());
            let mut connection = Connection::new(
                original.provider,
                original.authority,
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                EndpointRole::Provider,
            )
            .unwrap();

            assert!(
                connection
                    .install_connected_packet_schema(&binding, &owner)
                    .is_err()
            );
            assert!(!connection.has_packet_schema());
            assert!(!connection.has_connected_packet_schema());
            assert!(connection.guard.unused());
            assert!(supervisor.0.borrow().is_empty());
        }
    }

    #[test]
    fn connected_packet_installed_source_cannot_move_to_another_owner_or_incarnation() {
        for changed in 0..3 {
            let original = negotiated(true, true);
            let (mut binding, mut owner) = binding();
            match changed {
                0 => binding.authority.incarnation_id = id("foreign-incarnation"),
                1 => owner.owner.id = id("foreign-owner"),
                _ => {
                    owner.node_bindings[0].binding_hash =
                        canonical::json_hash("cnp.node-binding.v1", &json!({"foreign":true}))
                            .unwrap()
                }
            }
            let supervisor = Rc::new(Supervisor::default());
            let mut connection = Connection::new(
                original.provider,
                original.authority,
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                EndpointRole::Provider,
            )
            .unwrap();

            assert!(
                connection
                    .install_connected_packet_schema(&binding, &owner)
                    .is_err()
            );
            assert!(!connection.has_connected_packet_schema());
            assert!(connection.guard.unused());
            assert!(supervisor.0.borrow().is_empty());
        }
    }

    #[test]
    fn connected_packet_rejects_foreign_context_before_original_registration() {
        for changed in 0..10 {
            let mut original = negotiated(true, true);
            let (binding, owner) = binding();
            let supervisor = Rc::new(Supervisor::default());
            let mut provider = Connection::new(
                original.provider,
                original.authority,
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                EndpointRole::Provider,
            )
            .unwrap();
            provider
                .install_connected_packet_schema(&binding, &owner)
                .unwrap();
            let mut request = input(&owner, 2, changed == 7);
            match changed {
                0 => request
                    .extensions
                    .insert("foreign.feature/1".into(), json!({})),
                1 => request
                    .body
                    .insert("extensions".into(), json!({"foreign.feature/1":{}})),
                2 => {
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["cut"]["schema_version"] =
                        json!(3);
                    None
                }
                3 => {
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["cut"]["owner_generation"] =
                        json!("8");
                    None
                }
                4 => {
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["cut"]["node_id"] =
                        json!("foreign-node");
                    None
                }
                5 => {
                    let forged =
                        canonical::json_hash("cnp.input-batch.v1", &json!({"forged":true}))
                            .unwrap();
                    request
                        .body
                        .insert("batch_hash".into(), serde_json::to_value(&forged).unwrap());
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["cut"]["batch_hash"] =
                        serde_json::to_value(forged).unwrap();
                    None
                }
                6 => {
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["foreign"] =
                        json!(true);
                    None
                }
                7 => {
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["input_request_id"] =
                        json!("original-commit-request");
                    None
                }
                9 => {
                    let mut body: InputRequest =
                        serde_json::from_value(serde_json::Value::Object(request.body.clone()))
                            .unwrap();
                    body.events[0].destination.node_id = id("foreign-node");
                    let changed_batch = InputBatch {
                        schema_version: 1,
                        execution_owner_id: owner.owner.id.clone(),
                        input_epoch: body.input_epoch.clone(),
                        batch_id: body.batch_id.clone(),
                        batch_sequence: body.batch_sequence,
                        events: body.events.clone(),
                        extensions: Extensions::new(),
                    };
                    body.batch_hash = changed_batch.identity().unwrap();
                    request.extensions.get_mut(PACKET_INPUT_FEATURE).unwrap()["cut"]["batch_hash"] =
                        serde_json::to_value(&body.batch_hash).unwrap();
                    request.body = serde_json::to_value(body)
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .clone();
                    None
                }
                _ => {
                    request.method = Method::Discover;
                    request.node_id = Nullable(None);
                    request.execution_owner_id = Nullable(None);
                    request.body = serde_json::to_value(DiscoverRequest {
                        profile_ids: Vec::new(),
                        cursor: None,
                        extensions: Extensions::new(),
                    })
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone();
                    None
                }
            };
            write_frame(
                &mut original.controller,
                &serde_json::to_value(request).unwrap(),
                65_536,
            )
            .unwrap();

            assert!(provider.receive().is_err());
            assert_eq!(provider.guard.incoming_requests().count(), 0);
            let incidents = supervisor.0.borrow();
            assert_eq!(incidents.len(), 1);
            assert!(incidents[0].incoming.is_empty());
            assert!(incidents[0].transport_fenced);
        }
    }

    #[test]
    fn connected_packet_empty_response_extensions_keep_original_request_custody() {
        for changed in 0..4 {
            let mut original = negotiated(true, true);
            let (binding, owner) = binding();
            let supervisor = Rc::new(Supervisor::default());
            let mut controller = Connection::new(
                original.controller,
                original.authority,
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                EndpointRole::Controller,
            )
            .unwrap();
            controller
                .install_connected_packet_schema(&binding, &owner)
                .unwrap();
            let request = input(&owner, 2, false);
            controller.send(request.clone()).unwrap();
            let actual: Envelope = serde_json::from_value(
                FrameReader::with_limits(&mut original.provider, 65_536, 64)
                    .unwrap()
                    .read()
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(actual, request);
            let mut response = refusal(&actual, 2);
            match changed {
                0 => response.extensions = request.extensions.clone(),
                1 => {
                    response
                        .body
                        .insert("extensions".into(), json!({PACKET_INPUT_FEATURE:{}}));
                }
                2 => response.request_id = Nullable(Some(id("foreign-request"))),
                _ => response.node_id = Nullable(Some(id("foreign-node"))),
            }
            write_frame(
                &mut original.provider,
                &serde_json::to_value(response).unwrap(),
                65_536,
            )
            .unwrap();

            assert!(controller.receive().is_err());
            assert_eq!(controller.guard.pending_requests().count(), 1);
            let incidents = supervisor.0.borrow();
            assert_eq!(incidents.len(), 1);
            assert_eq!(incidents[0].outgoing, vec![request]);
        }
    }

    #[test]
    fn connected_packet_schema_cannot_replace_used_or_prepared_original_streams() {
        for completed in [false, true] {
            let mut original = negotiated(true, true);
            let (binding, owner) = binding();
            let mut controller = Connection::new(
                original.controller,
                original.authority,
                Rc::new(Supervisor::default()),
                Rc::new(UninstalledSchemas),
                EndpointRole::Controller,
            )
            .unwrap();
            let mut request = input(&owner, 2, false);
            request.extensions.clear();
            controller
                .prepare_send(request.clone())
                .unwrap()
                .publish()
                .unwrap();
            if completed {
                FrameReader::with_limits(&mut original.provider, 65_536, 64)
                    .unwrap()
                    .read()
                    .unwrap()
                    .unwrap();
                write_frame(
                    &mut original.provider,
                    &serde_json::to_value(refusal(&request, 2)).unwrap(),
                    65_536,
                )
                .unwrap();
                controller.receive().unwrap().unwrap();
                assert_eq!(controller.guard.pending_requests().count(), 0);
            }

            assert!(
                controller
                    .install_connected_packet_schema(&binding, &owner)
                    .is_err()
            );
            assert!(!controller.has_connected_packet_schema());
        }
    }

    #[test]
    fn connected_packet_old_codec_and_immutable_selection_stay_separate() {
        let (binding, owner) = binding();
        for connected in [false, true] {
            let original = negotiated(true, true);
            let supervisor = Rc::new(Supervisor::default());
            let mut connection = Connection::new(
                original.controller,
                original.authority,
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                EndpointRole::Controller,
            )
            .unwrap();
            if connected {
                connection
                    .install_connected_packet_schema(&binding, &owner)
                    .unwrap();
                assert!(connection.install_packet_schema().is_err());
                assert!(
                    connection
                        .install_connected_packet_schema(&binding, &owner)
                        .is_err()
                );
                assert!(
                    connection.has_connected_packet_schema() && !connection.has_packet_schema()
                );
            } else {
                connection.install_packet_schema().unwrap();
                assert!(
                    connection
                        .install_connected_packet_schema(&binding, &owner)
                        .is_err()
                );
                assert!(
                    connection.has_packet_schema() && !connection.has_connected_packet_schema()
                );
                assert!(connection.send(input(&owner, 2, false)).is_err());
                assert!(connection.guard.unused());
                let mut legacy = input(&owner, 2, false);
                legacy.extensions.clear();
                connection.send(legacy).unwrap();
            }
            assert!(supervisor.0.borrow().is_empty());
        }
    }

    #[test]
    fn connected_packet_controller_installs_only_its_original_source_route() {
        use std::os::unix::fs::MetadataExt;

        let executable = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let peer_identity = crate::client::ClientPeer {
            pid: std::process::id(),
            uid: std::fs::metadata("/proc/self").unwrap().uid(),
            executable: canonical::content_ref(&executable, "application/octet-stream").unwrap(),
        };
        for foreign in [false, true] {
            let (mut handshake, hello, response) = hello_records(true, true);
            let (binding, owner) = binding();
            let supervisor = Rc::new(Supervisor::default());
            let (stream, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let expected_hello = hello.clone();
            let (installed, installation) = std::sync::mpsc::channel();
            let provider = std::thread::spawn(move || {
                let original: Envelope = serde_json::from_value(
                    FrameReader::with_limits(&mut peer, 65_536, 64)
                        .unwrap()
                        .read()
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(original, expected_hello);
                write_frame(&mut peer, &serde_json::to_value(response).unwrap(), 65_536).unwrap();
                installation.recv_timeout(Duration::from_secs(2)).unwrap();
                peer.set_nonblocking(true).unwrap();
                let mut byte = [0; 1];
                assert_eq!(
                    std::io::Read::read(&mut peer, &mut byte)
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::WouldBlock
                );
            });
            let session = ClientSession::negotiate(
                stream,
                &peer_identity,
                &hello,
                id("original-client-connection"),
                &mut handshake,
                &mut ModelTrust::default(),
                supervisor.clone(),
                Rc::new(UninstalledSchemas),
                Duration::from_secs(2),
                65_536,
                64,
            )
            .unwrap();
            let custody =
                ClientCustody::new(4, ClientContent::new(65_536, 4, 4096).unwrap()).unwrap();
            let route = ControllerRoute {
                node: if foreign {
                    id("foreign-node")
                } else {
                    binding.compatibility.node_id.clone()
                },
                execution_owner: owner.owner.id.clone(),
            };
            let mut controller =
                CnpController::new(session, custody, route, Duration::from_secs(1)).unwrap();

            let result = controller.install_connected_packet_transport_schema(&binding, &owner);
            assert_eq!(result.is_err(), foreign);
            assert_eq!(controller.has_connected_packet_transport_schema(), !foreign);
            assert!(!controller.has_packet_transport_schema());
            assert!(supervisor.0.borrow().is_empty());
            installed.send(()).unwrap();
            provider.join().unwrap();
        }
    }
}
