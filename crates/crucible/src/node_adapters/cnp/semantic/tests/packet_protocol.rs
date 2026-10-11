//! Actual complete packet realization fixture and original handshake comparisons.

#![cfg(test)]

use std::collections::BTreeMap;

use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, bodies::*, envelope::*, handshake::*};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::packet_definition::Definition;

pub(super) const FRAME: usize = 65_536;

pub(super) fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
pub(super) fn object(value: impl Serialize) -> Map<String, Value> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}
pub(super) fn bytes(value: impl Serialize) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap()
}
pub(super) fn reference(value: &[u8]) -> ContentRef {
    canonical::content_ref(value, "application/json").unwrap()
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Bootstrap {
    pub executable: ContentRef,
    pub manifest: ProviderManifest,
    pub definition: Bytes,
    pub limit: Position,
    pub realization: RealizationManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_guarantees: Option<ContentRef>,
}

impl Bootstrap {
    pub fn new(definition: &Definition) -> Self {
        let install = &definition.installation;
        Self {
            executable: install.provider.implementation.artifacts[0].content.clone(),
            manifest: install.provider.clone(),
            definition: Bytes::new(definition.content[&install.descriptor.model_ref].clone()),
            limit: Position::new(Tick::new(10), U64::new(0), Phase::BoundaryControl),
            source_requests: None,
            source_guarantees: None,
            realization: RealizationManifest {
                schema_version: 1,
                realization_id: install.realize.realization_id.clone(),
                provider_manifest: reference(&bytes(&install.provider)),
                descriptors: vec![install.descriptor.clone()],
                bindings: vec![install.binding.clone()],
                owners: vec![install.owner.owner.clone()],
                owner_bindings: vec![install.owner.clone()],
                extensions: Extensions::new(),
            },
        }
    }

    pub fn features(&self) -> Vec<Id> {
        vec![id("cnp.control-evidence/1"), id("cnp.core/1")]
    }
    pub fn limits(&self) -> Limits {
        Limits {
            frame_bytes: U64::new(FRAME as u64),
            nesting: U64::new(64),
            requests: U64::new(self.source_requests.unwrap_or(8)),
            journal_entries: U64::new(if self.source_guarantees.is_some() {
                256
            } else {
                128
            }),
            blob_chunk_bytes: U64::new(4096),
        }
    }
    fn guarantees(&self) -> ContentRef {
        self.source_guarantees
            .clone()
            .unwrap_or_else(|| reference(self.definition.as_slice()))
    }

    pub fn handshake(&self) -> Handshake {
        Handshake::new(
            TrustedInstallation {
                session_id: id("packet-session"),
                incarnation_id: id("packet-incarnation"),
                measured_implementation: self.manifest.implementation.clone(),
                launch_receipt: reference(self.definition.as_slice()),
                admission_token: [7; 32],
            },
            NegotiationPolicy {
                supported_features: self.features(),
                required_features: self.features(),
                provider_limits: self.limits(),
                required_schemas: vec![],
                required_guarantees: self.guarantees(),
                envelope_extension_features: BTreeMap::new(),
            },
        )
        .unwrap()
    }
    pub fn hello(&self) -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(id("packet-hello"))),
            sequence: U64::new(1),
            method: Method::Hello,
            body: object(HelloRequest {
                versions: vec!["CNP/1".into()],
                session_id: id("packet-session"),
                controller_nonce: Bytes::new(vec![3; 32]),
                required_features: self.features(),
                optional_features: vec![],
                limits: self.limits(),
                admission_token: Bytes::new(vec![7; 32]),
                resume_session: None,
                extensions: Extensions::new(),
            }),
            extensions: Extensions::new(),
        }
    }
    pub fn begin(&self) -> BeginRequest {
        BeginRequest {
            kind: BeginKind::ExactRun,
            binding_hash: self.realization.owner_bindings[0].identity().unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(Some(id("packet-activation"))),
            world_generation: U64::new(1),
            arguments: object(ExactRunArguments {
                grant_id: id("packet-op"),
                participant_ids: vec![id("relay")],
                realization_id: id("packet-realization"),
                activation_id: id("packet-activation"),
                world_generation: U64::new(1),
                owner_generation: U64::new(1),
                input_epoch: id("packet-input-epoch"),
                mode: OperatingMode::Exact,
                ordering_profile: "superdense-v1".into(),
                start: Position::new(Tick::new(0), U64::new(0), Phase::BoundaryControl),
                limit: self.limit,
                boundary_policy: BoundaryPolicy::OrdinaryStop,
                input_authorization: reference(self.definition.as_slice()),
                input_watermark: U64::new(0),
            }),
            extensions: Extensions::new(),
        }
    }
}

pub(super) struct Verifier<'a>(pub &'a Bootstrap);

impl TrustedHandshakeVerifier for Verifier<'_> {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        installation: &TrustedInstallation,
        _: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if installation.measured_implementation != self.0.manifest.implementation
            || result.provider_identity != self.0.manifest
        {
            return Err(ProviderError::Correlation(
                "changed source-selected packet process",
            ));
        }
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        manifest: &ProviderManifest,
        _: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if manifest != &self.0.manifest || !schemas.is_empty() || guarantees != &self.0.guarantees()
        {
            return Err(ProviderError::Correlation(
                "changed packet source contracts",
            ));
        }
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        operations: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        if !operations.is_empty() {
            return Err(ProviderError::Correlation(
                "packet fixture cannot restore originals",
            ));
        }
        Ok(vec![])
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation("no previous packet connection"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PacketReceipt {
    pub schema: String,
    pub operation: Id,
    pub port: Id,
    pub payload: Bytes,
    pub position: Position,
    pub native_effects: U64,
}

/// Connects only the original unopened peer under the unchanged startup deadline.
pub(super) fn connect_original_peer(
    child: &mut std::process::Child,
    socket: &std::path::Path,
) -> std::os::unix::net::UnixStream {
    super::operational_poll::original_poll(|| {
        assert!(child.try_wait().unwrap().is_none());
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(stream) => Some(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                None
            }
            Err(error) => panic!("original peer startup failed: {error}"),
        }
    })
}
