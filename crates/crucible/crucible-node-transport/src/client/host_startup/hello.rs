//! Closes the initial host Hello to the actual installed packet declaration.
//!
//! The retained registration is the existing closed Source version-five data:
//!
//! ```text
//! {"schema":"source-owned.packet-canonical-ack-registration/5",
//!  "role":"controller","connection_id":"...","session_id":"...",
//!  "incarnation_id":"...","limits":{...},"features":[...],
//!  "extensions":[],"envelope_extensions":[...]}
//! ```
//!
//! Its labels supply no private key, Source member or process permission.

use std::collections::BTreeMap;

use crucible_node_format::{
    Bytes, ContentRef, Extensions, Id, IdSet, ProviderManifest, SchemaRef, U64,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    ProviderError,
    connection::{BodySchemaVerifier, ReceivedBody},
    envelope::{Envelope, MessageKind, Method, Nullable},
    handshake::{
        ConnectionAuthority, EXTENSION_NEGOTIATION_V1, ExtensionOfferV1, Handshake, HelloRequest,
        HelloResult, Limits, NegotiationPolicy, ResumedOperation, TrustedHandshakeVerifier,
        TrustedInstallation,
    },
    reference_packet::{control::PacketControlSelection, service::PacketNative5SourceLaunch},
};

use super::refused;
use crate::reference_packet::service::native_startup::data_equality::matches;

pub(in crate::client) const MAXIMUM_HELLO_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::client) struct Registration {
    pub(super) schema: String,
    pub(super) role: String,
    pub(super) connection_id: Id,
    pub(super) session_id: Id,
    pub(super) incarnation_id: Id,
    pub(super) limits: Limits,
    pub(super) features: IdSet,
    pub(super) extensions: Vec<crucible_node_format::ExtensionSelection>,
    pub(super) envelope_extensions: Vec<String>,
}

impl Registration {
    pub(super) fn observe(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            role,
            connection_id,
            session_id,
            incarnation_id,
            limits,
            features,
            extensions,
            envelope_extensions,
        } = self;
        observer.observe(schema)?;
        observer.observe(role)?;
        observer.observe(connection_id)?;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(limits)?;
        observer.observe(features)?;
        observer.observe(extensions)?;
        observer.observe(envelope_extensions)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ProviderError> {
        let value = crucible_node_format::canonical::parse_json(bytes, 16 * 1024)?;
        serde_json::from_value(value)
            .map_err(crucible_node_format::ContractError::from)
            .map_err(Into::into)
    }

    pub(super) fn authenticate_launch(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        if self.schema != "source-owned.packet-canonical-ack-registration/5"
            || self.role != "controller"
            || self.session_id != binding.authority.session_id
            || self.incarnation_id != binding.authority.incarnation_id
            || self.limits != launch.limits
            || !self.extensions.is_empty()
            || self.features.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .envelope_extensions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || [
                "cnp.core/1",
                "cnp.control-evidence/1",
                EXTENSION_NEGOTIATION_V1,
            ]
            .iter()
            .any(|name| {
                !self
                    .features
                    .iter()
                    .any(|feature| feature.as_str() == *name)
            })
            || launch.admission_token.as_slice().len() != 32
            || launch.selection.realization.descriptors.len() != 1
            || launch.selection.realization.owner_bindings.len() != 1
        {
            return Err(refused());
        }
        for key in &self.envelope_extensions {
            let feature = feature_for_key(key);
            if !self
                .features
                .iter()
                .any(|original| original.as_str() == feature)
            {
                return Err(refused());
            }
        }
        Ok(())
    }
}

fn feature_for_key(key: &str) -> &str {
    use crate::reference_packet::service::{confirmation, fresh_restore_allocation};
    match key {
        confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION => {
            confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE
        }
        fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY
        | fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING => {
            fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_FEATURE
        }
        _ => key,
    }
}

pub(super) fn handshake(
    launch: &PacketNative5SourceLaunch,
    registration: &Registration,
) -> Result<Handshake, ProviderError> {
    registration.authenticate_launch(launch)?;
    let binding = &launch.selection.realization.bindings[0];
    let token = launch
        .admission_token
        .as_slice()
        .try_into()
        .map_err(|_| refused())?;
    let mut extensions = BTreeMap::new();
    for key in &registration.envelope_extensions {
        extensions.insert(key.clone(), Id::new(feature_for_key(key))?);
    }
    Handshake::new(
        TrustedInstallation {
            session_id: registration.session_id.clone(),
            incarnation_id: registration.incarnation_id.clone(),
            measured_implementation: launch.selection.provider.implementation.clone(),
            launch_receipt: launch.selection.admission_receipt.clone(),
            admission_token: token,
        },
        NegotiationPolicy {
            supported_features: registration.features.clone(),
            required_features: registration.features.clone(),
            provider_limits: registration.limits,
            required_schemas: Vec::new(),
            required_guarantees: binding.compatibility.guarantees_ref.clone(),
            envelope_extension_features: extensions,
        },
    )
}

pub(super) fn request(
    launch: &PacketNative5SourceLaunch,
    registration: &Registration,
    nonce: &[u8; 32],
    hello_id: &Id,
) -> Result<Envelope, ProviderError> {
    let request = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: registration.session_id.clone(),
        controller_nonce: Bytes::new(nonce.to_vec()),
        required_features: registration.features.clone(),
        optional_features: Vec::new(),
        limits: registration.limits,
        admission_token: Bytes::new(launch.admission_token.as_slice().to_vec()),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let value = serde_json::to_value(request).map_err(crucible_node_format::ContractError::from)?;
    let Value::Object(body) = value else {
        return Err(refused());
    };
    let mut extensions = Extensions::new();
    extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionOfferV1 {
            format: U64::new(1),
            required: Vec::new(),
            optional: Vec::new(),
        })
        .map_err(crucible_node_format::ContractError::from)?,
    );
    Ok(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(None),
        incarnation_id: Nullable(None),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(hello_id.clone())),
        sequence: U64::new(1),
        method: Method::Hello,
        body,
        extensions,
    })
}

pub(in crate::client) struct Verifier<'a> {
    pub(super) selection: &'a PacketControlSelection,
    pub(super) registration: &'a Registration,
}

impl TrustedHandshakeVerifier for Verifier<'_> {
    fn authenticate_exchange(
        &mut self,
        connection: &Id,
        installed: &TrustedInstallation,
        request: &HelloRequest,
        result: &HelloResult,
    ) -> Result<(), ProviderError> {
        if connection != &self.registration.connection_id
            || installed.measured_implementation != self.selection.provider.implementation
            || installed.launch_receipt != self.selection.admission_receipt
            || installed.session_id != self.registration.session_id
            || installed.incarnation_id != self.registration.incarnation_id
            || request.session_id != self.registration.session_id
            || result.session_id != self.registration.session_id
            || result.incarnation_id != self.registration.incarnation_id
            || result.provider_identity != self.selection.provider
            || !result.resumed_operations.is_empty()
            || result.resume_token.0.is_some()
        {
            return Err(refused());
        }
        Ok(())
    }

    fn verify_contract_selection(
        &mut self,
        provider: &ProviderManifest,
        features: &IdSet,
        schemas: &[SchemaRef],
        guarantees: &ContentRef,
    ) -> Result<(), ProviderError> {
        if provider != &self.selection.provider
            || features != &self.registration.features
            || !schemas.is_empty()
            || guarantees
                != &self.selection.realization.bindings[0]
                    .compatibility
                    .guarantees_ref
        {
            return Err(refused());
        }
        Ok(())
    }

    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Err(refused())
    }

    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Err(refused())
    }
}

pub(in crate::client) struct ResponseGuard<'a> {
    pub(in crate::client) selection: &'a PacketControlSelection,
    pub(in crate::client) registration: &'a Registration,
    pub(in crate::client) request: &'a Envelope,
    pub(in crate::client) executable: &'a ContentRef,
}

impl ResponseGuard<'_> {
    pub(in crate::client) fn authenticate_peer(
        &self,
        peer: &crate::client::ClientPeer,
    ) -> Result<(), ProviderError> {
        if &peer.executable != self.executable || peer.pid == 0 {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::client) fn authenticate(&self, value: &Value) -> Result<(), ProviderError> {
        let outer = value.as_object().ok_or_else(refused)?;
        let body = outer
            .get("body")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let result = body
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        if outer.len() != 13
            || outer.get("protocol").and_then(Value::as_str) != Some("CNP/1")
            || outer.get("message").and_then(Value::as_str) != Some("response")
            || outer.get("method").and_then(Value::as_str) != Some("hello")
            || !outer
                .get("sequence")
                .is_some_and(|actual| matches(actual, &U64::new(1)))
            || !outer
                .get("request_id")
                .is_some_and(|actual| matches(actual, &self.request.request_id))
            || body.len() != 4
            || body.get("status").and_then(Value::as_str) != Some("completed")
            || body.get("operation_state").and_then(Value::as_str) != Some("completed")
            || body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|map| !map.is_empty())
            || result.len() != 10
        {
            return Err(refused());
        }
        for (field, expected) in [
            ("version", "CNP/1"),
            ("session_id", self.registration.session_id.as_str()),
            ("incarnation_id", self.registration.incarnation_id.as_str()),
        ] {
            if result.get(field).and_then(Value::as_str) != Some(expected) {
                return Err(refused());
            }
        }
        if !result
            .get("provider_identity")
            .is_some_and(|actual| matches(actual, &self.selection.provider))
            || !result
                .get("selected_features")
                .is_some_and(|actual| matches(actual, &self.registration.features))
            || !result
                .get("limits")
                .is_some_and(|actual| matches(actual, &self.registration.limits))
            || result.get("controller_nonce") != self.request.body.get("controller_nonce")
            || result
                .get("provider_nonce")
                .and_then(Value::as_str)
                .is_none_or(|nonce| {
                    nonce.len() != 43
                        || !nonce
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
            || result.get("resume_token") != Some(&Value::Null)
            || result
                .get("resumed_operations")
                .and_then(Value::as_array)
                .is_none_or(|values| !values.is_empty())
        {
            return Err(refused());
        }
        for field in [
            "session_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "operation_id",
        ] {
            if outer.get(field) != Some(&Value::Null) {
                return Err(refused());
            }
        }
        if outer.get("incarnation_id").and_then(Value::as_str)
            != Some(self.registration.incarnation_id.as_str())
        {
            return Err(refused());
        }
        let extensions = outer
            .get("extensions")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        let selected = extensions
            .get(EXTENSION_NEGOTIATION_V1)
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        if extensions.len() != 1
            || selected.len() != 2
            || !selected
                .get("format")
                .is_some_and(|value| matches(value, &U64::new(1)))
            || selected
                .get("selected")
                .and_then(Value::as_array)
                .is_none_or(|values| !values.is_empty())
        {
            return Err(refused());
        }
        Ok(())
    }
}

/// Uses the same fixed procfs spelling as the separately admitted stream reader.
pub(in crate::client) struct PeerExecutablePath {
    bytes: [u8; 30],
    length: usize,
}

impl PeerExecutablePath {
    pub(in crate::client) fn new(pid: u32) -> Result<Self, ProviderError> {
        if pid == 0 {
            return Err(refused());
        }
        const PREFIX: &[u8] = b"/proc/";
        const SUFFIX: &[u8] = b"/exe";
        let mut digits = [0; 20];
        let mut start = digits.len();
        let mut remaining = u64::from(pid);
        while remaining != 0 {
            start -= 1;
            digits[start] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
        }
        let mut result = Self {
            bytes: [0; 30],
            length: PREFIX.len() + digits.len() - start + SUFFIX.len(),
        };
        result.bytes[..PREFIX.len()].copy_from_slice(PREFIX);
        let end = PREFIX.len() + digits.len() - start;
        result.bytes[PREFIX.len()..end].copy_from_slice(&digits[start..]);
        result.bytes[end..result.length].copy_from_slice(SUFFIX);
        Ok(result)
    }

    pub(in crate::client) fn as_path(&self) -> Result<&std::path::Path, ProviderError> {
        let path = std::str::from_utf8(&self.bytes[..self.length]).map_err(|_| refused())?;
        Ok(std::path::Path::new(path))
    }
}

pub(crate) struct InitialHelloSchema;

impl BodySchemaVerifier for InitialHelloSchema {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if envelope.method != Method::Hello
            || envelope.extensions.len() != 1
            || !envelope.extensions.contains_key(EXTENSION_NEGOTIATION_V1)
        {
            return Err(refused());
        }
        Ok(())
    }
}
