//! Authenticates one inherited private boot and its actual assigned Admit.

use crate::reference_packet::service::{PacketNative5SourceLaunch, ack_emitter::*};
use crate::{
    ProviderError, envelope::Envelope, handshake::ConnectionAuthority,
    native_hello::OriginalNativeHelloJournal,
};
use crucible_node_contract::{Bytes, ContentRef, ContractError, Id, U64, canonical};
use serde::Deserialize;
use std::{cell::RefCell, rc::Rc, thread::ThreadId};

#[path = "owned11.rs"]
mod owned11;

#[path = "restore.rs"]
mod restore;
pub(crate) use restore::{
    NativeRestoredControlEvidence, OriginalCompleteRestoreCommit, VerifiedCompleteRestoration,
    VerifiedCompleteRestorationHeld,
};
#[path = "restore_prepare.rs"]
mod restore_prepare;
pub(crate) use restore_prepare::{
    VerifiedCanonicalRestoreInputAdmission, VerifiedCompleteRestorePrepare,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootData {
    schema: String,
    private_key: Bytes,
    birth_id: Bytes,
    source_birth: serde_json::Value,
    expected_host_registration: serde_json::Value,
    private_launch: Id,
    host_executable: ContentRef,
}

pub(crate) struct NativeAckBoot {
    creator: u32,
    thread: ThreadId,
    data: BootData,
    launch_body: Vec<u8>,
    pub(crate) policy: Option<Rc<crate::reference_packet::Native5Policy>>,
    source_body: Vec<u8>,
    host_body: Vec<u8>,
    normalized: [Option<serde_json::Value>; 5],
    banks: [Vec<u8>; 5],
    context: Option<PacketCanonicalAckAdmissionContext>,
    proof: Option<PacketCanonicalAckAdmissionProof>,
    original: Option<Envelope>,
    ready: bool,
    attempted: bool,
    verified: bool,
    restoration: Option<Rc<RefCell<restore::NativeCompleteRestoreAttempt>>>,
    transfer: Option<Rc<RefCell<restore_prepare::NativeCompleteRestorePrepareAttempt>>>,
}

/// Returns the actual shared boot payload layout for historical row validation.
pub(crate) const fn original_native_ack_boot_layout() -> usize {
    std::mem::size_of::<RefCell<NativeAckBoot>>()
}

pub(crate) struct VerifiedCanonicalAckAdmission {
    identity: crate::connection::OriginalNativeAckConnectionIdentity,
    pub(crate) boot: Rc<RefCell<NativeAckBoot>>,
    pub(crate) policy: Rc<crate::reference_packet::Native5Policy>,
    pub(crate) authority: ConnectionAuthority,
    pub(crate) original: Envelope,
}

impl NativeAckBoot {
    pub(super) fn prepare_into(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        original_launch_body: Vec<u8>,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(ProviderError::Conflict("native ACK boot already attempted"));
        }
        crate::connection::serialized_credit(value, 512 * 1024)?;
        let data: BootData =
            BootData::deserialize(value).map_err(crucible_node_contract::ContractError::from)?;
        let original = Rc::new(RefCell::new(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            data,
            launch_body: original_launch_body,
            policy: None,
            source_body: Vec::new(),
            host_body: Vec::new(),
            normalized: std::array::from_fn(|_| None),
            banks: std::array::from_fn(|_| Vec::new()),
            context: None,
            proof: None,
            original: None,
            ready: false,
            attempted: false,
            verified: false,
            restoration: None,
            transfer: None,
        }));
        *completed = Some(Rc::clone(&original));
        let mut owner = original
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
        owner.ensure_origin()?;
        if owner.data.schema != "source-owned.packet-canonical-ack-private-boot/5"
            || owner.data.private_key.as_slice().len() != 32
            || owner.data.birth_id.as_slice().len() != 32
            || owner.data.host_executable != launch.controller_executable
        {
            return Err(ProviderError::Correlation(
                "native private ACK boot grammar",
            ));
        }
        let expected = blake3::Hash::from(blake3::derive_key(
            "source-owned.packet-canonical-ack-birth/5",
            owner.data.private_key.as_slice(),
        ));
        if expected != *owner.data.birth_id.as_slice() {
            return Err(ProviderError::Correlation(
                "native private ACK birth identity",
            ));
        }
        let source = &owner.data.source_birth;
        let object = source
            .as_object()
            .ok_or(ProviderError::Correlation("native source binding object"))?;
        let mut keys = vec![
            "schema",
            "selection",
            "program",
            "coordinator",
            "limits",
            "storage",
            "capture_profile",
            "confirmation_selection",
            "ack_emitter_selection",
            "codec_metadata_extent",
        ];
        let schema = if launch.restore_input_emitter_selection.is_some() {
            keys.extend(["native_codec_metadata_extent", "protocol_metadata_limits", "complete_restore_selection", "restore_input_emitter_selection"]);
            "source-owned.packet-canonical-ack-source-binding/11"
        } else if launch.complete_restore_selection == Some(
            crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            keys.push("complete_restore_selection");
            "source-owned.packet-canonical-ack-source-binding/10"
        } else if launch.complete_restore_selection.is_some() {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            keys.push("complete_restore_selection");
            "source-owned.packet-canonical-ack-source-binding/9"
        } else if launch.protocol_metadata_limits.is_some() {
            keys.push("native_codec_metadata_extent");
            keys.push("protocol_metadata_limits");
            "source-owned.packet-canonical-ack-source-binding/8"
        } else if launch.native_codec_metadata_extent.is_some() {
            keys.push("native_codec_metadata_extent");
            "source-owned.packet-canonical-ack-source-binding/7"
        } else {
            "source-owned.packet-canonical-ack-source-binding/6"
        };
        if object.len() != keys.len()
            || keys.iter().any(|key| !object.contains_key(*key))
            || source["schema"] != schema
            || source["codec_metadata_extent"] != "CanonicalAck512KiB"
        {
            return Err(ProviderError::Correlation("native source binding grammar"));
        }
        let coordinator =
            canonical::parse_json(launch.initial_coordinator.bytes.as_slice(), 384 * 1024)?;
        let mut expected_source = serde_json::json!({"schema":schema, "selection":launch.selection,"program":launch.program,"coordinator":coordinator,"limits":launch.limits,"storage":launch.storage,"capture_profile":launch.capture_profile,"confirmation_selection":launch.confirmation_selection,"ack_emitter_selection":launch.ack_emitter_selection,"codec_metadata_extent":"CanonicalAck512KiB"});
        if let Some(extent) = launch.native_codec_metadata_extent {
            expected_source["native_codec_metadata_extent"] =
                serde_json::to_value(extent).map_err(ContractError::from)?;
        }
        if let Some(metadata) = launch.protocol_metadata_limits {
            expected_source["protocol_metadata_limits"] =
                serde_json::to_value(metadata).map_err(ContractError::from)?;
        }
        if let Some(restoration) = launch.complete_restore_selection {
            expected_source["complete_restore_selection"] =
                serde_json::to_value(restoration).map_err(ContractError::from)?;
        }
        if let Some(emitter) = launch.restore_input_emitter_selection {
            expected_source["restore_input_emitter_selection"] =
                serde_json::to_value(emitter).map_err(ContractError::from)?;
        }
        if *source != expected_source {
            return Err(ProviderError::Correlation(
                "native original source binding differs",
            ));
        }
        owner.source_body = canonical::canonical_json(&owner.data.source_birth)?;
        owner.host_body = canonical::canonical_json(&owner.data.expected_host_registration)?;
        if owner.source_body.len() > 384 * 1024 || owner.host_body.len() > 16 * 1024 {
            return Err(ProviderError::ResourceExhausted(
                "native ACK boot input extent",
            ));
        }
        for (bank, limit) in
            owner
                .banks
                .iter_mut()
                .zip([512 * 1024, 4 * 1024, 416 * 1024, 16 * 1024, 65536])
        {
            bank.try_reserve_exact(limit)
                .map_err(|_| ProviderError::ResourceExhausted("native ACK context bank"))?;
        }
        owner.ready = true;
        Ok(())
    }

    pub(crate) fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation("native ACK boot foreign origin"));
        }
        Ok(())
    }
}

impl NativeAckBoot {
    pub(crate) fn verify_admit<S: crate::connection::ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        policy: Rc<crate::reference_packet::Native5Policy>,
        authority: &ConnectionAuthority,
        hello: &OriginalNativeHelloJournal,
        original: &Envelope,
        connection: &crate::connection::Connection<S>,
    ) -> Result<VerifiedCanonicalAckAdmission, ProviderError> {
        connection.authenticate_native5_source_codec()?;
        authority.ensure_live()?;
        let mut owner = boot
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("native ACK boot borrowed"))?;
        owner.ensure_origin()?;
        if !owner.ready || owner.attempted {
            return Err(ProviderError::Conflict(
                "native ACK Admit already attempted",
            ));
        }
        owner.attempted = true;
        let launch = PacketNative5SourceLaunch::decode(&owner.launch_body, 1024 * 1024)?;
        owner.original = Some(original.clone());
        let proof_value = original
            .extensions
            .get(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
            .ok_or(ProviderError::Correlation("native assigned proof absent"))?;
        validate_proof_value(proof_value)?;
        owner.proof = Some(
            serde_json::from_value(proof_value.clone())
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        let expected_host = &owner.data.expected_host_registration;
        let host = expected_host.as_object().ok_or(ProviderError::Correlation(
            "native host registration grammar",
        ))?;
        let keys = [
            "schema",
            "role",
            "connection_id",
            "session_id",
            "incarnation_id",
            "limits",
            "features",
            "extensions",
            "envelope_extensions",
        ];
        if host.len() != keys.len() || keys.iter().any(|key| !host.contains_key(*key)) {
            return Err(ProviderError::Correlation(
                "native host registration closed grammar",
            ));
        }
        let host_connection_id: Id = serde_json::from_value(host["connection_id"].clone())
            .map_err(crucible_node_contract::ContractError::from)?;
        let extensions = authority
            .selected_extensions()
            .ok_or(ProviderError::Correlation(
                "native typed extension roster absent",
            ))?;
        let registration = |role: &str, id: &Id| serde_json::json!({"schema":"source-owned.packet-canonical-ack-registration/5","role":role,"connection_id":id,"session_id":authority.session_id(),"incarnation_id":authority.incarnation_id(),"limits":authority.limits(),"features":authority.selected_features(),"extensions":extensions,"envelope_extensions":authority.envelope_extensions()});
        if registration("controller", &host_connection_id) != *expected_host {
            return Err(ProviderError::Correlation(
                "native negotiated host registration differs",
            ));
        }
        let expected_body = serde_json::to_value(crate::bodies::AdmitRequest {
            bindings: launch.selection.realization.bindings.clone(),
            world_binding_hash: launch.selection.world.clone(),
            admission_receipt: launch.selection.admission_receipt.clone(),
            extensions: Default::default(),
        })
        .map_err(crucible_node_contract::ContractError::from)?;
        if original.method != crate::envelope::Method::Admit
            || original.message != crate::envelope::MessageKind::Request
            || original.extensions.len() != 1
            || serde_json::Value::Object(original.body.clone()) != expected_body
        {
            return Err(ProviderError::Correlation(
                "native assigned Admit body differs",
            ));
        }
        let native_executable = crate::conformance::measure_executable(&std::env::current_exe()?)?;
        owner.normalized[0] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-birth-association/5","birth_id":owner.data.birth_id,"private_launch":owner.data.private_launch,"host_executable":owner.data.host_executable,"source_binding":owner.data.source_birth,"expected_host_registration":owner.data.expected_host_registration}),
        );
        owner.normalized[1] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-kernel-binding/5","controller":{"pid":launch.controller_pid,"uid":launch.controller_uid,"executable":launch.controller_executable},"native":{"pid":U64::new(u64::from(std::process::id())),"uid":U64::new(u64::from(rustix::process::geteuid().as_raw())),"executable":native_executable}}),
        );
        owner.normalized[2] = Some(
            serde_json::json!({"schema":"source-owned.packet-canonical-ack-policy-binding/5","source_binding":owner.data.source_birth,"negotiated":{"limits":authority.limits(),"features":authority.selected_features(),"extensions":extensions,"envelope_extensions":authority.envelope_extensions()}}),
        );
        owner.normalized[3] = Some(registration("native", authority.connection_id()));
        let mut base = original.clone();
        base.extensions
            .remove(PACKET_CANONICAL_ACK_ADMISSION_FEATURE);
        owner.normalized[4] =
            Some(serde_json::to_value(base).map_err(crucible_node_contract::ContractError::from)?);
        for index in 0..5 {
            let value = owner.normalized[index]
                .as_ref()
                .ok_or(ProviderError::Correlation("native context value absent"))?;
            let bytes = canonical::canonical_json(value)?;
            if bytes.len() > owner.banks[index].capacity() {
                return Err(ProviderError::ResourceExhausted(
                    "native context selected extent",
                ));
            }
            owner.banks[index].extend_from_slice(&bytes);
        }
        let pair = hello.original_literal_frame_digests()?;
        let digest = |b: &[u8]| Bytes::new(blake3::hash(b).as_bytes().to_vec());
        owner.context = Some(PacketCanonicalAckAdmissionContext {
            schema: "source-owned.packet-canonical-ack-admission-context/5".into(),
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.into(),
            source_birth: digest(&owner.banks[0]),
            kernel_binding: digest(&owner.banks[1]),
            policy_binding: digest(&owner.banks[2]),
            host_registration: digest(&owner.host_body),
            native_registration: digest(&owner.banks[3]),
            hello_request: Bytes::new(pair.request_frame_digest.to_vec()),
            hello_response: Bytes::new(pair.response_frame_digest.to_vec()),
            assigned_admit: digest(&owner.banks[4]),
        });
        let key: [u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Correlation("native retained key extent"))?;
        verify_canonical_ack_admission_proof_data(
            &key,
            owner
                .context
                .as_ref()
                .ok_or(ProviderError::Correlation("native context absent"))?,
            owner
                .proof
                .as_ref()
                .ok_or(ProviderError::Correlation("native proof absent"))?,
        )?;
        owner.ensure_origin()?;
        authority.ensure_live()?;
        let identity = connection.retain_original_native_ack_identity(original, &policy)?;
        identity.authenticate_installation(connection, original)?;
        owner.verified = true;
        Ok(VerifiedCanonicalAckAdmission {
            identity,
            boot: Rc::clone(boot),
            policy,
            authority: authority.clone(),
            original: original.clone(),
        })
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn authenticate_installation<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_native5_source_codec()?;
        self.authenticate_retained_issuer()?;
        self.identity
            .authenticate_installation(connection, &self.original)
    }

    pub(crate) fn authenticate_current<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_native5_source_codec()?;
        self.authenticate_retained_issuer()?;
        self.identity.authenticate_current(connection)
    }

    fn authenticate_retained_issuer(&self) -> Result<(), ProviderError> {
        self.authority.ensure_live()?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native verified boot borrowed"))?;
        boot.ensure_origin()?;
        if !boot.verified
            || boot.original.as_ref() != Some(&self.original)
            || !boot
                .policy
                .as_ref()
                .is_some_and(|policy| Rc::ptr_eq(policy, &self.policy))
        {
            return Err(ProviderError::Correlation(
                "native verified original issuer differs",
            ));
        }
        Ok(())
    }
}

#[path = "control_admit.rs"]
mod control_admit;
pub(crate) use control_admit::OriginalCanonicalAckControlAdmit;
