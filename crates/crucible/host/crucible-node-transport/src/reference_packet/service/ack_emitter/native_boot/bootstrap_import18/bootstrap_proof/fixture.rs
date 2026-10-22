//! Signs fixture DATA from the actual private wire and published public Hello.
//!
//! The parent constructs its oracle independently of the child's retained hash
//! outputs. Neither this signer nor any model admission supplies Source funding.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    native_import18_bootstrap_ack_proof_data,
};
use crate::reference_packet::service::complete_restore::import18::hello::{
    NATIVE_IMPORT18_CONNECTION_ID, native_import18_hello_declaration_data,
};
use crate::reference_packet::service::complete_restore::import18::{
    NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES, PacketNativeImport18SelectedLaunchWireData,
    decode_native_import18_private_prefix_data, native_import18_restored_record_schema_data,
    native_import18_schema_data, native_import18_stage_schema_data,
};
use crucible_node_format::canonical;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{Read, Write};

fn digest(value: &Value) -> Bytes {
    Bytes::new(
        blake3::hash(&canonical::canonical_json(value).unwrap())
            .as_bytes()
            .to_vec(),
    )
}

fn frame_digest(frame: &[u8]) -> Bytes {
    let mut hash = blake3::Hasher::new_derive_key("source-owned.cnp-original-hello-frame/5");
    hash.update(frame);
    Bytes::new(hash.finalize().as_bytes().to_vec())
}

/// Retains an independent parent oracle for the one actual bootstrap response.
pub(in super::super::super::super) struct PublicationOracle {
    context: Context,
    key: [u8; 32],
    request: Envelope,
}

impl PublicationOracle {
    /// Verifies correspondence, assigned response and distinct receipt MAC.
    pub(in super::super::super::super) fn verify_data(&self, response: &Envelope) {
        use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
            NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT, PacketNativeImport18BootstrapAckReceipt,
            native_import18_bootstrap_ack_assigned_response_digest,
            verify_native_import18_bootstrap_ack_receipt_data,
        };
        self.request.matches_response(response).unwrap();
        let assigned = native_import18_bootstrap_ack_assigned_response_digest(
            &self.request,
            response,
            crate::transport::MAX_FRAME_BYTES,
        )
        .unwrap();
        let receipt: PacketNativeImport18BootstrapAckReceipt = serde_json::from_value(
            response.extensions[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT].clone(),
        )
        .unwrap();
        verify_native_import18_bootstrap_ack_receipt_data(
            &self.key,
            &self.context,
            &assigned,
            &receipt,
        )
        .unwrap();
        assert_eq!(
            response.body["result"]["recipe_identity"],
            serde_json::to_value(&self.context.recipe_identity).unwrap()
        );
        assert_eq!(
            response.body["result"]["initial_funding"],
            serde_json::to_value(self.context.initial_funding).unwrap()
        );
    }
}

/// Sends a proof while keeping its independent response oracle in the parent.
pub(in super::super::super::super) fn write_parent_publication_frame(
    peer: &mut UnixStream,
    wire: &[u8],
    native_pid: u32,
    hello_body: &[u8],
) -> std::io::Result<(Vec<u8>, PublicationOracle)> {
    write_parent_frame_and_oracle(
        "initial_policy_kernel_normalizations_host_proof_complete",
        peer,
        wire,
        native_pid,
        hello_body,
    )
}

/// Reads the actual response before computing and sending the bootstrap proof.
pub(in super::super::super::super) fn write_parent_frame(
    case: &str,
    peer: &mut UnixStream,
    wire: &[u8],
    native_pid: u32,
    hello_body: &[u8],
) -> std::io::Result<Vec<u8>> {
    write_parent_frame_and_oracle(case, peer, wire, native_pid, hello_body).map(|(frame, _)| frame)
}

fn write_parent_frame_and_oracle(
    case: &str,
    peer: &mut UnixStream,
    wire: &[u8],
    native_pid: u32,
    hello_body: &[u8],
) -> std::io::Result<(Vec<u8>, PublicationOracle)> {
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut header = [0u8; 4];
    peer.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    assert!((1..=crate::transport::MAX_FRAME_BYTES).contains(&length));
    let mut response = vec![0; length];
    peer.read_exact(&mut response)?;
    let mut response_frame = header.to_vec();
    response_frame.extend_from_slice(&response);
    let hello_response: Envelope = serde_json::from_slice(&response).unwrap();
    assert_eq!(hello_response.method, crate::envelope::Method::Hello);
    assert_eq!(hello_response.body["status"], "completed");
    let result = &hello_response.body["result"];

    let prefix = decode_native_import18_private_prefix_data(
        &wire[..NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
        [usize::MAX; 3],
        usize::MAX,
    )
    .unwrap();
    let lengths = prefix.body_lengths_data().unwrap();
    let mut offset = NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES;
    let mut bodies = Vec::new();
    for length in lengths {
        bodies.push(serde_json::from_slice::<Value>(&wire[offset..offset + length]).unwrap());
        offset += length;
    }
    assert_eq!(offset, wire.len());
    let selected: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(bodies[1].clone()).unwrap();
    let launch = selected.launch_data();
    let launch_value = &bodies[1]["launch"];
    let boot = &bodies[2];
    let declaration = native_import18_hello_declaration_data(launch).unwrap();
    let keys: BTreeSet<String> = declaration
        .keys_data()
        .iter()
        .flatten()
        .map(|(key, _)| key.to_string())
        .collect();
    assert_eq!(keys.len(), declaration.key_count_data());
    let mut selection = None;
    declaration
        .retain_selection_into_data(&mut selection)
        .unwrap();
    let (features, declared_keys) = selection.unwrap();
    assert_eq!(result["selected_features"], json!(features));
    assert_eq!(keys, declared_keys.keys().cloned().collect::<BTreeSet<_>>());
    let negotiated_extensions =
        &hello_response.extensions[crate::handshake::EXTENSION_NEGOTIATION_V1];
    assert_eq!(negotiated_extensions["format"], "1");
    let empty_extensions = negotiated_extensions["selected"].clone();
    assert_eq!(empty_extensions, json!([]));
    let negotiated = json!({"limits":result["limits"], "features":result["selected_features"],
        "extensions":empty_extensions, "envelope_extensions":keys});
    let binding = &launch.selection.realization.bindings[0];
    assert_eq!(result["session_id"], json!(binding.authority.session_id));
    assert_eq!(
        result["incarnation_id"],
        json!(binding.authority.incarnation_id)
    );
    let recipe: crate::reference_packet::service::complete_restore::import18::PacketNativeImport18PrebirthRecipeWireData = serde_json::from_value(bodies[0].clone()).unwrap();
    let recipe = Bytes::new(recipe.announced_identity_data().to_vec());
    let mut envelope: Envelope = serde_json::from_value(json!({
        "protocol":"CNP/1", "message":"request", "method":"native_import18_bootstrap",
        "session_id":binding.authority.session_id, "incarnation_id":binding.authority.incarnation_id,
        "node_id":null,"execution_owner_id":null,"capture_owner_id":null,
        "request_id":"bootstrap","operation_id":null,"sequence":"2",
        "body":{"schema":NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,"recipe_identity":recipe,
            "initial_funding":prefix.initial_funding_data().unwrap()},"extensions":{},
    })).unwrap();
    let assigned = native_import18_bootstrap_ack_assigned_request_digest(
        &envelope,
        crate::transport::MAX_FRAME_BYTES,
    )
    .unwrap();
    let mut hello_frame = u32::try_from(hello_body.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    hello_frame.extend_from_slice(hello_body);
    let mut context = Context {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        source_birth: digest(
            &json!({"schema":"source-owned.packet-native-import-bootstrap-birth-association/18",
            "birth_id":boot["birth_id"],"private_launch":boot["private_launch"],"host_executable":boot["host_executable"],
            "source_binding":boot["source_birth"],"expected_host_registration":boot["expected_host_registration"]}),
        ),
        kernel_binding: digest(
            &json!({"schema":"source-owned.packet-canonical-ack-kernel-binding/5",
            "controller":{"pid":launch_value["controller_pid"],"uid":launch_value["controller_uid"],"executable":launch_value["controller_executable"]},
            "native":{"pid":native_pid.to_string(),"uid":rustix::process::geteuid().as_raw().to_string(),"executable":launch_value["controller_executable"]}}),
        ),
        policy_binding: digest(
            &json!({"schema":"source-owned.packet-native-import-bootstrap-policy-binding/18",
            "source_binding":boot["source_birth"],"recipe_identity":recipe,"definitions":{
                "mechanism":crate::reference_packet::service::complete_restore::import18::PacketNativeImport18Selection::SourceSignedImport18,"import":native_import18_schema_data().unwrap(),
                "stage":native_import18_stage_schema_data().unwrap(),"record":native_import18_restored_record_schema_data().unwrap()},
            "negotiated":negotiated}),
        ),
        host_registration: digest(&boot["expected_host_registration"]),
        native_registration: digest(
            &json!({"schema":"source-owned.packet-canonical-ack-registration/5","role":"native",
            "connection_id":NATIVE_IMPORT18_CONNECTION_ID,"session_id":result["session_id"],"incarnation_id":result["incarnation_id"],
            "limits":result["limits"],"features":result["selected_features"],"extensions":empty_extensions,"envelope_extensions":keys}),
        ),
        hello_request: frame_digest(&hello_frame),
        hello_response: frame_digest(&response_frame),
        assigned_request: Bytes::new(assigned.to_vec()),
        recipe_identity: recipe,
        initial_funding: prefix.initial_funding_data().unwrap(),
    };
    let suffix = case.strip_prefix(PREFIX).unwrap();
    let changed = Bytes::new(vec![7; 32]);
    match suffix {
        "wrong_birth" => context.source_birth = changed,
        "wrong_kernel" => context.kernel_binding = changed,
        "wrong_policy" => context.policy_binding = changed,
        "wrong_host" => context.host_registration = changed,
        "wrong_native" => context.native_registration = changed,
        "wrong_hello_request" => context.hello_request = changed,
        "wrong_hello_response" => context.hello_response = changed,
        "wrong_assignment" => context.assigned_request = changed,
        "wrong_recipe" => context.recipe_identity = changed,
        "wrong_funding" => {
            context.initial_funding.retained_requested_bytes = crucible_node_format::U64::new(1)
        }
        _ => {}
    }
    let key: Bytes = serde_json::from_value(boot["private_key"].clone()).unwrap();
    let mut signing_key: [u8; 32] = key.as_slice().try_into().unwrap();
    if suffix == "wrong_key" {
        signing_key[0] ^= 1;
    }
    let mut proof = native_import18_bootstrap_ack_proof_data(&signing_key, &context).unwrap();
    if suffix == "wrong_mac" {
        proof.mac = Bytes::new(vec![0; 32]);
    }
    if suffix == "wrong_digest" {
        proof.context_digest = Bytes::new(vec![0; 32]);
    }
    envelope.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        serde_json::to_value(proof).unwrap(),
    );
    let body = serde_json::to_vec(&envelope).unwrap();
    peer.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    peer.write_all(&body).unwrap();
    peer.write_all(b"unconsumed suffix").unwrap();
    Ok((
        response_frame,
        PublicationOracle {
            context,
            key: signing_key,
            request: envelope,
        },
    ))
}
