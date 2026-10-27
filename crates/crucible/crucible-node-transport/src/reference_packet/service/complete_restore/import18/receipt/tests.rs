//! Checks portable receipt correspondence without constructing a native issuer.
//!
//! Every fixture below is inert typed protocol DATA. Matching MACs grant no
//! Source loan, initial funding, prepared input bank, installed model or Hold.

use super::*;
use crate::envelope::{MessageKind, Method, Nullable};
use crate::reference_packet::service::complete_restore::{
    PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA, PacketCompleteRestoreContext,
    import17::native_import17_proof_data,
    transfer::{
        PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION, PacketCompleteRestoreCommitContext,
        PacketCompleteRestorePrepareContext,
    },
};
use serde_json::{Value, json};

const KEY: [u8; 32] = [12; 32];
const MAXIMUM_FRAME: usize = 65536;

fn digest(value: &impl Serialize) -> Bytes {
    bytes32(*blake3::hash(&bounded(value, MAXIMUM_FRAME).unwrap()).as_bytes())
}

struct PrepareFixture {
    request: PacketCompleteRestorePrepareRequest,
    binding: PacketNativeImport18Binding,
    original: Envelope,
    response: Envelope,
    context: PacketNativeImport17Context,
}

fn original(
    request: &impl Serialize,
    binding: &PacketNativeImport18Binding,
    phase: PacketNativeImport18Phase,
) -> Envelope {
    let mut original = crate::envelope::tests::request();
    original.method = Method::Begin;
    original.request_id = Nullable(Some(Id::new(format!("receipt/{phase:?}")).unwrap()));
    original.body = json!({
        "kind": "prepare_restore",
        "binding_hash": canonical::hash("cnp.owner-binding.v1", b"fresh").unwrap(),
        "owner_generation": "1", "activation_id": null, "world_generation": "1",
        "arguments": {
            "transaction_id": "restore/transaction",
            "capture_manifest": canonical::content_ref(b"{}", "application/json").unwrap(),
            "expected_world_binding_hash": canonical::hash("cnp.world-binding.v1", b"fresh").unwrap(),
            "expected_owner_binding_hash": canonical::hash("cnp.owner-binding.v1", b"fresh").unwrap(),
            "destination_owner_ids": ["owner-1"]
        },
        "extensions": {}
    }).as_object().unwrap().clone();

    original.extensions = [
        (
            phase.request_extension().to_owned(),
            serde_json::to_value(request).unwrap(),
        ),
        (
            NATIVE_IMPORT18_EXTENSION.to_owned(),
            serde_json::to_value(binding).unwrap(),
        ),
    ]
    .into_iter()
    .collect();
    original
}

fn response(original: &Envelope) -> Envelope {
    let mut response = original.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(2);
    response.extensions.clear();
    // This body is deliberately DATA: the receipt helper authenticates complete
    // literal correspondence; it does not issue a native completion witness.
    response.body = json!({"fixture": "inert response"})
        .as_object()
        .unwrap()
        .clone();
    response
}

fn sign(
    original: &mut Envelope,
    binding: &PacketNativeImport18Binding,
    peer: PacketNativeImport17PeerContext,
    phase: PacketNativeImport18Phase,
) -> PacketNativeImport17Context {
    let assigned =
        bytes32(native_import18_assigned_request_digest(original, phase, MAXIMUM_FRAME).unwrap());
    let mut context = PacketNativeImport17Context {
        schema: "source-owned.packet-native-import-context/17".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        peer,
        import_binding_digest: bytes32(binding.digest_data().unwrap()),
        assigned_original_digest: assigned,
    };
    match &mut context.peer {
        PacketNativeImport17PeerContext::Prepare(peer) => {
            peer.assigned_prepare = bytes32(*digest32(&context.assigned_original_digest).unwrap());
        }
        PacketNativeImport17PeerContext::Commit(peer) => {
            peer.restoration.assigned_restore =
                bytes32(*digest32(&context.assigned_original_digest).unwrap());
        }
    }

    let proof = native_import17_proof_data(&KEY, &context).unwrap();
    original.extensions.insert(
        phase.proof_extension().to_owned(),
        serde_json::to_value(proof).unwrap(),
    );
    context
}

fn prepare() -> PrepareFixture {
    let mut request = super::super::super::transfer::tests::prepare();
    request.restoration.backend_schema.id =
        Id::new("source-owned.packet-native-continuation/17").unwrap();
    request.restoration.backend_schema.version = 17;

    let mut binding = super::super::tests::fixture();
    binding.prepare_digest = digest(&request);

    let mut original = original(&request, &binding, PacketNativeImport18Phase::Prepare);
    let peer = PacketCompleteRestorePrepareContext {
        schema: "source-owned.packet-complete-restore-prepare-context/12".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        source_birth: bytes32([1; 32]),
        kernel_binding: bytes32([2; 32]),
        policy_binding: bytes32([3; 32]),
        host_registration: bytes32([4; 32]),
        native_registration: bytes32([5; 32]),
        hello_request: bytes32([6; 32]),
        hello_response: bytes32([7; 32]),
        assigned_prepare: bytes32([0; 32]),
        prepare_request: digest(&request),
        input_roster: native_import18_input_roster_digest_data(&request, &binding).unwrap(),
    };
    let context = sign(
        &mut original,
        &binding,
        PacketNativeImport17PeerContext::Prepare(peer),
        PacketNativeImport18Phase::Prepare,
    );

    PrepareFixture {
        response: response(&original),
        request,
        binding,
        original,
        context,
    }
}

impl PrepareFixture {
    fn receipt(&self) -> PacketNativeImport17PrepareReceipt {
        native_import18_prepare_receipt_data(
            &KEY,
            &self.binding,
            &self.request,
            &PacketNativeImport18ReceiptContextData {
                expected_backend_schema: &self.request.restoration.backend_schema,
                context: &self.context,
            },
            &PacketNativeImportReceiptAssignmentData {
                original: &self.original,
                response: &self.response,
                maximum_frame_bytes: MAXIMUM_FRAME,
            },
        )
        .unwrap()
    }

    fn verify(
        &self,
        key: &[u8; 32],
        receipt: &PacketNativeImport17PrepareReceipt,
    ) -> Result<(), ProviderError> {
        verify_native_import18_prepare_receipt_data(
            key,
            &self.binding,
            &self.request,
            &PacketNativeImport18ReceiptContextData {
                expected_backend_schema: &self.request.restoration.backend_schema,
                context: &self.context,
            },
            &PacketNativeImportReceiptAssignmentData {
                original: &self.original,
                response: &self.response,
                maximum_frame_bytes: MAXIMUM_FRAME,
            },
            receipt,
        )
    }
}

struct CommitFixture {
    request: PacketCompleteRestoreCommitRequest,
    binding: PacketNativeImport18Binding,
    original: Envelope,
    response: Envelope,
    context: PacketNativeImport17Context,
}

fn commit() -> CommitFixture {
    let mut prepared = prepare();
    let receipt = prepared.receipt();
    prepared.response.extensions.insert(
        PacketNativeImport18Phase::Prepare
            .receipt_extension()
            .to_owned(),
        serde_json::to_value(&receipt).unwrap(),
    );
    let request = PacketCompleteRestoreCommitRequest {
        schema: PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION.to_owned(),
        // This is an inert Envelope occurrence, not a completed Capture loan.
        capture_terminal: prepared.response.clone(),
        prepare_request_id: prepared.original.request_id.0.clone().unwrap(),
        prepare_request_sequence: prepared.original.sequence,
        prepare_request_digest: digest(&prepared.original),
        prepare_response_sequence: prepared.response.sequence,
        prepare_response_digest: digest(&prepared.response),
        transfer_token: receipt.transfer_token,
        prepare: prepared.request,
    };
    let bindings = request.prepare.restoration.context_bindings(b"{}").unwrap();
    let restoration = PacketCompleteRestoreContext {
        schema: PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        source_birth: bytes32([1; 32]),
        kernel_binding: bytes32([2; 32]),
        policy_binding: bytes32([3; 32]),
        host_registration: bytes32([4; 32]),
        native_registration: bytes32([5; 32]),
        hello_request: bytes32([6; 32]),
        hello_response: bytes32([7; 32]),
        assigned_restore: bytes32([0; 32]),
        archive_binding: bindings.archive_binding,
        target_binding: bindings.target_binding,
        mapping_binding: bindings.mapping_binding,
        request_binding: bindings.request_binding,
    };
    let peer = PacketCompleteRestoreCommitContext {
        schema: "source-owned.packet-complete-restore-commit-context/12".to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        restoration,
        commit_request: digest(&request),
        prepare_request: request.prepare_request_digest.clone(),
        prepare_response: request.prepare_response_digest.clone(),
        transfer_token: request.transfer_token.clone(),
        input_roster: native_import18_input_roster_digest_data(&request.prepare, &prepared.binding)
            .unwrap(),
    };
    let mut original = original(
        &request,
        &prepared.binding,
        PacketNativeImport18Phase::Commit,
    );
    original.sequence = U64::new(3);
    let context = sign(
        &mut original,
        &prepared.binding,
        PacketNativeImport17PeerContext::Commit(peer),
        PacketNativeImport18Phase::Commit,
    );

    CommitFixture {
        response: response(&original),
        request,
        binding: prepared.binding,
        original,
        context,
    }
}

impl CommitFixture {
    fn receipt(&self) -> PacketNativeImport17CommitReceipt {
        native_import18_commit_receipt_data(
            &KEY,
            &self.binding,
            &self.request,
            &PacketNativeImport18ReceiptContextData {
                expected_backend_schema: &self.request.prepare.restoration.backend_schema,
                context: &self.context,
            },
            &PacketNativeImportReceiptAssignmentData {
                original: &self.original,
                response: &self.response,
                maximum_frame_bytes: MAXIMUM_FRAME,
            },
            b"{}",
        )
        .unwrap()
    }

    fn verify(
        &self,
        key: &[u8; 32],
        receipt: &PacketNativeImport17CommitReceipt,
    ) -> Result<(), ProviderError> {
        verify_native_import18_commit_receipt_data(
            key,
            &self.binding,
            &self.request,
            &PacketNativeImport18ReceiptContextData {
                expected_backend_schema: &self.request.prepare.restoration.backend_schema,
                context: &self.context,
            },
            &PacketNativeImportReceiptAssignmentData {
                original: &self.original,
                response: &self.response,
                maximum_frame_bytes: MAXIMUM_FRAME,
            },
            b"{}",
            receipt,
        )
    }
}

#[test]
fn prepare_receipt_binds_seventh_bank_and_exact_receipt_exclusion() {
    let mut fixture = prepare();
    let receipt = fixture.receipt();
    fixture.verify(&KEY, &receipt).unwrap();
    assert_ne!(
        receipt.input_roster,
        fixture.request.input_roster_digest_data().unwrap()
    );

    fixture.response.extensions.insert(
        PacketNativeImport18Phase::Prepare
            .receipt_extension()
            .to_owned(),
        serde_json::to_value(&receipt).unwrap(),
    );
    fixture.verify(&KEY, &receipt).unwrap();
    assert!(fixture.verify(&[13; 32], &receipt).is_err());

    fixture.response.extensions.insert(
        PacketNativeImport18Phase::Prepare
            .payload_phase_data()
            .receipt_extension()
            .to_owned(),
        serde_json::to_value(&receipt).unwrap(),
    );
    assert!(fixture.verify(&KEY, &receipt).is_err());
}

#[test]
fn commit_receipt_binds_prepare_receipt_chain_and_exact_receipt_exclusion() {
    let mut fixture = commit();
    let receipt = fixture.receipt();
    fixture.verify(&KEY, &receipt).unwrap();
    assert_eq!(receipt.transfer_token, fixture.request.transfer_token);
    assert_eq!(receipt.installed_mapping, fixture.binding.normalization);

    fixture.response.extensions.insert(
        PacketNativeImport18Phase::Commit
            .receipt_extension()
            .to_owned(),
        serde_json::to_value(&receipt).unwrap(),
    );
    fixture.verify(&KEY, &receipt).unwrap();
    assert!(fixture.verify(&[13; 32], &receipt).is_err());

    fixture.response.extensions.insert(
        PacketNativeImport18Phase::Commit
            .payload_phase_data()
            .receipt_extension()
            .to_owned(),
        serde_json::to_value(&receipt).unwrap(),
    );
    assert!(fixture.verify(&KEY, &receipt).is_err());
}

fn changed_receipt_field(field: &str, original: &Value) -> Value {
    match field {
        "schema" | "algorithm" => json!("foreign"),
        "generation" | "native_sequence" => json!("99"),
        "installed_mapping" => {
            serde_json::to_value(canonical::content_ref(b"foreign", "application/json").unwrap())
                .unwrap()
        }
        _ => {
            let mut bytes = serde_json::from_value::<Bytes>(original.clone())
                .unwrap()
                .as_slice()
                .to_vec();
            assert_eq!(bytes.len(), 32);
            bytes[0] ^= 1;
            serde_json::to_value(Bytes::new(bytes)).unwrap()
        }
    }
}

#[test]
fn every_prepare_receipt_field_is_authenticated() {
    let fixture = prepare();
    let original = serde_json::to_value(fixture.receipt()).unwrap();
    for (field, value) in original.as_object().unwrap() {
        let mut changed = original.clone();
        changed[field] = changed_receipt_field(field, value);
        let receipt: PacketNativeImport17PrepareReceipt = serde_json::from_value(changed).unwrap();
        assert!(
            fixture.verify(&KEY, &receipt).is_err(),
            "accepted changed {field}"
        );
    }
}

#[test]
fn every_commit_receipt_field_is_authenticated() {
    let fixture = commit();
    let original = serde_json::to_value(fixture.receipt()).unwrap();
    for (field, value) in original.as_object().unwrap() {
        let mut changed = original.clone();
        changed[field] = changed_receipt_field(field, value);
        let receipt: PacketNativeImport17CommitReceipt = serde_json::from_value(changed).unwrap();
        assert!(
            fixture.verify(&KEY, &receipt).is_err(),
            "accepted changed {field}"
        );
    }
}

#[test]
fn prepare_receipt_rejects_changed_response_and_original_proof() {
    let mut fixture = prepare();
    let receipt = fixture.receipt();
    fixture
        .response
        .body
        .insert("changed".to_owned(), json!(true));
    assert!(fixture.verify(&KEY, &receipt).is_err());
    fixture.response = response(&fixture.original);
    fixture.response.request_id = Nullable(Some(Id::new("foreign-request").unwrap()));
    assert!(fixture.verify(&KEY, &receipt).is_err());
    fixture.response = response(&fixture.original);
    fixture
        .original
        .extensions
        .remove(PacketNativeImport18Phase::Prepare.proof_extension());
    assert!(fixture.verify(&KEY, &receipt).is_err());
}

#[test]
fn commit_receipt_rejects_changed_token_mapping_and_prepare_chain() {
    let mut fixture = commit();
    let receipt = fixture.receipt();
    fixture.request.transfer_token = bytes32([99; 32]);
    assert!(fixture.verify(&KEY, &receipt).is_err());

    let mut fixture = commit();
    fixture.request.prepare_response_digest = bytes32([99; 32]);
    assert!(fixture.verify(&KEY, &receipt).is_err());

    let fixture = commit();
    assert!(
        verify_native_import18_commit_receipt_data(
            &KEY,
            &fixture.binding,
            &fixture.request,
            &PacketNativeImport18ReceiptContextData {
                expected_backend_schema: &fixture.request.prepare.restoration.backend_schema,
                context: &fixture.context,
            },
            &PacketNativeImportReceiptAssignmentData {
                original: &fixture.original,
                response: &fixture.response,
                maximum_frame_bytes: MAXIMUM_FRAME,
            },
            b"{ }",
            &receipt
        )
        .is_err()
    );
}

#[test]
fn prepare_receipt_rejects_changed_seventh_bank_and_phase_context() {
    let mut fixture = prepare();
    let receipt = fixture.receipt();
    fixture.binding.semantic_spend = canonical::content_ref(
        b"foreign semantic state",
        fixture.binding.semantic_spend_family.media_type_data(),
    )
    .unwrap();
    assert!(fixture.verify(&KEY, &receipt).is_err());

    let mut fixture = prepare();
    let PacketNativeImport17PeerContext::Prepare(peer) = &mut fixture.context.peer else {
        panic!("Prepare DATA fixture");
    };
    peer.native_registration = bytes32([99; 32]);
    assert!(fixture.verify(&KEY, &receipt).is_err());
}

#[test]
fn commit_receipt_rejects_changed_response_and_original_proof() {
    let mut fixture = commit();
    let receipt = fixture.receipt();
    fixture.response.sequence = U64::new(99);
    assert!(fixture.verify(&KEY, &receipt).is_err());

    fixture.response = response(&fixture.original);
    fixture
        .original
        .extensions
        .remove(PacketNativeImport18Phase::Commit.proof_extension());
    assert!(fixture.verify(&KEY, &receipt).is_err());
}
