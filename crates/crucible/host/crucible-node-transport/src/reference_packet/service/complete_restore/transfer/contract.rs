//! Registers both transfer phases and their complete portable definition.

use super::*;

/// Selects one of three closed registered envelope value grammars.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketCompleteRestoreTransferSchema {
    /// Binds the exact assigned phase request.
    Request,
    /// Authenticates the independently derived phase context.
    Proof,
    /// Authenticates the actual assigned phase response.
    Receipt,
}

/// Encodes the full immutable prepare/commit transfer contract.
///
/// # Errors
/// Reports canonical specification encoding failure.
pub fn complete_restore_transfer_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(CompleteRestoreTransferContractValue)
            .map_err(crucible_node_format::ContractError::from)?,
    )?)
}

/// Names one exact registered phase schema and the full immutable definition.
///
/// # Errors
/// Reports invalid identifier or canonical contract serialization failure.
pub fn complete_restore_transfer_schema(
    phase: PacketCompleteRestoreTransferPhase,
    kind: PacketCompleteRestoreTransferSchema,
) -> Result<SchemaRef, ProviderError> {
    let id = match kind {
        PacketCompleteRestoreTransferSchema::Request => phase.request_extension(),
        PacketCompleteRestoreTransferSchema::Proof => phase.proof_extension(),
        PacketCompleteRestoreTransferSchema::Receipt => phase.receipt_extension(),
    };
    Ok(SchemaRef {
        id: Id::new(id)?,
        version: 12,
        definition: canonical::content_ref(
            &complete_restore_transfer_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.
struct CompleteRestoreTransferContractValue;

impl serde::Serialize for CompleteRestoreTransferContractValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
        static VALUE: V<'static> = V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-complete-restore-transfer-contract/12"),
            ),
            ("feature", V::Text(PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE)),
            (
                "selection",
                V::Text(
                    "SourceSignedTransfer12 is distinct from SourceSignedOwned11; absence preserves all old routes and bytes; Owned11 and portable schema values alone never grant transport or installation permission",
                ),
            ),
            (
                "registered_extensions",
                V::Array(&[
                    V::Text(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION),
                    V::Text(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION),
                    V::Text(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION),
                    V::Text(PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION),
                    V::Text(PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION),
                    V::Text(PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION),
                ]),
            ),
            (
                "baseline",
                V::Text(
                    "two distinct assigned Begin/PrepareRestore originals share exact transaction_id, capture_manifest, fresh world/owner bindings and singleton destination roster; selected endpoint retains transaction independently of ordinary Control.begin; scenario Admit is not repeated",
                ),
            ),
            (
                "prepare_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("restoration"),
                    V::Text("host_protocol"),
                    V::Text("native_protocol"),
                    V::Text("native_control"),
                    V::Text("native_anchor"),
                    V::Text("transaction_id"),
                    V::Text("generation"),
                    V::Text("allocation"),
                ]),
            ),
            (
                "restoration",
                V::Text(
                    "exact closed PacketCompleteRestoreRequest/11 including full authenticated Index3 body ref, CaptureManifest ref, owner state, journal, runtime, backend implementation/schema, archived cut/ordinal, fresh target world/owner/bindings/activation/generations, mapping fullref and nonce; no missing-field defaults",
                ),
            ),
            (
                "input_roster",
                V::Text(
                    "BLAKE3 of canonical tuple [source-owned.packet-complete-restore-input-roster/12,host_protocol,native_protocol,native_control,native_anchor,restoration.owner_state,restoration.journal,restoration.mapping,restoration.nonce,transaction_id,generation,allocation]",
                ),
            ),
            (
                "transport_inputs",
                V::Text(
                    "native_protocol, native_control, native_anchor, restoration.owner_state, restoration.journal and restoration.mapping only, compared by full ContentRef including exact length/media; host_protocol is a mapping commitment retained host-side; duplicate references share no allocation credit unless actual same original bank is authenticated",
                ),
            ),
            (
                "allocation_fields",
                V::Array(&[
                    V::Text("maximum_known_requested_bytes"),
                    V::Text("maximum_input_bytes"),
                    V::Text("maximum_nodes"),
                    V::Text("maximum_depth"),
                    V::Text("maximum_owned_backing_bytes"),
                    V::Text("maximum_tree_entries"),
                    V::Text("maximum_metadata_rows"),
                    V::Text("maximum_literal_backing_bytes"),
                    V::Text("maximum_content_transfers"),
                    V::Text("maximum_content_objects"),
                    V::Text("maximum_content_groups"),
                    V::Text("maximum_content_bytes"),
                    V::Text("maximum_content_metadata_bytes"),
                    V::Text("maximum_model_bytes"),
                ]),
            ),
            (
                "allocation",
                V::Text(
                    "positive finite data bounds, total at most512MiB, byte limits at mosttotal, depth at most64 and metadata rows at most131072; whole actual raw inputs, encoded banks, DOM, typed owners, aliases, native model/Control/raw snapshot, tree/shared headers, lookups, scratch and retained displaced state must pass source selected admission before any upload effect; per-field syntax checks confer no memory permission",
                ),
            ),
            (
                "prepare_context_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("source_birth"),
                    V::Text("kernel_binding"),
                    V::Text("policy_binding"),
                    V::Text("host_registration"),
                    V::Text("native_registration"),
                    V::Text("hello_request"),
                    V::Text("hello_response"),
                    V::Text("assigned_prepare"),
                    V::Text("prepare_request"),
                    V::Text("input_roster"),
                ]),
            ),
            (
                "prepare_context",
                V::Text(
                    "schema source-owned.packet-complete-restore-prepare-context/12; first seven role normalized inputs exactly canonical ACK admission from actual fresh boot/kernel/Hello/registration/policy; assigned_prepare hashes actual full canonical assigned prepare envelope including sequence, removing ONLY its proof; prepare_request hashes entire canonical prepare extension; input_roster uses exact tuple above",
                ),
            ),
            (
                "proof_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("context_digest"),
                    V::Text("mac"),
                ]),
            ),
            ("algorithm", V::Text(PACKET_COMPLETE_RESTORE_ALGORITHM)),
            (
                "prepare_mac",
                V::Text(
                    "K=blake3.derive_key(source-owned.packet-complete-restore-prepare-key/12,fresh32Bbirthkey); keyed_hash(K,full canonical prepare context); context_digest=BLAKE3(full context)",
                ),
            ),
            (
                "token",
                V::Text(
                    "blake3.keyed_hash(blake3.derive_key(source-owned.packet-complete-restore-transfer-token-key/12,fresh32Bbirthkey),full canonical prepare context); native opaque lease retains exact context/request/original/banks, one-shot state and token before fallible checks; portable token alone is never authority",
                ),
            ),
            (
                "prepare_receipt_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("prepare_digest"),
                    V::Text("context_digest"),
                    V::Text("input_roster"),
                    V::Text("transfer_token"),
                    V::Text("generation"),
                    V::Text("native_sequence"),
                    V::Text("assigned_response"),
                    V::Text("mac"),
                ]),
            ),
            (
                "prepare_receipt_mac",
                V::Text(
                    "K=derive_key(source-owned.packet-complete-restore-prepare-receipt-key/12,freshkey); keyed_hash over canonical whole closed prepare receipt removing ONLY mac; digest fields bind full prepare/context, original input roster, actual token/generation and actual assigned response sequence/full envelope removing ONLY own receipt; receipt admits exact input custody, never installation",
                ),
            ),
            (
                "commit_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("prepare"),
                    V::Text("capture_terminal"),
                    V::Text("prepare_request_id"),
                    V::Text("prepare_request_sequence"),
                    V::Text("prepare_request_digest"),
                    V::Text("prepare_response_sequence"),
                    V::Text("prepare_response_digest"),
                    V::Text("transfer_token"),
                ]),
            ),
            (
                "captured_terminal",
                V::Text(
                    "exact full actual original Capture terminal envelope from authenticated archived host history; source hashes whole commit, native compares journal terminal hash/sequence and exact snapshot request/control/anchor transition; no reconstructed or predicted terminal",
                ),
            ),
            (
                "restored_stage",
                V::Text(
                    "source-owned.packet-restored-native/12 is a separately registered selected native record; it retains unchanged native_receipt logical inventory and separately authenticates actual held/released physical restore gate plus installed context and full commit/response refs; never reinterpret old receipt5 or set historical logical gate true",
                ),
            ),
            (
                "commit_chain",
                V::Text(
                    "prepare_request_digest and prepare_response_digest hash full actual canonical original envelopes INCLUDING proof/receipt and actual sequence; IDs/sequences must equal retained originals; prepare data, transaction, generation, token and input roster are unchanged; distinct commit request ID is allowed",
                ),
            ),
            (
                "commit_context_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("restoration"),
                    V::Text("commit_request"),
                    V::Text("prepare_request"),
                    V::Text("prepare_response"),
                    V::Text("transfer_token"),
                    V::Text("input_roster"),
                ]),
            ),
            (
                "commit_context",
                V::Text(
                    "schema source-owned.packet-complete-restore-commit-context/12; restoration is full twelve-input PacketCompleteRestoreContext/11 derived independently after receiving exact bodies; restoration.assigned_restore hashes actual assigned COMMIT envelope removing ONLY commit proof; restoration request_binding hashes nested prepare.restoration, mapping_binding hashes actual full-reference-verified prepared SDK mapping bytes; remaining context fields bind full commit and original prepare chain",
                ),
            ),
            (
                "commit_mac",
                V::Text(
                    "K=derive_key(source-owned.packet-complete-restore-commit-key/12,freshkey); keyed_hash(K,full canonical commit context); distinct from prepare and all11 namespaces",
                ),
            ),
            (
                "commit_receipt_fields",
                V::Array(&[
                    V::Text("schema"),
                    V::Text("algorithm"),
                    V::Text("commit_digest"),
                    V::Text("context_digest"),
                    V::Text("installed_mapping"),
                    V::Text("transfer_token"),
                    V::Text("native_sequence"),
                    V::Text("assigned_response"),
                    V::Text("mac"),
                ]),
            ),
            (
                "commit_receipt_mac",
                V::Text(
                    "K=derive_key(source-owned.packet-complete-restore-commit-receipt-key/12,freshkey); keyed_hash over canonical whole closed commit receipt removing ONLY mac; binds exact commit/context, same installed mapping/token and actual assigned response sequence/full envelope removing ONLY own receipt",
                ),
            ),
            (
                "digest_width",
                V::Text(
                    "all context digests, MACs and token are exactly32 decoded bytes; standard BLAKE3 hash for full canonical projections; Hello raw header+body uses existing source-owned.cnp-original-hello-frame/5 role-normalized digests; no canonical reconstruction of raw Hello",
                ),
            ),
            (
                "bounds",
                V::Object(&[
                    (
                        "request",
                        V::Number(MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES as u64),
                    ),
                    (
                        "context",
                        V::Number(MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES as u64),
                    ),
                    (
                        "proof",
                        V::Number(MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES as u64),
                    ),
                    (
                        "receipt",
                        V::Number(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES as u64),
                    ),
                ]),
            ),
            (
                "source_issuer",
                V::Text(
                    "actual selected-load complete Index3/Core native ticket/full owner-linked archive journal and complete semantic/literal Capture->after->fourthPoll closure, same measured backend, fresh Core target context, actual fresh key/Hello/controller/native registration/current lease and actual SDK mapping must authenticate; no old Source Rc is required or accepted as substitute",
                ),
            ),
            (
                "native_issuer",
                V::Text(
                    "native independently authenticates its fresh boot/key/rawHello/current registration/policy and assigned original; retain attempt before validation; authenticate prepare MAC and whole finite plan before allocating/accepting exact listed inputs; generic BlobReceiver limits unchanged; after complete exact fullrefs/hash/decoder/model transition and commit chain, spend same one-shot lease before first install effect",
                ),
            ),
            (
                "failure",
                V::Text(
                    "partial header/body, decode/allocation/proof/signing/install failure/unwind retains originals, banks, partial vectors, actual offsets, keys, cuts and attempted/spent flags; no generic retry, ID recycling, sequence reassignment, deadline renewal or refund; no completed receipt before actual installation",
                ),
            ),
            (
                "freshness",
                V::Text(
                    "historical keys/proofs/registrations remain inert archived state, fresh active authority/codec/socket/literals/guards retained; oldworld, foreignkey, changed backend/cut/mapping/nonce/generation, replay and doubleconsume refuse; two restores require independently admitted sources/tickets/fresh peers",
                ),
            ),
            (
                "boundary",
                V::Text(
                    "only explicitly versioned bytes cross the process boundary; no Rust pointers/layout/callbacks or decoded-state authority constructors",
                ),
            ),
        ]);
        serde::Serialize::serialize(&VALUE, serializer)
    }
}

pub(crate) fn complete_restore_transfer_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CompleteRestoreTransferContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}
