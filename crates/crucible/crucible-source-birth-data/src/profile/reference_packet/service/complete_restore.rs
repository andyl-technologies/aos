//! Defines the unchanged closed complete restore selector data.

use serde::{Deserialize, Serialize};

/// Selects the explicit complete restoration mechanism without granting authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketNative5CompleteRestoreSelection {
    /// Requires a current source-signed request and one-shot native installation.
    SourceSignedOwned11,
    /// Authenticates exact large-object preparation before the one-shot commit.
    SourceSignedTransfer12,
}

/// Selects one closed original SDK restoration-input writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketNative5RestoreInputEmitterSelection {
    /// Requires the source-bound canonical SDK writer and append-only segment.
    CanonicalSdkRestoreInputs12,
}

/// Names the separately negotiated complete restoration feature and request key.
pub const PACKET_COMPLETE_RESTORE_FEATURE: &str = "source-owned.packet-complete-restore/11";

/// Names the assigned request's proof extension.
pub const PACKET_COMPLETE_RESTORE_PROOF_EXTENSION: &str =
    "source-owned.packet-complete-restore-proof/11";

/// Names the actual completed response's receipt extension.
pub const PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION: &str =
    "source-owned.packet-complete-restore-receipt/11";

/// Names the distinct normalized restoration context grammar.
pub const PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA: &str =
    "source-owned.packet-complete-restore-context/11";

/// Names the keyed BLAKE3 construction, independently domain-separated from Admit.
pub const PACKET_COMPLETE_RESTORE_ALGORITHM: &str = "blake3-keyed-canonical/1";

/// Bounds the canonical request extension, independently of the enclosing frame.
pub const MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES: usize = 8192;

/// Bounds the canonical twelve-digest context and its charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_CONTEXT_BYTES: usize = 2048;

/// Bounds the canonical proof extension before assigning its original frame.
pub const MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES: usize = 256;

/// Bounds the canonical completed receipt extension.
pub const MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES: usize = 1024;

mod contract;
pub use contract::{
    CompleteRestoreContractValue, complete_restore_contract, complete_restore_proof_schema,
    complete_restore_receipt_schema, complete_restore_request_schema,
};

mod input_emitter;
pub use input_emitter::{
    CanonicalRestoreInputsContractValue, PACKET_CANONICAL_RESTORE_INPUTS_FEATURE,
    canonical_restore_inputs_contract, canonical_restore_inputs_schema,
};

/// Defines immutable transfer grammar and phase identities.
pub mod transfer;

mod restored_record;
pub use restored_record::{
    NativeRestoredRecordContractValue, PACKET_NATIVE_RESTORED_RECORD_FEATURE,
    native_restored_record_contract, native_restored_record_schema,
};

/// Defines unchanged import17 inert phase and stage vocabulary.
pub mod import17;
/// Defines unchanged import18 inert roster and phase vocabulary.
pub mod import18;
