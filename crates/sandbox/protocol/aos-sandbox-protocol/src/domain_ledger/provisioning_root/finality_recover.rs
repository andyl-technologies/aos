//! Frames metadata-only Create finality recovery as passive comparison DATA.
//!
//! The protected Controller admission records the actual new authorization
//! separately from the historical Create. Neither its codec nor a stored row
//! constructs a native receiver, original TLS session, lease or Root ACK.

mod admission;
mod exchange;

pub use exchange::{FinalityRecoverQueryDataV1, FinalityRecoverAcknowledgementDataV1,
    FINALITY_RECOVER_QUERY_BYTES_V1, FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1,
    finality_admission_commitment_v1, finality_inventory_commitment_v1,
    finality_acknowledgement_commitment_v1, finality_controller_transaction_commitment_v1};
pub use admission::{CreateFinalityObservationAdmissionDataV1,
    FinalityRecoverDataErrorV1, OBSERVATION_ADMISSION_HEADER_BYTES_V1,
    OBSERVATION_ADMISSION_KEY_BYTES_V1};

/// Owns canonical metadata-only public admission and joint terminal DATA recipes.
pub mod public_operation;
