//! Historical original Host archive DATA and independent comparison joins.
//!
//! The public codec borrows complete bounded archive frames. Private helpers
//! reauthenticate historical sessions against comparison inputs without
//! loading credentials, observing a floor or constructing current authority.
//! This module owns no ledger, Root writer, signer or settlement continuation.

mod historical_profile;
mod originals;

pub use originals::{
    FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4, FailedCreateOriginalHistoriesDataV4,
    FailedCreateOriginalHistoryErrorV4, encode_failed_create_original_histories_v4,
    failed_create_original_histories_encoded_len_v4,
};
