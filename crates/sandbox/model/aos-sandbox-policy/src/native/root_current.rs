//! Retains genuine purpose-specific Root current originals.
//!
//! Bare current writers precede RootOpen, Ready, and actual issuer custody.
//! This module exposes no supplied-completion or ordinary fallback factory.

mod history_post;
mod writers;
pub use writers::RootCurrentWriterDemandErrorV1;
pub(in crate::native) use writers::RootCurrentWritersOriginalV1;

// The actual writable full-family geometry binding is a mandatory provider.
// It is authored separately over the sole typed Ledger geometry recipe.
mod preopen_geometry;

mod initial_open;
pub(in crate::native) use initial_open::RootInitialOpenAppendGateV1;

mod owned;
pub use owned::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};

mod initial_geometry;
mod initial_post;
mod initial_provision;

mod initial_controls;
pub use initial_open::RootInitialOpenErrorV1;

mod initial_ready;
mod initial_ready_controls;
mod initial_subject;
pub use initial_subject::RootInitialSubjectFrameBorrowV1;

mod initial_pins;
mod initial_pins_controls;
mod initial_receiving;
mod initial_writer_sample;
pub use initial_pins::RootInitialPinsErrorV1;
pub use owned::RootInitialPinsBorrowV1;

mod initial_inputs;
mod initial_inputs_controls;
pub use initial_inputs::RootInitialPolicyInputsErrorV1;

mod initial_location;
mod initial_trust;
mod initial_trust_controls;
pub use initial_trust::RootInitialTrustErrorV1;

mod initial_source_query;
mod initial_source_query_controls;
pub use initial_source_query::RootInitialSourceQueryErrorV1;

mod initial_source_exchange;
mod initial_source_exchange_controls;
pub use initial_source_exchange::RootInitialSourceExchangeErrorV1;

mod initial_bundle;
mod initial_bundle_controls;
pub use initial_bundle::{
    RootInitialBundleOwnershipErrorV1, RootInitialBundleOwnershipFrameBorrowV1,
};

mod initial_cache;
mod initial_cache_controls;
pub use initial_cache::{RootInitialCacheProofErrorV1, RootInitialCacheProofFrameBorrowV1};

mod initial_controller;
pub(in crate::native) mod readonly_receiving;
mod storage_inventory;
pub use initial_controller::{
    RootInitialControllerReadonlyErrorV1, RootInitialControllerReadonlyPreparedBorrowV1,
    RootInitialControllerReadonlyReplayBorrowV1,
};

mod history_pair;
mod initial_use_authorized;
pub use initial_use_authorized::{
    RootInitialUseAuthorizedErrorV1, RootInitialUseAuthorizedPreparedBorrowV1,
    RootInitialUseProspectiveInputsDataV1,
};

mod use_tail;
pub use use_tail::reserved::RootUseReservedErrorV1;

mod proof_turn;
mod refreshed_controls;

pub use use_tail::admitted::RootUseAdmittedErrorV1;

pub use use_tail::signed::RootSignedBoundErrorV1;
pub use use_tail::signed_input::{RootSignedInputBorrowV1, RootSignedInputErrorV1};
