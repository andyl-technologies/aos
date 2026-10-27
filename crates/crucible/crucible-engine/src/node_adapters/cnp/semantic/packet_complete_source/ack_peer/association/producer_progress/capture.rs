//! Owns the distinct selected Capture17 transport and logical-state helpers.
//!
//! The administrative Runtime ticket and live Window claim remain independent
//! of every quoted row and archived value. Helpers retain actual Source/SDK
//! partials without enabling ordinary Capture or changing legacy15/16 readers.
//! The parent owning quote/effect and whole Source reader are still required.

#[path = "capture/capacities.rs"]
mod capacities;

#[path = "capture/bridge.rs"]
mod bridge;
#[path = "capture/confirmation.rs"]
mod confirmation;
#[path = "capture/current.rs"]
mod current;
#[path = "capture/encoding_extent.rs"]
mod encoding_extent;
#[path = "capture/logical.rs"]
mod logical;
#[path = "capture/owner.rs"]
mod owner;
#[path = "capture/post_confirmation.rs"]
mod post_confirmation;
pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) use owner::CaptureOnceOwner;

#[path = "capture/prefix.rs"]
mod prefix;
#[path = "capture/sdk_effect.rs"]
mod sdk_effect;
#[path = "capture/signing.rs"]
mod signing;
#[path = "capture/transport_quote.rs"]
mod transport_quote;
#[path = "capture/upload.rs"]
mod upload;

pub(crate) use logical::OriginalSourceRestoredProducerHistory17Read;

pub(crate) use logical::OriginalSourceRestoredFirstObservationHistory17Read;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) use owner::{
    CapturePreEncoderCut, CapturePrefixEncoder,
};

pub(crate) use logical::{
    OriginalSourceCaptureHousekeeping17Read, OriginalSourcePreEncoderCaptureHousekeeping17Read,
};

pub(crate) use logical::{
    OriginalSourceRestoredInstallation17, OriginalSourceRestoredInstallationExpected17,
    OriginalSourceRestoredLimits17, OriginalSourceRestoredProducerCheckpoint17,
    OriginalSourceRestoredSettled17DecodeAttempt, OriginalSourceRestoredSettled17Prelude,
    OriginalSourceRestoredSettled17Read, OriginalSourceRestoredSettled17ReadInputs,
};

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) use logical::{
    OriginalSourceRestoredSettled17WriteInputs, OriginalSourceRestoredSettledSemantic17View,
};

#[path = "capture/accounting.rs"]
mod accounting;
#[path = "capture/construction_data.rs"]
mod construction_data;
#[path = "capture/construction_quote.rs"]
mod construction_quote;
#[path = "capture/effect.rs"]
mod effect;
#[path = "capture/quote_context.rs"]
mod quote_context;
pub use construction_data::OriginalSourceRestoredCaptureConstructionData;
pub(crate) use effect::OriginalSourceRestoredCaptureCompletion;
pub(crate) use quote_context::OriginalSourceRestoredCaptureQuoteInputs;

#[path = "capture/ancestry.rs"]
mod ancestry;
pub(crate) use ancestry::OriginalRestoredCaptureAncestry17Data;
pub(crate) use quote_context::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use quote_context::OriginalSourceRestoredCaptureCountingBanksData;

#[path = "capture/finalization.rs"]
mod finalization;

#[path = "capture/read_owner.rs"]
mod read_owner;

#[path = "capture/materialization_storage.rs"]
mod materialization_storage;
