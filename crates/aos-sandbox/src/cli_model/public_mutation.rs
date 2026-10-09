//! Original entry paths for Protocol's exact public mutation envelopes.
//!
//! The canonical DATA codec and full method-selected protobuf validator live in
//! Protocol. Native admission retains authenticated transport and protected
//! currentness checks above these direct reexports.

pub use aos_sandbox_protocol::public_api::mutation::{
    PublicMutationRequestError, PublicMutationRequestV1,
};
