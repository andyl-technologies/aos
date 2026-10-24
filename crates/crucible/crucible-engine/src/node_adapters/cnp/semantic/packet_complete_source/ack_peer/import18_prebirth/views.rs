//! Adapts the ordinary prebirth constructor to the shared pure data serializers.
//!
//! No Source/ack-peer internals become public through these type aliases.

pub(super) use crate::node_adapters::cnp::source_birth_derivation::views::{
    RegistrationView, SourceBirthView,
};

#[cfg(test)]
#[path = "views/tests.rs"]
mod tests;
