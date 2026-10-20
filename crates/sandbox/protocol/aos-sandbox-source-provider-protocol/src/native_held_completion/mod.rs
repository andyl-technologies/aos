//! Closed, nonauthorizing native held-completion control and journal data.
//!
//! These formats correlate one original Root -> Provider -> Storage flight.
//! They contain no descriptor, clock, journal guard, signing owner, or permission
//! to dispatch. Actual owners must independently authenticate their peers and
//! signer provenance, retain the original writer cut, and validate their concrete
//! canonical records before committing a transition. In particular, settlement
//! does not establish manager custody or revive an original flight after restart.
//!
//! ```text
//! AOSNHC01 | version:u16be=1 | kind:u8 | sender:u8 | payload_length:u32be |
//! reserved[8] | common[272] | closed_sections | existing_role_signer | signature[64]
//! AOSNHS01 | version:u16be=1 | owner:u8 | phase:u8 | flags:u16be=0 |
//! reserved:u16be=0 | flight[32] | prepared_length:u32be | count:u16be |
//! reserved:u16be=0 | prepared | (kind:u8 | reserved[3] | length:u32be | control)*
//! ```
//!
//! [`frame`] validates the closed kind/section graph. [`assertion`] separates
//! stable unsigned disposition and settlement identities from signed archives.
//! [`recovery`] owns bounded zero-descriptor historical claims. [`suffix`] owns
//! append-once archive structure; concrete owner reducers remain in their actual
//! record-owner crates. Diagnostic sequences and byte witnesses are not authority.

pub mod assertion;
mod codec;
pub mod frame;
mod kind;
pub mod recovery;
mod scope;
mod selected_execution;
pub mod suffix;
pub mod witness;

pub use kind::{NativeHeldControlKindV1, NativeHeldOwnerV1, NativeHeldSectionTagV1};
pub use scope::{NativeHeldScopeV1, native_held_flight_digest_v1};
pub use selected_execution::{
    SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1, SourceSelectedNativeExecutionInputDataV1,
    SourceSelectedNativeExecutionInputFieldsV1,
};

/// Bounds one complete signed control, including nested copies and signature.
pub const MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1: usize = 8_192;

/// Bounds the complete unsigned prepared control, including its fixed signer.
pub const MAXIMUM_NATIVE_HELD_PREPARED_BYTES_V1: usize = 8_192;

/// Bounds append-once top-level controls in any owner's native suffix.
pub const MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1: usize = 12;

/// Bounds one native suffix, including the prepared control and every archive.
pub const MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1: usize = 56
    + MAXIMUM_NATIVE_HELD_PREPARED_BYTES_V1
    + MAXIMUM_NATIVE_HELD_RETAINED_CONTROLS_V1 * (8 + MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1);

const _: () = assert!(MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1 == 106_648);

/// Reports malformed or inconsistent nonauthorizing native completion data.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeHeldCompletionErrorV1 {
    /// A canonical byte, field, closed graph, or original-scope invariant failed.
    #[error("invalid native held-completion data: {0}")]
    Invalid(&'static str),
    /// A hard format or finite-nesting ceiling was exceeded.
    #[error("native held-completion limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A signature does not match the independently supplied signer and key.
    #[error("native held-completion signature mismatch")]
    Signature,
}

/// Returns pure format validation without granting an owner or effect permit.
pub type Result<T> = std::result::Result<T, NativeHeldCompletionErrorV1>;

#[cfg(test)]
mod tests;
