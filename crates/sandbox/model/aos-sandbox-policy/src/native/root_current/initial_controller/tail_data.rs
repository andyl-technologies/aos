//! Retains the exact Signed, Outcome and Closed expected native comparison rows.
//!
//! These are reconstructed DATA from genuine phase borrowers and the captured
//! Audit. Only the same actual second native pass can satisfy their suffixes.

mod closed;
mod outcome;
mod signed;
pub(in crate::native::root_current) use closed::RootControllerClosedSuffixDataV1;
pub(in crate::native::root_current) use outcome::RootControllerOutcomeSuffixDataV1;
pub(in crate::native::root_current) use signed::RootControllerSignedSuffixDataV1;
