//! Shares canonical ordinary comparison DATA used by the actual Source owner.
//!
//! These private recipes preserve each concrete role's existing types and
//! diagnostic errors. The same bodies are used by Domain's current callers and
//! Source's ordinary path. They construct no native owner, paid role, signer,
//! journal authority or mutation exception.

mod time_floor;
mod record_helpers;
mod account_coverage;
mod native_account;
mod issuance;
mod runtime_issuance;
mod capability_record;
mod initial_issuance;
mod git_ordinary;
