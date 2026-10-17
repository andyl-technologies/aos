//! Owns source-private edition-eleven historical data reconstruction.
//!
//! Borrowed plans admit the complete field and metadata roster before final
//! typed owners are copied. Actual source cuts, current registrations and native
//! admission tokens remain opaque associations; none is created by these data
//! modules. Archive-only fresh-world enrollment remains a distinct trusted
//! source-factory route rather than a portable authority constructor.
//!
//! ```text
//! ["source-private.cnp-protocol/11", typed_controller_data, capacity_records, shared_aliases]
//! ```

pub mod assigned;
pub mod assigned_restore;
pub mod envelope;
pub mod json_value;

pub(crate) mod correspondence;
mod schema;
pub(crate) mod typed;

pub mod aliases;

pub mod state;

pub mod codec;

pub mod outer;

pub mod reader;

pub mod native;

pub mod supervisor;

pub(crate) use typed::{
    Fields as OriginalOwned11Fields, invalid as original_owned11_invalid,
    plain_string as original_owned11_plain_string, unsigned as original_owned11_unsigned,
};

pub mod host_registry;

mod retained_storage;
