//! OCI descriptor, platform, manifest, index, and image-config models.
//!
//! Each document provides a bounded `from_json` constructor and a structural
//! `validate` method. Deserialization intentionally ignores unknown
//! non-annotation fields for forward-compatible catalog projection; callers
//! handling uploaded content must retain the original body as its immutable
//! representation.

mod config;
mod descriptor;
mod manifest;

pub use config::{EmptyObject, HistoryEntry, ImageConfig, ImageRuntimeConfig, RootFs, RootFsType};
pub use descriptor::{Descriptor, Platform};
pub use manifest::{ImageIndex, ImageManifest};

use serde::Serialize;

use crate::canonical::to_canonical_json;
use crate::error::Result;

fn validate_canonical_size<T>(value: &T) -> Result<()>
where
    T: Serialize,
{
    to_canonical_json(value).map(|_| ())
}

fn validate_printable_ascii(value: &str, field: &'static str, allow_empty: bool) -> Result<()> {
    if !allow_empty && value.is_empty() {
        return Err(crate::Error::invalid(field, "value must not be empty"));
    }
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(crate::Error::invalid(
            field,
            "value must contain printable ASCII only",
        ));
    }
    Ok(())
}
