//! Shared bounded PE extraction for finalized image payloads.

use std::path::Path;

use anyhow::{Context as _, Result};

/// Copies an optional PE payload to a new private file without trimming bytes.
pub(crate) fn extract_section(image: &Path, name: &str, output: &Path) -> Result<()> {
    aos_boot_identity::pe::copy_section(image, name, output)
        .context("extracting image-owned PE section")
}
