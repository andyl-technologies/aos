//! Private validation and rendering helpers for launch profiles.

use crucible::ContentHash;

use super::{LaunchProfileError, QemuLaunchCommandError, canonical_node_tick_scale_lines};
use crucible::NodeId;

pub(super) fn validate_node_ids(node_ids: &[NodeId]) -> Result<(), LaunchProfileError> {
    canonical_node_tick_scale_lines(node_ids)?;
    Ok(())
}

pub(super) fn validate_launch_text(
    field: &'static str,
    value: &str,
) -> Result<(), QemuLaunchCommandError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(QemuLaunchCommandError::InvalidLaunchText { field })
    } else {
        Ok(())
    }
}

pub(super) fn validate_store_path(
    field: &'static str,
    path: &str,
) -> Result<(), QemuLaunchCommandError> {
    validate_launch_text(field, path)?;
    if path.starts_with("/nix/store/")
        && !path.contains("/../")
        && !path.ends_with("/..")
        && !path.contains("/./")
        && !path.ends_with("/.")
        && !path.contains('\\')
        && !path.contains(',')
    {
        Ok(())
    } else {
        Err(QemuLaunchCommandError::InvalidStorePath {
            field,
            path: path.to_owned(),
        })
    }
}

pub(super) fn validate_overlay_file_name(file_name: &str) -> Result<(), QemuLaunchCommandError> {
    validate_launch_text("root_overlay_file_name", file_name)?;
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains(',') {
        Err(QemuLaunchCommandError::InvalidOverlayFileName {
            file_name: file_name.to_owned(),
        })
    } else {
        Ok(())
    }
}

pub(super) fn validate_fd(field: &'static str, fd: i32) -> Result<(), QemuLaunchCommandError> {
    if fd < 0 {
        Err(QemuLaunchCommandError::InvalidFileDescriptor { field, fd })
    } else {
        Ok(())
    }
}

pub(super) fn content_hash_hex(hash: ContentHash) -> String {
    let mut hex = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        hex.push(nibble_to_hex(byte >> 4));
        hex.push(nibble_to_hex(byte & 0x0f));
    }
    hex
}

fn nibble_to_hex(nibble: u8) -> char {
    const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    char::from(LOWER_HEX_DIGITS[usize::from(nibble & 0x0f)])
}
