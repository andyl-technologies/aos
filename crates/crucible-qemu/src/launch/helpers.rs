//! Private validation and rendering helpers for launch profiles.

use crucible::ContentHash;

use super::{
    LaunchProfileError, NodeIcountShift, QemuLaunchCommandError, canonical_node_icount_shift_lines,
};

pub(super) fn validate_node_icount_shifts(
    scenario_shift: u8,
    node_shifts: &[NodeIcountShift],
) -> Result<(), LaunchProfileError> {
    canonical_node_icount_shift_lines(scenario_shift, node_shifts)?;
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
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked to four bits"),
    }
}
