//! Bounded identities of the actual kernel and selected deployment artifacts.
//!
//! Kernel release strings do not identify a kernel build. The GNU ELF note
//! observed through sysfs must match the build ID of the booted AOS vmlinux.

use std::io::{self, Read};
use std::path::Path;

const MAX_KERNEL_NOTES_BYTES: usize = 8192;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Reads the build identity published by the running kernel.
///
/// # Errors
///
/// Returns an error for inaccessible, oversized, malformed or ambiguous notes.
pub(crate) fn kernel_build_id() -> io::Result<Vec<u8>> {
    let mut notes = Vec::new();
    std::fs::File::open("/sys/kernel/notes")?
        .take(MAX_KERNEL_NOTES_BYTES as u64 + 1)
        .read_to_end(&mut notes)?;
    decode_kernel_build_id(&notes)
}

#[cfg(test)]
pub(crate) fn artifact_hash(path: &Path) -> io::Result<blake3::Hash> {
    artifact_hash_with_boundary(path, &mut || Ok(()))
}

/// Accepts only store-owned paths whose links never traverse mutable namespaces.
///
/// # Errors
///
/// Returns an error when an otherwise store-owned path cannot be authenticated.
pub(super) fn immutable_store_artifact(path: &Path) -> io::Result<bool> {
    use std::path::Component;

    let store = Path::new("/nix/store");
    if !path.starts_with(store)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Ok(false);
    }
    for component_path in path.ancestors().take_while(|ancestor| *ancestor != store) {
        if !std::fs::canonicalize(component_path)?.starts_with(store) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Authenticates one selected build artifact while polling the original deadline.
///
/// # Errors
///
/// Returns an error for failed reads, oversized artifacts or boundary refusal.
pub(super) fn artifact_hash_with_boundary(
    path: &Path,
    boundary: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<blake3::Hash> {
    boundary()?;
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_ARTIFACT_BYTES {
        return Err(invalid("qualification artifact exceeds bound"));
    }
    let mut hasher = blake3::Hasher::new();
    let mut bytes = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        boundary()?;
        let count = file.read(&mut bytes)?;
        if count == 0 {
            return Ok(hasher.finalize());
        }
        total = total
            .checked_add(count as u64)
            .filter(|total| *total <= MAX_ARTIFACT_BYTES)
            .ok_or_else(|| invalid("qualification artifact grew beyond bound"))?;
        hasher.update(&bytes[..count]);
    }
}

fn decode_kernel_build_id(notes: &[u8]) -> io::Result<Vec<u8>> {
    if notes.len() > MAX_KERNEL_NOTES_BYTES {
        return Err(invalid("kernel notes exceed bound"));
    }
    let mut position = 0;
    let mut identity = None;
    while position < notes.len() {
        let header = field(notes, &mut position, 12)?;
        let name_length = word(&header[..4])? as usize;
        let descriptor_length = word(&header[4..8])? as usize;
        let kind = word(&header[8..])?;
        let name = note_field(notes, &mut position, name_length)?;
        let descriptor = note_field(notes, &mut position, descriptor_length)?;
        if name == b"GNU\0" && kind == 3 {
            if identity.is_some() || !(16..=64).contains(&descriptor.len()) {
                return Err(invalid("ambiguous or invalid kernel build ID"));
            }
            identity = Some(descriptor.to_vec());
        }
    }
    identity.ok_or_else(|| invalid("kernel GNU build ID is absent"))
}

fn word(bytes: &[u8]) -> io::Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| invalid("truncated ELF note word"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn note_field<'a>(notes: &'a [u8], position: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let value = field(notes, position, length)?;
    let padding = (4 - length % 4) % 4;
    field(notes, position, padding)?;
    Ok(value)
}

fn field<'a>(notes: &'a [u8], position: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = position
        .checked_add(length)
        .ok_or_else(|| invalid("ELF note length overflow"))?;
    let value = notes
        .get(*position..end)
        .ok_or_else(|| invalid("truncated ELF note"))?;
    *position = end;
    Ok(value)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[test]
fn kernel_identity_uses_the_exact_gnu_note() {
    let mut notes = vec![4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0];
    notes.extend(0_u8..20);
    assert_eq!(
        decode_kernel_build_id(&notes).unwrap_or_else(|error| panic!("GNU ELF note: {error}")),
        (0_u8..20).collect::<Vec<_>>()
    );
}

#[test]
fn kernel_identity_refuses_truncation_duplicates_and_unbounded_headers() {
    let mut notes = vec![4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0];
    notes.extend(0_u8..20);
    for length in 0..notes.len() {
        assert!(decode_kernel_build_id(&notes[..length]).is_err());
    }
    assert!(decode_kernel_build_id(&[0xff; 12]).is_err());
    assert!(decode_kernel_build_id(&vec![0; MAX_KERNEL_NOTES_BYTES + 1]).is_err());
    notes.extend(notes.clone());
    assert!(decode_kernel_build_id(&notes).is_err());
}
