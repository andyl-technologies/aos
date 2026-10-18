//! Bounded extraction of identity payloads from image-owned PE files.
//!
//! The COFF section table describes virtual lengths, padded file lengths and
//! offsets. Binary extraction preserves payload bytes; boot identity text adds
//! required-section, size, UTF-8 and NUL checks without reading the whole UKI.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Limits a boot identity text section to 64 KiB before trimming NUL padding.
pub const MAX_IDENTITY_TEXT_BYTES: u64 = 64 * 1024;

/// Locates a section payload without its file-alignment padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionRange {
    /// Byte offset of the payload in the PE file.
    pub offset: u64,
    /// Number of payload bytes represented in the file.
    pub length: u64,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Finds one named PE section using bounded header reads.
///
/// Names omit the leading dot. An absent section returns `None`; a present
/// empty section remains distinguishable from an absent one.
///
/// # Errors
/// Returns an error for malformed or truncated headers, duplicate selected
/// sections, out-of-file raw ranges, or failed reads and seeks.
pub fn section_range<R: Read + Seek>(
    input: &mut R,
    name: &str,
) -> io::Result<Option<SectionRange>> {
    let image_length = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;
    let mut dos = [0_u8; 64];
    input.read_exact(&mut dos)?;
    if &dos[..2] != b"MZ" {
        return Err(invalid("PE section input has no DOS header"));
    }

    let pe_offset =
        u64::from(u32::from_le_bytes(dos[60..64].try_into().map_err(
            |error: std::array::TryFromSliceError| invalid(error.to_string()),
        )?));
    input.seek(SeekFrom::Start(pe_offset))?;
    let mut coff = [0_u8; 24];
    input.read_exact(&mut coff)?;
    if &coff[..4] != b"PE\0\0" {
        return Err(invalid("PE section input has no COFF header"));
    }

    let count = u64::from(u16::from_le_bytes([coff[6], coff[7]]));
    let optional_length = u64::from(u16::from_le_bytes([coff[20], coff[21]]));
    let table_offset = pe_offset + 24 + optional_length;
    let table_end = table_offset + count * 40;
    if table_end > image_length {
        return Err(invalid("PE section table extends beyond its input file"));
    }

    let expected_name = format!(".{name}");
    let mut selected = None;
    input.seek(SeekFrom::Start(table_offset))?;
    for _ in 0..count {
        let mut header = [0_u8; 40];
        input.read_exact(&mut header)?;
        let section_name = header[..8].split(|byte| *byte == 0).next();
        if section_name != Some(expected_name.as_bytes()) {
            continue;
        }
        if selected.is_some() {
            return Err(invalid(format!(
                "PE section input repeats section {expected_name}"
            )));
        }

        let virtual_length =
            u64::from(u32::from_le_bytes(header[8..12].try_into().map_err(
                |error: std::array::TryFromSliceError| invalid(error.to_string()),
            )?));
        let raw_length =
            u64::from(u32::from_le_bytes(header[16..20].try_into().map_err(
                |error: std::array::TryFromSliceError| invalid(error.to_string()),
            )?));
        let offset =
            u64::from(u32::from_le_bytes(header[20..24].try_into().map_err(
                |error: std::array::TryFromSliceError| invalid(error.to_string()),
            )?));
        if offset + raw_length > image_length || (raw_length != 0 && offset < table_end) {
            return Err(invalid(format!(
                "PE section {expected_name} has an invalid file range"
            )));
        }

        let length = if virtual_length == 0 {
            raw_length
        } else {
            virtual_length.min(raw_length)
        };
        selected = Some(SectionRange { offset, length });
    }
    Ok(selected)
}

/// Copies a PE payload to a new file, preserving binary bytes.
///
/// Missing optional sections produce an empty file. Existing outputs are never
/// overwritten, and extraction allocates no buffer proportional to image size.
///
/// # Errors
/// Returns an error for non-regular input, invalid PE sections, inaccessible
/// files, an existing output, or input truncated during copying.
pub fn copy_section(image: &Path, name: &str, output: &Path) -> io::Result<()> {
    let mut input = open_regular(image)?;
    let range = section_range(&mut input, name)?;
    let mut extracted = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    if let Some(range) = range {
        input.seek(SeekFrom::Start(range.offset))?;
        let copied = io::copy(&mut input.take(range.length), &mut extracted)?;
        if copied != range.length {
            return Err(invalid("PE section input changed during extraction"));
        }
    }
    Ok(())
}

fn open_regular(path: &Path) -> io::Result<File> {
    let input = File::open(path)?;
    if !input.metadata()?.file_type().is_file() {
        return Err(invalid("PE section input changed to a non-regular file"));
    }
    Ok(input)
}

/// Reads one required `cmdline` or `osrel` boot identity section.
///
/// Only trailing NUL padding is removed. The result otherwise preserves exact
/// UTF-8 bytes, including whitespace, for the caller's authenticated comparison.
/// This extracts bytes; it does not authenticate the image or authorize boot.
///
/// # Errors
/// Returns an error for another section name, missing or empty sections,
/// payloads over 64 KiB, invalid UTF-8, interior NULs, or malformed PE input.
pub fn read_uki_text(image: &Path, section: &str) -> io::Result<String> {
    if !matches!(section, "cmdline" | "osrel") {
        return Err(invalid("boot identity section must be cmdline or osrel"));
    }
    if !fs::symlink_metadata(image)?.file_type().is_file() {
        return Err(invalid("UKI identity input is not a regular file"));
    }
    let mut input = open_regular(image)?;
    let range = section_range(&mut input, section)?
        .ok_or_else(|| invalid(format!("required UKI section .{section} is missing")))?;
    if range.length == 0 || range.length > MAX_IDENTITY_TEXT_BYTES {
        return Err(invalid("UKI identity section is empty or exceeds 64 KiB"));
    }

    input.seek(SeekFrom::Start(range.offset))?;
    let mut bytes = vec![0_u8; range.length as usize];
    input.read_exact(&mut bytes)?;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(invalid(
            "UKI identity section is empty or contains an interior NUL",
        ));
    }
    String::from_utf8(bytes).map_err(|error| invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn image(machine: u16, names: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&machine.to_le_bytes());
        bytes[70..72].copy_from_slice(&(names.len() as u16).to_le_bytes());
        for (index, name) in names.iter().enumerate() {
            let offset = 88 + index * 40;
            bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
            bytes[offset + 8..offset + 12].copy_from_slice(&4_u32.to_le_bytes());
            bytes[offset + 16..offset + 20].copy_from_slice(&8_u32.to_le_bytes());
            bytes[offset + 20..offset + 24].copy_from_slice(&256_u32.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn both_efi_architectures_preserve_virtual_payload_length() {
        for machine in [0x8664, 0xaa64] {
            let mut input = Cursor::new(image(machine, &[".cmdline"]));
            assert_eq!(
                section_range(&mut input, "cmdline").unwrap(),
                Some(SectionRange {
                    offset: 256,
                    length: 4
                })
            );
            assert_eq!(section_range(&mut input, "osrel").unwrap(), None);
        }
    }

    #[test]
    fn duplicate_selected_sections_are_rejected() {
        let mut input = Cursor::new(image(0x8664, &[".cmdline", ".cmdline"]));
        assert!(section_range(&mut input, "cmdline").is_err());
    }

    #[test]
    fn truncated_headers_and_out_of_file_ranges_are_rejected() {
        for length in [0, 63, 87, 127] {
            let mut bytes = image(0x8664, &[".cmdline"]);
            bytes.truncate(length);
            assert!(section_range(&mut Cursor::new(bytes), "cmdline").is_err());
        }
        for offset in [100_u32, 510, u32::MAX] {
            let mut bytes = image(0x8664, &[".cmdline"]);
            bytes[108..112].copy_from_slice(&offset.to_le_bytes());
            assert!(section_range(&mut Cursor::new(bytes), "cmdline").is_err());
        }
    }

    #[test]
    fn invalid_signatures_are_rejected() {
        for index in [0, 64] {
            let mut bytes = image(0x8664, &[".cmdline"]);
            bytes[index] = b'X';
            assert!(section_range(&mut Cursor::new(bytes), "cmdline").is_err());
        }
    }
}
