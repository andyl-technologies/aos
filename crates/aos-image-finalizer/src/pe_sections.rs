//! Portable extraction of payload sections from image-owned PE files.
//!
//! The COFF section table records each section's virtual length, padded file
//! length, and file offset. Extraction omits file-alignment padding, matching
//! the payload bytes embedded by ukify on either supported EFI architecture.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// Copies one PE section's payload to a new private output file.
///
/// Missing optional sections produce an empty file.
///
/// # Errors
/// Returns an error for inaccessible files, invalid or truncated headers,
/// duplicate sections, section data outside the file, or an existing output.
pub(crate) fn extract_section(image: &Path, name: &str, output: &Path) -> Result<()> {
    let mut input = File::open(image).context("opening PE section input")?;
    let image_length = input.metadata()?.len();
    let mut dos_header = [0_u8; 64];
    input.read_exact(&mut dos_header)?;
    if &dos_header[..2] != b"MZ" {
        bail!("PE section input has no DOS header");
    }

    let pe_offset = u64::from(u32::from_le_bytes([
        dos_header[60],
        dos_header[61],
        dos_header[62],
        dos_header[63],
    ]));
    input.seek(SeekFrom::Start(pe_offset))?;
    let mut pe_header = [0_u8; 24];
    input.read_exact(&mut pe_header)?;
    if &pe_header[..4] != b"PE\0\0" {
        bail!("PE section input has no COFF header");
    }

    let section_count = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let optional_header_length = u16::from_le_bytes([pe_header[20], pe_header[21]]);
    let table_offset = pe_offset + 24 + u64::from(optional_header_length);
    let table_end = table_offset + u64::from(section_count) * 40;
    if table_end > image_length {
        bail!("PE section table extends beyond its input file");
    }

    let expected_name = format!(".{name}");
    let mut selected_range = None;
    input.seek(SeekFrom::Start(table_offset))?;
    for _ in 0..section_count {
        let mut header = [0_u8; 40];
        input.read_exact(&mut header)?;
        let section_name = header[..8].split(|byte| *byte == 0).next();
        if section_name != Some(expected_name.as_bytes()) {
            continue;
        }
        if selected_range.is_some() {
            bail!("PE section input repeats section {expected_name}");
        }

        let virtual_length = u64::from(u32::from_le_bytes([
            header[8], header[9], header[10], header[11],
        ]));
        let file_length = u64::from(u32::from_le_bytes([
            header[16], header[17], header[18], header[19],
        ]));
        let file_offset = u64::from(u32::from_le_bytes([
            header[20], header[21], header[22], header[23],
        ]));
        if file_offset + file_length > image_length {
            bail!("PE section {expected_name} extends beyond its input file");
        }

        let payload_length = if virtual_length == 0 {
            file_length
        } else {
            virtual_length.min(file_length)
        };
        selected_range = Some((file_offset, payload_length));
    }

    let mut extracted = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    if let Some((offset, length)) = selected_range {
        input.seek(SeekFrom::Start(offset))?;
        let copied = std::io::copy(&mut std::io::Read::take(&mut input, length), &mut extracted)?;
        if copied != length {
            bail!("PE section input changed during extraction");
        }
    }
    Ok(())
}
