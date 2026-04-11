use std::io::Write;

use anyhow::{Context, Result};

/// Nix export magic number.
const EXPORT_MAGIC: u64 = 0x4558504f52540000;

/// Build a Nix export stream from a NAR + metadata.
///
/// The Nix export format is:
/// ```text
/// [NAR bytes]
/// u64: EXPORT_MAGIC (0x4558504f52540000)
/// nix-string: store_path
/// u64: reference count
/// nix-string[]: reference paths
/// nix-string: deriver (empty string if none)
/// u64: 0 (no signatures in export format)
/// ```
///
/// Where nix-string = `u64 length + bytes + \0 padding to 8-byte boundary`.
pub fn build_export(
    nar_data: &[u8],
    store_path: &str,
    references: &[String],
    deriver: Option<&str>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(nar_data.len() + 1024);

    // NAR data
    buf.extend_from_slice(nar_data);

    // Export magic
    buf.extend_from_slice(&EXPORT_MAGIC.to_le_bytes());

    // Store path
    write_nix_string(&mut buf, store_path)?;

    // Reference count
    buf.extend_from_slice(&(references.len() as u64).to_le_bytes());

    // Reference paths
    for r in references {
        write_nix_string(&mut buf, r)?;
    }

    // Deriver (empty string if none)
    write_nix_string(&mut buf, deriver.unwrap_or(""))?;

    // No signatures
    buf.extend_from_slice(&0u64.to_le_bytes());

    Ok(buf)
}

/// Write a Nix-format string (length-prefixed, null-padded to 8-byte alignment).
fn write_nix_string(buf: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u64;

    // Length
    buf.extend_from_slice(&len.to_le_bytes());

    // Content
    buf.extend_from_slice(bytes);

    // Padding to 8-byte boundary
    let padding = (8 - (bytes.len() % 8)) % 8;
    for _ in 0..padding {
        buf.push(0);
    }

    Ok(())
}

/// Build a Nix export stream incrementally — writes the trailer after NAR data
/// has been streamed through a writer.
pub struct ExportTrailer {
    store_path: String,
    references: Vec<String>,
    deriver: Option<String>,
}

impl ExportTrailer {
    pub fn new(store_path: &str, references: Vec<String>, deriver: Option<String>) -> Self {
        Self {
            store_path: store_path.to_string(),
            references,
            deriver,
        }
    }

    /// Write the export trailer (everything after the NAR data) to the writer.
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        // Export magic
        w.write_all(&EXPORT_MAGIC.to_le_bytes())
            .context("writing export magic")?;

        // Store path
        write_nix_string_to(w, &self.store_path)?;

        // Reference count
        w.write_all(&(self.references.len() as u64).to_le_bytes())
            .context("writing reference count")?;

        // Reference paths
        for r in &self.references {
            write_nix_string_to(w, r)?;
        }

        // Deriver
        write_nix_string_to(w, self.deriver.as_deref().unwrap_or(""))?;

        // No signatures
        w.write_all(&0u64.to_le_bytes())
            .context("writing signature count")?;

        Ok(())
    }
}

/// Write a Nix-format string to a generic writer.
fn write_nix_string_to<W: Write>(w: &mut W, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u64;

    w.write_all(&len.to_le_bytes()).context("writing string length")?;
    w.write_all(bytes).context("writing string content")?;

    let padding = (8 - (bytes.len() % 8)) % 8;
    let zeros = [0u8; 8];
    w.write_all(&zeros[..padding]).context("writing padding")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_has_magic() {
        let export = build_export(
            b"nar-data-here",
            "/nix/store/abc123-hello",
            &["/nix/store/def456-glibc".to_string()],
            Some("/nix/store/ghi789-hello.drv"),
        )
        .unwrap();

        let nar_len = b"nar-data-here".len();
        let magic_bytes = &export[nar_len..nar_len + 8];
        let magic = u64::from_le_bytes(magic_bytes.try_into().unwrap());
        assert_eq!(magic, EXPORT_MAGIC);
    }

    #[test]
    fn nix_string_padding() {
        let mut buf = Vec::new();
        write_nix_string(&mut buf, "hello").unwrap();
        // len(8) + "hello"(5) + padding(3) = 16
        assert_eq!(buf.len(), 16);
        assert_eq!(&buf[0..8], &5u64.to_le_bytes());
        assert_eq!(&buf[8..13], b"hello");
        assert_eq!(&buf[13..16], &[0, 0, 0]);
    }

    #[test]
    fn nix_string_aligned() {
        let mut buf = Vec::new();
        write_nix_string(&mut buf, "hi there").unwrap(); // 8 bytes, already aligned
        // len(8) + "hi there"(8) + padding(0) = 16
        assert_eq!(buf.len(), 16);
    }
}
