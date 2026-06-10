//! The `nix-store --export` / `--import` stream format.
//!
//! A Nix export wraps a NAR with a trailer carrying the path's identity:
//! the store path itself, its references, its deriver, and (in this
//! implementation, always empty) signatures. Strings are encoded in the
//! Nix wire convention -- a little-endian `u64` length, the raw bytes,
//! and zero padding to an 8-byte boundary.
//!
//! Two entry points are provided:
//!
//! - [`build_export`] assembles a complete export for an in-memory NAR.
//! - [`ExportTrailer`] supports streaming: write the NAR through any
//!   writer first, then append the trailer (and, via
//!   [`ExportTrailer::write_import_stream`], the framing words that
//!   `nix-store --import` expects around each path).

use std::io::Write;

use anyhow::{Context, Result};

/// Nix export magic number — `0x4558494e`, the four bytes `NIXE`.
/// Matches Nix's `exportMagic` (`src/libstore/export-import.cc`); written
/// as an 8-byte little-endian integer it lands on disk as
/// `4e 49 58 45 00 00 00 00`.
const EXPORT_MAGIC: u64 = 0x4558494e;

/// Builds a complete Nix export stream from a NAR plus its metadata.
///
/// The Nix export format is:
/// ```text
/// [NAR bytes]
/// u64: EXPORT_MAGIC (0x4558494e)
/// nix-string: store_path
/// u64: reference count
/// nix-string[]: reference paths
/// nix-string: deriver (empty string if none)
/// u64: 0 (no signatures in export format)
/// ```
///
/// Where nix-string = `u64 length + bytes + \0 padding to 8-byte boundary`.
///
/// Note that this produces a single bare export; to feed the result to
/// `nix-store --import`, use [`ExportTrailer::write_import_stream`],
/// which adds the required per-path framing words.
///
/// # Errors
///
/// Currently infallible (the output is assembled in memory); the
/// `Result` mirrors the streaming [`ExportTrailer`] API.
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

/// Writes a Nix-format string (length-prefixed, null-padded to 8-byte
/// alignment) into an in-memory buffer.
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

/// Builds a Nix export stream incrementally — writes the trailer after NAR data
/// has been streamed through a writer.
///
/// This is the streaming counterpart to [`build_export`]: stream the NAR
/// bytes through the writer yourself, then call
/// [`write_to`](Self::write_to) to append the metadata trailer. For a
/// stream destined for `nix-store --import`, use
/// [`write_import_stream`](Self::write_import_stream) instead, which
/// also emits the surrounding framing words.
pub struct ExportTrailer {
    store_path: String,
    references: Vec<String>,
    deriver: Option<String>,
}

impl ExportTrailer {
    /// Creates a trailer for the given store path, its references, and
    /// optional deriver.
    pub fn new(store_path: &str, references: Vec<String>, deriver: Option<String>) -> Self {
        Self {
            store_path: store_path.to_string(),
            references,
            deriver,
        }
    }

    /// Writes the export trailer (everything after the NAR data) to the
    /// writer: export magic, store path, references, deriver, and a zero
    /// signature count.
    ///
    /// # Errors
    ///
    /// Returns an error if any write to `w` fails.
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

    /// Writes a complete single-path `nix-store --import` stream: the
    /// path-follows marker, the NAR, this trailer, and the end marker.
    ///
    /// `nix-store --import` reads a `u64` framing word before each path
    /// (`1` = a path follows, `0` = end of stream). Omitting them makes
    /// the importer read the NAR's leading bytes as the framing word and
    /// reject the input with "doesn't look like something created by
    /// 'nix-store --export'".
    ///
    /// # Errors
    ///
    /// Returns an error if any write to `w` fails.
    pub fn write_import_stream<W: Write>(&self, w: &mut W, nar_data: &[u8]) -> Result<()> {
        // Path-follows marker.
        w.write_all(&1u64.to_le_bytes())
            .context("writing import path marker")?;
        // The NAR archive.
        w.write_all(nar_data).context("writing NAR data")?;
        // magic + path + references + deriver + signatures.
        self.write_to(w)?;
        // End-of-stream marker.
        w.write_all(&0u64.to_le_bytes())
            .context("writing import end marker")?;
        Ok(())
    }
}

/// Writes a Nix-format string (length-prefixed, null-padded) to a
/// generic writer.
fn write_nix_string_to<W: Write>(w: &mut W, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u64;

    w.write_all(&len.to_le_bytes())
        .context("writing string length")?;
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
