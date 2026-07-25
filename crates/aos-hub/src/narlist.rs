//! A read-only Nix Archive (NAR) lister: parse a NAR's directory tree without
//! materializing file contents.
//!
//! RFC-0004 "11-caches" NAR explorer. The cache facade already serves (and
//! streams) whole NARs; this lets the native hub render a NAR's *internal* file
//! tree — names, kinds, and sizes — for the browse UI, by walking the archive
//! and skipping over file contents rather than buffering them. It is native-only
//! (the worker serves NARs but does not parse them); the parser itself is pure.
//!
//! # NAR wire format
//!
//! A NAR is a sequence of length-prefixed byte strings. Each string is a
//! little-endian `u64` length, the bytes, then zero-padding to the next 8-byte
//! boundary. The grammar (after the `"nix-archive-1"` magic) is a *node*:
//!
//! ```text
//! node := "(" "type" kind ... ")"
//! kind := "regular" ["executable" ""] "contents" <u64 len> <bytes>
//!       | "symlink" "target" <str>
//!       | "directory" ( "entry" "(" "name" <str> "node" node ")" )*
//! ```

use anyhow::{bail, Context, Result};

/// One entry in a NAR's file tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarEntry {
    /// Path within the NAR, rooted at `""` (the archive root) — e.g. `"/bin/sh"`.
    pub path: String,
    /// `directory` | `regular` | `executable` | `symlink`.
    pub kind: &'static str,
    /// File size in bytes for a regular file; `0` for directories/symlinks.
    pub size: u64,
    /// Symlink target, when `kind == "symlink"`.
    pub target: Option<String>,
}

/// The maximum number of entries listed, so a pathological archive cannot
/// produce an unbounded result.
const MAX_ENTRIES: usize = 100_000;

/// The maximum directory nesting depth, so a crafted deeply-nested archive
/// cannot overflow the stack via recursion.
const MAX_DEPTH: usize = 256;

/// Cursor over a NAR byte buffer reading length-prefixed, 8-byte-padded strings.
struct NarReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> NarReader<'a> {
    fn read_u64(&mut self) -> Result<u64> {
        let end = self.pos.checked_add(8).context("nar: truncated length")?;
        let bytes = self
            .data
            .get(self.pos..end)
            .context("nar: truncated length")?;
        self.pos = end;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a length-prefixed string's bytes, consuming the 8-byte padding.
    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.read_u64()?).context("nar: string too large")?;
        let end = self.pos.checked_add(len).context("nar: truncated string")?;
        let bytes = self
            .data
            .get(self.pos..end)
            .context("nar: truncated string")?;
        // Advance past the bytes and the zero-padding to the next 8-byte boundary.
        let padded = len.div_ceil(8) * 8;
        self.pos = self
            .pos
            .checked_add(padded)
            .context("nar: padding overflow")?;
        if self.pos > self.data.len() {
            bail!("nar: truncated padding");
        }
        Ok(bytes)
    }

    fn read_str(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.read_bytes()?).context("nar: non-utf8 token")
    }

    /// Read a regular file's contents string, returning its length and skipping
    /// the bytes + padding (contents are never materialized).
    fn skip_contents(&mut self) -> Result<u64> {
        let len = self.read_u64()?;
        let padded = usize::try_from(len)
            .context("nar: contents too large")?
            .div_ceil(8)
            * 8;
        self.pos = self
            .pos
            .checked_add(padded)
            .context("nar: contents overflow")?;
        if self.pos > self.data.len() {
            bail!("nar: truncated contents");
        }
        Ok(len)
    }

    fn expect(&mut self, want: &str) -> Result<()> {
        let got = self.read_str()?;
        if got != want {
            bail!("nar: expected '{want}', got '{got}'");
        }
        Ok(())
    }
}

/// List the file tree of a (decompressed) NAR in archive pre-order (root first).
///
/// Returns one [`NarEntry`] per node. File contents are skipped, so memory use
/// is bounded by the tree shape, not the data size.
///
/// # Errors
///
/// Returns an error for a malformed/truncated NAR, a bad magic, a non-UTF-8
/// path, directory nesting deeper than [`MAX_DEPTH`], or more than
/// [`MAX_ENTRIES`] entries.
pub fn list_nar(data: &[u8]) -> Result<Vec<NarEntry>> {
    let mut r = NarReader { data, pos: 0 };
    r.expect("nix-archive-1")?;
    let mut entries = Vec::new();
    parse_node(&mut r, String::new(), &mut entries, 0)?;
    Ok(entries)
}

/// Parse one node at `path`, appending it (and its descendants) to `entries`.
fn parse_node(
    r: &mut NarReader,
    path: String,
    entries: &mut Vec<NarEntry>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("nar: directory nesting too deep (>{MAX_DEPTH})");
    }
    if entries.len() >= MAX_ENTRIES {
        bail!("nar: too many entries (>{MAX_ENTRIES})");
    }
    r.expect("(")?;
    r.expect("type")?;
    match r.read_str()? {
        "regular" => {
            let mut tag = r.read_str()?;
            let executable = tag == "executable";
            if executable {
                r.expect("")?; // the executable marker carries an empty value
                tag = r.read_str()?;
            }
            if tag != "contents" {
                bail!("nar: regular file missing contents, got '{tag}'");
            }
            let size = r.skip_contents()?;
            entries.push(NarEntry {
                path,
                kind: if executable { "executable" } else { "regular" },
                size,
                target: None,
            });
            r.expect(")")?;
        }
        "symlink" => {
            r.expect("target")?;
            let target = r.read_str()?.to_string();
            entries.push(NarEntry {
                path,
                kind: "symlink",
                size: 0,
                target: Some(target),
            });
            r.expect(")")?;
        }
        "directory" => {
            entries.push(NarEntry {
                path: if path.is_empty() {
                    "/".to_string()
                } else {
                    path.clone()
                },
                kind: "directory",
                size: 0,
                target: None,
            });
            // Zero or more `entry ( name <name> node <node> )`, then `)`.
            loop {
                match r.read_str()? {
                    ")" => break,
                    "entry" => {
                        r.expect("(")?;
                        r.expect("name")?;
                        let name = r.read_str()?.to_string();
                        r.expect("node")?;
                        parse_node(r, format!("{path}/{name}"), entries, depth + 1)?;
                        r.expect(")")?;
                    }
                    other => bail!("nar: expected 'entry' or ')', got '{other}'"),
                }
            }
        }
        other => bail!("nar: unknown node type '{other}'"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a NAR length-prefixed, 8-byte-padded string.
    fn put(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
        let pad = (8 - (s.len() % 8)) % 8;
        out.extend(std::iter::repeat_n(0u8, pad));
    }

    #[test]
    fn lists_a_directory_with_a_file_and_symlink() {
        // directory { "hi" = regular("ab"), "ln" = symlink("hi") }
        let mut nar = Vec::new();
        put(&mut nar, b"nix-archive-1");
        put(&mut nar, b"(");
        put(&mut nar, b"type");
        put(&mut nar, b"directory");
        put(&mut nar, b"entry");
        put(&mut nar, b"(");
        put(&mut nar, b"name");
        put(&mut nar, b"hi");
        put(&mut nar, b"node");
        put(&mut nar, b"(");
        put(&mut nar, b"type");
        put(&mut nar, b"regular");
        put(&mut nar, b"contents");
        put(&mut nar, b"ab");
        put(&mut nar, b")");
        put(&mut nar, b")");
        put(&mut nar, b"entry");
        put(&mut nar, b"(");
        put(&mut nar, b"name");
        put(&mut nar, b"ln");
        put(&mut nar, b"node");
        put(&mut nar, b"(");
        put(&mut nar, b"type");
        put(&mut nar, b"symlink");
        put(&mut nar, b"target");
        put(&mut nar, b"hi");
        put(&mut nar, b")");
        put(&mut nar, b")");
        put(&mut nar, b")");

        let entries = list_nar(&nar).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "/");
        assert_eq!(entries[0].kind, "directory");
        assert_eq!(entries[1].path, "/hi");
        assert_eq!(entries[1].kind, "regular");
        assert_eq!(entries[1].size, 2);
        assert_eq!(entries[2].path, "/ln");
        assert_eq!(entries[2].kind, "symlink");
        assert_eq!(entries[2].target.as_deref(), Some("hi"));
    }

    #[test]
    fn single_executable_file_root() {
        let mut nar = Vec::new();
        put(&mut nar, b"nix-archive-1");
        put(&mut nar, b"(");
        put(&mut nar, b"type");
        put(&mut nar, b"regular");
        put(&mut nar, b"executable");
        put(&mut nar, b"");
        put(&mut nar, b"contents");
        put(&mut nar, b"#!/bin/sh\n");
        put(&mut nar, b")");
        let entries = list_nar(&nar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "executable");
        assert_eq!(entries[0].size, 10);
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert!(list_nar(b"not a nar").is_err());
        let mut nar = Vec::new();
        put(&mut nar, b"nix-archive-1");
        put(&mut nar, b"(");
        // truncated mid-node
        assert!(list_nar(&nar).is_err());
    }
}
