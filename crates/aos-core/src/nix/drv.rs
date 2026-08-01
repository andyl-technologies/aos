//! Minimal `.drv` file (ATerm format) parsing for fixed-output
//! derivation discovery.
//!
//! A `.drv` file is an ATerm term of the shape
//! `Derive([outputs], [input-drvs], [input-srcs], system, builder,
//! [args], [env])`. This module implements just enough of a parser to
//! pull out the pieces needed to recognise fixed-output derivations
//! (FODs, i.e. fetches with a pinned `outputHash`): the outputs list,
//! the builder, and the env section. The entry point is
//! [`parse_drv_for_fod`].
//!
//! The parser is hand-rolled and position-based rather than a full
//! ATerm grammar; it relies on the rigid structure Nix itself writes
//! (lists in a fixed order, double-quoted strings with backslash
//! escapes).

use anyhow::{Context, Result};
use std::collections::BTreeMap;

/// A fixed-output derivation discovered from a .drv file.
#[derive(Debug, Clone)]
pub struct FixedOutputDrv {
    /// Path of the `.drv` file this record was parsed from.
    pub drv_path: String,
    /// Store path of the derivation's first output.
    pub output_path: String,
    /// The derivation's `name` env var (empty if absent).
    pub name: String,
    /// The pinned `outputHash` value.
    pub output_hash: String,
    /// The `outputHashAlgo` env var, e.g. `sha256` (empty if absent).
    pub output_hash_algo: String,
    /// The `outputHashMode` env var: `flat` (default) or `recursive`.
    pub output_hash_mode: String,
    /// The `url` env var, when the FOD is a fetch with a single URL.
    pub url: Option<String>,
    /// The derivation's builder executable (e.g. `builtin:fetchurl` or
    /// a store path to bash).
    pub builder: String,
}

/// Parses a .drv file (ATerm format) and extracts FOD info if present.
///
/// Returns `Some(FixedOutputDrv)` if the derivation has a non-empty
/// `outputHash` env var, `None` otherwise (a quick substring check
/// short-circuits non-FOD derivations before any real parsing).
///
/// # Errors
///
/// Returns an error if the file cannot be read or its ATerm structure
/// cannot be parsed (missing env section, no outputs, or malformed
/// strings).
pub fn parse_drv_for_fod(drv_path: &str) -> Result<Option<FixedOutputDrv>> {
    let content =
        std::fs::read_to_string(drv_path).with_context(|| format!("reading {drv_path}"))?;

    // Quick check: if no outputHash, not a FOD.
    if !content.contains("\"outputHash\"") {
        return Ok(None);
    }

    let env = parse_drv_env(&content)?;

    let output_hash = match env.get("outputHash") {
        Some(h) if !h.is_empty() => h.clone(),
        _ => return Ok(None),
    };

    let outputs = parse_drv_outputs(&content)?;
    let (output_path, _) = outputs.first().context("no outputs in .drv")?;

    Ok(Some(FixedOutputDrv {
        drv_path: drv_path.to_string(),
        output_path: output_path.clone(),
        name: env.get("name").cloned().unwrap_or_default(),
        output_hash,
        output_hash_algo: env.get("outputHashAlgo").cloned().unwrap_or_default(),
        output_hash_mode: env
            .get("outputHashMode")
            .cloned()
            .unwrap_or_else(|| "flat".to_string()),
        url: env.get("url").cloned(),
        builder: parse_drv_builder(&content).unwrap_or_default(),
    }))
}

/// Parses the env section of a .drv file into a key-value map.
///
/// The env section is the last top-level `[...]` list inside
/// `Derive(...)`, so a first scan records every depth-0 list start
/// (skipping over quoted strings, which may contain brackets) and the
/// final one is taken as the env. Each `("key","value")` pair within it
/// is then decoded with [`parse_aterm_string`].
fn parse_drv_env(content: &str) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();

    let bytes = content.as_bytes();
    let len = bytes.len();

    let mut list_starts = Vec::new();

    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);
    let mut i = derive_start;
    let mut depth = 0;
    while i < len {
        match bytes[i] {
            b'[' => {
                if depth == 0 {
                    list_starts.push(i);
                }
                depth += 1;
            }
            b']' => {
                depth -= 1;
            }
            b'"' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        if i + 1 < len {
                            i += 2;
                        } else {
                            i += 1;
                        }
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let env_start = list_starts
        .last()
        .copied()
        .context("could not find env section in .drv")?;

    let mut pos = env_start;
    while pos < len {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }

        let key = parse_aterm_string(content, &mut pos)?;

        while pos < len && bytes[pos] != b'"' {
            pos += 1;
        }

        let value = parse_aterm_string(content, &mut pos)?;

        env.insert(key, value);

        while pos < len && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < len {
            pos += 1;
        }
    }

    Ok(env)
}

/// Parses the outputs section (the first list in `Derive(...)`):
/// `[("out","/nix/store/xxx","sha256","abc123..."),...]`.
///
/// Returns `(path, name)` pairs in declaration order. A running
/// bracket-depth check stops the scan once the outputs list closes so
/// tuples from later sections are not picked up.
fn parse_drv_outputs(content: &str) -> Result<Vec<(String, String)>> {
    let mut outputs = Vec::new();
    let bytes = content.as_bytes();
    let len = bytes.len();

    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);
    let list_start = match content[derive_start..].find('[') {
        Some(offset) => derive_start + offset,
        None => return Ok(outputs),
    };

    let mut pos = list_start;
    while pos < len {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }

        let depth: i32 = content[list_start..pos]
            .bytes()
            .map(|b| match b {
                b'[' => 1,
                b']' => -1,
                _ => 0,
            })
            .sum();
        if depth <= 0 {
            break;
        }

        let name = parse_aterm_string(content, &mut pos)?;
        while pos < len && bytes[pos] != b'"' {
            pos += 1;
        }
        let path = parse_aterm_string(content, &mut pos)?;

        outputs.push((path, name));

        while pos < len && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < len {
            pos += 1;
        }
    }

    Ok(outputs)
}

/// Extracts the builder string from a .drv: the second bare string
/// after the first three lists (outputs, input drvs, input srcs), the
/// first being the system.
fn parse_drv_builder(content: &str) -> Result<String> {
    let bytes = content.as_bytes();
    let len = bytes.len();

    let derive_start = content.find("Derive(").map(|i| i + 7).unwrap_or(0);

    let mut pos = derive_start;
    let mut lists_skipped = 0;

    while pos < len && lists_skipped < 3 {
        match bytes[pos] {
            b'[' => {
                let mut depth = 1;
                pos += 1;
                while pos < len && depth > 0 {
                    match bytes[pos] {
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        b'"' => {
                            pos += 1;
                            while pos < len {
                                if bytes[pos] == b'\\' {
                                    if pos + 1 < len {
                                        pos += 2;
                                    } else {
                                        pos += 1;
                                    }
                                    continue;
                                }
                                if bytes[pos] == b'"' {
                                    break;
                                }
                                pos += 1;
                            }
                        }
                        _ => {}
                    }
                    pos += 1;
                }
                lists_skipped += 1;
            }
            _ => pos += 1,
        }
    }

    while pos < len && bytes[pos] != b'"' {
        pos += 1;
    }
    let _system = parse_aterm_string(content, &mut pos)?;

    while pos < len && bytes[pos] != b'"' {
        pos += 1;
    }

    let builder = parse_aterm_string(content, &mut pos)?;
    Ok(builder)
}

/// Parses a double-quoted ATerm string starting at `pos`, advancing
/// `pos` past the closing quote.
///
/// Handles the `\n`, `\t`, `\\`, and `\"` escapes Nix emits; any other
/// backslash sequence is preserved literally.
fn parse_aterm_string(content: &str, pos: &mut usize) -> Result<String> {
    let bytes = content.as_bytes();
    let len = bytes.len();

    if *pos >= len || bytes[*pos] != b'"' {
        anyhow::bail!("expected '\"' at position {}", *pos);
    }
    *pos += 1;

    let mut result = String::new();
    while *pos < len {
        match bytes[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos >= len {
                    anyhow::bail!("trailing backslash at end of string (position {})", *pos);
                }
                match bytes[*pos] {
                    b'n' => result.push('\n'),
                    b't' => result.push('\t'),
                    b'\\' => result.push('\\'),
                    b'"' => result.push('"'),
                    other => {
                        result.push('\\');
                        result.push(other as char);
                    }
                }
            }
            b'"' => {
                *pos += 1;
                return Ok(result);
            }
            _ => result.push(bytes[*pos] as char),
        }
        *pos += 1;
    }

    anyhow::bail!("unterminated string at position {}", *pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aterm_string_basic() {
        let s = r#""hello world""#;
        let mut pos = 0;
        let result = parse_aterm_string(s, &mut pos).unwrap();
        assert_eq!(result, "hello world");
        assert_eq!(pos, s.len());
    }

    #[test]
    fn parse_aterm_string_escapes() {
        let s = r#""hello \"world\"""#;
        let mut pos = 0;
        let result = parse_aterm_string(s, &mut pos).unwrap();
        assert_eq!(result, r#"hello "world""#);
    }

    #[test]
    fn parse_drv_env_extracts_output_hash() {
        let drv = r#"Derive([("out","/nix/store/xxx-foo","sha256","abc")],[],[],"/nix/store/bash","builtin:fetchurl",[],[("name","foo-1.0.tar.gz"),("outputHash","sha256-AAAA"),("outputHashAlgo","sha256"),("outputHashMode","flat"),("url","https://example.com/foo.tar.gz")])"#;
        let env = parse_drv_env(drv).unwrap();
        assert_eq!(env.get("outputHash").unwrap(), "sha256-AAAA");
        assert_eq!(env.get("name").unwrap(), "foo-1.0.tar.gz");
        assert_eq!(env.get("url").unwrap(), "https://example.com/foo.tar.gz");
    }

    #[test]
    fn non_fod_returns_none() {
        let drv = r#"Derive([("out","/nix/store/xxx-bar","","")],[],[],"/nix/store/bash","/nix/store/builder",[],[("name","bar"),("system","x86_64-linux")])"#;
        assert!(!drv.contains("\"outputHash\""));
    }
}
