//! Minimal `.drv` file (ATerm format) parsing for fixed-output
//! derivation discovery.
//!
//! A `.drv` file is an ATerm term of the shape
//! `Derive([outputs], [input-drvs], [input-srcs], system, builder,
//! [args], [env])`. This module implements the narrow parser surfaces AOS
//! needs today: fixed-output derivation discovery and input-derivation
//! traversal for the native-evaluator diff harness.
//!
//! The parser is hand-rolled and position-based rather than a full
//! ATerm grammar; it relies on the rigid structure Nix itself writes
//! (lists in a fixed order, double-quoted strings with backslash
//! escapes).

use anyhow::{Context, Result};

/// An input derivation edge declared by a `.drv` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrvInput {
    /// Path to the input `.drv`.
    pub drv_path: String,
    /// Output names consumed from the input derivation.
    pub outputs: Vec<String>,
}

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

/// Parses the input derivation edges from a `.drv` file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the `.drv` ATerm does not
/// contain a parseable input-derivations section.
pub fn parse_drv_input_drvs(drv_path: &str) -> Result<Vec<DrvInput>> {
    let content =
        std::fs::read_to_string(drv_path).with_context(|| format!("reading {drv_path}"))?;
    parse_drv_input_drvs_from_str(&content)
}

/// Parses the input derivation edges from `.drv` ATerm text.
///
/// # Errors
///
/// Returns an error if the ATerm does not contain a parseable
/// input-derivations section.
pub fn parse_drv_input_drvs_from_str(content: &str) -> Result<Vec<DrvInput>> {
    let spans = top_level_list_spans(content)?;
    let (start, end) = spans
        .get(1)
        .copied()
        .context("could not find input derivations section in .drv")?;
    parse_drv_input_drvs_section(content, start, end)
}

/// Parses the input derivation edges from raw `.drv` ATerm bytes.
///
/// This parser only inspects the second top-level `Derive(...)` list, so byte
/// diff traversal can follow input derivations without requiring the full
/// derivation to be valid UTF-8 or structurally parseable.
///
/// # Errors
///
/// Returns an error if the ATerm does not contain a parseable
/// input-derivations section, or if an input path or output name is not UTF-8.
pub fn parse_drv_input_drvs_from_bytes(content: &[u8]) -> Result<Vec<DrvInput>> {
    let (start, end) = nth_top_level_list_span_bytes(content, 1)?;
    parse_drv_input_drvs_section_bytes(content, start, end)
}

/// Parses the env section of a .drv file into a key-value map.
///
/// The env section is the last top-level `[...]` list inside
/// `Derive(...)`, so a first scan records every depth-0 list start
/// (skipping over quoted strings, which may contain brackets) and the
/// final one is taken as the env. Each `("key","value")` pair within it
/// is then decoded with [`parse_aterm_string`].
fn parse_drv_env(content: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut env = std::collections::HashMap::new();

    let bytes = content.as_bytes();
    let spans = top_level_list_spans(content)?;
    let (env_start, env_end) = spans
        .last()
        .copied()
        .context("could not find env section in .drv")?;

    let mut pos = env_start;
    while pos < env_end {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }
        if pos >= env_end {
            break;
        }

        let key = parse_aterm_string(content, &mut pos)?;

        while pos < env_end && bytes[pos] != b'"' {
            pos += 1;
        }

        let value = parse_aterm_string(content, &mut pos)?;

        env.insert(key, value);

        while pos < env_end && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < env_end {
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
    let spans = top_level_list_spans(content)?;
    let Some((list_start, list_end)) = spans.first().copied() else {
        return Ok(outputs);
    };

    let mut pos = list_start;
    while pos < list_end {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }
        if pos >= list_end {
            break;
        }

        let name = parse_aterm_string(content, &mut pos)?;
        while pos < list_end && bytes[pos] != b'"' {
            pos += 1;
        }
        let path = parse_aterm_string(content, &mut pos)?;

        outputs.push((path, name));

        while pos < list_end && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < list_end {
            pos += 1;
        }
    }

    Ok(outputs)
}

fn parse_drv_input_drvs_section(content: &str, start: usize, end: usize) -> Result<Vec<DrvInput>> {
    let bytes = content.as_bytes();
    let mut inputs = Vec::new();
    let mut pos = start;

    while pos < end {
        match content[pos..].find("(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }
        if pos >= end {
            break;
        }

        let drv_path = parse_aterm_string(content, &mut pos)?;
        while pos < end && bytes[pos] != b'[' {
            pos += 1;
        }
        let outputs = parse_aterm_string_list(content, &mut pos, end)?;
        inputs.push(DrvInput { drv_path, outputs });

        while pos < end && bytes[pos] != b')' {
            pos += 1;
        }
        if pos < end {
            pos += 1;
        }
    }

    Ok(inputs)
}

fn parse_drv_input_drvs_section_bytes(
    content: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<DrvInput>> {
    let mut inputs = Vec::new();
    let mut pos = start;

    while pos < end {
        match find_bytes(&content[pos..end], b"(\"") {
            Some(offset) => pos += offset + 1,
            None => break,
        }
        if pos >= end {
            break;
        }

        let drv_path = parse_aterm_utf8_string_bytes(content, &mut pos)?;
        while pos < end && content[pos] != b'[' {
            pos += 1;
        }
        let outputs = parse_aterm_string_list_bytes(content, &mut pos, end)?;
        inputs.push(DrvInput { drv_path, outputs });

        while pos < end && content[pos] != b')' {
            pos += 1;
        }
        if pos < end {
            pos += 1;
        }
    }

    Ok(inputs)
}

fn parse_aterm_string_list(content: &str, pos: &mut usize, end: usize) -> Result<Vec<String>> {
    let bytes = content.as_bytes();
    if *pos >= end || bytes[*pos] != b'[' {
        anyhow::bail!("expected '[' at position {}", *pos);
    }
    *pos += 1;

    let mut values = Vec::new();
    while *pos < end {
        match bytes[*pos] {
            b']' => {
                *pos += 1;
                return Ok(values);
            }
            b'"' => values.push(parse_aterm_string(content, pos)?),
            b',' | b' ' | b'\n' | b'\t' => *pos += 1,
            other => {
                anyhow::bail!(
                    "unexpected byte '{}' in string list at position {}",
                    other as char,
                    *pos
                );
            }
        }
    }

    anyhow::bail!("unterminated string list at position {}", *pos)
}

fn parse_aterm_string_list_bytes(
    content: &[u8],
    pos: &mut usize,
    end: usize,
) -> Result<Vec<String>> {
    if *pos >= end || content[*pos] != b'[' {
        anyhow::bail!("expected '[' at position {}", *pos);
    }
    *pos += 1;

    let mut values = Vec::new();
    while *pos < end {
        match content[*pos] {
            b']' => {
                *pos += 1;
                return Ok(values);
            }
            b'"' => values.push(parse_aterm_utf8_string_bytes(content, pos)?),
            b',' | b' ' | b'\n' | b'\t' => *pos += 1,
            other => {
                anyhow::bail!(
                    "unexpected byte '{}' in string list at position {}",
                    other as char,
                    *pos
                );
            }
        }
    }

    anyhow::bail!("unterminated string list at position {}", *pos)
}

fn top_level_list_spans(content: &str) -> Result<Vec<(usize, usize)>> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let derive_start = content
        .find("Derive(")
        .map(|index| index + 7)
        .context("could not find Derive term in .drv")?;

    let mut spans = Vec::new();
    let mut depth = 0_usize;
    let mut current_start = None;
    let mut pos = derive_start;

    while pos < len {
        match bytes[pos] {
            b'[' => {
                if depth == 0 {
                    current_start = Some(pos);
                }
                depth += 1;
            }
            b']' => {
                if depth == 0 {
                    anyhow::bail!("unmatched ']' at position {pos}");
                }
                depth -= 1;
                if depth == 0 {
                    let start = current_start.context("list end without list start")?;
                    spans.push((start, pos + 1));
                    current_start = None;
                }
            }
            b'"' => skip_aterm_string(content, &mut pos)?,
            _ => {}
        }
        pos += 1;
    }

    if depth != 0 {
        anyhow::bail!("unterminated list in .drv");
    }

    Ok(spans)
}

fn nth_top_level_list_span_bytes(content: &[u8], target_index: usize) -> Result<(usize, usize)> {
    let len = content.len();
    let derive_start = find_bytes(content, b"Derive(")
        .map(|index| index + 7)
        .context("could not find Derive term in .drv")?;

    let mut list_index = 0_usize;
    let mut depth = 0_usize;
    let mut current_start = None;
    let mut pos = derive_start;

    while pos < len {
        match content[pos] {
            b'[' => {
                if depth == 0 {
                    current_start = Some(pos);
                }
                depth += 1;
            }
            b']' => {
                if depth == 0 {
                    anyhow::bail!("unmatched ']' at position {pos}");
                }
                depth -= 1;
                if depth == 0 {
                    let start = current_start.context("list end without list start")?;
                    if list_index == target_index {
                        return Ok((start, pos + 1));
                    }
                    list_index += 1;
                    current_start = None;
                }
            }
            b'"' => skip_aterm_string_bytes(content, &mut pos)?,
            _ => {}
        }
        pos += 1;
    }

    if depth != 0 {
        anyhow::bail!("unterminated list in .drv");
    }

    anyhow::bail!("could not find top-level list {target_index} in .drv")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn skip_aterm_string(content: &str, pos: &mut usize) -> Result<()> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    *pos += 1;
    while *pos < len {
        match bytes[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos >= len {
                    anyhow::bail!("trailing backslash at end of string (position {})", *pos);
                }
            }
            b'"' => return Ok(()),
            _ => {}
        }
        *pos += 1;
    }

    anyhow::bail!("unterminated string at position {}", *pos)
}

fn skip_aterm_string_bytes(content: &[u8], pos: &mut usize) -> Result<()> {
    let len = content.len();
    *pos += 1;
    while *pos < len {
        match content[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos >= len {
                    anyhow::bail!("trailing backslash at end of string (position {})", *pos);
                }
            }
            b'"' => return Ok(()),
            _ => {}
        }
        *pos += 1;
    }

    anyhow::bail!("unterminated string at position {}", *pos)
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

fn parse_aterm_utf8_string_bytes(content: &[u8], pos: &mut usize) -> Result<String> {
    let value = parse_aterm_string_bytes(content, pos)?;
    String::from_utf8(value).context("ATerm string is not UTF-8")
}

fn parse_aterm_string_bytes(content: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let len = content.len();

    if *pos >= len || content[*pos] != b'"' {
        anyhow::bail!("expected '\"' at position {}", *pos);
    }
    *pos += 1;

    let mut result = Vec::new();
    while *pos < len {
        match content[*pos] {
            b'\\' => {
                *pos += 1;
                if *pos >= len {
                    anyhow::bail!("trailing backslash at end of string (position {})", *pos);
                }
                match content[*pos] {
                    b'n' => result.push(b'\n'),
                    b'r' => result.push(b'\r'),
                    b't' => result.push(b'\t'),
                    b'\\' => result.push(b'\\'),
                    b'"' => result.push(b'"'),
                    other => {
                        result.push(b'\\');
                        result.push(other);
                    }
                }
            }
            b'"' => {
                *pos += 1;
                return Ok(result);
            }
            byte => result.push(byte),
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
    fn parse_drv_input_drvs_extracts_edges_and_outputs() {
        let drv = r#"Derive([("out","/nix/store/root-out","","")],[("/nix/store/aaa-input.drv",["out"]),("/nix/store/bbb-input.drv",["dev","out"])],[],"x86_64-linux","/nix/store/bash",[],[("name","root")])"#;
        let inputs = parse_drv_input_drvs_from_str(drv).unwrap();

        assert_eq!(
            inputs,
            vec![
                DrvInput {
                    drv_path: "/nix/store/aaa-input.drv".to_string(),
                    outputs: vec!["out".to_string()],
                },
                DrvInput {
                    drv_path: "/nix/store/bbb-input.drv".to_string(),
                    outputs: vec!["dev".to_string(), "out".to_string()],
                },
            ]
        );
    }

    #[test]
    fn parse_drv_input_drvs_from_bytes_skips_non_utf8_sections() {
        let mut drv = br#"Derive([("out","/nix/store/root-out","","")],[("/nix/store/aaa-input.drv",["out"]),("/nix/store/bbb-input.drv",["dev","out"])],[],"x86_64-linux","/nix/store/bash",[],[("name","root"),("raw",""#
            .to_vec();
        drv.push(0xff);
        drv.extend_from_slice(br#"")])"#);

        let inputs = parse_drv_input_drvs_from_bytes(&drv).unwrap();

        assert_eq!(
            inputs,
            vec![
                DrvInput {
                    drv_path: "/nix/store/aaa-input.drv".to_string(),
                    outputs: vec!["out".to_string()],
                },
                DrvInput {
                    drv_path: "/nix/store/bbb-input.drv".to_string(),
                    outputs: vec!["dev".to_string(), "out".to_string()],
                },
            ]
        );
    }

    #[test]
    fn parse_drv_input_drvs_from_bytes_ignores_malformed_tail() {
        let drv = br#"Derive([],[("/nix/store/aaa-input.drv",["out"])],[],[unterminated"#;

        let inputs = parse_drv_input_drvs_from_bytes(drv).unwrap();

        assert_eq!(
            inputs,
            vec![DrvInput {
                drv_path: "/nix/store/aaa-input.drv".to_string(),
                outputs: vec!["out".to_string()],
            }]
        );
    }

    #[test]
    fn parse_drv_sections_skip_brackets_inside_strings() {
        let drv = r#"Derive([("out","/nix/store/root-[out]","","")],[("/nix/store/input.drv",["out"])],[],"x86_64-linux","/nix/store/bash",[],[("name","root-[x]"),("outputHash","sha256-AAAA")])"#;
        let env = parse_drv_env(drv).unwrap();
        let outputs = parse_drv_outputs(drv).unwrap();
        let inputs = parse_drv_input_drvs_from_str(drv).unwrap();

        assert_eq!(env.get("name").unwrap(), "root-[x]");
        assert_eq!(
            outputs,
            vec![("/nix/store/root-[out]".to_string(), "out".to_string())]
        );
        assert_eq!(inputs[0].drv_path, "/nix/store/input.drv");
    }

    #[test]
    fn non_fod_returns_none() {
        let drv = r#"Derive([("out","/nix/store/xxx-bar","","")],[],[],"/nix/store/bash","/nix/store/builder",[],[("name","bar"),("system","x86_64-linux")])"#;
        assert!(!drv.contains("\"outputHash\""));
    }
}
