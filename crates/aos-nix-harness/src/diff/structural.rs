//! Structural .drv parsing for the differential harness.

use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result};
use aos_nix_compat::drv::{DrvInput, parse_drv_input_drvs_from_bytes};
use nix_compat::derivation::Derivation;

use super::{DiffSide, DrvDiff, DrvDiffReport};

pub(super) fn parse_structural_pair(
    oracle_bytes: &[u8],
    candidate_bytes: &[u8],
    oracle_path: &Path,
    candidate_path: &Path,
    report: &mut DrvDiffReport,
) -> Option<(ParsedDerivation, ParsedDerivation)> {
    let oracle = parse_derivation_for_path(oracle_bytes, oracle_path).map_err(|error| {
        report.divergences.push(DrvDiff::StructuralParse {
            side: DiffSide::Oracle,
            path: oracle_path.to_path_buf(),
            error,
        });
    });
    let candidate = parse_derivation_for_path(candidate_bytes, candidate_path).map_err(|error| {
        report.divergences.push(DrvDiff::StructuralParse {
            side: DiffSide::Candidate,
            path: candidate_path.to_path_buf(),
            error,
        });
    });
    match (oracle, candidate) {
        (Ok(oracle), Ok(candidate)) => Some((oracle, candidate)),
        _ => None,
    }
}

pub(super) struct ParsedDerivation {
    derivation: Derivation,
    input_derivations: Vec<DrvInput>,
    path_sections: DerivationPathSections,
}

pub(super) const NIX_STORE_DIR: &str = "/nix/store";

fn parse_derivation_for_path(bytes: &[u8], path: &Path) -> Result<ParsedDerivation, String> {
    let store_dir = path
        .parent()
        .ok_or_else(|| format!("drv path has no store directory: {}", path.display()))?
        .to_path_buf();
    let path_sections = derivation_path_sections(bytes)?;
    let input_derivations = parse_drv_inputs_from_bytes(bytes, path, "structural")
        .map_err(|error| error.to_string())?;
    let normalized = normalize_drv_path_fields(bytes, &store_dir)?;
    let derivation = parse_derivation(&normalized)?;
    Ok(ParsedDerivation {
        derivation,
        input_derivations,
        path_sections,
    })
}

fn parse_derivation(bytes: &[u8]) -> Result<Derivation, String> {
    Derivation::from_aterm_bytes(bytes).map_err(|source| format!("{source:?}"))
}

fn normalize_drv_path_fields<'a>(
    bytes: &'a [u8],
    store_dir: &Path,
) -> Result<Cow<'a, [u8]>, String> {
    let store_dir = store_dir
        .to_str()
        .ok_or_else(|| format!("store directory is not UTF-8: {}", store_dir.display()))?;
    if store_dir.is_empty() || !store_dir.starts_with('/') {
        return Err(format!(
            "drv store directory is not absolute: {store_dir:?}"
        ));
    }
    if store_dir == NIX_STORE_DIR {
        return Ok(Cow::Borrowed(bytes));
    }
    if store_dir == "/" {
        return Err("structural drv parsing does not support / as the store directory".to_string());
    }

    rewrite_store_dir_in_path_sections(bytes, store_dir.as_bytes(), NIX_STORE_DIR.as_bytes())
}

pub(super) fn rewrite_store_dir_in_path_sections<'a>(
    bytes: &'a [u8],
    from: &[u8],
    to: &[u8],
) -> Result<Cow<'a, [u8]>, String> {
    if from.is_empty() {
        return Err("source store directory is empty".to_string());
    }
    if from == to {
        return Ok(Cow::Borrowed(bytes));
    }

    let ranges = derivation_arg_ranges(bytes)?;
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    let mut changed = false;
    for range in ranges.iter().take(3) {
        normalized.extend_from_slice(&bytes[cursor..range.start]);
        let section = rewrite_bytes(&bytes[range.clone()], from, to);
        changed |= matches!(section, Cow::Owned(_));
        normalized.extend_from_slice(&section);
        cursor = range.end;
    }

    if !changed {
        Ok(Cow::Borrowed(bytes))
    } else {
        normalized.extend_from_slice(&bytes[cursor..]);
        Ok(Cow::Owned(normalized))
    }
}

fn rewrite_bytes<'a>(bytes: &'a [u8], from: &[u8], to: &[u8]) -> Cow<'a, [u8]> {
    let mut rewritten = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(offset) = rest.windows(from.len()).position(|window| window == from) {
        rewritten.extend_from_slice(&rest[..offset]);
        rewritten.extend_from_slice(to);
        rest = &rest[offset + from.len()..];
    }
    if rewritten.is_empty() {
        Cow::Borrowed(bytes)
    } else {
        rewritten.extend_from_slice(rest);
        Cow::Owned(rewritten)
    }
}

#[derive(PartialEq, Eq)]
struct DerivationPathSections {
    outputs: Vec<u8>,
    input_derivations: Vec<u8>,
    input_sources: Vec<u8>,
}

fn derivation_path_sections(bytes: &[u8]) -> Result<DerivationPathSections, String> {
    let ranges = derivation_arg_ranges(bytes)?;
    Ok(DerivationPathSections {
        outputs: bytes[ranges[0].clone()].to_vec(),
        input_derivations: bytes[ranges[1].clone()].to_vec(),
        input_sources: bytes[ranges[2].clone()].to_vec(),
    })
}

fn derivation_arg_ranges(bytes: &[u8]) -> Result<[std::ops::Range<usize>; 7], String> {
    const PREFIX: &[u8] = b"Derive(";
    if !bytes.starts_with(PREFIX) || !bytes.ends_with(b")") {
        return Err("drv ATerm does not have the expected Derive(...) shape".to_string());
    }

    let mut ranges = Vec::with_capacity(7);
    let mut start = PREFIX.len();
    let end = bytes.len() - 1;
    let mut index = start;
    let mut square_depth = 0usize;
    let mut paren_depth = 0usize;
    while index < end {
        match bytes[index] {
            b'"' => index = skip_aterm_string(bytes, index)?,
            b'[' => square_depth += 1,
            b']' => {
                square_depth = square_depth
                    .checked_sub(1)
                    .ok_or_else(|| "drv ATerm has an unmatched ']'".to_string())?;
            }
            b'(' => paren_depth += 1,
            b')' => {
                paren_depth = paren_depth
                    .checked_sub(1)
                    .ok_or_else(|| "drv ATerm has an unmatched ')'".to_string())?;
            }
            b',' if square_depth == 0 && paren_depth == 0 => {
                ranges.push(start..index);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }

    if square_depth != 0 || paren_depth != 0 {
        return Err("drv ATerm has unbalanced delimiters".to_string());
    }
    ranges.push(start..end);
    ranges
        .try_into()
        .map_err(|ranges: Vec<std::ops::Range<usize>>| {
            format!("drv ATerm has {} fields, expected 7", ranges.len())
        })
}

fn skip_aterm_string(bytes: &[u8], quote: usize) -> Result<usize, String> {
    let mut index = quote + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index = index
                    .checked_add(1)
                    .ok_or_else(|| "drv ATerm string escape overflowed".to_string())?;
            }
            b'"' => return Ok(index),
            _ => {}
        }
        index += 1;
    }
    Err("drv ATerm has an unterminated string".to_string())
}

pub(super) fn drv_inputs_from_derivation(parsed: &ParsedDerivation) -> Vec<DrvInput> {
    parsed.input_derivations.clone()
}

pub(super) fn first_derivation_diff_field(
    oracle: &ParsedDerivation,
    candidate: &ParsedDerivation,
) -> &'static str {
    if oracle.path_sections.outputs != candidate.path_sections.outputs
        || oracle.derivation.outputs != candidate.derivation.outputs
    {
        "outputs"
    } else if oracle.path_sections.input_derivations != candidate.path_sections.input_derivations
        || oracle.derivation.input_derivations != candidate.derivation.input_derivations
    {
        "input_derivations"
    } else if oracle.path_sections.input_sources != candidate.path_sections.input_sources
        || oracle.derivation.input_sources != candidate.derivation.input_sources
    {
        "input_sources"
    } else if oracle.derivation.system != candidate.derivation.system {
        "system"
    } else if oracle.derivation.builder != candidate.derivation.builder {
        "builder"
    } else if oracle.derivation.arguments != candidate.derivation.arguments {
        "arguments"
    } else if oracle.derivation.environment != candidate.derivation.environment {
        "environment"
    } else {
        "serialization"
    }
}

pub(super) fn parse_drv_inputs_from_bytes(
    bytes: &[u8],
    path: &Path,
    label: &str,
) -> Result<Vec<DrvInput>> {
    parse_drv_input_drvs_from_bytes(bytes)
        .with_context(|| format!("parsing {label} drv inputs {}", path.display()))
}
