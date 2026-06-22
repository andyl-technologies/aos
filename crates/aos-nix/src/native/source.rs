//! Source-text construction, derivation materialization, and attribute-path
//! parsing for the native evaluator shim.
//!
//! These helpers wrap raw expressions in the `builtins.toJSON`/`.drvPath`
//! scaffolding the tree-walk oracle expects, write evaluated `.drv` closures
//! into the configured store, and translate `-A` attribute selectors into the
//! byte segments the instantiation entry points consume.

use super::*;

pub(super) fn materialize_drv_closure(closure: &NativeDrvClosure) -> Result<()> {
    for (path, bytes) in closure.drvs() {
        materialize_drv(path, bytes).map_err(|source| NativeEvalError::Internal {
            message: source.to_string(),
        })?;
    }
    Ok(())
}

pub(super) fn json_wrapper_source(expr: &str) -> String {
    format!("{JSON_WRAPPER_PREFIX}{expr}{JSON_WRAPPER_SUFFIX}")
}

pub(super) fn derivation_path_wrapper_source(expr: &str) -> String {
    format!("{DRV_PATH_WRAPPER_PREFIX}{expr}{DRV_PATH_WRAPPER_SUFFIX}")
}

pub(super) fn derivation_path_from_value(
    value: Value,
    heap: &crate::eval::EvalHeap,
) -> Result<PathBuf> {
    let string = heap
        .get_string(value)
        .map_err(|source| NativeEvalError::EvalError {
            message: format!("native instantiation did not produce a string drvPath: {source}"),
        })?;
    let path =
        std::str::from_utf8(string.bytes()).map_err(|source| NativeEvalError::EvalError {
            message: format!("native instantiation produced a non-UTF-8 drvPath: {source}"),
        })?;
    if !path.ends_with(".drv") {
        return Err(NativeEvalError::EvalError {
            message: format!("native instantiation produced a non-derivation path: {path}"),
        }
        .into());
    }
    Ok(PathBuf::from(path))
}

#[cfg(test)]
pub(super) fn attr_path_selector(attr: &str) -> Result<String> {
    let mut selector = String::new();
    for segment in parse_attr_path_segments(attr)? {
        selector.push('.');
        selector.push_str(&nix_string_literal(&segment)?);
    }
    Ok(selector)
}

pub(super) fn attr_path_drv_path_segments(attr: &str) -> Result<Vec<Vec<u8>>> {
    let mut segments = parse_attr_path_segments(attr)?;
    segments.push(b"drvPath".to_vec());
    Ok(segments)
}

pub(super) fn parse_attr_path_segments(attr: &str) -> Result<Vec<Vec<u8>>> {
    let bytes = attr.as_bytes();
    let mut segments = Vec::new();
    let mut segment = Vec::new();
    let mut cursor = 0;
    let mut in_quote = false;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => in_quote = !in_quote,
            b'.' if !in_quote => {
                if segment.is_empty() {
                    if cursor + 1 == bytes.len()
                        && !segments.is_empty()
                        && !matches!(bytes.get(cursor.wrapping_sub(1)), Some(b'.' | b'"'))
                    {
                        return Ok(segments);
                    }
                    return Err(NativeEvalError::EvalError {
                        message: format!(
                            "native instantiation attribute path has an empty segment: {attr}"
                        ),
                    }
                    .into());
                }
                segments.push(std::mem::take(&mut segment));
            }
            byte => segment.push(byte),
        }
        cursor += 1;
    }

    if in_quote {
        return Err(NativeEvalError::EvalError {
            message: format!(
                "native instantiation attribute path has an unterminated string: {attr}"
            ),
        }
        .into());
    }
    if !segment.is_empty() {
        segments.push(segment);
    }
    Ok(segments)
}

pub(super) fn path_bytes(path: &Path) -> Result<Vec<u8>> {
    let bytes = path.as_os_str().as_bytes();
    if path.is_absolute() {
        Ok(bytes.to_vec())
    } else {
        let mut out = std::env::current_dir()
            .map_err(|source| NativeEvalError::EvalError {
                message: format!(
                    "failed to resolve current directory for native instantiation: {source}"
                ),
            })?
            .into_os_string()
            .into_vec();
        out.push(b'/');
        out.extend_from_slice(bytes);
        Ok(out)
    }
}

#[cfg(test)]
pub(super) fn nix_string_literal(bytes: &[u8]) -> Result<String> {
    let mut out = String::new();
    out.push('"');
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => out.push_str(r"\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str(r"\n"),
            b'\r' => out.push_str(r"\r"),
            b'\t' => out.push_str(r"\t"),
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                out.push_str(r"\${");
                cursor += 1;
            }
            0x20..=0x7e => out.push(char::from(bytes[cursor])),
            _ => {
                return Err(NativeEvalError::Unsupported {
                    feature: "non-ASCII path or attribute segment in native instantiation"
                        .to_string(),
                    span: None,
                }
                .into());
            }
        }
        cursor += 1;
    }
    out.push('"');
    Ok(out)
}
