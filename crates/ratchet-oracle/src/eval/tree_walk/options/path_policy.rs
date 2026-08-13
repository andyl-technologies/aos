//! Path normalization, store path validation, and search-path joining helpers.

use super::*;

pub(crate) fn normalize_store_dir(store_dir: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    normalize_absolute_path(
        store_dir,
        DEFAULT_STORE_DIR,
        TreeWalkOptionsError::RelativeStoreDir,
    )
}

pub(crate) fn normalize_absolute_path(
    path: Vec<u8>,
    empty_default: &[u8],
    relative_error: TreeWalkOptionsError,
) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() {
        return Ok(empty_default.to_vec());
    }
    if !path.starts_with(b"/") {
        return Err(relative_error);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub(crate) fn normalize_allowed_path(path: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() || !path.starts_with(b"/") {
        return Err(TreeWalkOptionsError::RelativeAllowedPath);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub(crate) fn normalize_allowed_uri(uri: Vec<u8>) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if uri.is_empty() {
        return Err(TreeWalkOptionsError::EmptyAllowedUri);
    }

    Ok(uri)
}

pub(crate) fn normalize_required_absolute_path(
    path: Vec<u8>,
    relative_error: TreeWalkOptionsError,
) -> Result<Vec<u8>, TreeWalkOptionsError> {
    if path.is_empty() || !path.starts_with(b"/") {
        return Err(relative_error);
    }

    Ok(normalize_absolute_path_bytes(&path))
}

pub fn normalize_absolute_path_bytes(path: &[u8]) -> Vec<u8> {
    let mut components = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            components.pop();
            continue;
        }
        components.push(component);
    }

    let mut normalized = Vec::with_capacity(path.len());
    for component in components {
        normalized.push(b'/');
        normalized.extend_from_slice(component);
    }

    if normalized.is_empty() {
        normalized.push(b'/');
    }

    normalized
}

pub(crate) fn path_is_under_root(path: &[u8], root: &[u8]) -> bool {
    if root == b"/" {
        return path.starts_with(b"/");
    }
    path == root || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
}

pub fn canonicalize_policy_path(path: &[u8]) -> Option<Vec<u8>> {
    let path = Path::new(OsStr::from_bytes(path));
    let resolved = fs::canonicalize(path).ok()?;
    Some(normalize_absolute_path_bytes(
        resolved.as_os_str().as_bytes(),
    ))
}

pub(crate) fn is_valid_store_path(path: &[u8], store_dir: &[u8]) -> bool {
    if path.len() <= store_dir.len() + 34 || !path.starts_with(store_dir) {
        return false;
    }
    if path.get(store_dir.len()) != Some(&b'/') {
        return false;
    }
    let name = &path[store_dir.len() + 1..];
    if name.len() < 34 || name.get(32) != Some(&b'-') {
        return false;
    }
    let store_name = &name[33..];
    if store_name.is_empty() || store_name.len() > 211 || store_name == b"." || store_name == b".."
    {
        return false;
    }
    name[..32].iter().all(|byte| is_nix_base32_byte(*byte))
        && store_name.iter().all(|byte| is_store_name_byte(*byte))
}

pub(crate) fn store_path_root<'a>(path: &'a [u8], store_dir: &[u8]) -> Option<&'a [u8]> {
    if path.len() <= store_dir.len() + 34 || !path.starts_with(store_dir) {
        return None;
    }
    if path.get(store_dir.len()) != Some(&b'/') {
        return None;
    }
    let suffix = &path[store_dir.len() + 1..];
    let component_len = suffix
        .iter()
        .position(|byte| *byte == b'/')
        .unwrap_or(suffix.len());
    let root_len = store_dir.len() + 1 + component_len;
    let root = &path[..root_len];
    is_valid_store_path(root, store_dir).then_some(root)
}

pub(crate) fn is_nix_base32_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'a'
            | b'b'
            | b'c'
            | b'd'
            | b'f'
            | b'g'
            | b'h'
            | b'i'
            | b'j'
            | b'k'
            | b'l'
            | b'm'
            | b'n'
            | b'p'
            | b'q'
            | b'r'
            | b's'
            | b'v'
            | b'w'
            | b'x'
            | b'y'
            | b'z'
    )
}

pub(crate) fn is_store_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'+'
            | b'-'
            | b'.'
            | b'_'
            | b'?'
            | b'='
    )
}

pub(crate) fn file_type_name(file_type: fs::FileType) -> &'static [u8] {
    if file_type.is_file() {
        b"regular"
    } else if file_type.is_dir() {
        b"directory"
    } else if file_type.is_symlink() {
        b"symlink"
    } else {
        b"unknown"
    }
}

pub(crate) fn path_without_trailing_path_markers(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    loop {
        let previous_end = end;
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        if end > 2 && path[end - 2] == b'/' && path[end - 1] == b'.' {
            end -= 2;
            continue;
        }
        if end == 2 && path[0] == b'/' && path[1] == b'.' {
            end = 1;
        }
        if end == previous_end {
            break;
        }
    }
    &path[..end]
}

pub(crate) fn path_exists_requires_directory(path: &[u8]) -> bool {
    path.ends_with(b"/") || path.ends_with(b"/.")
}

pub(crate) fn search_path_suffix<'a>(prefix: &[u8], lookup: &'a [u8]) -> Option<&'a [u8]> {
    if prefix.is_empty() {
        return Some(lookup);
    }
    if lookup == prefix {
        return Some(&[]);
    }
    lookup
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix(b"/"))
}

pub(crate) fn search_path_literal_lookup(
    id: IrId,
    span: Span,
    literal: &[u8],
) -> Result<&[u8], TreeWalkError> {
    literal
        .strip_prefix(b"<")
        .and_then(|literal| literal.strip_suffix(b">"))
        .ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSearchPathLiteral {
                    id,
                    literal: literal.to_vec(),
                },
                span,
            )
        })
}

pub(crate) fn join_search_path(
    id: IrId,
    span: Span,
    base: &[u8],
    path: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, TreeWalkError> {
    let mut joined = Vec::new();

    if path.starts_with(b"/") {
        append_search_path_component(id, span, &mut joined, path)?;
    } else {
        append_search_path_component(id, span, &mut joined, base)?;
        append_search_path_component(id, span, &mut joined, path)?;
    }

    append_search_path_component(id, span, &mut joined, suffix)?;
    TreeWalk::absolute_path_bytes_for_node(id, span, &joined)
}

pub(crate) fn join_path_literal(
    id: IrId,
    span: Span,
    base: &[u8],
    path: &[u8],
) -> Result<Vec<u8>, TreeWalkError> {
    let mut joined = Vec::new();
    append_search_path_component(id, span, &mut joined, base)?;
    append_search_path_component(id, span, &mut joined, path)?;
    TreeWalk::absolute_path_bytes_for_node(id, span, &joined)
}

pub(crate) fn append_search_path_component(
    id: IrId,
    span: Span,
    joined: &mut Vec<u8>,
    component: &[u8],
) -> Result<(), TreeWalkError> {
    if component.is_empty() {
        return Ok(());
    }

    let needs_separator = !joined.is_empty() && !joined.ends_with(b"/");
    let additional = component
        .len()
        .checked_add(usize::from(needs_separator))
        .ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
    let len = joined.len().checked_add(additional).ok_or_else(|| {
        TreeWalkError::new(
            TreeWalkErrorKind::ByteAllocationFailed {
                id,
                len: usize::MAX,
            },
            span,
        )
    })?;
    joined.try_reserve_exact(additional).map_err(|_| {
        TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
    })?;

    if needs_separator {
        joined.push(b'/');
    }
    joined.extend_from_slice(component);
    Ok(())
}
