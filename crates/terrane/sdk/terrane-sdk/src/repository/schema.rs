//! Evaluates declared schemas using authenticated metadata without content I/O.
//!
//! Schema paths are root relative. `*` matches one path component and `**`
//! matches zero or more components. A literal `/` selects the root. Required
//! literal entries establish existence; wildcard kinds and entry attributes
//! constrain matches and permit empty collections. Malformed patterns fail even
//! when the view has no entries.

use crate::repository::Error;
use terrane_format::surface::{SchemaEntryKind, TreeSchema};
use terrane_format::{
    cbor::Decoder,
    identity::Digest,
    tree_format::{self, EntryKind},
};

/// Holds a view metadata projection without an object reader.
///
/// These data fields confer no repository authority; exposure preparation obtains
/// its separate opaque authority binding from the repository.
#[derive(Clone, Debug)]
pub struct ViewMetadata {
    /// Exact immutable commit supplying this projection.
    pub commit: Digest,
    /// Minimum chunk size needed to decode the existing canonical entries.
    pub minimum_chunk_size: u64,
    /// Scoped entry paths and existing canonical entry encodings.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// Root attributes in their existing canonical CBOR encoding.
    pub root_attributes: Vec<(String, Vec<u8>)>,
    /// Validated effective property values requested by the schema.
    pub properties: Vec<(String, Vec<u8>)>,
}

/// Validates a surface schema against metadata alone.
///
/// # Errors
/// Returns a schema error for absent, forbidden or mistyped metadata and a tree
/// error for invalid canonical entries. No object content is fetched.
pub fn validate_schema(schema: &TreeSchema, metadata: &ViewMetadata) -> Result<(), Error> {
    for pattern in schema
        .required_entries
        .iter()
        .map(|(path, _)| path)
        .chain(schema.required_attributes.iter().map(|(path, _, _)| path))
        .chain(schema.forbidden_entries.iter())
    {
        validate_pattern(pattern)?;
    }
    let entries = metadata
        .entries
        .iter()
        .map(|(path, bytes)| {
            tree_format::decode_entry_bytes(bytes, metadata.minimum_chunk_size)
                .map(|entry| (path.as_slice(), entry))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (pattern, required) in &schema.required_entries {
        if pattern == b"/" {
            if !matches!(required, SchemaEntryKind::Root | SchemaEntryKind::Directory) {
                return Err(Error::Schema);
            }
            continue;
        }
        let matches = entries
            .iter()
            .filter(|(path, _)| path_matches(pattern, path))
            .collect::<Vec<_>>();
        if (matches.is_empty() && !has_wildcard(pattern))
            || matches
                .iter()
                .any(|(_, entry)| !kind_matches(*required, &entry.kind))
        {
            return Err(Error::Schema);
        }
    }
    for pattern in &schema.forbidden_entries {
        if pattern == b"/" {
            return Err(Error::Schema);
        }
        if entries.iter().any(|(path, _)| path_matches(pattern, path)) {
            return Err(Error::Schema);
        }
    }
    for (pattern, name, major) in &schema.required_attributes {
        if *major > 7 {
            return Err(Error::Schema);
        }
        if pattern == b"/" {
            let value = metadata
                .root_attributes
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_slice());
            check_type(value, *major)?;
            continue;
        }
        let matches = entries
            .iter()
            .filter(|(path, _)| path_matches(pattern, path))
            .collect::<Vec<_>>();
        for (_, entry) in matches {
            check_type(
                entry
                    .attrs
                    .iter()
                    .find(|attr| attr.name == name)
                    .map(|attr| attr.value),
                *major,
            )?;
        }
    }
    for (name, allowed) in &schema.required_properties {
        let value = metadata
            .properties
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value);
        if !value.is_some_and(|value| allowed.contains(value)) {
            return Err(Error::Schema);
        }
    }
    Ok(())
}

fn validate_pattern(pattern: &[u8]) -> Result<(), Error> {
    if pattern == b"/" {
        return Ok(());
    }
    let relative = pattern.strip_prefix(b"/").unwrap_or(pattern);
    if relative.is_empty()
        || relative.contains(&0)
        || relative
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(Error::Schema);
    }
    Ok(())
}

fn has_wildcard(pattern: &[u8]) -> bool {
    pattern
        .split(|byte| *byte == b'/')
        .any(|component| component == b"*" || component == b"**")
}

fn check_type(value: Option<&[u8]>, major: u8) -> Result<(), Error> {
    let value = value.ok_or(Error::Schema)?;
    let mut decoder = Decoder::new(value);
    if major > 7 || decoder.peek_major().map_err(|_| Error::Schema)? != major {
        return Err(Error::Schema);
    }
    decoder.skip_value(value.len()).map_err(|_| Error::Schema)?;
    decoder.finish().map_err(|_| Error::Schema)
}

fn kind_matches(required: SchemaEntryKind, actual: &EntryKind<'_>) -> bool {
    matches!(
        (required, actual),
        (SchemaEntryKind::File, EntryKind::File { .. })
            | (SchemaEntryKind::Directory, EntryKind::Directory { .. })
            | (SchemaEntryKind::Symlink, EntryKind::Symlink { .. })
            | (SchemaEntryKind::Tree, EntryKind::Tree { .. })
    )
}

fn path_matches(pattern: &[u8], path: &[u8]) -> bool {
    let pattern = pattern.strip_prefix(b"/").unwrap_or(pattern);
    let components = pattern.split(|byte| *byte == b'/').collect::<Vec<_>>();
    let path = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    // Iterative wildcard matching avoids recursion proportional to untrusted paths.
    let mut reachable = vec![false; path.len() + 1];
    reachable[0] = true;
    for component in components {
        let mut next = vec![false; path.len() + 1];
        if component == b"**" {
            let mut seen = false;
            for index in 0..=path.len() {
                seen |= reachable[index];
                next[index] = seen;
            }
        } else {
            for index in 0..path.len() {
                next[index + 1] =
                    reachable[index] && (component == b"*" || component == path[index]);
            }
        }
        reachable = next;
    }
    reachable[path.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching_respects_components() {
        assert!(path_matches(b"cas/*/*", b"cas/sha256/abcd"));
        assert!(!path_matches(b"cas/*", b"cas/sha256/abcd"));
        assert!(path_matches(b"**/file", b"a/b/file"));
        assert!(path_matches(b"**/file", b"file"));
    }

    #[test]
    fn empty_schema_accepts_empty_metadata_and_requirements_fail_closed() {
        let metadata = ViewMetadata {
            commit: [1; 32],
            minimum_chunk_size: 65536,
            entries: Vec::new(),
            root_attributes: Vec::new(),
            properties: Vec::new(),
        };
        assert!(validate_schema(&TreeSchema::default(), &metadata).is_ok());
        let schema = TreeSchema {
            required_entries: vec![(b"missing".to_vec(), SchemaEntryKind::File)],
            ..TreeSchema::default()
        };
        assert!(matches!(
            validate_schema(&schema, &metadata),
            Err(Error::Schema)
        ));
    }
}
