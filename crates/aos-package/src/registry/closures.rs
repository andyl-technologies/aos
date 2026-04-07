use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::types::ClosureMeta;

// ---------------------------------------------------------------------------
// Closure directory loading
// ---------------------------------------------------------------------------

/// Load all closure files from a registry's `closures/` directory.
///
/// Returns a map from store path hash to parsed `ClosureMeta`.
/// Missing or empty `closures/` directory is not an error — returns empty map.
pub fn load_closures(registry_dir: &Path) -> Result<HashMap<String, ClosureMeta>> {
    let closures_dir = registry_dir.join("closures");
    let mut map = HashMap::new();

    if !closures_dir.is_dir() {
        return Ok(map);
    }

    for entry in std::fs::read_dir(&closures_dir)
        .with_context(|| format!("reading {}", closures_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        // Skip directories and hidden files.
        if path.is_dir() {
            continue;
        }
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if !n.starts_with('.') => n.to_string(),
            _ => continue,
        };

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading closure file {}", path.display()))?;

        let meta = ClosureMeta::parse(&filename, &content);
        map.insert(filename, meta);
    }

    Ok(map)
}

/// Load a single closure file for a specific store path hash.
///
/// Returns `None` if the file does not exist.
pub fn load_closure(registry_dir: &Path, hash: &str) -> Result<Option<ClosureMeta>> {
    let path = registry_dir.join("closures").join(hash);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading closure file {}", path.display()))?;
    Ok(Some(ClosureMeta::parse(hash, &content)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Test fixtures used by both closures.rs and mod.rs tests.
#[cfg(test)]
pub(crate) const CURL_CLOSURE: &str = "\
h7j3k8l2m9n4 r4q1m2kp8v3x xr5is7by89v3q kl9m3n0o5p6q
r4q1m2kp8v3x
xr5is7by89v3q q8mn2pv73w0x
q8mn2pv73w0x
kl9m3n0o5p6q
";

#[cfg(test)]
pub(crate) const ZLIB_CLOSURE: &str = "\
r4q1m2kp8v3x
";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parse_closure_adjacency_list() {
        let meta = ClosureMeta::parse("h7j3k8l2m9n4", CURL_CLOSURE);
        assert_eq!(meta.root, "h7j3k8l2m9n4");
        assert_eq!(meta.members.len(), 5);
        assert_eq!(meta.members[0], "h7j3k8l2m9n4");

        // Root's direct deps.
        let root_deps = meta.direct_deps("h7j3k8l2m9n4");
        assert_eq!(root_deps.len(), 3);
        assert_eq!(root_deps[0], "r4q1m2kp8v3x");

        // Leaf node has no deps.
        assert!(meta.direct_deps("r4q1m2kp8v3x").is_empty());

        // Indirect dep.
        let xr_deps = meta.direct_deps("xr5is7by89v3q");
        assert_eq!(xr_deps, &["q8mn2pv73w0x"]);
    }

    #[test]
    fn parse_closure_leaf() {
        let meta = ClosureMeta::parse("r4q1m2kp8v3x", ZLIB_CLOSURE);
        assert_eq!(meta.members.len(), 1);
        assert!(meta.direct_deps("r4q1m2kp8v3x").is_empty());
    }

    #[test]
    fn parse_closure_skips_comments_and_blanks() {
        let content = "# comment\n\nh7j3k8l2m9n4 r4q1m2kp8v3x\n\nr4q1m2kp8v3x\n";
        let meta = ClosureMeta::parse("h7j3k8l2m9n4", content);
        assert_eq!(meta.members.len(), 2);
    }

    #[test]
    fn closure_contains() {
        let meta = ClosureMeta::parse("h7j3k8l2m9n4", CURL_CLOSURE);
        assert!(meta.contains("h7j3k8l2m9n4"));
        assert!(meta.contains("q8mn2pv73w0x"));
        assert!(!meta.contains("nonexistent"));
    }

    #[test]
    fn serialize_round_trip() {
        let meta = ClosureMeta::parse("h7j3k8l2m9n4", CURL_CLOSURE);
        let serialized = meta.serialize();
        let reparsed = ClosureMeta::parse("h7j3k8l2m9n4", &serialized);
        assert_eq!(meta.members, reparsed.members);
        for member in &meta.members {
            assert_eq!(meta.direct_deps(member), reparsed.direct_deps(member));
        }
    }

    #[test]
    fn load_closures_from_dir() {
        let tmp = TempDir::new().unwrap();
        let closures_dir = tmp.path().join("closures");
        fs::create_dir_all(&closures_dir).unwrap();

        fs::write(closures_dir.join("h7j3k8l2m9n4"), CURL_CLOSURE).unwrap();
        fs::write(closures_dir.join("r4q1m2kp8v3x"), ZLIB_CLOSURE).unwrap();

        let map = load_closures(tmp.path()).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("h7j3k8l2m9n4"));
        assert!(map.contains_key("r4q1m2kp8v3x"));
        assert_eq!(map["h7j3k8l2m9n4"].members.len(), 5);
        assert_eq!(map["r4q1m2kp8v3x"].members.len(), 1);
    }

    #[test]
    fn load_closures_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let map = load_closures(tmp.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn load_single_closure() {
        let tmp = TempDir::new().unwrap();
        let closures_dir = tmp.path().join("closures");
        fs::create_dir_all(&closures_dir).unwrap();
        fs::write(closures_dir.join("h7j3k8l2m9n4"), CURL_CLOSURE).unwrap();

        let meta = load_closure(tmp.path(), "h7j3k8l2m9n4").unwrap();
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().members.len(), 5);

        let missing = load_closure(tmp.path(), "nonexistent").unwrap();
        assert!(missing.is_none());
    }
}
