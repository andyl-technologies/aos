//! Registry state persistence.
//!
//! Each registry config file (`registries.d/{name}.toml`) contains a
//! `[registry.state]` section that is written by `apm update` to track
//! the last-synced commit and channel rollout state.  User-edited fields
//! (name, url, signing, etc.) are preserved on every save.
//!
//! Because the rest of the file is user-owned, saving works by textual
//! section surgery rather than full-file re-serialization: the existing
//! `[registry.state]` (or `[registry.signing_keys]`) block is located by its
//! header line and replaced in place, leaving all other bytes untouched.
//!
//! A fully populated state section looks like:
//!
//! ```toml
//! [registry.state]
//! last_commit = "abc123def456"
//! floor = "1.4.2"
//! bucket = 183
//! retained = ["1.0.0", "1.4.0", "1.4.2"]
//! last_update = "2026-02-13T10:30:00Z"
//! ```

use std::path::Path;

use anyhow::{Context, Result};

use crate::types::{RegistryFile, RegistryState, SigningKeySource};

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load state from a registry config file's `[registry.state]` section.
///
/// Returns `Ok(None)` if the file has no state section or does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or is not valid
/// registry TOML.
pub fn load_state(path: &Path) -> Result<Option<RegistryState>> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    Ok(rf.registry.state)
}

/// Save/update the `[registry.state]` section in a registry config file.
///
/// Preserves user-edited fields — only appends or replaces the state
/// section. Unset state fields are omitted from the rendered section
/// entirely.
///
/// # Errors
///
/// Returns an error when the config file does not exist, cannot be read, or
/// cannot be rewritten.
pub fn save_state(path: &Path, state: &RegistryState) -> Result<()> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    // Build the new state section text.
    let mut state_lines = String::from("\n[registry.state]\n");
    if let Some(ref commit) = state.last_commit {
        state_lines.push_str(&format!("last_commit = \"{commit}\"\n"));
    }
    if let Some(ref floor) = state.floor {
        state_lines.push_str(&format!("floor = \"{}\"\n", escape_toml_string(floor)));
    }
    if let Some(bucket) = state.bucket {
        state_lines.push_str(&format!("bucket = {bucket}\n"));
    }
    if !state.retained.is_empty() {
        state_lines.push_str("retained = [");
        for (i, release) in state.retained.iter().enumerate() {
            if i > 0 {
                state_lines.push_str(", ");
            }
            state_lines.push('"');
            state_lines.push_str(&escape_toml_string(release));
            state_lines.push('"');
        }
        state_lines.push_str("]\n");
    }
    if let Some(ref ts) = state.last_update {
        state_lines.push_str(&format!("last_update = \"{ts}\"\n"));
    }

    // Check whether a [registry.state] section already exists.
    let new_content = if let Some(start) = find_state_section(&content) {
        // Find the end of the state section (next `[` header or EOF).
        let after_header = start + "[registry.state]".len();
        let end = content[after_header..]
            .find("\n[")
            .map(|pos| after_header + pos)
            .unwrap_or(content.len());

        // Trim any trailing whitespace before the state section
        let before = content[..start].trim_end_matches('\n');
        let after = &content[end..];

        format!("{before}{state_lines}{after}")
    } else {
        // No existing state section — append.
        let trimmed = content.trim_end_matches('\n');
        format!("{trimmed}{state_lines}")
    };

    std::fs::write(path, &new_content).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// Record a signing-key source in the `[registry.signing_keys]` section.
///
/// Reads the existing map, inserts or replaces the entry for `id`, and
/// rewrites only that section, preserving every other user-edited field
/// (mirroring [`save_state`]). Path sources render as a bare string; command
/// sources render as an inline `{ command = "..." }` table.
///
/// # Errors
///
/// Returns an error when the config file does not exist, cannot be
/// parsed, or cannot be rewritten.
pub fn upsert_signing_key(path: &Path, id: &str, source: &SigningKeySource) -> Result<()> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let mut signing_keys = rf.registry.signing_keys;
    signing_keys.insert(id.to_string(), source.clone());

    let mut section = String::from("\n[registry.signing_keys]\n");
    for (entry_id, entry_source) in &signing_keys {
        section.push_str(&format!(
            "\"{}\" = {}\n",
            escape_toml_string(entry_id),
            render_signing_key_source(entry_source),
        ));
    }

    let new_content = if let Some(start) = find_section(&content, "[registry.signing_keys]") {
        let after_header = start + "[registry.signing_keys]".len();
        let end = content[after_header..]
            .find("\n[")
            .map(|pos| after_header + pos)
            .unwrap_or(content.len());
        let before = content[..start].trim_end_matches('\n');
        let after = &content[end..];
        format!("{before}{section}{after}")
    } else {
        let trimmed = content.trim_end_matches('\n');
        format!("{trimmed}{section}")
    };

    std::fs::write(path, &new_content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Render a [`SigningKeySource`] as the right-hand side of a TOML key entry.
///
/// A path source becomes a quoted string; a command source becomes an inline
/// `{ command = "..." }` table. A degenerate entry that somehow carries both
/// (or neither) is rendered losslessly so a hand-edited file round-trips.
fn render_signing_key_source(source: &SigningKeySource) -> String {
    match (source.path(), source.command()) {
        (Some(path), None) => format!("\"{}\"", escape_toml_string(path)),
        (None, Some(command)) => {
            format!("{{ command = \"{}\" }}", escape_toml_string(command))
        }
        (Some(path), Some(command)) => format!(
            "{{ path = \"{}\", command = \"{}\" }}",
            escape_toml_string(path),
            escape_toml_string(command),
        ),
        (None, None) => "\"\"".to_string(),
    }
}

/// Escape backslashes and double quotes for a basic TOML string literal.
fn escape_toml_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Find the byte offset of the `[registry.state]` header in the file content.
fn find_state_section(content: &str) -> Option<usize> {
    find_section(content, "[registry.state]")
}

/// Find the byte offset of a `[section]` header at the start of a line.
fn find_section(content: &str, header: &str) -> Option<usize> {
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == header {
            // Calculate byte offset: sum of previous lines + newlines.
            let offset: usize = content
                .lines()
                .take(i)
                .map(|l| l.len() + 1) // +1 for newline
                .sum();
            return Some(offset);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn load_state_from_registry_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"

[registry.state]
last_commit = "abc123def456"
floor = "1.4.2"
bucket = 183
retained = ["1.0.0", "1.4.0", "1.4.2"]
last_update = "2026-02-13T10:30:00Z"
"#,
        )
        .unwrap();

        let state = load_state(&path).unwrap().unwrap();
        assert_eq!(state.last_commit.unwrap(), "abc123def456");
        assert_eq!(state.floor.unwrap(), "1.4.2");
        assert_eq!(state.bucket.unwrap(), 183);
        assert_eq!(state.retained, vec!["1.0.0", "1.4.0", "1.4.2"]);
        assert_eq!(state.last_update.unwrap(), "2026-02-13T10:30:00Z");
    }

    #[test]
    fn load_state_returns_none_when_no_state_section() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
"#,
        )
        .unwrap();

        let state = load_state(&path).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn load_state_returns_none_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let state = load_state(&path).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn save_state_appends_to_file_without_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("deadbeef".into()),
            floor: Some("1.4.2".into()),
            bucket: Some(183),
            retained: vec!["1.0.0".into(), "1.4.0".into(), "1.4.2".into()],
            last_update: Some("2026-02-16T12:00:00Z".into()),
        };
        save_state(&path, &state).unwrap();

        // Verify the file is still valid TOML and contains the state.
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[registry.signing]"));
        assert!(content.contains("public_key"));
        assert!(content.contains("[registry.state]"));
        assert!(content.contains("last_commit = \"deadbeef\""));
        assert!(content.contains("floor = \"1.4.2\""));
        assert!(content.contains("bucket = 183"));
        assert!(content.contains("retained = [\"1.0.0\", \"1.4.0\", \"1.4.2\"]"));

        // Verify it round-trips through load_state.
        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.unwrap(), "deadbeef");
        assert_eq!(loaded.floor.unwrap(), "1.4.2");
        assert_eq!(loaded.bucket.unwrap(), 183);
        assert_eq!(loaded.retained, vec!["1.0.0", "1.4.0", "1.4.2"]);
    }

    #[test]
    fn save_state_replaces_existing_state_section() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.state]
last_commit = "old_commit"
last_update = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("new_commit".into()),
            floor: Some("1.4.2".into()),
            bucket: Some(183),
            retained: vec!["1.4.2".into()],
            last_update: Some("2026-02-16T12:00:00Z".into()),
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("old_commit"));
        assert!(content.contains("new_commit"));
        assert!(content.contains("floor = \"1.4.2\""));
        assert!(content.contains("bucket = 183"));

        // Verify user fields are preserved.
        assert!(content.contains("name = \"aos-core\""));
        assert!(content.contains("url = \"https://registry.aos.dev/core\""));

        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.unwrap(), "new_commit");
        assert_eq!(loaded.floor.unwrap(), "1.4.2");
        assert_eq!(loaded.bucket.unwrap(), 183);
        assert_eq!(loaded.retained, vec!["1.4.2"]);
    }

    #[test]
    fn upsert_signing_key_round_trips_path_and_command_sources() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("aos-core.toml");
        fs::write(
            &path,
            r#"[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing_keys]
alice = "/run/secrets/alice"
"#,
        )
        .unwrap();

        // Add a command source alongside the existing path source.
        upsert_signing_key(
            &path,
            "bob",
            &SigningKeySource::Spec(crate::types::SigningKeySpec {
                path: None,
                command: Some("pass show apm/bob".to_string()),
            }),
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"bob\" = { command = \"pass show apm/bob\" }"));
        // The user-edited [registry] header is preserved.
        assert!(content.contains("name = \"aos-core\""));

        // Both forms parse back through the untagged enum.
        let rf: crate::types::RegistryFile = toml::from_str(&content).unwrap();
        let keys = &rf.registry.signing_keys;
        assert_eq!(
            keys.get("alice").and_then(|s| s.path()),
            Some("/run/secrets/alice")
        );
        assert_eq!(keys.get("alice").and_then(|s| s.command()), None);
        assert_eq!(
            keys.get("bob").and_then(|s| s.command()),
            Some("pass show apm/bob")
        );
        assert_eq!(keys.get("bob").and_then(|s| s.path()), None);
    }

    #[test]
    fn save_state_preserves_fields_after_state_section() {
        // Edge case: content after the state section should be preserved
        // (though unusual, this tests robustness).
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.toml");
        fs::write(
            &path,
            r#"[registry]
name = "test"
url = "https://example.com"

[registry.state]
last_commit = "old"

[registry.signing]
required = false
public_key = "test:Ed25519:abc"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("new".into()),
            last_update: None,
            ..RegistryState::default()
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("last_commit = \"new\""));
        // The signing section after state should be preserved.
        assert!(content.contains("[registry.signing]"));
        assert!(content.contains("public_key = \"test:Ed25519:abc\""));
    }
}
