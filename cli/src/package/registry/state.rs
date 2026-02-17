//! Registry state persistence and downgrade protection.
//!
//! Each registry config file (`registries.d/{name}.toml`) contains a
//! `[registry.state]` section that is written by `apm update` to track
//! the last-synced commit and creation token.  User-edited fields
//! (name, url, signing, etc.) are preserved on every save.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::package::types::{RegistryFile, RegistryState};

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load state from a registry config file's `[registry.state]` section.
///
/// Returns `Ok(None)` if the file has no state section or does not exist.
pub fn load_state(path: &Path) -> Result<Option<RegistryState>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let rf: RegistryFile = toml::from_str(&content)
        .with_context(|| format!("parsing {}", path.display()))?;

    Ok(rf.registry.state)
}

/// Save/update the `[registry.state]` section in a registry config file.
///
/// Preserves user-edited fields — only appends or replaces the state section.
pub fn save_state(path: &Path, state: &RegistryState) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Build the new state section text.
    let mut state_lines = String::from("\n[registry.state]\n");
    if let Some(ref commit) = state.last_commit {
        state_lines.push_str(&format!("last_commit = \"{commit}\"\n"));
    }
    if let Some(token) = state.last_creation_token {
        state_lines.push_str(&format!("last_creation_token = {token}\n"));
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

    std::fs::write(path, &new_content)
        .with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// Find the byte offset of the `[registry.state]` header in the file content.
fn find_state_section(content: &str) -> Option<usize> {
    // Look for the header at the start of a line.
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[registry.state]" {
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
// Monotonic token ordering
// ---------------------------------------------------------------------------

/// Check monotonic creation_token ordering.
///
/// Returns `Err` if `new_token <= old_token` (i.e. a downgrade).
pub fn check_monotonic(old_token: u64, new_token: u64) -> Result<()> {
    if new_token <= old_token {
        bail!(
            "registry downgrade detected: creation_token {} is not newer \
             than previous token {} (version {} -> {}). \
             This could indicate a downgrade attack or a stale mirror.",
            new_token,
            old_token,
            token_to_version(old_token),
            token_to_version(new_token),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Version <-> token encoding
// ---------------------------------------------------------------------------

/// Encode a version tag as a creation_token.
///
/// Format: `YYYYMMPPP` where `YYYY` is year, `MM` is month (01-12), and
/// `PPP` is the patch number (0 for no patch, 1+ for patches).
///
/// Examples:
/// - `"v2026.02"` -> `2026020000`
/// - `"v2026.02.3"` -> `2026020003`
pub fn version_to_token(tag: &str) -> Result<u64> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = stripped.split('.').collect();

    if parts.len() < 2 || parts.len() > 3 {
        bail!(
            "invalid version tag '{}': expected vYYYY.MM or vYYYY.MM.P",
            tag
        );
    }

    let year: u64 = parts[0]
        .parse()
        .with_context(|| format!("invalid year in tag '{tag}'"))?;
    let month: u64 = parts[1]
        .parse()
        .with_context(|| format!("invalid month in tag '{tag}'"))?;

    if !(1..=12).contains(&month) {
        bail!("invalid month {} in tag '{}'", month, tag);
    }

    let patch: u64 = if parts.len() == 3 {
        parts[2]
            .parse()
            .with_context(|| format!("invalid patch in tag '{tag}'"))?
    } else {
        0
    };

    if patch > 9999 {
        bail!("patch number {} exceeds maximum (9999) in tag '{}'", patch, tag);
    }

    Ok(year * 1_000_000 + month * 10_000 + patch)
}

/// Decode a creation_token to a version string.
///
/// Examples:
/// - `2026020003` -> `"v2026.02.3"`
/// - `2026020000` -> `"v2026.02"`
pub fn token_to_version(token: u64) -> String {
    let patch = token % 10_000;
    let remaining = token / 10_000;
    let month = remaining % 100;
    let year = remaining / 100;

    if patch == 0 {
        format!("v{year}.{month:02}")
    } else {
        format!("v{year}.{month:02}.{patch}")
    }
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
    fn version_to_token_with_patch() {
        assert_eq!(version_to_token("v2026.02.3").unwrap(), 2026020003);
    }

    #[test]
    fn version_to_token_without_patch() {
        assert_eq!(version_to_token("v2026.02").unwrap(), 2026020000);
    }

    #[test]
    fn version_to_token_high_patch() {
        assert_eq!(version_to_token("v2026.12.99").unwrap(), 2026120099);
    }

    #[test]
    fn version_to_token_no_v_prefix() {
        assert_eq!(version_to_token("2026.02.3").unwrap(), 2026020003);
    }

    #[test]
    fn version_to_token_invalid_format() {
        assert!(version_to_token("v2026").is_err());
        assert!(version_to_token("v2026.02.3.4").is_err());
        assert!(version_to_token("vfoo.02").is_err());
        assert!(version_to_token("v2026.bar").is_err());
    }

    #[test]
    fn version_to_token_invalid_month() {
        assert!(version_to_token("v2026.13").is_err());
        assert!(version_to_token("v2026.00").is_err());
    }

    #[test]
    fn token_to_version_with_patch() {
        assert_eq!(token_to_version(2026020003), "v2026.02.3");
    }

    #[test]
    fn token_to_version_without_patch() {
        assert_eq!(token_to_version(2026020000), "v2026.02");
    }

    #[test]
    fn token_to_version_high_patch() {
        assert_eq!(token_to_version(2026120099), "v2026.12.99");
    }

    #[test]
    fn token_version_round_trip() {
        let tags = &["v2026.02.3", "v2026.02", "v2026.12.99", "v2025.01.1"];
        for tag in tags {
            let token = version_to_token(tag).unwrap();
            assert_eq!(token_to_version(token), *tag);
        }
    }

    #[test]
    fn check_monotonic_succeeds_when_newer() {
        assert!(check_monotonic(2026020000, 2026020001).is_ok());
        assert!(check_monotonic(2026010000, 2026020000).is_ok());
    }

    #[test]
    fn check_monotonic_fails_when_equal() {
        let result = check_monotonic(2026020003, 2026020003);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("downgrade"), "got: {err}");
    }

    #[test]
    fn check_monotonic_fails_when_older() {
        let result = check_monotonic(2026020003, 2026020001);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("downgrade"), "got: {err}");
    }

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
last_creation_token = 2026020003
last_update = "2026-02-13T10:30:00Z"
"#,
        )
        .unwrap();

        let state = load_state(&path).unwrap().unwrap();
        assert_eq!(state.last_commit.unwrap(), "abc123def456");
        assert_eq!(state.last_creation_token.unwrap(), 2026020003);
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
            last_creation_token: Some(2026020003),
            last_update: Some("2026-02-16T12:00:00Z".into()),
        };
        save_state(&path, &state).unwrap();

        // Verify the file is still valid TOML and contains the state.
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[registry.signing]"));
        assert!(content.contains("public_key"));
        assert!(content.contains("[registry.state]"));
        assert!(content.contains("last_commit = \"deadbeef\""));
        assert!(content.contains("last_creation_token = 2026020003"));

        // Verify it round-trips through load_state.
        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.unwrap(), "deadbeef");
        assert_eq!(loaded.last_creation_token.unwrap(), 2026020003);
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
last_creation_token = 2026010000
last_update = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();

        let state = RegistryState {
            last_commit: Some("new_commit".into()),
            last_creation_token: Some(2026020003),
            last_update: Some("2026-02-16T12:00:00Z".into()),
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(!content.contains("old_commit"));
        assert!(content.contains("new_commit"));
        assert!(content.contains("2026020003"));

        // Verify user fields are preserved.
        assert!(content.contains("name = \"aos-core\""));
        assert!(content.contains("url = \"https://registry.aos.dev/core\""));

        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.last_commit.unwrap(), "new_commit");
        assert_eq!(loaded.last_creation_token.unwrap(), 2026020003);
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
            last_creation_token: Some(2026020001),
            last_update: None,
        };
        save_state(&path, &state).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("last_commit = \"new\""));
        // The signing section after state should be preserved.
        assert!(content.contains("[registry.signing]"));
        assert!(content.contains("public_key = \"test:Ed25519:abc\""));
    }
}
