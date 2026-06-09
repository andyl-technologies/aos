//! Helpers for adapting user-facing messages to how the CLI was invoked.
//!
//! The `aos` binary ships under several names. When run as `apm` it behaves as
//! `aos package`, and when run as `apr` it behaves as `aos package registry`
//! (see the argv\[0\] dispatch in the binary's `main`). Hint messages such as
//! "add one with `… add <url>`" should echo the name the user actually typed
//! rather than always naming `apm`, so this module derives that prefix from
//! `argv[0]`.

use std::path::Path;

/// Returns the normalised name of the currently-running binary.
///
/// The name is taken from the file component of `argv[0]`, with a leading `.`
/// and a trailing `-unwrapped` removed so that wrapper scripts which
/// `exec .apm-unwrapped` are still recognised as `apm`.
///
/// # Examples
///
/// ```no_run
/// // When the process was started as `/usr/bin/apr`:
/// assert_eq!(aos_core::invocation::binary_name(), "apr");
/// ```
pub fn binary_name() -> String {
    let argv0 = std::env::args().next().unwrap_or_default();
    let raw = Path::new(&argv0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    normalize(&raw)
}

/// Strips a leading `.` and a trailing `-unwrapped` from a raw binary name.
fn normalize(raw: &str) -> String {
    let stripped = raw.strip_prefix('.').unwrap_or(raw);
    stripped
        .strip_suffix("-unwrapped")
        .unwrap_or(stripped)
        .to_string()
}

/// Returns the command users should type to reach package-manager subcommands
/// (`update`, `remove`, `install`, …), matching how the tool was invoked.
///
/// - invoked as `apm` → `"apm"`
/// - invoked as `apr` → `"apm"` (the registry-only `apr` cannot run
///   package-manager commands, so its sibling `apm` is suggested instead)
/// - anything else (e.g. `aos`) → `"aos package"`
///
/// Use this for hints that point at package-manager commands. For commands
/// under the `registry` subtree, use [`package_registry_command`] instead.
///
/// # Examples
///
/// ```no_run
/// let cmd = aos_core::invocation::package_manager_command();
/// println!("Run `{cmd} update` to sync.");
/// ```
pub fn package_manager_command() -> &'static str {
    package_manager_command_for(&binary_name())
}

/// Maps a normalised binary name to its package-manager command prefix.
fn package_manager_command_for(name: &str) -> &'static str {
    match name {
        "apm" | "apr" => "apm",
        _ => "aos package",
    }
}

/// Returns the command users should type to reach `registry` subcommands,
/// matching how the tool was invoked.
///
/// - invoked as `apr` → `"apr"`
/// - invoked as `apm` → `"apm registry"`
/// - anything else (e.g. `aos`) → `"aos package registry"`
///
/// Use this when building hint messages so the suggested command echoes the
/// name the user actually ran. For package-manager commands outside the
/// `registry` subtree, use [`package_manager_command`] instead.
///
/// # Examples
///
/// ```no_run
/// let cmd = aos_core::invocation::package_registry_command();
/// println!("Add one with `{cmd} add <url>`.");
/// ```
pub fn package_registry_command() -> &'static str {
    package_registry_command_for(&binary_name())
}

/// Maps a normalised binary name to its `registry` command prefix.
fn package_registry_command_for(name: &str) -> &'static str {
    match name {
        "apr" => "apr",
        "apm" => "apm registry",
        _ => "aos package registry",
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize, package_manager_command_for, package_registry_command_for};

    #[test]
    fn normalize_plain_name_is_unchanged() {
        assert_eq!(normalize("apm"), "apm");
        assert_eq!(normalize("apr"), "apr");
        assert_eq!(normalize("aos"), "aos");
    }

    #[test]
    fn normalize_strips_unwrapped_suffix() {
        assert_eq!(normalize("apm-unwrapped"), "apm");
    }

    #[test]
    fn normalize_strips_leading_dot() {
        assert_eq!(normalize(".apm"), "apm");
    }

    #[test]
    fn normalize_strips_dot_and_unwrapped_together() {
        assert_eq!(normalize(".apm-unwrapped"), "apm");
        assert_eq!(normalize(".apr-unwrapped"), "apr");
    }

    #[test]
    fn package_manager_command_matches_invocation() {
        assert_eq!(package_manager_command_for("apm"), "apm");
        // `apr` is registry-only, so package-manager hints fall back to `apm`.
        assert_eq!(package_manager_command_for("apr"), "apm");
        assert_eq!(package_manager_command_for("aos"), "aos package");
    }

    #[test]
    fn package_registry_command_matches_invocation() {
        assert_eq!(package_registry_command_for("apr"), "apr");
        assert_eq!(package_registry_command_for("apm"), "apm registry");
        assert_eq!(package_registry_command_for("aos"), "aos package registry");
    }
}
