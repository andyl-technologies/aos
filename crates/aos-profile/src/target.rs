//! Resolution of a user-supplied profiling target to a store path.
//!
//! A target is whatever the user types after `aos profile`. It is
//! either an already-realised store path or a Nix attribute that must be
//! built first. This module owns only the *parsing* of the spec into a
//! [`Target`]; realising an [`Target::Attr`] needs a project-rooted
//! `NixRunner`, which lives in the `aos` binary, so the caller performs
//! the build and hands the resulting path to [`closure`](crate::closure).

/// A parsed profiling target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An absolute store path that already exists and can be profiled
    /// directly (`/nix/store/…` or an `AOS_ROOT`-relative store path).
    StorePath(String),
    /// A Nix attribute to build first, e.g. `pkgs.systemd` or
    /// `system.config.system.build.toplevel`.
    Attr(String),
}

/// Parses a target spec into a [`Target`].
///
/// The heuristics mirror the other `aos` subcommands so the CLI feels
/// consistent:
///
/// - A spec beginning with `/` is taken as a literal store path.
/// - A spec containing a `.` is a fully-qualified attribute path (Nix
///   package names never contain dots), used verbatim.
/// - Anything else is a bare package name and is prefixed with `pkgs.`,
///   matching `aos graph` and `aos why-depends`.
///
/// # Examples
///
/// ```no_run
/// use aos_profile::target::{resolve, Target};
///
/// assert_eq!(resolve("systemd"), Target::Attr("pkgs.systemd".into()));
/// assert_eq!(
///     resolve("system.config.system.build.toplevel"),
///     Target::Attr("system.config.system.build.toplevel".into()),
/// );
/// assert!(matches!(resolve("/nix/store/abc-foo"), Target::StorePath(_)));
/// ```
pub fn resolve(spec: &str) -> Target {
    if spec.starts_with('/') {
        Target::StorePath(spec.to_string())
    } else if spec.contains('.') {
        Target::Attr(spec.to_string())
    } else {
        Target::Attr(format!("pkgs.{spec}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_is_package_attr() {
        assert_eq!(resolve("jq"), Target::Attr("pkgs.jq".into()));
    }

    #[test]
    fn dotted_name_is_verbatim_attr() {
        assert_eq!(
            resolve("system.config.system.build.toplevel"),
            Target::Attr("system.config.system.build.toplevel".into()),
        );
    }

    #[test]
    fn absolute_path_is_store_path() {
        assert_eq!(
            resolve("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foo-1.0"),
            Target::StorePath("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foo-1.0".into()),
        );
    }
}
