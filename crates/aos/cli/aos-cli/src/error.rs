//! User-facing command failures and process exit conventions.
//!
//! Library crates report their own domain errors. This module translates those
//! errors and application argument failures into the existing CLI exit codes.

use aos_nar::verify::NarVerificationError;
use aos_nix::error::NixError;
use aos_package_manager::error::PackageError;
use thiserror::Error;

/// Describes an application command that could not complete.
#[derive(Debug, Error)]
pub(crate) enum CliError {
    /// Indicates an invalid argument or flag combination.
    #[error("{message}")]
    InvalidArgument { message: String },
    /// Indicates an interrupted command with retained resumable state.
    #[error("{message}")]
    Interrupted { message: String },
}

/// Selects the existing command-family exit status from typed domain errors.
pub(crate) fn exit_code(error: &anyhow::Error) -> i32 {
    if let Some(error) = error.downcast_ref::<CliError>() {
        return match error {
            CliError::InvalidArgument { .. } => 2,
            CliError::Interrupted { .. } => 130,
        };
    }
    if let Some(error) = error.downcast_ref::<NixError>() {
        return match error {
            NixError::NixBuild { .. } | NixError::NixEval { .. } => 1,
            NixError::NixNotFound | NixError::RootNotFound => 3,
        };
    }
    if error.downcast_ref::<NarVerificationError>().is_some() {
        return 4;
    }
    if let Some(error) = error.downcast_ref::<PackageError>() {
        return match error {
            PackageError::InvalidArgument { .. } | PackageError::PackageNotFound { .. } => 2,
            PackageError::DownloadError { .. } => 3,
            PackageError::HashMismatch { .. } => 4,
            PackageError::UserCancelled => 100,
            PackageError::Interrupted { .. } => 130,
            PackageError::RegistryError { .. }
            | PackageError::ProfileError { .. }
            | PackageError::RegistryHasPackages { .. } => 1,
        };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_domain_exit_codes_through_context() {
        let cases = [
            (anyhow::Error::from(NixError::NixNotFound), 3),
            (anyhow::Error::from(NixError::RootNotFound), 3),
            (
                anyhow::Error::from(NixError::NixBuild {
                    exit_code: 17,
                    stderr: "failure".into(),
                }),
                1,
            ),
            (
                anyhow::Error::from(NarVerificationError::HashMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                }),
                4,
            ),
            (anyhow::Error::from(PackageError::UserCancelled), 100),
            (
                anyhow::Error::from(PackageError::HashMismatch {
                    expected: "a".into(),
                    actual: "b".into(),
                }),
                4,
            ),
            (
                anyhow::Error::from(PackageError::DownloadError {
                    message: "offline".into(),
                }),
                3,
            ),
            (
                anyhow::Error::from(PackageError::PackageNotFound {
                    name: "missing".into(),
                }),
                2,
            ),
            (
                anyhow::Error::from(CliError::Interrupted {
                    message: "interrupted".into(),
                }),
                130,
            ),
            (
                anyhow::Error::from(CliError::InvalidArgument {
                    message: "bad argument".into(),
                }),
                2,
            ),
            (anyhow::anyhow!("untyped error"), 1),
        ];
        for (error, expected) in cases {
            assert_eq!(exit_code(&error.context("outer operation")), expected);
        }
    }
}
