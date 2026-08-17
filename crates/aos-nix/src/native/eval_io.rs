//! Small evaluation I/O helpers for the native entry points.
//!
//! Outcome-to-JSON extraction, instantiation source-file resolution, and the
//! restrict-eval filesystem access check shared by the `NixNative` methods in
//! the parent module.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use ratchet_oracle::eval::tree_walk::{
    EvalOutcome, TreeWalkOptions, canonicalize_policy_path, normalize_absolute_path_bytes,
};

use super::{EvalMode, NativeEvalError, Result, path_bytes};

pub(super) fn json_string_from_outcome(outcome: &EvalOutcome) -> Result<String> {
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .map_err(|source| NativeEvalError::Internal {
            message: format!("JSON renderer returned a non-string value: {source}"),
        })?;
    String::from_utf8(string.bytes().to_vec()).map_err(|source| {
        NativeEvalError::Internal {
            message: format!("JSON renderer returned non-UTF-8 bytes: {source}"),
        }
        .into()
    })
}

pub(super) fn native_source_file(file: &Path, options: &TreeWalkOptions) -> Result<PathBuf> {
    let requested = PathBuf::from(std::ffi::OsString::from_vec(path_bytes(file)?));
    check_native_filesystem_path_access(options, requested.as_os_str().as_bytes())?;
    let metadata = fs::metadata(&requested).map_err(|source| NativeEvalError::EvalError {
        message: format!(
            "failed to stat native instantiation source {}: {source}",
            requested.display()
        ),
    })?;
    let target = if metadata.is_dir() {
        let target = requested.join("default.nix");
        check_native_filesystem_path_access(options, target.as_os_str().as_bytes())?;
        target
    } else {
        requested
    };
    fs::canonicalize(&target).map_err(|source| {
        NativeEvalError::EvalError {
            message: format!(
                "failed to resolve native instantiation source {}: {source}",
                target.display()
            ),
        }
        .into()
    })
}

pub(super) fn check_native_filesystem_path_access(
    options: &TreeWalkOptions,
    path: &[u8],
) -> Result<()> {
    if options.eval_mode() == EvalMode::Impure {
        return Ok(());
    }
    if !Path::new(OsStr::from_bytes(path)).is_absolute() {
        return Err(NativeEvalError::EvalError {
            message: format!(
                "{:?} evaluation requires an absolute native instantiation source path: {}",
                options.eval_mode(),
                String::from_utf8_lossy(path)
            ),
        }
        .into());
    }

    let normalized = normalize_absolute_path_bytes(path);
    if options.path_is_allowed(&normalized) {
        if let Some(resolved) = canonicalize_policy_path(path) {
            if !options.resolved_path_is_allowed(&resolved) {
                return Err(native_filesystem_access_denied(options.eval_mode(), &resolved).into());
            }
        }
        return Ok(());
    }

    Err(native_filesystem_access_denied(options.eval_mode(), &normalized).into())
}

pub(super) fn native_filesystem_access_denied(mode: EvalMode, path: &[u8]) -> NativeEvalError {
    NativeEvalError::EvalError {
        message: format!(
            "{mode:?} evaluation forbids filesystem access to native instantiation source {}",
            String::from_utf8_lossy(path)
        ),
    }
}
