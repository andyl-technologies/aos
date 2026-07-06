//! Stable digest over the result-affecting subset of `TreeWalkOptions`.
//!
//! Isolates the [`result_affecting_fingerprint`] reducer that folds every option
//! able to change an expression's derivation closure — but not otherwise
//! captured by the impure-input trace — into one BLAKE3 digest. The digest is a
//! component of the durable root-record cutoff key, so its byte layout is a
//! stability contract: each field is length-tagged and labeled so no two field
//! sets can alias, and the domain string is versioned.

use super::*;

/// Computes a stable digest over the result-affecting evaluator settings.
///
/// Path-resolution configuration (store dir, search-path bases, `NIX_PATH`,
/// home and corepkgs directories) is included because a change to it can
/// redirect a lookup to a different file that replaying the recorded per-path
/// observations would not detect. Pure performance and cache-plumbing knobs and
/// the environment-variable map are excluded: the latter's observed reads are
/// already covered fingerprint-by-fingerprint by the trace.
pub(super) fn result_affecting_fingerprint(options: &TreeWalkOptions) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"aos-nix-treewalk-result-affecting-v1");
    let mut field = |label: &[u8], bytes: &[u8]| {
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(b"store_dir", &options.store_dir);
    field(b"search_path_base", &options.search_path_base);
    match &options.path_literal_base {
        Some(base) => field(b"path_literal_base", base),
        None => field(b"path_literal_base_unset", &[]),
    }
    match &options.home_dir {
        Some(home) => field(b"home_dir", home),
        None => field(b"home_dir_unset", &[]),
    }
    field(b"eval_mode", &[options.eval_mode as u8]);
    field(
        b"allowed_path_count",
        &(options.allowed_paths.len() as u64).to_le_bytes(),
    );
    for path in &options.allowed_paths {
        field(b"allowed_path", path);
    }
    field(
        b"allowed_uri_count",
        &(options.allowed_uris.len() as u64).to_le_bytes(),
    );
    for uri in &options.allowed_uris {
        field(b"allowed_uri", uri);
    }
    match &options.current_system {
        Some(system) => field(b"current_system", system),
        None => field(b"current_system_unset", &[]),
    }
    match options.current_time {
        Some(time) => field(b"current_time", &time.to_le_bytes()),
        None => field(b"current_time_unset", &[]),
    }
    field(
        b"parse_toml_timestamps",
        &[options.parse_toml_timestamps as u8],
    );
    field(b"abort_on_warn", &[options.abort_on_warn as u8]);
    field(
        b"max_call_depth",
        &(options.max_call_depth as u64).to_le_bytes(),
    );
    field(
        b"reject_ambient_search_path",
        &[options.reject_ambient_search_path as u8],
    );
    field(
        b"reject_unconfigured_impure_builtin_constants",
        &[options.reject_unconfigured_impure_builtin_constants as u8],
    );
    field(
        b"nix_path_count",
        &(options.nix_path.len() as u64).to_le_bytes(),
    );
    for entry in &options.nix_path {
        field(b"nix_path_prefix", entry.prefix());
        field(b"nix_path_path", entry.path());
    }
    match &options.corepkgs_path {
        Some(path) => field(b"corepkgs_path", path),
        None => field(b"corepkgs_path_unset", &[]),
    }
    field(
        b"flake_ref_count",
        &(options.flake_ref_resolutions.len() as u64).to_le_bytes(),
    );
    for (indirect, target) in &options.flake_ref_resolutions {
        field(b"flake_ref_indirect", indirect);
        field(b"flake_ref_target", target);
    }
    *hasher.finalize().as_bytes()
}
