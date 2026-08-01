//! The configuration manifest materializer for on-host configuration
//! evaluation.
//!
//! [`super::stock`] and [`super::run_fixpoint`] *produce* an
//! `aos.config-manifest/v1` document (`/run/aos/manifest.json`); this module
//! *applies* it, rendering the manifest's `/etc` tree into a per-generation
//! lower directory so a generation's `/etc` reflects the operator `host.nix`.
//! The manifest is the sole source of a generation's per-host `/etc`.
//!
//! # The manifest (`aos.config-manifest/v1`)
//!
//! The subset this materializer consumes — the `/etc` tree and the job scripts
//! its unit bodies reference:
//!
//! ```json
//! {
//!   "schema": "aos.config-manifest/v1",
//!   "etc": {
//!     "apm/registries.d/andyl.toml": { "kind": "text", "mode": "0644", "text": "…" },
//!     "localtime": { "kind": "store-symlink", "target": "/nix/store/…/UTC" },
//!     "systemd/system/getty.target.wants/getty@tty1.service":
//!         { "kind": "symlink", "target": "../getty@tty1.service" }
//!   },
//!   "jobScripts": {
//!     "aos-attest.service:ExecStart.0": { "mode": "0755", "name": "…", "text": "#!/…/bash\n…" }
//!   }
//! }
//! ```
//!
//! Each `etc` entry is written under a caller-supplied root:
//! - `text`  — a regular file with the given octal `mode`. Any
//!   `#aos-jobscript:<key>#` placeholder in the body (from the F2-A job-script
//!   inversion) is rewritten to the job script's materialized absolute path.
//! - `symlink` / `store-symlink` — a symlink to `target` (relative install
//!   symlinks and absolute `/nix/store` links respectively; both are created
//!   verbatim with `symlink(2)`).
//!
//! Every job script is written under `<root>/aos-job-scripts/<key>` (mode
//! `0755`), and the placeholder rewrite points unit `Exec*=` lines at
//! `<job_scripts_runtime_dir>/<key>` — the path that directory has once the
//! lower is mounted as `/etc`.
//!
//! `users`, `presets`, and `units` are carried by the manifest too, but the
//! `/etc` materialization here consumes only `etc` + `jobScripts`; the others
//! are applied by their own reconcilers (users via the passwd path, presets are
//! already `etc` entries under `systemd/system-preset/`).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The runtime directory a materialized job script resolves to once the
/// per-generation lower is mounted at `/etc`. Unit `Exec*=` placeholders are
/// rewritten to `<this>/<key>`.
pub const DEFAULT_JOB_SCRIPTS_RUNTIME_DIR: &str = "/etc/aos-job-scripts";

/// The subdirectory (relative to the materialization root) that job scripts are
/// written into. Kept in lockstep with [`DEFAULT_JOB_SCRIPTS_RUNTIME_DIR`]'s
/// final path component.
const JOB_SCRIPTS_SUBDIR: &str = "aos-job-scripts";

/// The `aos.config-manifest/v1` document, deserialized from the JSON the
/// on-host evaluator writes. Only the fields the materializer consumes are
/// modeled; unknown fields (`users`, `presets`, `storePaths`, `units`,
/// `module_abi`, `inputs`) are ignored.
#[derive(Debug, Deserialize)]
pub struct ConfigManifest {
    /// The schema tag; must be [`Self::SCHEMA`].
    pub schema: String,
    /// The `/etc` tree keyed by target path (relative to `/etc`).
    #[serde(default)]
    pub etc: BTreeMap<String, EtcEntry>,
    /// Job-script bodies keyed by `<unit>:<slot>.<index>`.
    #[serde(rename = "jobScripts", default)]
    pub job_scripts: BTreeMap<String, JobScript>,
}

impl ConfigManifest {
    /// The only schema tag this materializer understands.
    pub const SCHEMA: &'static str = "aos.config-manifest/v1";
}

/// One `/etc` entry, discriminated by its `kind` tag.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EtcEntry {
    /// Inline file content written with an explicit octal mode.
    Text {
        /// The file body. `#aos-jobscript:<key>#` placeholders are rewritten.
        text: String,
        /// The octal mode string, e.g. `"0644"`.
        mode: String,
    },
    /// A symlink whose `target` is a relative install-symlink path
    /// (e.g. `../getty@tty1.service`).
    Symlink {
        /// The verbatim symlink target.
        target: String,
    },
    /// A symlink whose `target` is an absolute `/nix/store` path.
    StoreSymlink {
        /// The verbatim symlink target.
        target: String,
    },
}

/// A job-script body written to `<root>/aos-job-scripts/<key>`.
#[derive(Debug, Deserialize)]
pub struct JobScript {
    /// The script body (including its `#!` interpreter line).
    pub text: String,
    /// The octal mode string, e.g. `"0755"`.
    pub mode: String,
}

/// Reads the manifest at `manifest_path` and applies its `/etc` tree under
/// `etc_root`, writing job scripts under `<etc_root>/aos-job-scripts/` and
/// rewriting unit-body placeholders to `<job_scripts_runtime_dir>/<key>`.
///
/// This is idempotent: existing files at target paths are overwritten and
/// existing symlinks are replaced, so re-materializing the same manifest is a
/// no-op in effect.
///
/// # Errors
///
/// Returns an error if the manifest cannot be read or parsed, if its `schema`
/// tag is not [`ConfigManifest::SCHEMA`], or if any filesystem write fails.
pub fn materialize_manifest(
    manifest_path: &Path,
    etc_root: &Path,
    job_scripts_runtime_dir: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: ConfigManifest = serde_json::from_str(&raw)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    apply(&manifest, etc_root, job_scripts_runtime_dir)
}

/// Applies an already-parsed [`ConfigManifest`] under `etc_root`.
///
/// Split from [`materialize_manifest`] so the pure rendering logic is unit
/// testable without touching a real manifest file.
///
/// # Errors
///
/// Returns an error if the schema tag is wrong or any filesystem write fails.
pub fn apply(
    manifest: &ConfigManifest,
    etc_root: &Path,
    job_scripts_runtime_dir: &str,
) -> Result<()> {
    if manifest.schema != ConfigManifest::SCHEMA {
        bail!(
            "unsupported config-manifest schema {:?} (expected {:?})",
            manifest.schema,
            ConfigManifest::SCHEMA
        );
    }

    // 1. Job scripts first: their materialized paths are what the unit-body
    //    placeholder rewrite below points at.
    let job_dir = etc_root.join(JOB_SCRIPTS_SUBDIR);
    let mut placeholders: Vec<(String, String)> = Vec::with_capacity(manifest.job_scripts.len());
    for (key, script) in &manifest.job_scripts {
        let dest = job_dir.join(key);
        write_file(&dest, script.text.as_bytes(), &script.mode)
            .with_context(|| format!("writing job script {key}"))?;
        placeholders.push((
            format!("#aos-jobscript:{key}#"),
            format!("{}/{key}", job_scripts_runtime_dir.trim_end_matches('/')),
        ));
    }

    // 2. The /etc tree.
    for (target, entry) in &manifest.etc {
        let dest = etc_root.join(target);
        match entry {
            EtcEntry::Text { text, mode } => {
                let rendered = substitute_placeholders(text, &placeholders);
                write_file(&dest, rendered.as_bytes(), mode)
                    .with_context(|| format!("writing /etc/{target}"))?;
            }
            EtcEntry::Symlink { target: link } | EtcEntry::StoreSymlink { target: link } => {
                write_symlink(&dest, link)
                    .with_context(|| format!("linking /etc/{target} -> {link}"))?;
            }
        }
    }

    Ok(())
}

/// Rewrites every `#aos-jobscript:<key>#` placeholder in `body` to its
/// materialized job-script path. `replacements` pairs are
/// `(placeholder, absolute_path)`.
fn substitute_placeholders(body: &str, replacements: &[(String, String)]) -> String {
    let mut out = body.to_string();
    for (placeholder, path) in replacements {
        if out.contains(placeholder.as_str()) {
            out = out.replace(placeholder.as_str(), path);
        }
    }
    out
}

/// Writes `contents` to `dest` with octal `mode`, creating parent directories.
/// Overwrites any existing file (idempotent re-materialization).
///
/// # Errors
///
/// Returns an error if `mode` is not a valid octal string or any filesystem
/// operation fails.
fn write_file(dest: &Path, contents: &[u8], mode: &str) -> Result<()> {
    let perm = parse_octal_mode(mode)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Replace any existing file OR symlink at the destination.
    let _ = std::fs::remove_file(dest);
    std::fs::write(dest, contents).with_context(|| format!("writing {}", dest.display()))?;
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(perm))
        .with_context(|| format!("chmod {:o} {}", perm, dest.display()))?;
    Ok(())
}

/// Creates a symlink at `dest` pointing at `target`, creating parent
/// directories and replacing any existing entry (idempotent).
///
/// # Errors
///
/// Returns an error if any filesystem operation fails.
fn write_symlink(dest: &Path, target: &str) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(dest);
    std::os::unix::fs::symlink(target, dest)
        .with_context(|| format!("symlink {} -> {target}", dest.display()))?;
    Ok(())
}

/// Parses a 3- or 4-digit octal mode string (e.g. `"0644"`) into a `u32`.
///
/// # Errors
///
/// Returns an error if `mode` is not valid octal.
fn parse_octal_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("invalid octal mode {mode:?}"))
}

/// Emits the set of unit-body placeholders a manifest declares. Exposed for
/// callers that want to inspect the job-script wiring without materializing.
///
/// The returned paths use [`DEFAULT_JOB_SCRIPTS_RUNTIME_DIR`].
pub fn job_script_placeholders(manifest: &ConfigManifest) -> Vec<(String, PathBuf)> {
    manifest
        .job_scripts
        .keys()
        .map(|key| {
            (
                format!("#aos-jobscript:{key}#"),
                PathBuf::from(DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).join(key),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_from(json: &str) -> ConfigManifest {
        serde_json::from_str(json).expect("valid manifest json")
    }

    #[test]
    fn rejects_unknown_schema() {
        let m = manifest_from(r#"{ "schema": "wrong/v9", "etc": {}, "jobScripts": {} }"#);
        let dir = tempdir();
        let err = apply(&m, &dir, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported config-manifest schema"),
            "{err}"
        );
    }

    #[test]
    fn writes_text_entry_with_mode() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "apm/registries.d/x.toml": { "kind": "text", "mode": "0640", "text": "hello\n" } },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        let f = root.join("apm/registries.d/x.toml");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello\n");
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode {mode:o}");
    }

    #[test]
    fn creates_relative_and_store_symlinks() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd/system/getty.target.wants/getty@tty1.service":
                     { "kind": "symlink", "target": "../getty@tty1.service" },
                   "localtime": { "kind": "store-symlink", "target": "/nix/store/abc-tzdata/UTC" }
                 },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        let wants = root.join("systemd/system/getty.target.wants/getty@tty1.service");
        assert_eq!(
            std::fs::read_link(&wants).unwrap().to_str().unwrap(),
            "../getty@tty1.service"
        );
        let lt = root.join("localtime");
        assert_eq!(
            std::fs::read_link(&lt).unwrap().to_str().unwrap(),
            "/nix/store/abc-tzdata/UTC"
        );
    }

    #[test]
    fn materializes_job_script_and_rewrites_placeholder() {
        let m = manifest_from(
            r##"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd/system/svc.service":
                     { "kind": "text", "mode": "0644",
                       "text": "[Service]\nExecStart=#aos-jobscript:svc.service:ExecStart.0# --flag\n" }
                 },
                 "jobScripts": {
                   "svc.service:ExecStart.0": { "mode": "0755", "name": "svc-start", "text": "#!/bin/sh\necho hi\n" }
                 } }"##,
        );
        let root = tempdir();
        apply(&m, &root, "/etc/aos-job-scripts").unwrap();

        // The job script is written under aos-job-scripts/<key> mode 0755.
        let js = root.join("aos-job-scripts/svc.service:ExecStart.0");
        assert_eq!(
            std::fs::read_to_string(&js).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
        assert_eq!(
            std::fs::metadata(&js).unwrap().permissions().mode() & 0o777,
            0o755
        );

        // The unit body's placeholder is rewritten to the materialized path.
        let unit = std::fs::read_to_string(root.join("systemd/system/svc.service")).unwrap();
        assert!(
            unit.contains("ExecStart=/etc/aos-job-scripts/svc.service:ExecStart.0 --flag"),
            "unit body not rewritten: {unit}"
        );
        assert!(
            !unit.contains("#aos-jobscript:"),
            "placeholder left behind: {unit}"
        );
    }

    #[test]
    fn is_idempotent_over_reruns() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "hostname": { "kind": "text", "mode": "0644", "text": "host-a\n" } },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("hostname")).unwrap(),
            "host-a\n"
        );
    }

    #[test]
    fn text_entry_replaces_an_existing_symlink() {
        // A path that was a symlink in a prior generation and is a text file now
        // must be replaced, not have the write follow the dangling link.
        let root = tempdir();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("/nonexistent", root.join("hostname")).unwrap();
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "hostname": { "kind": "text", "mode": "0644", "text": "host-b\n" } },
                 "jobScripts": {} }"#,
        );
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("hostname")).unwrap(),
            "host-b\n"
        );
    }

    /// Creates a unique temp dir under the process temp root. Avoids a
    /// dev-dependency; the path includes the test thread id for isolation.
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "aos-materialize-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
