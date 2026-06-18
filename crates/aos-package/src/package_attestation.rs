//! Package-set TPM measurement for RFC-0001 runtime attestation.
//!
//! Activation writes an AOS package event log at
//! `/run/log/aos-packages.cel` and, on the live system root, extends PCR 15
//! through AOS-built `systemd-pcrextend`. The measured package tuple is:
//!
//! ```text
//! H(name || version || root-digest || manifest-digest)
//! ```
//!
//! The implementation uses a stable length-prefixed text encoding for the
//! tuple so a verifier can replay the event log without guessing separators.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::types::{ApmMeta, InstalledMeta};

const AOS_PACKAGE_CEL_REL: &str = "run/log/aos-packages.cel";
const PCR_EXTEND_ENV: &str = "AOS_SYSTEMD_PCREXTEND";
const PCR_INDEX: u8 = 15;
const PCR_BANK: &str = "sha256";
const PACKAGE_EVENT_TYPE: &str = "aos-package";
const PACKAGE_SET_EVENT_TYPE: &str = "aos-package-set";

/// Measures the activated exposed package set into PCR 15.
///
/// The event log is rooted at `root` so tests and image construction can
/// exercise the same code against an alternate filesystem. PCR extension runs
/// only for the live `/` root; non-live roots still get deterministic event
/// log contents.
///
/// # Errors
///
/// Returns an error if package metadata cannot be converted into measurement
/// events, the event log cannot be written, or live PCR extension fails.
pub(crate) fn measure_activated_packages(root: &Path, installed: &[InstalledMeta]) -> Result<()> {
    let events = measurement_events(root, installed)?;
    append_event_log(root, &events)?;
    if root == Path::new("/") {
        let pcrextend = trusted_systemd_pcrextend_path()?;
        extend_pcr15(&pcrextend, &events)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasurementEvent {
    event_type: &'static str,
    word: String,
    digest: String,
    package: Option<MeasuredPackage>,
    package_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasuredPackage {
    name: String,
    version: String,
    root_digest: String,
    manifest_digest: String,
}

#[derive(Serialize)]
struct EventLogRecord<'a> {
    format: &'static str,
    pcr: u8,
    bank: &'static str,
    event_type: &'static str,
    digest: &'a str,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_count: Option<usize>,
}

fn measurement_events(root: &Path, installed: &[InstalledMeta]) -> Result<Vec<MeasurementEvent>> {
    let mut packages = installed
        .iter()
        .filter_map(|entry| {
            let apm = entry.apm.as_ref()?;
            if !apm.explicit || apm.expose.is_none() {
                return None;
            }
            Some(measured_package(root, entry, apm))
        })
        .collect::<Result<Vec<_>>>()?;
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
            .then(left.root_digest.cmp(&right.root_digest))
    });

    let mut events = Vec::with_capacity(packages.len() + 1);
    let package_events = packages
        .into_iter()
        .map(package_event)
        .collect::<Result<Vec<_>>>()?;
    events.push(package_set_event(&package_events));
    events.extend(package_events);
    Ok(events)
}

fn measured_package(root: &Path, entry: &InstalledMeta, apm: &ApmMeta) -> Result<MeasuredPackage> {
    let root_digest = package_root_digest(entry, apm);
    let manifest_digest = package_manifest_digest(root, apm)?;
    let package = MeasuredPackage {
        name: apm.name.clone(),
        version: apm.version.clone(),
        root_digest,
        manifest_digest,
    };

    if let Some(expected) = &apm.attestation.measurement {
        let expected = canonical_digest(expected);
        let actual = package_measurement_digest(
            &package.name,
            &package.version,
            &package.root_digest,
            &package.manifest_digest,
        );
        if expected != actual {
            bail!(
                "attestation measurement for package '{}' does not match installed metadata",
                apm.name
            );
        }
    }

    Ok(package)
}

fn package_root_digest(entry: &InstalledMeta, apm: &ApmMeta) -> String {
    if let Some(root_hash) = &apm.attestation.root_hash {
        return canonical_digest(root_hash);
    }

    if let Some(expose) = &apm.expose
        && let Some(root_hash) = expose
            .images
            .iter()
            .find_map(|image| image.root_hash.as_deref())
    {
        return canonical_digest(root_hash);
    }

    canonical_digest(&entry.apm.as_ref().map_or_else(
        || entry.store_path.clone(),
        |apm| {
            if apm.source_nar_hash.is_empty() {
                entry.store_path.clone()
            } else {
                apm.source_nar_hash.clone()
            }
        },
    ))
}

fn package_manifest_digest(root: &Path, apm: &ApmMeta) -> Result<String> {
    if let Some(artifact) = &apm.expose_artifact {
        let manifest = Path::new(&artifact.store_path).join("manifest.json");
        if manifest.is_file() {
            let bytes = fs::read(&manifest)
                .with_context(|| format!("reading expose manifest {}", manifest.display()))?;
            return Ok(package_manifest_digest_bytes(&bytes));
        }
        if root == Path::new("/") {
            bail!(
                "exposed package '{}' is missing signed manifest at {}",
                apm.name,
                manifest.display()
            );
        }
    }

    let bytes = serde_json::to_vec(&apm.permissions)
        .with_context(|| format!("serializing permissions for package '{}'", apm.name))?;
    Ok(package_manifest_digest_bytes(&bytes))
}

/// Returns the RFC-0001 golden package measurement tuple digest.
pub(crate) fn package_measurement_digest(
    name: &str,
    version: &str,
    root_digest: &str,
    manifest_digest: &str,
) -> String {
    let package = MeasuredPackage {
        name: name.to_string(),
        version: version.to_string(),
        root_digest: canonical_digest(root_digest),
        manifest_digest: canonical_digest(manifest_digest),
    };
    format!("sha256:{}", digest_for_word(&package_tuple_word(&package)))
}

/// Returns the manifest digest format used in package measurement events.
pub(crate) fn package_manifest_digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_hex(bytes))
}

fn package_event(package: MeasuredPackage) -> Result<MeasurementEvent> {
    let word = package_tuple_word(&package);
    let digest = format!("sha256:{}", digest_for_word(&word));
    Ok(MeasurementEvent {
        event_type: PACKAGE_EVENT_TYPE,
        word,
        digest,
        package: Some(package),
        package_count: None,
    })
}

fn package_set_event(package_events: &[MeasurementEvent]) -> MeasurementEvent {
    let digests = package_events
        .iter()
        .map(|event| event.digest.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let word = length_prefixed_word(
        "aos-package-set-v1",
        &[
            ("package-count", package_events.len().to_string()),
            ("package-digests", digests),
        ],
    );
    let digest = format!("sha256:{}", digest_for_word(&word));
    MeasurementEvent {
        event_type: PACKAGE_SET_EVENT_TYPE,
        word,
        digest,
        package: None,
        package_count: Some(package_events.len()),
    }
}

fn package_tuple_word(package: &MeasuredPackage) -> String {
    length_prefixed_word(
        "aos-package-v1",
        &[
            ("name", package.name.clone()),
            ("version", package.version.clone()),
            ("root-digest", package.root_digest.clone()),
            ("manifest-digest", package.manifest_digest.clone()),
        ],
    )
}

fn length_prefixed_word(schema: &str, fields: &[(&str, String)]) -> String {
    let mut word = String::from(schema);
    for (name, value) in fields {
        word.push('|');
        word.push_str(name);
        word.push('=');
        word.push_str(&value.len().to_string());
        word.push(':');
        word.push_str(value);
    }
    word
}

fn extend_pcr15(pcrextend: &Path, events: &[MeasurementEvent]) -> Result<()> {
    for event in events {
        let status = Command::new(pcrextend)
            .arg("--graceful")
            .arg(format!("--bank={PCR_BANK}"))
            .arg(format!("--pcr={PCR_INDEX}"))
            .arg(&event.word)
            .status()
            .with_context(|| format!("running {}", pcrextend.display()))?;
        if !status.success() {
            bail!(
                "{} failed to extend PCR {PCR_INDEX}: {status}",
                pcrextend.display()
            );
        }
    }
    Ok(())
}

fn append_event_log(root: &Path, events: &[MeasurementEvent]) -> Result<()> {
    let path = rooted_absolute_path(root, Path::new("/").join(AOS_PACKAGE_CEL_REL).as_path())?;
    let parent = path
        .parent()
        .with_context(|| format!("event log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    for event in events {
        let line = event_log_line(event)?;
        writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn event_log_line(event: &MeasurementEvent) -> Result<String> {
    let package = event.package.as_ref();
    let record = EventLogRecord {
        format: "aos-package-cel-v1",
        pcr: PCR_INDEX,
        bank: PCR_BANK,
        event_type: event.event_type,
        digest: &event.digest,
        event: &event.word,
        package: package.map(|package| package.name.as_str()),
        version: package.map(|package| package.version.as_str()),
        root_digest: package.map(|package| package.root_digest.as_str()),
        manifest_digest: package.map(|package| package.manifest_digest.as_str()),
        package_count: event.package_count,
    };
    serde_json::to_string(&record).context("serializing package measurement event")
}

fn trusted_systemd_pcrextend_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(PCR_EXTEND_ENV) {
        if path.is_empty() {
            bail!("{PCR_EXTEND_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/lib/systemd/systemd-pcrextend") {
            bail!("{PCR_EXTEND_ENV} must point to an absolute systemd-pcrextend binary");
        }
        return Ok(PathBuf::from(path));
    }

    #[cfg(test)]
    {
        return Ok(PathBuf::from(
            "/nix/store/hash-systemd-0/lib/systemd/systemd-pcrextend",
        ));
    }

    #[cfg(not(test))]
    {
        bail!("{PCR_EXTEND_ENV} is not configured for package-set measurement");
    }
}

fn rooted_absolute_path(root: &Path, path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("path must be absolute: {}", path.display());
    }
    Ok(root.join(path.strip_prefix("/").unwrap_or(path)))
}

fn canonical_digest(value: &str) -> String {
    let value = value.trim();
    let digest = value
        .strip_prefix("sha256:")
        .or_else(|| value.strip_prefix("sha256-"));
    if let Some(digest) = digest
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return format!("sha256:{}", digest.to_ascii_lowercase());
    }
    value.to_string()
}

fn digest_for_word(word: &str) -> String {
    digest_hex(word.as_bytes())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ApmMeta, AttestationMeta, ExposeArtifactMeta, ExposeMeta, HostPathMode, HostPathPermission,
        InstalledMeta, NetworkPermission, PermissionsMeta, SysrootImageEntry,
    };
    use tempfile::TempDir;

    fn installed_fixture(tmp: &TempDir, manifest: &[u8]) -> InstalledMeta {
        let artifact = tmp.path().join("artifact");
        fs::create_dir_all(artifact.join("units")).expect("artifact units");
        fs::write(artifact.join("manifest.json"), manifest).expect("manifest");
        InstalledMeta {
            store_path: "/nix/store/hash-web-1.0".into(),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "web".into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test".into(),
                installed_at: "2026-06-18T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: "sha256:nar".into(),
                expose: Some(ExposeMeta {
                    target: "aos-pkg-web.target".into(),
                    units: vec!["web.service".into()],
                    images: vec![SysrootImageEntry {
                        format: "ext4-verity".into(),
                        store_path: "/nix/store/image-web".into(),
                        nar_hash: "sha256:image".into(),
                        nar_size: 1,
                        sb_signer_cert_sha256: None,
                        sbat: Vec::new(),
                        expected_pcr11: None,
                        root_image: Some("root.img".into()),
                        root_verity: Some("root.verity".into()),
                        root_hash: Some(
                            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                .into(),
                        ),
                        root_hash_sig: Some("root.roothash.p7s".into()),
                    }],
                    requires: Vec::new(),
                    config: Default::default(),
                    provides: Vec::new(),
                    uses: Vec::new(),
                }),
                expose_artifact: Some(ExposeArtifactMeta {
                    store_path: artifact.display().to_string(),
                    nar_hash: "sha256:artifact".into(),
                    nar_size: manifest.len() as u64,
                }),
                permissions: PermissionsMeta {
                    network: Some(NetworkPermission::Private),
                    host_paths: vec![HostPathPermission {
                        path: "/var/lib/web".into(),
                        mode: HostPathMode::Rw,
                    }],
                    ..Default::default()
                },
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    #[test]
    fn package_measurement_includes_root_and_manifest_digests() {
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{"network":"private"}}"#);

        let events = measurement_events(tmp.path(), &[installed]).expect("events");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
        let package = events[1].package.as_ref().expect("package event");
        assert_eq!(package.name, "web");
        assert_eq!(
            package.root_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            package.manifest_digest,
            format!(
                "sha256:{}",
                digest_hex(br#"{"permissions":{"network":"private"}}"#)
            )
        );
        assert!(events[1].word.contains("name=3:web"));
    }

    #[test]
    fn package_measurement_changes_when_manifest_changes() {
        let tmp = TempDir::new().expect("tempdir");
        let first = installed_fixture(&tmp, br#"{"permissions":{"network":"private"}}"#);
        let first_digest = measurement_events(tmp.path(), &[first]).expect("first")[1]
            .digest
            .clone();
        let second = installed_fixture(&tmp, br#"{"permissions":{"network":"host"}}"#);
        let second_digest = measurement_events(tmp.path(), &[second]).expect("second")[1]
            .digest
            .clone();

        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn package_measurement_accepts_matching_registry_measurement() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let mut installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_mut().expect("apm metadata");
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_digest = package_manifest_digest_bytes(manifest);
        apm.attestation = AttestationMeta {
            root_hash: Some(root_hash.into()),
            root_hash_sig: Some("root.roothash.p7s".into()),
            provenance: None,
            measurement: Some(package_measurement_digest(
                &apm.name,
                &apm.version,
                root_hash,
                &manifest_digest,
            )),
        };

        measurement_events(tmp.path(), &[installed]).expect("matching measurement");
    }

    #[test]
    fn package_measurement_rejects_mismatched_registry_measurement() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = br#"{"permissions":{"network":"private"}}"#;
        let mut installed = installed_fixture(&tmp, manifest);
        let apm = installed.apm.as_mut().expect("apm metadata");
        apm.attestation = AttestationMeta {
            root_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            root_hash_sig: Some("root.roothash.p7s".into()),
            provenance: None,
            measurement: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ),
        };

        let err = measurement_events(tmp.path(), &[installed]).unwrap_err();
        assert!(format!("{err:#}").contains("does not match installed metadata"));
    }

    #[test]
    fn measure_activated_packages_writes_event_log_under_root() {
        let tmp = TempDir::new().expect("tempdir");
        let installed = installed_fixture(&tmp, br#"{"permissions":{}}"#);

        measure_activated_packages(tmp.path(), &[installed]).expect("measure");

        let log = fs::read_to_string(tmp.path().join(AOS_PACKAGE_CEL_REL)).expect("log");
        assert!(log.contains("\"format\":\"aos-package-cel-v1\""));
        assert!(log.contains("\"event_type\":\"aos-package-set\""));
        assert!(log.contains("\"event_type\":\"aos-package\""));
        assert!(log.contains("\"package\":\"web\""));
    }

    #[test]
    fn empty_package_set_still_has_replayable_set_event() {
        let tmp = TempDir::new().expect("tempdir");

        let events = measurement_events(tmp.path(), &[]).expect("events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, PACKAGE_SET_EVENT_TYPE);
        assert_eq!(events[0].package_count, Some(0));
    }
}
