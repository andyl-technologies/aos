//! Selects and independently measures a declared installed source tuple before Child.
//!
//! The controller supplies the current suite-owned manifest at runtime, after
//! the provider package is built. Absence refuses; it never skips a selected
//! native witness or falls back to a historical scratch installation.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crucible_node_contract::{ContentRef, HashRef, Validate, canonical};
use crucible_node_provider::ProviderError;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    artifacts: BTreeMap<String, Artifact>,
    limitations: Vec<String>,
    policy_id: String,
    policy_version: u16,
    schema: String,
    source_artifacts: BTreeMap<String, Artifact>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub(super) content: ContentRef,
    pub(super) path: PathBuf,
}

pub(crate) struct PackageSelection {
    provider: Artifact,
    device: Artifact,
    objects: BTreeMap<String, ContentRef>,
}

impl PackageSelection {
    pub(crate) fn from_environment() -> Result<Self, ProviderError> {
        Self::from_binding(std::env::var_os(
            "CRUCIBLE_REFERENCE_LINEAGE_IMPLEMENTATION_MANIFEST",
        ))
    }

    fn from_binding(binding: Option<OsString>) -> Result<Self, ProviderError> {
        let path = binding
            .filter(|path| !path.is_empty())
            .ok_or(ProviderError::Correlation(
                "installed lineage manifest binding is required",
            ))?;
        let package: Package = serde_json::from_value(canonical::parse_json(
            &read(&PathBuf::from(path), 16 * 1024)?,
            16 * 1024,
        )?)
        .map_err(crucible_node_contract::ContractError::from)?;
        if package.schema != "crucible.reference.installed-implementation.v1"
            || package.policy_id != "public-ordered-consumption-checksum-v1"
            || package.policy_version != 1
            || package
                .artifacts
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != ["device", "provider"]
            || package
                .source_artifacts
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != ["build_closure", "contract", "recipe", "source"]
            || !package
                .limitations
                .iter()
                .any(|limit| limit == "source-class-unqualified")
        {
            return Err(invalid());
        }

        let mut total = 0;
        for (role, artifact) in &package.source_artifacts {
            let media = match role.as_str() {
                "source" | "contract" => "application/gzip",
                "recipe" => "text/plain",
                "build_closure" => "application/json",
                _ => return Err(invalid()),
            };
            verify_artifact(artifact, media, &mut total)?;
        }
        let provider = package
            .artifacts
            .get("provider")
            .ok_or_else(invalid)?
            .clone();
        let device = package.artifacts.get("device").ok_or_else(invalid)?.clone();
        verify_artifact(&provider, "application/octet-stream", &mut total)?;
        verify_artifact(&device, "application/octet-stream", &mut total)?;

        let closure = package
            .source_artifacts
            .get("build_closure")
            .ok_or_else(invalid)?;
        let bytes = read(&closure.path, 1024 * 1024)?;
        closure.content.verify(&bytes)?;
        let closure = canonical::parse_json(&bytes, 1024 * 1024)?;
        if closure.get("schema").and_then(serde_json::Value::as_str)
            != Some("crucible.reference.runtime-closure.v1")
        {
            return Err(invalid());
        }
        let values = closure
            .get("objects")
            .and_then(serde_json::Value::as_array)
            .filter(|objects| objects.len() <= 4096)
            .ok_or_else(invalid)?;
        let mut objects = BTreeMap::new();
        for value in values {
            let artifact: Artifact = serde_json::from_value(value.clone())
                .map_err(crucible_node_contract::ContractError::from)?;
            artifact.content.validate()?;
            let path = artifact.path.to_str().ok_or_else(invalid)?.to_owned();
            if objects.insert(path, artifact.content).is_some() {
                return Err(invalid());
            }
        }
        for artifact in [&provider, &device] {
            if objects.get(artifact.path.to_str().ok_or_else(invalid)?) != Some(&artifact.content) {
                return Err(invalid());
            }
        }
        Ok(Self {
            provider,
            device,
            objects,
        })
    }

    pub(crate) fn provider_path(&self) -> &Path {
        &self.provider.path
    }

    pub(crate) fn device_path(&self) -> &Path {
        &self.device.path
    }

    pub(super) fn provider(&self) -> &Artifact {
        &self.provider
    }

    pub(super) fn device(&self) -> &Artifact {
        &self.device
    }

    pub(super) fn objects(&self) -> &BTreeMap<String, ContentRef> {
        &self.objects
    }
}

fn verify_artifact(artifact: &Artifact, media: &str, total: &mut u64) -> Result<(), ProviderError> {
    artifact.content.validate()?;
    if artifact.content.media_type != media || artifact.content.length.get() > 512 * 1024 * 1024 {
        return Err(invalid());
    }
    *total = total
        .checked_add(artifact.content.length.get())
        .filter(|bytes| *bytes <= 1024 * 1024 * 1024)
        .ok_or_else(invalid)?;
    let mut file = open(&artifact.path)?;
    let before = file.metadata()?;
    if before.len() != artifact.content.length.get() {
        return Err(invalid());
    }

    let domain = "cnp.blob.v1";
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&(domain.len() as u32).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update(&before.len().to_be_bytes());
    let mut observed = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .filter(|length| *length <= before.len())
            .ok_or_else(invalid)?;
        hash.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if observed != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || artifact.content.hash
            != (HashRef {
                algorithm: "blake3-256".into(),
                domain: domain.into(),
                digest: hash.finalize().to_hex().to_string(),
            })
    {
        return Err(invalid());
    }
    Ok(())
}

fn open(path: &Path) -> Result<File, ProviderError> {
    if !path.starts_with("/nix/store") || std::fs::canonicalize(path)? != path {
        return Err(invalid());
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    Ok(file)
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("selected installed lineage manifest differs")
}

#[test]
fn absent_installed_binding_refuses_before_source_allocation() {
    assert!(matches!(
        PackageSelection::from_binding(None),
        Err(ProviderError::Correlation(
            "installed lineage manifest binding is required"
        ))
    ));
    assert!(PackageSelection::from_binding(Some(OsString::new())).is_err());
}

#[test]
fn altered_artifact_media_refuses_before_path_lookup() {
    let artifact = Artifact {
        content: canonical::content_ref(b"original typed source body", "text/plain").unwrap(),
        path: PathBuf::from("must-not-be-opened"),
    };
    let mut total = 0;

    let result = verify_artifact(&artifact, "application/gzip", &mut total);

    assert!(matches!(result, Err(ProviderError::Correlation(_))));
    assert_eq!(total, 0);
}

#[test]
fn excessive_original_extent_refuses_before_stream_allocation() {
    let mut reference = canonical::content_ref(b"extent fixture", "application/gzip").unwrap();
    reference.length = crucible_node_contract::U64::new(512 * 1024 * 1024 + 1);
    let artifact = Artifact {
        content: reference,
        path: PathBuf::from("must-not-be-opened"),
    };
    let mut total = 0;

    let result = verify_artifact(&artifact, "application/gzip", &mut total);

    assert!(matches!(result, Err(ProviderError::Correlation(_))));
    assert_eq!(total, 0);
}
