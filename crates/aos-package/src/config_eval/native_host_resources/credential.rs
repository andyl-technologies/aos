//! Credential source authentication and protected workload views.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::builtin::{CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA, CREDENTIAL_VIEW_OUTPUT};
use aos_ability_model::{LocalKey, ResourceId};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::super::native_resource_map::NativeResourceQualification;
use super::{
    CREDENTIAL_ROOT, CREDENTIAL_SOURCE_ROOT, CredentialInput, HostState, MAX_CREDENTIAL_BYTES,
    NativeDependencyBinding, NativeHostRecord, NativeHostRequest, QualifiedHostResource,
    ability_value, atomic_write_root, decode_input, invalid, new_state, path_text,
    read_protected_file, read_state_optional, record, remove_atomic_temporary_root,
    remove_regular_optional, require_current_state, require_matching_state, resource_key,
    store_error, write_state,
};

const SOURCE_SCHEMA: &str = "aos.ability.credential-source/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CredentialPhase {
    Delivering,
    Delivered,
    Releasing,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialStateDetails {
    phase: CredentialPhase,
    view: String,
    active_version: String,
    versions: Vec<CredentialVersionState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialVersionState {
    version: String,
    view_path: String,
    content_digest: Sha256Digest,
}

/// Commits to one authenticated secret-free credential view.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialEvidence {
    /// Names the logical credential resource that owns the view.
    pub(crate) resource: ResourceId,
    /// Identifies the opaque source version selected by the producer.
    pub(crate) version: String,
    /// Names the protected provider-controlled workload path.
    pub(crate) view_path: String,
    /// Commits to the bytes read from the protected view.
    pub(crate) content_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialSourceRecord {
    schema: String,
    resource: ResourceId,
    version: String,
    source_path: String,
    content_digest: Sha256Digest,
}

#[derive(Serialize)]
struct CredentialSourceKey<'a> {
    resource: &'a ResourceId,
    version: &'a str,
}

#[derive(Serialize)]
struct CredentialViewKey<'a> {
    resource: &'a ResourceId,
    version: &'a str,
}

pub(super) fn execute_credential(
    request: &NativeHostRequest,
) -> Result<NativeHostRecord, io::Error> {
    let input: CredentialInput = decode_input(&request.durable.inputs, "credential")?;
    let view_path = credential_view_path(&request.durable.resource, &input.version)?;
    let marker_path = request.resource.state_path.clone();

    match request.durable.method.as_str() {
        "deliver" => {
            let existing = authenticate_existing_view(request, &input)?;
            let secret = read_credential_source(&request.durable.resource, &input.version)?;
            let content_digest = Sha256Digest::of_bytes(secret.as_slice());
            let view_path_text = path_text(&view_path)?;
            let (details, added_version) = next_credential_details(
                existing,
                &input.view,
                &input.version,
                view_path_text,
                content_digest,
            )?;
            if added_version {
                authenticate_unrecorded_view(&view_path, content_digest)?;
            }
            reject_unrecorded_versioned_views(&request.durable.resource, &details.versions)?;

            atomic_write_root(&view_path, secret.as_slice(), 0o400)?;
            write_typed_state(request, details)?;

            credential_record(&input, true, Some(&input.version), Some(&view_path))
        }
        "acquire" => {
            let state = require_current_state(request)?;
            let details = credential_details(&state)?;
            let version = credential_version(&details, &input.version)?;
            let secret = Zeroizing::new(read_protected_file(
                &view_path,
                MAX_CREDENTIAL_BYTES,
                0,
                0o400,
            )?);
            if details.phase != CredentialPhase::Delivered
                || details.view != input.view
                || details.active_version != input.version
                || version.view_path != path_text(&view_path)?
                || version.content_digest != Sha256Digest::of_bytes(secret.as_slice())
            {
                return Err(invalid(
                    "credential view is stale or differs from protected state",
                ));
            }
            credential_record(&input, true, Some(&input.version), Some(&view_path))
        }
        "release" => {
            let state = read_state_optional(&marker_path)?;
            match state {
                Some(state) => {
                    require_matching_state(request, &state)?;
                    let mut details = credential_details(&state)?;
                    reject_unrecorded_versioned_views(&state.resource, &details.versions)?;
                    details.phase = CredentialPhase::Releasing;
                    write_typed_state(request, details.clone())?;
                    for version in &details.versions {
                        let owned_path = credential_view_path(&state.resource, &version.version)?;
                        if version.view_path != path_text(&owned_path)? {
                            return Err(invalid(
                                "credential release found a foreign versioned view",
                            ));
                        }
                        remove_regular_optional(&owned_path, 0)?;
                        remove_atomic_temporary_root(&owned_path, 0o400)?;
                        if fs::symlink_metadata(&owned_path).is_ok() {
                            return Err(io::Error::other("credential view remained after release"));
                        }
                    }
                    remove_regular_optional(&marker_path, 0)?;
                }
                None => {
                    remove_atomic_temporary_root(&marker_path, 0o600)?;
                    reject_unowned_versioned_views(&request.durable.resource)?;
                }
            }
            credential_record(&input, false, None, None)
        }
        _ => Err(invalid("unsupported credential method")),
    }
}

pub(super) fn credential_healthy(state: &HostState) -> Result<bool, io::Error> {
    let details = credential_details(state)?;
    if details.phase != CredentialPhase::Delivered {
        return Ok(false);
    }
    let active = credential_version(&details, &details.active_version)?;
    let bytes =
        match read_protected_file(Path::new(&active.view_path), MAX_CREDENTIAL_BYTES, 0, 0o400) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
    Ok(active.content_digest == Sha256Digest::of_bytes(bytes.as_slice()))
}

pub(super) fn authenticate_credential_view(
    view_path: &Path,
    version: &str,
) -> Result<(CredentialEvidence, Zeroizing<Vec<u8>>), io::Error> {
    let evidence = authenticate_credential_marker(view_path, version, None)?;
    let secret = Zeroizing::new(read_protected_file(
        view_path,
        MAX_CREDENTIAL_BYTES,
        0,
        0o400,
    )?);
    if secret.is_empty() || Sha256Digest::of_bytes(secret.as_slice()) != evidence.content_digest {
        return Err(invalid("credential view bytes differ from protected state"));
    }
    Ok((evidence, secret))
}

pub(super) fn authenticate_credential_dependency(
    binding: &NativeDependencyBinding,
    view_path: &Path,
    version: &str,
) -> Result<CredentialEvidence, io::Error> {
    let evidence = authenticate_credential_marker(view_path, version, Some(&binding.resource))?;
    let digest = resource_key(&binding.resource)?;
    let marker_path = Path::new(CREDENTIAL_ROOT).join(format!(".{digest}.json"));
    let state = read_state_optional(&marker_path)?
        .ok_or_else(|| invalid("credential dependency has no ownership marker"))?;
    if state.revision != binding.revision || state.qualification != binding.qualification {
        return Err(invalid(
            "credential dependency differs from its producer qualification",
        ));
    }
    Ok(evidence)
}

/// Authenticates one typed credential view against its checked producer.
///
/// The returned evidence contains only the logical resource, opaque version,
/// protected path, and content digest. Secret bytes are zeroized before this
/// function returns.
///
/// # Errors
///
/// Returns an error when the view or its ownership marker is unsafe, stale,
/// inconsistent with the producer binding, or differs from its recorded digest.
pub(crate) fn authenticate_credential_dependency_view(
    binding: &NativeDependencyBinding,
    view_path: &Path,
    version: &str,
) -> Result<CredentialEvidence, io::Error> {
    let producer_evidence = authenticate_credential_dependency(binding, view_path, version)?;
    let (content_evidence, secret) = authenticate_credential_view(view_path, version)?;
    drop(secret);

    if content_evidence != producer_evidence {
        return Err(invalid(
            "credential content evidence differs from its producer authority",
        ));
    }

    Ok(content_evidence)
}

/// Authenticates one typed credential view and returns secret-free evidence.
///
/// Secret bytes are read only to verify their recorded digest and are zeroized
/// before this function returns.
///
/// # Errors
///
/// Returns an error when the view or its ownership marker is unsafe, stale, or
/// differs from the protected credential bytes.
pub(crate) fn authenticate_credential_view_evidence(
    view_path: &Path,
    version: &str,
) -> Result<CredentialEvidence, io::Error> {
    let (evidence, secret) = authenticate_credential_view(view_path, version)?;
    drop(secret);

    Ok(evidence)
}

pub(super) fn validate_delivery_before_intent(
    resource: &QualifiedHostResource,
    input: &CredentialInput,
) -> Result<(), io::Error> {
    let secret = read_credential_source(&resource.spec.resource, &input.version)?;
    let content_digest = Sha256Digest::of_bytes(secret.as_slice());
    let view_path = credential_view_path(&resource.spec.resource, &input.version)?;
    let view_path_text = path_text(&view_path)?;
    let existing = authenticate_existing_state(resource, input)?;
    let recorded = existing.as_ref().and_then(|details| {
        details
            .versions
            .iter()
            .find(|recorded| recorded.version == input.version)
    });
    if recorded.is_some_and(|recorded| {
        recorded.content_digest != content_digest || recorded.view_path != view_path_text
    }) {
        return Err(invalid(
            "credential version resolves to different protected content",
        ));
    }
    if recorded.is_none() {
        authenticate_unrecorded_view(&view_path, content_digest)?;
    }
    Ok(())
}

pub(super) fn authenticate_credential_marker(
    view_path: &Path,
    version: &str,
    expected_resource: Option<&ResourceId>,
) -> Result<CredentialEvidence, io::Error> {
    if view_path.parent() != Some(Path::new(CREDENTIAL_ROOT)) {
        return Err(invalid(
            "credential view is outside the protected runtime root",
        ));
    }
    let file_name = view_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("credential view name is not UTF-8"))?;
    let (resource_digest, _) = parse_credential_view_name(file_name)?;
    let marker_path = Path::new(CREDENTIAL_ROOT).join(format!(".{resource_digest}.json"));
    let state = read_state_optional(&marker_path)?
        .ok_or_else(|| invalid("credential view has no ownership marker"))?;
    let details = credential_details(&state)?;
    let recorded = credential_version(&details, version)?;
    if resource_key(&state.resource)? != resource_digest
        || expected_resource.is_some_and(|resource| resource != &state.resource)
        || details.phase != CredentialPhase::Delivered
        || credential_view_path(&state.resource, version)? != view_path
        || recorded.view_path != path_text(view_path)?
    {
        return Err(invalid("credential view differs from its ownership marker"));
    }
    let NativeResourceQualification::CredentialDelivery { view } = &state.qualification else {
        return Err(invalid("credential marker has another qualification"));
    };
    if details.view != *view {
        return Err(invalid("credential marker view identity is inconsistent"));
    }
    Ok(CredentialEvidence {
        resource: state.resource,
        version: recorded.version.clone(),
        view_path: recorded.view_path.clone(),
        content_digest: recorded.content_digest,
    })
}

pub(super) fn credential_view_path(
    resource: &ResourceId,
    version: &str,
) -> Result<PathBuf, io::Error> {
    // The resource prefix keeps ownership and locking stable while the version
    // suffix lets a failed renewal leave the previously served bytes intact.
    let resource_digest = resource_key(resource)?;
    let version_digest = Sha256Digest::of_canonical(
        "aos.ability.credential-view-key/v1",
        &CredentialViewKey { resource, version },
    )
    .map_err(store_error)?
    .hex();

    Ok(Path::new(CREDENTIAL_ROOT).join(format!("{resource_digest}-{version_digest}.view")))
}

fn authenticate_existing_view(
    request: &NativeHostRequest,
    input: &CredentialInput,
) -> Result<Option<CredentialStateDetails>, io::Error> {
    let state = read_state_optional(&request.resource.state_path)?;
    match state {
        Some(state) => {
            require_matching_state(request, &state)?;
            let details = credential_details(&state)?;
            if details.view != input.view {
                return Err(invalid("credential marker binds another workload view"));
            }
            Ok(Some(details))
        }
        None => Ok(None),
    }
}

fn authenticate_existing_state(
    resource: &QualifiedHostResource,
    input: &CredentialInput,
) -> Result<Option<CredentialStateDetails>, io::Error> {
    let state = read_state_optional(&resource.state_path)?;
    match state {
        Some(state) => {
            if state.resource != resource.spec.resource
                || state.qualification != resource.spec.qualification
            {
                return Err(invalid("credential marker is foreign"));
            }
            let details = credential_details(&state)?;
            if details.view != input.view {
                return Err(invalid("credential marker binds another workload view"));
            }
            Ok(Some(details))
        }
        None => {
            reject_unowned_versioned_views(&resource.spec.resource)?;
            Ok(None)
        }
    }
}

fn credential_details(state: &HostState) -> Result<CredentialStateDetails, io::Error> {
    let details: CredentialStateDetails = serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid credential state details: {error}")))?;
    if details.versions.is_empty()
        || !details
            .versions
            .windows(2)
            .all(|pair| pair[0].version < pair[1].version)
        || !details
            .versions
            .iter()
            .any(|version| version.version == details.active_version)
    {
        return Err(invalid("credential state has invalid version membership"));
    }
    for version in &details.versions {
        if credential_view_path(&state.resource, &version.version)? != Path::new(&version.view_path)
        {
            return Err(invalid(
                "credential state contains a foreign versioned view",
            ));
        }
    }

    Ok(details)
}

fn credential_version<'a>(
    details: &'a CredentialStateDetails,
    version: &str,
) -> Result<&'a CredentialVersionState, io::Error> {
    details
        .versions
        .iter()
        .find(|recorded| recorded.version == version)
        .ok_or_else(|| invalid("credential version is absent from its ownership marker"))
}

fn next_credential_details(
    existing: Option<CredentialStateDetails>,
    view: &str,
    version: &str,
    view_path: String,
    content_digest: Sha256Digest,
) -> Result<(CredentialStateDetails, bool), io::Error> {
    let mut versions = match existing {
        Some(details) if details.view == view => details.versions,
        Some(_) => return Err(invalid("credential marker binds another workload view")),
        None => Vec::new(),
    };
    let desired = CredentialVersionState {
        version: version.to_string(),
        view_path,
        content_digest,
    };
    let added = match versions.iter().find(|recorded| recorded.version == version) {
        Some(recorded) if recorded == &desired => false,
        Some(_) => {
            return Err(invalid(
                "credential version resolves to different protected content",
            ));
        }
        None => {
            versions.push(desired);
            versions.sort_by(|left, right| left.version.cmp(&right.version));
            true
        }
    };

    Ok((
        CredentialStateDetails {
            phase: CredentialPhase::Delivered,
            view: view.to_string(),
            active_version: version.to_string(),
            versions,
        },
        added,
    ))
}

fn authenticate_unrecorded_view(
    view_path: &Path,
    expected_digest: Sha256Digest,
) -> Result<(), io::Error> {
    let bytes = match read_protected_file(view_path, MAX_CREDENTIAL_BYTES, 0, 0o400) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if Sha256Digest::of_bytes(bytes.as_slice()) != expected_digest {
        return Err(invalid(
            "unrecorded credential view differs from the protected source",
        ));
    }

    Ok(())
}

fn reject_unowned_versioned_views(resource: &ResourceId) -> Result<(), io::Error> {
    reject_unrecorded_versioned_views(resource, &[])
}

fn reject_unrecorded_versioned_views(
    resource: &ResourceId,
    recorded: &[CredentialVersionState],
) -> Result<(), io::Error> {
    let expected_resource = resource_key(resource)?;
    for entry in fs::read_dir(CREDENTIAL_ROOT)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let owned_by_resource = parse_credential_view_name(&name)
            .is_ok_and(|(resource_digest, _)| resource_digest == expected_resource);
        let path = entry.path();
        let is_recorded = recorded
            .iter()
            .any(|version| Path::new(&version.view_path) == path);
        if owned_by_resource && !is_recorded {
            return Err(invalid(
                "credential view exists without matching ownership state",
            ));
        }
    }

    Ok(())
}

fn parse_credential_view_name(name: &str) -> Result<(&str, &str), io::Error> {
    let stem = name
        .strip_suffix(".view")
        .ok_or_else(|| invalid("credential view name is not canonical"))?;
    let (resource_digest, version_digest) = stem
        .split_once('-')
        .ok_or_else(|| invalid("credential view name is not versioned"))?;
    if !is_lower_hex_digest(resource_digest) || !is_lower_hex_digest(version_digest) {
        return Err(invalid("credential view name is not canonical"));
    }

    Ok((resource_digest, version_digest))
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_typed_state(
    request: &NativeHostRequest,
    details: CredentialStateDetails,
) -> Result<(), io::Error> {
    write_state(
        &request.resource.state_path,
        &new_state(request, serde_json::to_value(details).map_err(store_error)?),
    )
}

fn read_credential_source(
    resource: &ResourceId,
    version: &str,
) -> Result<Zeroizing<Vec<u8>>, io::Error> {
    let (record_path, expected_source_path) = credential_source_paths(resource, version)?;
    let record_bytes = read_protected_file(&record_path, 16 * 1024, 0, 0o600)?;
    let record: CredentialSourceRecord =
        aos_contract::canonical::from_slice(&record_bytes, "credential source record")
            .map_err(store_error)?;
    if record.schema != SOURCE_SCHEMA
        || record.resource != *resource
        || record.version != version
        || record.source_path != path_text(&expected_source_path)?
    {
        return Err(invalid("credential source record has foreign authority"));
    }
    let secret = Zeroizing::new(read_protected_file(
        &expected_source_path,
        MAX_CREDENTIAL_BYTES,
        0,
        0o600,
    )?);
    validate_secret_bytes(secret.as_slice())?;
    if Sha256Digest::of_bytes(secret.as_slice()) != record.content_digest {
        return Err(invalid(
            "credential source bytes differ from their protected record",
        ));
    }
    Ok(secret)
}

fn validate_secret_bytes(secret: &[u8]) -> Result<(), io::Error> {
    if secret.is_empty() {
        return Err(invalid("credential source is empty"));
    }

    Ok(())
}

fn credential_source_paths(
    resource: &ResourceId,
    version: &str,
) -> Result<(PathBuf, PathBuf), io::Error> {
    let resource_root = Path::new(CREDENTIAL_SOURCE_ROOT).join(resource_key(resource)?);
    let source_key = Sha256Digest::of_canonical(
        "aos.ability.credential-source-key/v1",
        &CredentialSourceKey { resource, version },
    )
    .map_err(store_error)?
    .hex();
    Ok((
        resource_root.join(format!("{source_key}.json")),
        resource_root.join(format!("{source_key}.secret")),
    ))
}

fn credential_record(
    input: &CredentialInput,
    delivered: bool,
    observed_version: Option<&str>,
    view_path: Option<&Path>,
) -> Result<NativeHostRecord, io::Error> {
    let result = serde_json::json!({
        "schema": CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA,
        "delivered": delivered,
        "observed_version": observed_version,
        "requested_version": input.version,
        "view": input.view,
    });
    let outputs = view_path
        .map(|path| -> Result<_, io::Error> {
            Ok(BTreeMap::from([(
                LocalKey::new(CREDENTIAL_VIEW_OUTPUT).map_err(store_error)?,
                ability_value(serde_json::json!({
                    "path": path_text(path)?,
                    "version": input.version,
                }))?,
            )]))
        })
        .transpose()?
        .unwrap_or_default();
    record(result, outputs)
}

#[cfg(test)]
mod tests {
    use super::{
        credential_view_path, next_credential_details, parse_credential_view_name, resource_key,
        validate_secret_bytes,
    };
    use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId, LocalKey, ResourceId};
    use aos_contract::Sha256Digest;

    #[test]
    fn accepts_multiline_and_binary_credentials() {
        assert!(
            validate_secret_bytes(
                b"-----BEGIN CERTIFICATE-----\nbody\n-----END CERTIFICATE-----\n"
            )
            .is_ok()
        );
        assert!(validate_secret_bytes(&[0, 1, 2, 255]).is_ok());
    }

    #[test]
    fn rejects_empty_credentials() {
        assert!(validate_secret_bytes(&[]).is_err());
    }

    #[test]
    fn versioned_view_paths_bind_resource_and_version_digests() {
        let resource = credential_resource();
        let first = credential_view_path(&resource, "certificate-v1")
            .expect("first credential path is derived");
        let second = credential_view_path(&resource, "certificate-v2")
            .expect("second credential path is derived");
        assert_ne!(first, second);

        let name = first
            .file_name()
            .and_then(|name| name.to_str())
            .expect("credential view name is UTF-8");
        let (resource_digest, version_digest) =
            parse_credential_view_name(name).expect("versioned name parses");
        assert_eq!(
            resource_digest,
            resource_key(&resource).expect("resource digest is derived")
        );
        assert_eq!(version_digest.len(), 64);
        assert!(parse_credential_view_name(&format!("{resource_digest}.view")).is_err());
        assert!(
            parse_credential_view_name(&format!(
                "{}-{version_digest}.view",
                resource_digest.to_ascii_uppercase()
            ))
            .is_err()
        );
    }

    #[test]
    fn rotation_retains_the_prior_version_and_rejects_same_version_drift() {
        let resource = credential_resource();
        let first_path = credential_view_path(&resource, "certificate-v1")
            .expect("first credential path is derived");
        let second_path = credential_view_path(&resource, "certificate-v2")
            .expect("second credential path is derived");
        let first_digest = Sha256Digest::of_bytes(b"first-certificate");
        let second_digest = Sha256Digest::of_bytes(b"second-certificate");
        let (first, first_added) = next_credential_details(
            None,
            "edge-tls",
            "certificate-v1",
            first_path.to_string_lossy().into_owned(),
            first_digest,
        )
        .expect("first version is accepted");
        let (rotated, second_added) = next_credential_details(
            Some(first),
            "edge-tls",
            "certificate-v2",
            second_path.to_string_lossy().into_owned(),
            second_digest,
        )
        .expect("rotation is accepted");

        assert!(first_added);
        assert!(second_added);
        assert_eq!(rotated.active_version, "certificate-v2");
        assert_eq!(rotated.versions.len(), 2);
        assert_eq!(rotated.versions[0].content_digest, first_digest);
        assert_eq!(rotated.versions[1].content_digest, second_digest);

        assert!(
            next_credential_details(
                Some(rotated),
                "edge-tls",
                "certificate-v2",
                second_path.to_string_lossy().into_owned(),
                Sha256Digest::of_bytes(b"changed-certificate"),
            )
            .is_err()
        );
    }

    fn credential_resource() -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority is valid"),
                    key: LocalKey::new("host").expect("environment is valid"),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("credentials").expect("provider is valid"),
            },
            key: LocalKey::new("edge-tls").expect("resource is valid"),
        }
    }
}
