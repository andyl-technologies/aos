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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialStateDetails {
    phase: CredentialPhase,
    version: String,
    view: String,
    view_path: String,
    content_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialEvidence {
    pub(super) resource: ResourceId,
    pub(super) version: String,
    pub(super) view_path: String,
    pub(super) content_digest: Sha256Digest,
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

pub(super) fn execute_credential(
    request: &NativeHostRequest,
) -> Result<NativeHostRecord, io::Error> {
    let input: CredentialInput = decode_input(&request.durable.inputs, "credential")?;
    let view_path = credential_view_path(&request.durable.resource)?;
    let marker_path = request.resource.state_path.clone();

    match request.durable.method.as_str() {
        "deliver" => {
            let existing = authenticate_existing_view(request, &input, &view_path)?;
            let secret = read_credential_source(&request.durable.resource, &input.version)?;
            let content_digest = Sha256Digest::of_bytes(secret.as_slice());
            if existing.as_ref().is_some_and(|details| {
                details.version == input.version && details.content_digest != content_digest
            }) {
                return Err(invalid(
                    "credential version resolves to different protected content",
                ));
            }
            let view_path_text = path_text(&view_path)?;
            let details = |phase| CredentialStateDetails {
                phase,
                version: input.version.clone(),
                view: input.view.clone(),
                view_path: view_path_text.clone(),
                content_digest,
            };

            write_typed_state(request, details(CredentialPhase::Delivering))?;
            atomic_write_root(&view_path, secret.as_slice(), 0o400)?;
            write_typed_state(request, details(CredentialPhase::Delivered))?;

            credential_record(&input, true, Some(&input.version), Some(&view_path))
        }
        "acquire" => {
            let state = require_current_state(request)?;
            let details = credential_details(&state)?;
            let secret = Zeroizing::new(read_protected_file(
                &view_path,
                MAX_CREDENTIAL_BYTES,
                0,
                0o400,
            )?);
            if details.phase != CredentialPhase::Delivered
                || details.version != input.version
                || details.view != input.view
                || details.view_path != path_text(&view_path)?
                || details.content_digest != Sha256Digest::of_bytes(secret.as_slice())
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
                    details.phase = CredentialPhase::Releasing;
                    write_typed_state(request, details.clone())?;
                    remove_regular_optional(&view_path, 0)?;
                    remove_atomic_temporary_root(&view_path, 0o400)?;
                    if fs::symlink_metadata(&view_path).is_ok() {
                        return Err(io::Error::other("credential view remained after release"));
                    }
                    remove_regular_optional(&marker_path, 0)?;
                }
                None => {
                    remove_atomic_temporary_root(&view_path, 0o400)?;
                    match fs::symlink_metadata(&view_path) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Ok(_) => {
                            return Err(invalid(
                                "credential view exists without an ownership marker",
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                    remove_atomic_temporary_root(&marker_path, 0o600)?;
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
    let bytes = match read_protected_file(
        Path::new(&details.view_path),
        MAX_CREDENTIAL_BYTES,
        0,
        0o400,
    ) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(details.content_digest == Sha256Digest::of_bytes(bytes.as_slice()))
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

pub(super) fn validate_delivery_before_intent(
    resource: &QualifiedHostResource,
    input: &CredentialInput,
) -> Result<(), io::Error> {
    let secret = read_credential_source(&resource.spec.resource, &input.version)?;
    let content_digest = Sha256Digest::of_bytes(secret.as_slice());
    let view_path = credential_view_path(&resource.spec.resource)?;
    let existing = authenticate_existing_state(resource, input, &view_path)?;
    if existing.as_ref().is_some_and(|details| {
        details.version == input.version && details.content_digest != content_digest
    }) {
        return Err(invalid(
            "credential version resolves to different protected content",
        ));
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
    let digest = file_name
        .strip_suffix(".view")
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("credential view name is not canonical"))?;
    let marker_path = Path::new(CREDENTIAL_ROOT).join(format!(".{digest}.json"));
    let state = read_state_optional(&marker_path)?
        .ok_or_else(|| invalid("credential view has no ownership marker"))?;
    let details = credential_details(&state)?;
    if resource_key(&state.resource)? != digest
        || expected_resource.is_some_and(|resource| resource != &state.resource)
        || details.phase != CredentialPhase::Delivered
        || details.version != version
        || details.view_path != path_text(view_path)?
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
        version: details.version,
        view_path: details.view_path,
        content_digest: details.content_digest,
    })
}

pub(super) fn credential_view_path(resource: &ResourceId) -> Result<PathBuf, io::Error> {
    Ok(Path::new(CREDENTIAL_ROOT).join(format!("{}.view", resource_key(resource)?)))
}

fn authenticate_existing_view(
    request: &NativeHostRequest,
    input: &CredentialInput,
    view_path: &Path,
) -> Result<Option<CredentialStateDetails>, io::Error> {
    let state = read_state_optional(&request.resource.state_path)?;
    match state {
        Some(state) => {
            require_matching_state(request, &state)?;
            let details = credential_details(&state)?;
            if details.view != input.view || details.view_path != path_text(view_path)? {
                return Err(invalid("credential marker binds another workload view"));
            }
            Ok(Some(details))
        }
        None if fs::symlink_metadata(view_path).is_ok() => Err(invalid(
            "credential view exists without an ownership marker",
        )),
        None => Ok(None),
    }
}

fn authenticate_existing_state(
    resource: &QualifiedHostResource,
    input: &CredentialInput,
    view_path: &Path,
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
            if details.view != input.view || details.view_path != path_text(view_path)? {
                return Err(invalid("credential marker binds another workload view"));
            }
            Ok(Some(details))
        }
        None if fs::symlink_metadata(view_path).is_ok() => Err(invalid(
            "credential view exists without an ownership marker",
        )),
        None => Ok(None),
    }
}

fn credential_details(state: &HostState) -> Result<CredentialStateDetails, io::Error> {
    serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid credential state details: {error}")))
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
    validate_secret_line(secret.as_slice())?;
    if Sha256Digest::of_bytes(secret.as_slice()) != record.content_digest {
        return Err(invalid(
            "credential source bytes differ from their protected record",
        ));
    }
    Ok(secret)
}

fn validate_secret_line(secret: &[u8]) -> Result<(), io::Error> {
    let Some(content) = secret.strip_suffix(b"\n") else {
        return Err(invalid("credential source is not LF-terminated"));
    };
    if content.is_empty()
        || content.contains(&b'\n')
        || content.contains(&b'\r')
        || content.contains(&0)
        || std::str::from_utf8(content).is_err()
    {
        return Err(invalid("credential source must be one nonempty UTF-8 line"));
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
