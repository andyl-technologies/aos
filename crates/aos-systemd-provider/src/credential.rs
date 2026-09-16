//! systemd-backed named credential resolution and runtime credential views.
//!
//! The provider keeps systemd credential-store paths private to this package.
//! Public ability requests carry only a provider-neutral name, scope, source
//! resource, and encryption mode. Delivery copies the selected opaque bytes
//! into a resource-owned runtime view so rotation and release have one checked
//! owner and never expose credential content in observations or provider state.

use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics, ResourceId,
    ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::model::empty_outputs;
use crate::{decode_value, target_context, value};

const NAMED_CONTEXT_SCHEMA: &str = "aos.systemd.named-credential-context/v1";
const DELIVERY_CONTEXT_SCHEMA: &str = "aos.systemd.credential-delivery-context/v1";
const RECEIPT_SCHEMA: &str = "aos.systemd.credential-delivery-state/v1";
const VIEW_ROOT: &str = "/run/aos/credential-views";
const SYSTEM_CREDENTIAL_ROOT: &str = "/run/credentials/@system";
const ENCRYPTED_CREDENTIAL_ROOTS: &[&str] = &[
    "/run/credstore.encrypted",
    "/etc/credstore.encrypted",
    "/usr/lib/credstore.encrypted",
];
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialRole {
    Delivery,
    NamedResolution,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedCredential {
    name: LocalKey,
    scope: CredentialScope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CredentialScope {
    System,
    User,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDelivery {
    name: LocalKey,
    source: ResourceReference,
    encrypted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedCredentialContext {
    schema: String,
    name: LocalKey,
    scope: CredentialScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDeliveryContext {
    schema: String,
    path: String,
    receipt: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDeliveryReceipt {
    schema: String,
    resource: ResourceId,
    revision: RevisionId,
    source: ResourceReference,
    source_revision: RevisionId,
    encrypted: bool,
    path: String,
}

struct DeliveryPaths {
    directory: PathBuf,
    credential: PathBuf,
    receipt: PathBuf,
}

struct Source<'a> {
    context: &'a ResourceContext,
    named: NamedCredential,
}

struct DeliveryInspection {
    complete: bool,
    path: Option<String>,
}

pub(crate) fn admit(role: CredentialRole, request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported credential admission request schema");
    }
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    require_method(role, &request.method, &request.semantics)?;
    let observation_schema = request
        .contract
        .observation_discriminator()
        .context("selected credential method has no exact observation discriminator")?;
    if !request.resource_spec.realization.as_json().is_null() {
        bail!("credential request unexpectedly carries a desired realization");
    }

    let (observation, native_context, present) = match role {
        CredentialRole::NamedResolution => {
            admit_named(observation_schema, &request, Path::new("/"))?
        }
        CredentialRole::Delivery => admit_delivery(observation_schema, &request, Path::new("/"))?,
    };

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if present {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context,
        supported_purposes: supported_purposes()?,
    })
}

pub(crate) fn invoke(role: CredentialRole, invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported credential invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("credential invocation method is not bound to its checked contract");
    }
    require_method(role, &invocation.method, &invocation.semantics)?;
    require_method(
        role,
        &invocation.request.method,
        &invocation.request.semantics,
    )?;
    if invocation.method.interface != invocation.request.method.interface {
        bail!("credential invocation cannot cross interfaces");
    }
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("credential invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;
    let observation_schema = invocation
        .contract
        .observation_discriminator()
        .context("selected credential method has no exact observation discriminator")?
        .to_owned();

    let bound = validate_resource_context(target_context(&invocation)?)?;
    if invocation.request.inputs != bound.resource_spec.value {
        bail!("credential invocation inputs differ from the checked request");
    }
    if !bound.resource_spec.realization.as_json().is_null() {
        bail!("credential request unexpectedly carries a desired realization");
    }

    match role {
        CredentialRole::NamedResolution => {
            invoke_named(&observation_schema, invocation, &bound, Path::new("/"))
        }
        CredentialRole::Delivery => {
            invoke_delivery(&observation_schema, invocation, &bound, Path::new("/"))
        }
    }
}

fn admit_named(
    observation_schema: &str,
    request: &AdmissionRequest,
    root: &Path,
) -> Result<(AbilityValue, AbilityValue, bool)> {
    let desired: NamedCredential = decode_value(&request.resource_spec.value)?;
    require_system_scope(&desired)?;
    let present = named_credential_available(root, &desired.name)?;
    let realized = present.then(|| request.target.clone());
    let observation = named_observation(observation_schema, &desired, realized.as_ref(), present)?;
    let context = value(&NamedCredentialContext {
        schema: NAMED_CONTEXT_SCHEMA.to_string(),
        name: desired.name.clone(),
        scope: desired.scope,
    })?;
    Ok((observation, context, present))
}

fn invoke_named(
    observation_schema: &str,
    invocation: Invocation,
    bound: &aos_provider_protocol::BoundNativeContext,
    root: &Path,
) -> Result<InvocationResult> {
    if invocation.purpose != InvocationPurpose::Effect
        && !(invocation.purpose == InvocationPurpose::Reconcile
            && invocation.method.method.as_str() == "observe")
    {
        bail!("named credential provider does not advertise this invocation purpose");
    }
    let desired: NamedCredential = decode_value(&bound.resource_spec.value)?;
    require_system_scope(&desired)?;
    let context: NamedCredentialContext = decode_value(&bound.provider_context)?;
    if context.schema != NAMED_CONTEXT_SCHEMA
        || context.name != desired.name
        || context.scope != desired.scope
    {
        bail!("named credential provider context differs from the checked request");
    }

    let present = named_credential_available(root, &desired.name)?;
    let realized = present.then(|| invocation.request.target.clone());
    let evidence = named_observation(observation_schema, &desired, realized.as_ref(), present)?;
    let mut outputs = empty_outputs();
    outputs.insert(LocalKey::new("observation")?, evidence.clone());

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: InvocationDisposition::Completed,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn admit_delivery(
    observation_schema: &str,
    request: &AdmissionRequest,
    root: &Path,
) -> Result<(AbilityValue, AbilityValue, bool)> {
    let desired: CredentialDelivery = decode_value(&request.resource_spec.value)?;
    let source = source_context(&desired.source, &request.resources)?;
    let paths = delivery_paths(root, &request.resource_spec.resource, &desired.name)?;
    let removing = request.method.method.as_str() == "release";
    let inspection = inspect_delivery(
        root,
        &desired,
        &source,
        &request.resource_spec.resource,
        request.resource_spec.revision,
        &paths,
        removing,
    )?;
    let observation = delivery_observation(observation_schema, &desired, &inspection)?;
    let context = value(&CredentialDeliveryContext {
        schema: DELIVERY_CONTEXT_SCHEMA.to_string(),
        path: path_text(&paths.credential)?,
        receipt: path_text(&paths.receipt)?,
    })?;
    Ok((observation, context, inspection.complete))
}

fn invoke_delivery(
    observation_schema: &str,
    invocation: Invocation,
    bound: &aos_provider_protocol::BoundNativeContext,
    root: &Path,
) -> Result<InvocationResult> {
    let desired: CredentialDelivery = decode_value(&bound.resource_spec.value)?;
    let source = source_context(&desired.source, &invocation.request.resources)?;
    let paths = delivery_paths(root, &bound.resource_spec.resource, &desired.name)?;
    let context: CredentialDeliveryContext = decode_value(&bound.provider_context)?;
    if context.schema != DELIVERY_CONTEXT_SCHEMA
        || context.path != path_text(&paths.credential)?
        || context.receipt != path_text(&paths.receipt)?
    {
        bail!("credential delivery context differs from the checked resource paths");
    }

    let removing = invocation.request.method.method.as_str() == "release";
    if invocation.purpose == InvocationPurpose::Effect {
        match invocation.method.method.as_str() {
            "deliver" => deliver(
                root,
                &desired,
                &source,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
                &paths,
            )?,
            "release" => release(&paths)?,
            "observe" => {}
            _ => bail!("unsupported credential delivery method"),
        }
    } else if invocation.purpose != InvocationPurpose::Reconcile
        || invocation.method.method.as_str() != "observe"
    {
        bail!("credential delivery provider does not advertise this invocation purpose");
    }

    let inspection = inspect_delivery(
        root,
        &desired,
        &source,
        &bound.resource_spec.resource,
        bound.resource_spec.revision,
        &paths,
        removing,
    )?;
    let evidence = delivery_observation(observation_schema, &desired, &inspection)?;
    let mut outputs = empty_outputs();
    if inspection.complete {
        outputs.insert(LocalKey::new("observation")?, evidence.clone());
        if !removing && invocation.request.method.method.as_str() == "deliver" {
            outputs.insert(
                LocalKey::new("retained-resource")?,
                value(&invocation.request.target)?,
            );
            outputs.insert(
                LocalKey::new("credential-path")?,
                value(&path_text(&paths.credential)?)?,
            );
        }
    }

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: if inspection.complete {
            InvocationDisposition::Completed
        } else {
            InvocationDisposition::SafeToRetry
        },
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn source_context<'a>(
    reference: &ResourceReference,
    resources: &'a [ResourceContext],
) -> Result<Source<'a>> {
    let matches = resources
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    let [context] = matches.as_slice() else {
        bail!("credential delivery lacks one exact checked source context");
    };
    let bound = validate_resource_context(context)?;
    let named: NamedCredential = decode_value(&bound.resource_spec.value)?;
    require_system_scope(&named)?;
    let native: NamedCredentialContext = decode_value(&bound.provider_context)?;
    if native.schema != NAMED_CONTEXT_SCHEMA
        || native.name != named.name
        || native.scope != named.scope
    {
        bail!("credential source context is not owned by this systemd provider");
    }
    Ok(Source { context, named })
}

fn inspect_delivery(
    root: &Path,
    desired: &CredentialDelivery,
    source: &Source<'_>,
    resource: &ResourceId,
    revision: RevisionId,
    paths: &DeliveryPaths,
    removing: bool,
) -> Result<DeliveryInspection> {
    if removing {
        let absent = !path_exists(&paths.credential)? && !path_exists(&paths.receipt)?;
        return Ok(DeliveryInspection {
            complete: absent,
            path: None,
        });
    }

    let source_path = selected_source_path(root, &source.named, desired.encrypted)?;
    let source_bytes = read_regular_bounded(&source_path, "credential source")?;
    let view_bytes = read_optional_regular_bounded(&paths.credential, "credential view")?;
    let expected_receipt = receipt(desired, source, resource, revision, paths)?;
    let observed_receipt = read_optional_receipt(&paths.receipt)?;
    let complete = view_bytes.as_deref() == Some(source_bytes.as_slice())
        && observed_receipt.as_ref() == Some(&expected_receipt)
        && mode(&paths.credential)? == Some(0o400);

    Ok(DeliveryInspection {
        complete,
        path: complete.then(|| path_text(&paths.credential)).transpose()?,
    })
}

fn deliver(
    root: &Path,
    desired: &CredentialDelivery,
    source: &Source<'_>,
    resource: &ResourceId,
    revision: RevisionId,
    paths: &DeliveryPaths,
) -> Result<()> {
    let source_path = selected_source_path(root, &source.named, desired.encrypted)?;
    let bytes = read_regular_bounded(&source_path, "credential source")?;
    ensure_private_directory(&paths.directory)?;
    reject_symlink_if_present(&paths.credential, "credential view")?;
    reject_symlink_if_present(&paths.receipt, "credential receipt")?;
    write_atomic(&paths.credential, &bytes, 0o400)?;
    let receipt = receipt(desired, source, resource, revision, paths)?;
    let receipt_bytes = aos_contract::canonical::to_vec(&receipt)
        .context("encoding credential delivery receipt")?;
    write_atomic(&paths.receipt, &receipt_bytes, 0o600)
}

fn release(paths: &DeliveryPaths) -> Result<()> {
    remove_regular_if_present(&paths.credential, "credential view")?;
    remove_regular_if_present(&paths.receipt, "credential receipt")?;
    match fs::remove_dir(&paths.directory) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(error) => return Err(error).context("removing empty credential view directory"),
    }
    Ok(())
}

fn receipt(
    desired: &CredentialDelivery,
    source: &Source<'_>,
    resource: &ResourceId,
    revision: RevisionId,
    paths: &DeliveryPaths,
) -> Result<CredentialDeliveryReceipt> {
    Ok(CredentialDeliveryReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        resource: resource.clone(),
        revision,
        source: desired.source.clone(),
        source_revision: source.context.revision,
        encrypted: desired.encrypted,
        path: path_text(&paths.credential)?,
    })
}

fn named_observation(
    observation_schema: &str,
    desired: &NamedCredential,
    realized: Option<&ResourceReference>,
    present: bool,
) -> Result<AbilityValue> {
    value(&serde_json::json!({
        "schema": observation_schema,
        "expected": desired,
        "realized": realized,
        "state": if present { "ready" } else { "absent" },
    }))
}

fn delivery_observation(
    observation_schema: &str,
    desired: &CredentialDelivery,
    inspection: &DeliveryInspection,
) -> Result<AbilityValue> {
    value(&serde_json::json!({
        "schema": observation_schema,
        "expected": desired,
        "realized": inspection.path,
        "state": if inspection.complete { "ready" } else { "absent" },
    }))
}

fn delivery_paths(root: &Path, resource: &ResourceId, name: &LocalKey) -> Result<DeliveryPaths> {
    let digest = Sha256Digest::of_canonical("aos.systemd.credential-view/v1", resource)?;
    let key = digest.to_string();
    let key = key
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("credential resource digest lacks sha256 prefix"))?;
    let directory = rooted(root, VIEW_ROOT).join(key);
    Ok(DeliveryPaths {
        credential: directory.join(name.as_str()),
        receipt: directory.join("receipt.json"),
        directory,
    })
}

fn named_credential_available(root: &Path, name: &LocalKey) -> Result<bool> {
    let plaintext = rooted(root, SYSTEM_CREDENTIAL_ROOT).join(name.as_str());
    let plaintext_present = regular_file_present(&plaintext, "system credential")?;
    let encrypted_present = encrypted_source_candidates(root, name)?
        .iter()
        .map(|path| regular_file_present(path, "encrypted credential source"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .any(|present| present);
    Ok(plaintext_present || encrypted_present)
}

fn selected_source_path(root: &Path, named: &NamedCredential, encrypted: bool) -> Result<PathBuf> {
    require_system_scope(named)?;
    if !encrypted {
        let path = rooted(root, SYSTEM_CREDENTIAL_ROOT).join(named.name.as_str());
        if !regular_file_present(&path, "system credential")? {
            bail!("named system credential '{}' is unavailable", named.name);
        }
        return Ok(path);
    }

    let candidates = encrypted_source_candidates(root, &named.name)?;
    let present = candidates
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    match present.as_slice() {
        [path] => {
            read_regular_bounded(path, "encrypted credential source")?;
            Ok(path.clone())
        }
        [] => bail!("named encrypted credential '{}' is unavailable", named.name),
        _ => bail!(
            "named encrypted credential '{}' is ambiguous across credential stores",
            named.name
        ),
    }
}

fn encrypted_source_candidates(root: &Path, name: &LocalKey) -> Result<Vec<PathBuf>> {
    let candidates = ENCRYPTED_CREDENTIAL_ROOTS
        .iter()
        .map(|prefix| rooted(root, prefix).join(name.as_str()))
        .collect::<Vec<_>>();
    for path in &candidates {
        reject_symlink_if_present(path, "encrypted credential source")?;
    }
    Ok(candidates)
}

fn require_system_scope(desired: &NamedCredential) -> Result<()> {
    if desired.scope != CredentialScope::System {
        bail!("systemd credential provider supports only the system credential scope");
    }
    Ok(())
}

fn require_method(
    role: CredentialRole,
    method: &MethodReference,
    semantics: &MethodSemantics,
) -> Result<()> {
    let expected = match (role, method.method.as_str()) {
        (CredentialRole::NamedResolution, "observe") | (CredentialRole::Delivery, "observe") => {
            MethodSemantics::ordinary(AccessMode::Read)
        }
        (CredentialRole::Delivery, "deliver") => {
            MethodSemantics::ordinary(AccessMode::ExclusiveWrite)
        }
        (CredentialRole::Delivery, "release") => MethodSemantics::provider_stop(),
        _ => bail!("handler invocation selects an unsupported credential method"),
    };
    if *semantics != expected {
        bail!("credential method carries mismatched semantics");
    }
    Ok(())
}

fn supported_purposes() -> Result<SupportedPurposes> {
    SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("credential purpose set is not canonical"))
}

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("credential path is not UTF-8"))
}

fn regular_file_present(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{label} is not a regular file: {}", path.display())
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {label} {}", path.display())),
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn reject_symlink_if_present(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{label} must not be a symlink: {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {label} {}", path.display())),
    }
}

fn read_regular_bounded(path: &Path, label: &str) -> Result<Vec<u8>> {
    if !regular_file_present(path, label)? {
        bail!("{label} is unavailable: {}", path.display());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening {label} {}", path.display()))?
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        bail!("{label} exceeds the credential size bound");
    }
    Ok(bytes)
}

fn read_optional_regular_bounded(path: &Path, label: &str) -> Result<Option<Vec<u8>>> {
    if !path_exists(path)? {
        return Ok(None);
    }
    read_regular_bounded(path, label).map(Some)
}

fn read_optional_receipt(path: &Path) -> Result<Option<CredentialDeliveryReceipt>> {
    let Some(bytes) = read_optional_regular_bounded(path, "credential receipt")? else {
        return Ok(None);
    };
    let receipt: CredentialDeliveryReceipt =
        serde_json::from_slice(&bytes).context("decoding credential delivery receipt")?;
    if receipt.schema != RECEIPT_SCHEMA {
        bail!("unsupported credential delivery receipt schema");
    }
    Ok(Some(receipt))
}

fn mode(path: &Path) -> Result<Option<u32>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata.permissions().mode() & 0o7777)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading mode for {}", path.display())),
    }
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("credential view directory is not a real directory");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8], file_mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("credential output has no parent directory"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary credential in {}", parent.display()))?;
    temporary
        .as_file_mut()
        .write_all(bytes)
        .with_context(|| format!("writing temporary credential for {}", path.display()))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(file_mode))
        .with_context(|| format!("setting credential mode for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing temporary credential for {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing credential {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening credential directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing credential directory {}", parent.display()))
}

fn remove_regular_if_present(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{label} is not a regular file: {}", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("removing {label} {}", path.display()))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspecting {label} {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_ability_model::{
        EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, InterfaceName,
    };

    const NAMED_INTERFACE: &str = "aos.credential.named-resolution";
    const NAMED_OBSERVATION_SCHEMA: &str = "aos.ability.named-credential-observation/v1";

    fn resource(key: &str) -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority"),
                    key: LocalKey::new("host").expect("environment"),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("credentials").expect("provider"),
            },
            key: LocalKey::new(key).expect("resource"),
        }
    }

    fn reference(key: &str) -> ResourceReference {
        ResourceReference {
            interface: InterfaceKey {
                name: InterfaceName::new(NAMED_INTERFACE).expect("interface"),
                abi: std::num::NonZeroU32::new(1).expect("ABI"),
                descriptor: Sha256Digest::of_bytes(b"named-credential-interface"),
            },
            resource: resource(key),
            operations: vec![LocalKey::new("observe").expect("operation")],
            lifetime: aos_ability_model::ResourceLifetime::Instance,
        }
    }

    #[test]
    fn system_scope_resolves_plaintext_and_rejects_user_scope() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let source = rooted(temporary.path(), SYSTEM_CREDENTIAL_ROOT).join("bootstrap-token");
        fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        fs::write(&source, b"alpha").expect("source");

        let system = NamedCredential {
            name: LocalKey::new("bootstrap-token").expect("credential name"),
            scope: CredentialScope::System,
        };
        assert_eq!(
            selected_source_path(temporary.path(), &system, false).expect("system source"),
            source
        );

        let user = NamedCredential {
            name: LocalKey::new("bootstrap-token").expect("credential name"),
            scope: CredentialScope::User,
        };
        assert!(selected_source_path(temporary.path(), &user, false).is_err());
    }

    #[test]
    fn encrypted_source_rejects_ambiguous_store_entries() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let named = NamedCredential {
            name: LocalKey::new("join-token").expect("credential name"),
            scope: CredentialScope::System,
        };
        for root in &ENCRYPTED_CREDENTIAL_ROOTS[..2] {
            let path = rooted(temporary.path(), root).join(named.name.as_str());
            fs::create_dir_all(path.parent().expect("source parent")).expect("source directory");
            fs::write(path, b"ciphertext").expect("source");
        }

        assert!(selected_source_path(temporary.path(), &named, true).is_err());
    }

    #[test]
    fn delivery_rotates_and_release_revokes_one_owned_view() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let named = NamedCredential {
            name: LocalKey::new("bootstrap-token").expect("credential name"),
            scope: CredentialScope::System,
        };
        let source_path =
            rooted(temporary.path(), SYSTEM_CREDENTIAL_ROOT).join(named.name.as_str());
        fs::create_dir_all(source_path.parent().expect("source parent")).expect("source directory");
        fs::write(&source_path, b"alpha").expect("source");

        let source_reference = reference("source");
        let source_context = ResourceContext {
            assignment: serde_json::from_value(serde_json::json!({
                "provider": source_reference.resource.provider,
                "interface": source_reference.interface,
                "implementation": {
                    "descriptor": format!("sha256:{}", "1".repeat(64)),
                    "artifact": {
                        "content": format!("sha256:{}", "2".repeat(64)),
                        "store_path": "/nix/store/00000000000000000000000000000000-systemd-provider",
                        "nar_hash": format!("sha256:{}", "3".repeat(64)),
                        "closure": format!("sha256:{}", "4".repeat(64))
                    },
                    "handler": "named-credential-resolution"
                },
                "incarnation": "test-incarnation"
            }))
            .expect("assignment"),
            reference: source_reference.clone(),
            revision: RevisionId(Sha256Digest::of_bytes(b"source-revision")),
            observation: value(&serde_json::json!({
                "schema": NAMED_OBSERVATION_SCHEMA,
                "expected": named,
                "realized": source_reference,
                "state": "ready"
            }))
            .expect("observation"),
            native_context: value(&serde_json::json!({
                "schema": aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA,
                "resource_spec": {
                    "resource": source_reference.resource,
                    "kind": source_reference.interface.name,
                    "lifetime": "instance",
                    "value": named,
                    "realization": null,
                    "revision": format!("sha256:{}", Sha256Digest::of_bytes(b"source-revision").hex())
                },
                "provider_context": {
                    "schema": NAMED_CONTEXT_SCHEMA,
                    "name": "bootstrap-token",
                    "scope": "system"
                }
            }))
            .expect("native context"),
            native_context_digest: Sha256Digest::of_bytes(b"placeholder"),
        };
        let source = Source {
            context: &source_context,
            named,
        };
        let desired = CredentialDelivery {
            name: LocalKey::new("join-token").expect("credential name"),
            source: source_reference,
            encrypted: false,
        };
        let target = resource("view");
        let revision = RevisionId(Sha256Digest::of_bytes(b"view-revision"));
        let paths = delivery_paths(temporary.path(), &target, &desired.name).expect("paths");

        deliver(
            temporary.path(),
            &desired,
            &source,
            &target,
            revision,
            &paths,
        )
        .expect("initial delivery");
        assert_eq!(fs::read(&paths.credential).expect("view"), b"alpha");
        assert_eq!(mode(&paths.credential).expect("mode"), Some(0o400));

        fs::write(&source_path, b"beta").expect("rotated source");
        assert!(
            !inspect_delivery(
                temporary.path(),
                &desired,
                &source,
                &target,
                revision,
                &paths,
                false,
            )
            .expect("drift observation")
            .complete
        );
        deliver(
            temporary.path(),
            &desired,
            &source,
            &target,
            revision,
            &paths,
        )
        .expect("rotation");
        assert_eq!(fs::read(&paths.credential).expect("rotated view"), b"beta");

        release(&paths).expect("release");
        assert!(!paths.credential.exists());
        assert!(!paths.receipt.exists());
    }

    #[test]
    fn delivery_rejects_symlink_sources() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"secret").expect("outside source");
        let source = rooted(temporary.path(), SYSTEM_CREDENTIAL_ROOT).join("bootstrap-token");
        fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::os::unix::fs::symlink(outside, &source).expect("source symlink");
        let named = NamedCredential {
            name: LocalKey::new("bootstrap-token").expect("credential name"),
            scope: CredentialScope::System,
        };

        assert!(selected_source_path(temporary.path(), &named, false).is_err());
    }
}
