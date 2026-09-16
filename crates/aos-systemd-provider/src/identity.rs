//! systemd-sysusers-backed principal, group, and group-membership effects.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics, ResourceId,
    ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::NamedTempFile;

use crate::{decode_value, empty_outputs, target_context, value};

const ETC_ROOT: &str = "/etc";
const SYSUSERS: &str = "/run/current-system/sw/bin/systemd-sysusers";
const CONTEXT_SCHEMA: &str = "aos.systemd.identity-context/v1";
const IDENTITY_LOCK: &str = "/run/lock/aos-systemd-identity.lock";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Allocation {
    Ephemeral,
    Existing,
    Managed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GroupDesired {
    name: String,
    allocation: Allocation,
    requested_id: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDesired {
    name: String,
    allocation: Allocation,
    requested_id: Option<u32>,
    description: Option<String>,
    home_directory: Option<String>,
    login_access: Option<String>,
    primary_group: Option<String>,
    supplementary_groups: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MembershipDesired {
    name: String,
    group: ResourceReference,
    principals: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectRequest<T> {
    desired: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct IdentityRealization {
    #[serde(rename = "schema")]
    _schema: String,
    backend: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityContext {
    schema: String,
    receipt: String,
    fragment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityReceipt {
    schema: String,
    resource: ResourceId,
    revision: RevisionId,
    fragment: String,
    identity_name: Option<String>,
    numeric_id: Option<u32>,
    group: Option<String>,
    principals: Vec<String>,
    supplementary_groups: Vec<String>,
}

enum Desired {
    Principal(PrincipalDesired),
    Group(GroupDesired),
    Membership(MembershipDesired),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityRole {
    Group,
    GroupMembership,
    Principal,
}

pub(crate) async fn admit(
    role: IdentityRole,
    request: AdmissionRequest,
) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported identity admission request schema");
    }
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    let observation_schema = request
        .contract
        .observation_discriminator_at(&["observation", "schema"])
        .context("selected identity method has no exact observation discriminator")?;
    require_method(&request.method, &request.semantics)?;
    require_realization(&request.resource_spec.realization)?;

    let desired = desired_from_value(role, &request.resource_spec.value)?;
    let resolved = resolve_membership(&desired, &request.resources)?;
    let paths = paths_for(
        Path::new(ETC_ROOT),
        &request.resource_spec.resource,
        request.resource_spec.revision,
    )?;
    let complete = observe(
        &desired,
        &resolved,
        &request.resource_spec.resource,
        request.resource_spec.revision,
        &paths,
        false,
    )?;
    let observation = observation(
        observation_schema,
        &desired,
        &request.resource_spec.value,
        &resolved,
        complete,
        false,
    )?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("identity provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if complete {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: value(&IdentityContext {
            schema: CONTEXT_SCHEMA.to_string(),
            receipt: paths.receipt.to_string_lossy().into_owned(),
            fragment: paths.fragment.to_string_lossy().into_owned(),
        })?,
        supported_purposes,
    })
}

pub(crate) async fn invoke(role: IdentityRole, invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported identity invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("identity invocation method is not bound to its recovery contract");
    }
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("identity invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;
    let observation_schema = invocation
        .contract
        .observation_discriminator_at(&["observation", "schema"])
        .context("selected identity method has no exact observation discriminator")?;
    require_method(&invocation.method, &invocation.semantics)?;
    require_method(&invocation.request.method, &invocation.request.semantics)?;
    if invocation.method.interface != invocation.request.method.interface {
        bail!("identity recovery cannot cross effect interfaces");
    }

    let bound = validate_resource_context(target_context(&invocation)?)?;
    require_realization(&bound.resource_spec.realization)?;
    let desired = desired_from_value(role, &bound.resource_spec.value)?;
    require_inputs(&desired, &invocation.request.inputs)?;
    let resolved = resolve_membership(&desired, &invocation.request.resources)?;
    let paths = paths_for(
        Path::new(ETC_ROOT),
        &bound.resource_spec.resource,
        bound.resource_spec.revision,
    )?;
    let context: IdentityContext = decode_value(&bound.provider_context)?;
    if context.schema != CONTEXT_SCHEMA
        || context.receipt != paths.receipt.to_string_lossy()
        || context.fragment != paths.fragment.to_string_lossy()
    {
        bail!("identity provider context does not match the checked resource paths");
    }

    let method = invocation.method.method.as_str();
    let removing = invocation.request.method.method.as_str() == "remove";
    if invocation.purpose == InvocationPurpose::Effect {
        match method {
            "create" | "reconcile" | "update" => apply(
                &desired,
                &resolved,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
                &paths,
            )?,
            "remove" => remove(&desired, &paths)?,
            "observe" => {}
            _ => bail!("unsupported identity effect method"),
        }
    } else if invocation.purpose != InvocationPurpose::Reconcile || method != "observe" {
        bail!("identity provider does not advertise this invocation purpose");
    }

    let complete = observe(
        &desired,
        &resolved,
        &bound.resource_spec.resource,
        bound.resource_spec.revision,
        &paths,
        removing,
    )?;
    let evidence = observation(
        observation_schema,
        &desired,
        &bound.resource_spec.value,
        &resolved,
        complete,
        removing,
    )?;
    let disposition = if complete {
        InvocationDisposition::Completed
    } else {
        InvocationDisposition::SafeToRetry
    };
    let mut outputs = empty_outputs();
    if complete {
        outputs.insert(LocalKey::new("observation")?, evidence.clone());
    }

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    let expected = match method.method.as_str() {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "create" | "reconcile" | "update" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "remove" => MethodSemantics::provider_stop(),
        _ => bail!("unsupported identity effect method"),
    };
    if *semantics != expected {
        bail!("identity effect method carries mismatched semantics");
    }
    Ok(())
}

fn require_realization(value: &AbilityValue) -> Result<()> {
    let realization: IdentityRealization = decode_value(value)?;
    if realization.backend != "systemd-sysusers" {
        bail!("identity resource uses an unsupported realization");
    }
    Ok(())
}

fn desired_from_value(role: IdentityRole, value: &AbilityValue) -> Result<Desired> {
    match role {
        IdentityRole::Principal => Ok(Desired::Principal(decode_value(value)?)),
        IdentityRole::Group => Ok(Desired::Group(decode_value(value)?)),
        IdentityRole::GroupMembership => Ok(Desired::Membership(decode_value(value)?)),
    }
}

fn require_inputs(desired: &Desired, inputs: &AbilityValue) -> Result<()> {
    let matches = match desired {
        Desired::Principal(value) => {
            decode_value::<EffectRequest<PrincipalDesired>>(inputs)?.desired == *value
        }
        Desired::Group(value) => {
            decode_value::<EffectRequest<GroupDesired>>(inputs)?.desired == *value
        }
        Desired::Membership(value) => {
            decode_value::<EffectRequest<MembershipDesired>>(inputs)?.desired == *value
        }
    };
    if !matches {
        bail!("identity effect inputs differ from the checked desired resource");
    }
    Ok(())
}

struct IdentityPaths {
    fragment: PathBuf,
    receipts: PathBuf,
    receipt: PathBuf,
}

fn paths_for(root: &Path, resource: &ResourceId, revision: RevisionId) -> Result<IdentityPaths> {
    let digest = Sha256Digest::of_bytes(aos_contract::canonical::to_vec(resource)?);
    let stem = digest.hex();
    let receipts = root
        .join("aos/ability-revisions/identity")
        .join(&stem)
        .join("sha256");
    Ok(IdentityPaths {
        fragment: root.join("sysusers.d").join(format!("90-aos-{stem}.conf")),
        receipt: receipts.join(revision.0.hex()),
        receipts,
    })
}

#[derive(Default)]
struct ResolvedMembership {
    group: Option<String>,
    principals: Vec<String>,
}

fn resolve_membership(
    desired: &Desired,
    contexts: &[aos_provider_protocol::ResourceContext],
) -> Result<ResolvedMembership> {
    let Desired::Membership(membership) = desired else {
        return Ok(ResolvedMembership::default());
    };
    let group = name_from_reference(&membership.group, "aos.identity.group", contexts)?;
    let mut principals = membership
        .principals
        .iter()
        .map(|reference| name_from_reference(reference, "aos.identity.principal", contexts))
        .collect::<Result<Vec<_>>>()?;
    principals.sort();
    if principals.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("group membership resolves duplicate principal names");
    }
    Ok(ResolvedMembership {
        group: Some(group),
        principals,
    })
}

fn name_from_reference(
    reference: &ResourceReference,
    interface: &str,
    contexts: &[aos_provider_protocol::ResourceContext],
) -> Result<String> {
    if reference.interface.name.as_str() != interface
        || !reference
            .operations
            .iter()
            .any(|operation| operation.as_str() == "observe")
    {
        bail!("identity membership reference lacks exact observation authority");
    }
    let matches = contexts
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("identity membership reference has no unique checked resource context");
    }
    let bound = validate_resource_context(matches[0])?;
    bound
        .resource_spec
        .value
        .as_json()
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("identity membership resource has no canonical name")
}

fn apply(
    desired: &Desired,
    resolved: &ResolvedMembership,
    resource: &ResourceId,
    revision: RevisionId,
    paths: &IdentityPaths,
) -> Result<()> {
    let _lock = identity_lock()?;
    let previous_receipts = receipts(paths)?;
    let fragment = fragment(desired, resolved)?;
    if !fragment.is_empty() {
        publish(&paths.fragment, fragment.as_bytes())?;
        let status = Command::new(SYSUSERS)
            .arg(&paths.fragment)
            .status()
            .context("executing systemd-sysusers")?;
        if !status.success() {
            bail!("systemd-sysusers rejected the checked identity fragment");
        }
    }
    reconcile_owned_memberships(
        Path::new(ETC_ROOT),
        &owned_memberships(desired, resolved),
        &previous_receipts
            .iter()
            .flat_map(receipt_memberships)
            .collect::<Vec<_>>(),
    )?;
    let identity_name = desired.identity_name().map(str::to_owned);
    let numeric_id = match identity_name.as_deref() {
        Some(name) => Some(
            identity_numeric_id(Path::new(ETC_ROOT), desired, name)?
                .context("identity is absent after systemd-sysusers completed")?,
        ),
        None => None,
    };
    if desired
        .requested_id()
        .is_some_and(|id| Some(id) != numeric_id)
    {
        bail!("systemd-sysusers did not realize the requested numeric identity");
    }
    let receipt = IdentityReceipt {
        schema: "aos.systemd.identity-receipt/v1".to_string(),
        resource: resource.clone(),
        revision,
        fragment,
        identity_name,
        numeric_id,
        group: resolved.group.clone(),
        principals: resolved.principals.clone(),
        supplementary_groups: desired.supplementary_groups(),
    };
    publish(&paths.receipt, &aos_contract::canonical::to_vec(&receipt)?)?;
    remove_other_receipts(paths)
}

fn remove(desired: &Desired, paths: &IdentityPaths) -> Result<()> {
    let _lock = identity_lock()?;
    let receipts = receipts(paths)?;
    reconcile_owned_memberships(
        Path::new(ETC_ROOT),
        &[],
        &receipts
            .iter()
            .flat_map(receipt_memberships)
            .collect::<Vec<_>>(),
    )?;

    if desired.owns_identity() {
        let owned = receipts
            .iter()
            .find_map(|receipt| receipt.identity_name.as_deref().zip(receipt.numeric_id));
        if let Some((name, numeric_id)) = owned
            && !remove_identity(Path::new(ETC_ROOT), desired, name, numeric_id)?
        {
            return Ok(());
        }
    }
    remove_if_present(&paths.fragment)?;
    for receipt in receipt_paths(paths)? {
        remove_if_present(&receipt)?;
    }
    Ok(())
}

fn fragment(desired: &Desired, resolved: &ResolvedMembership) -> Result<String> {
    match desired {
        Desired::Group(group) if group.allocation != Allocation::Existing => Ok(format!(
            "g {} {}\n",
            group.name,
            group
                .requested_id
                .map_or_else(|| "-".to_string(), |id| id.to_string())
        )),
        Desired::Principal(principal) if principal.allocation != Allocation::Existing => {
            let id = principal
                .requested_id
                .map_or_else(|| "-".to_string(), |id| id.to_string());
            let group = principal.primary_group.as_deref().unwrap_or("-");
            let description = principal.description.as_deref().unwrap_or("-");
            let home = principal.home_directory.as_deref().unwrap_or("-");
            let shell = if principal.login_access.as_deref() == Some("enabled") {
                "/run/current-system/sw/bin/sh"
            } else {
                "/run/current-system/sw/bin/nologin"
            };
            let mut lines = vec![format!(
                "u {} {}:{} \"{}\" {} {}",
                principal.name,
                id,
                group,
                sysusers_quoted(description),
                sysusers_word(home),
                shell,
            )];
            for supplementary in principal.supplementary_groups.as_deref().unwrap_or(&[]) {
                lines.push(format!("m {} {}", principal.name, supplementary));
            }
            Ok(format!("{}\n", lines.join("\n")))
        }
        Desired::Membership(_) => {
            let group = resolved
                .group
                .as_deref()
                .context("membership has no resolved group")?;
            Ok(resolved
                .principals
                .iter()
                .map(|principal| format!("m {principal} {group}\n"))
                .collect())
        }
        _ => Ok(String::new()),
    }
}

fn sysusers_quoted(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('%', "%%")
}

fn sysusers_word(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{}\"", sysusers_quoted(value))
    } else {
        sysusers_quoted(value)
    }
}

fn observe(
    desired: &Desired,
    resolved: &ResolvedMembership,
    resource: &ResourceId,
    revision: RevisionId,
    paths: &IdentityPaths,
    removing: bool,
) -> Result<bool> {
    if removing {
        return Ok(!paths.fragment.exists() && receipt_paths(paths)?.is_empty());
    }
    let Some(receipt) = read_receipt(&paths.receipt)? else {
        return Ok(false);
    };
    let expected_receipt = IdentityReceipt {
        schema: "aos.systemd.identity-receipt/v1".to_string(),
        resource: resource.clone(),
        revision,
        fragment: fragment(desired, resolved)?,
        identity_name: desired.identity_name().map(str::to_owned),
        numeric_id: receipt.numeric_id,
        group: resolved.group.clone(),
        principals: resolved.principals.clone(),
        supplementary_groups: desired.supplementary_groups(),
    };
    if receipt != expected_receipt {
        return Ok(false);
    }
    match desired {
        Desired::Group(group) => group_exists(Path::new(ETC_ROOT), &group.name, receipt.numeric_id),
        Desired::Principal(principal) => {
            principal_exists(Path::new(ETC_ROOT), &principal.name, receipt.numeric_id)
        }
        Desired::Membership(_) => membership_exists(Path::new(ETC_ROOT), resolved),
    }
}

fn observation(
    observation_schema: &str,
    desired: &Desired,
    expected: &AbilityValue,
    resolved: &ResolvedMembership,
    complete: bool,
    removing: bool,
) -> Result<AbilityValue> {
    let (kind, realized) = match desired {
        Desired::Principal(principal) => ("aos.identity.principal", Some(json!(principal.name))),
        Desired::Group(group) => ("aos.identity.group", Some(json!(group.name))),
        Desired::Membership(_) => ("aos.identity.group-membership", None),
    };
    let mut inner = json!({
        "schema": observation_schema,
        "expected": expected.as_json(),
        "state": if complete && !removing { "ready" } else { "absent" },
    });
    if complete
        && !removing
        && let Some(realized) = realized
    {
        inner["realized"] = realized;
    }
    let _ = resolved;
    value(&json!({"kind": kind, "observation": inner}))
}

fn principal_exists(root: &Path, name: &str, requested_id: Option<u32>) -> Result<bool> {
    account_exists(&root.join("passwd"), name, requested_id)
}

fn group_exists(root: &Path, name: &str, requested_id: Option<u32>) -> Result<bool> {
    account_exists(&root.join("group"), name, requested_id)
}

fn account_exists(path: &Path, name: &str, requested_id: Option<u32>) -> Result<bool> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in content.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first() == Some(&name) {
            let id = fields.get(2).and_then(|value| value.parse::<u32>().ok());
            return Ok(requested_id.is_none() || id == requested_id);
        }
    }
    Ok(false)
}

fn membership_exists(root: &Path, resolved: &ResolvedMembership) -> Result<bool> {
    let group = resolved
        .group
        .as_deref()
        .context("membership has no resolved group")?;
    let content = fs::read_to_string(root.join("group")).context("reading group database")?;
    let members = content
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.first() == Some(&group)).then(|| fields.get(3).copied().unwrap_or(""))
        })
        .context("membership group is absent")?;
    let members = members
        .split(',')
        .filter(|member| !member.is_empty())
        .collect::<BTreeSet<_>>();
    Ok(resolved
        .principals
        .iter()
        .all(|principal| members.contains(principal.as_str())))
}

fn receipt_paths(paths: &IdentityPaths) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(&paths.receipts) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("reading identity receipt directory"),
    };
    let mut result = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    result.sort();
    Ok(result)
}

fn receipts(paths: &IdentityPaths) -> Result<Vec<IdentityReceipt>> {
    receipt_paths(paths)?
        .iter()
        .map(|path| {
            read_receipt(path)?.ok_or_else(|| anyhow::anyhow!("identity receipt disappeared"))
        })
        .collect()
}

fn remove_other_receipts(paths: &IdentityPaths) -> Result<()> {
    for path in receipt_paths(paths)? {
        if path != paths.receipt {
            remove_if_present(&path)?;
        }
    }
    Ok(())
}

fn read_receipt(path: &Path) -> Result<Option<IdentityReceipt>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("decoding identity receipt")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading identity receipt"),
    }
}

fn reconcile_owned_memberships(
    root: &Path,
    desired: &[(String, String)],
    prior: &[(String, String)],
) -> Result<()> {
    let groups = desired
        .iter()
        .chain(prior)
        .map(|(group, _)| group.as_str())
        .collect::<BTreeSet<_>>();
    if groups.is_empty() {
        return Ok(());
    }

    let prior = prior.iter().cloned().collect::<BTreeSet<_>>();
    let desired = desired.iter().cloned().collect::<BTreeSet<_>>();
    reconcile_membership_database(&root.join("group"), &groups, &desired, &prior)?;
    let gshadow = root.join("gshadow");
    if gshadow.exists() {
        reconcile_membership_database(&gshadow, &groups, &desired, &prior)?;
    }
    Ok(())
}

fn reconcile_membership_database(
    path: &Path,
    groups: &BTreeSet<&str>,
    desired: &BTreeSet<(String, String)>,
    prior: &BTreeSet<(String, String)>,
) -> Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading identity membership database {}", path.display()))?;
    let mut found = BTreeSet::new();
    let mut lines = Vec::new();
    for line in content.lines() {
        let mut fields = line.split(':').map(str::to_owned).collect::<Vec<_>>();
        if fields
            .first()
            .is_some_and(|name| groups.contains(name.as_str()))
        {
            let group = fields[0].clone();
            found.insert(group.clone());
            while fields.len() < 4 {
                fields.push(String::new());
            }
            let mut members = fields[3]
                .split(',')
                .filter(|member| {
                    !member.is_empty() && !prior.contains(&(group.clone(), (*member).to_owned()))
                })
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            members.extend(
                desired
                    .iter()
                    .filter(|(desired_group, _)| desired_group == &group)
                    .map(|(_, principal)| principal.clone()),
            );
            fields[3] = members.into_iter().collect::<Vec<_>>().join(",");
        }
        lines.push(fields.join(":"));
    }
    if found.len() != groups.len() {
        bail!("an identity membership group is absent from the group database");
    }
    publish(path, format!("{}\n", lines.join("\n")).as_bytes())
}

fn owned_memberships(desired: &Desired, resolved: &ResolvedMembership) -> Vec<(String, String)> {
    match desired {
        Desired::Principal(principal) => principal
            .supplementary_groups
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|group| (group.clone(), principal.name.clone()))
            .collect(),
        Desired::Membership(_) => resolved
            .group
            .iter()
            .flat_map(|group| {
                resolved
                    .principals
                    .iter()
                    .map(move |principal| (group.clone(), principal.clone()))
            })
            .collect(),
        Desired::Group(_) => Vec::new(),
    }
}

fn receipt_memberships(receipt: &IdentityReceipt) -> Vec<(String, String)> {
    let mut memberships = receipt
        .group
        .iter()
        .flat_map(|group| {
            receipt
                .principals
                .iter()
                .map(move |principal| (group.clone(), principal.clone()))
        })
        .collect::<Vec<_>>();
    if let Some(principal) = &receipt.identity_name {
        memberships.extend(
            receipt
                .supplementary_groups
                .iter()
                .map(|group| (group.clone(), principal.clone())),
        );
    }
    memberships
}

impl Desired {
    fn identity_name(&self) -> Option<&str> {
        match self {
            Self::Principal(principal) => Some(&principal.name),
            Self::Group(group) => Some(&group.name),
            Self::Membership(_) => None,
        }
    }

    fn owns_identity(&self) -> bool {
        match self {
            Self::Principal(principal) => principal.allocation != Allocation::Existing,
            Self::Group(group) => group.allocation != Allocation::Existing,
            Self::Membership(_) => false,
        }
    }

    fn supplementary_groups(&self) -> Vec<String> {
        match self {
            Self::Principal(principal) => {
                principal.supplementary_groups.clone().unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }

    fn requested_id(&self) -> Option<u32> {
        match self {
            Self::Principal(principal) => principal.requested_id,
            Self::Group(group) => group.requested_id,
            Self::Membership(_) => None,
        }
    }
}

fn identity_numeric_id(root: &Path, desired: &Desired, name: &str) -> Result<Option<u32>> {
    let database = match desired {
        Desired::Principal(_) => "passwd",
        Desired::Group(_) => "group",
        Desired::Membership(_) => return Ok(None),
    };
    account_id(&root.join(database), name)
}

fn account_id(path: &Path, name: &str) -> Result<Option<u32>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(content.lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        (fields.first() == Some(&name))
            .then(|| fields.get(2).and_then(|value| value.parse::<u32>().ok()))
            .flatten()
    }))
}

fn remove_identity(root: &Path, desired: &Desired, name: &str, numeric_id: u32) -> Result<bool> {
    match desired {
        Desired::Principal(_) => {
            let current = account_id(&root.join("passwd"), name)?;
            if current.is_some() && current != Some(numeric_id) {
                return Ok(false);
            }
            if current.is_none() {
                return Ok(true);
            }
            remove_principal_from_groups(root, name)?;
            remove_database_entry(&root.join("passwd"), name)?;
            remove_database_entry(&root.join("shadow"), name)?;
            Ok(true)
        }
        Desired::Group(_) => {
            let current = account_id(&root.join("group"), name)?;
            if current.is_some() && current != Some(numeric_id) {
                return Ok(false);
            }
            if current.is_none() {
                return Ok(true);
            }
            if group_is_referenced(root, name)? {
                return Ok(false);
            }
            remove_database_entry(&root.join("group"), name)?;
            remove_database_entry(&root.join("gshadow"), name)?;
            Ok(true)
        }
        Desired::Membership(_) => Ok(true),
    }
}

fn group_is_referenced(root: &Path, name: &str) -> Result<bool> {
    let Some(group_id) = account_id(&root.join("group"), name)? else {
        return Ok(false);
    };
    let passwd = fs::read_to_string(root.join("passwd")).context("reading passwd database")?;
    Ok(passwd.lines().any(|line| {
        line.split(':')
            .nth(3)
            .and_then(|value| value.parse::<u32>().ok())
            == Some(group_id)
    }))
}

fn remove_database_entry(path: &Path, name: &str) -> Result<()> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let retained = content
        .lines()
        .filter(|line| line.split(':').next() != Some(name))
        .collect::<Vec<_>>();
    publish(path, format!("{}\n", retained.join("\n")).as_bytes())
}

fn remove_principal_from_groups(root: &Path, name: &str) -> Result<()> {
    for database in ["group", "gshadow"] {
        let path = root.join(database);
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        };
        let lines = content
            .lines()
            .map(|line| {
                let mut fields = line.split(':').map(str::to_owned).collect::<Vec<_>>();
                if fields.len() >= 4 {
                    fields[3] = fields[3]
                        .split(',')
                        .filter(|member| !member.is_empty() && *member != name)
                        .collect::<Vec<_>>()
                        .join(",");
                }
                fields.join(":")
            })
            .collect::<Vec<_>>();
        publish(&path, format!("{}\n", lines.join("\n")).as_bytes())?;
    }
    Ok(())
}

fn identity_lock() -> Result<std::fs::File> {
    let path = Path::new(IDENTITY_LOCK);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .context("opening systemd identity lock")?;
    flock(&lock, FlockOperation::LockExclusive).context("locking systemd identity state")?;
    Ok(lock)
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("identity path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mode = fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let mut temporary =
        NamedTempFile::new_in(parent).context("creating identity temporary file")?;
    temporary
        .write_all(bytes)
        .context("writing identity temporary file")?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .context("setting identity file mode")?;
    temporary
        .as_file()
        .sync_all()
        .context("syncing identity temporary file")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("publishing identity file")?;
    let file = OpenOptions::new()
        .read(true)
        .open(parent)
        .context("opening identity parent")?;
    file.sync_all().context("syncing identity parent")
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        Allocation, Desired, GroupDesired, PrincipalDesired, ResolvedMembership, account_exists,
        fragment, membership_exists, reconcile_owned_memberships, remove_identity,
    };

    #[test]
    fn sysusers_fragments_preserve_declared_identity_fields() {
        let group = Desired::Group(GroupDesired {
            name: "operators".to_string(),
            allocation: Allocation::Managed,
            requested_id: Some(987),
        });
        assert_eq!(
            fragment(&group, &ResolvedMembership::default()).expect("group fragment renders"),
            "g operators 987\n"
        );

        let principal = Desired::Principal(PrincipalDesired {
            name: "daemon".to_string(),
            allocation: Allocation::Managed,
            requested_id: None,
            description: Some("Example daemon".to_string()),
            home_directory: Some("/var/lib/daemon".to_string()),
            login_access: Some("disabled".to_string()),
            primary_group: Some("operators".to_string()),
            supplementary_groups: Some(vec!["logs".to_string()]),
        });
        let rendered = fragment(&principal, &ResolvedMembership::default())
            .expect("principal fragment renders");
        assert!(rendered.contains("u daemon -:operators \"Example daemon\" /var/lib/daemon"));
        assert!(rendered.contains("m daemon logs"));
    }

    #[test]
    fn nss_observation_checks_ids_and_exact_membership() {
        let root = tempdir().expect("temporary NSS root is created");
        fs::write(
            root.path().join("passwd"),
            "daemon:x:123:456::/:/bin/false\n",
        )
        .expect("passwd fixture is written");
        fs::write(root.path().join("group"), "operators:x:456:alice,daemon\n")
            .expect("group fixture is written");

        assert!(
            account_exists(&root.path().join("passwd"), "daemon", Some(123))
                .expect("principal is observed")
        );
        assert!(
            !account_exists(&root.path().join("passwd"), "daemon", Some(124))
                .expect("mismatched principal is observed")
        );
        assert!(
            membership_exists(
                root.path(),
                &ResolvedMembership {
                    group: Some("operators".to_string()),
                    principals: vec!["alice".to_string(), "daemon".to_string()],
                },
            )
            .expect("membership is observed")
        );
    }

    #[test]
    fn membership_updates_and_owned_identity_removal_preserve_external_state() {
        let root = tempdir().expect("temporary NSS root is created");
        fs::write(
            root.path().join("passwd"),
            "daemon:x:123:456::/:/bin/false\noperator:x:124:457::/:/bin/false\n",
        )
        .expect("passwd fixture is written");
        fs::write(
            root.path().join("shadow"),
            "daemon:!:1::::::\noperator:!:1::::::\n",
        )
        .expect("shadow fixture is written");
        fs::write(
            root.path().join("group"),
            "old:x:455:daemon,external\ndaemon:x:456:\nnew:x:457:operator\n",
        )
        .expect("group fixture is written");
        fs::write(
            root.path().join("gshadow"),
            "old:!::daemon,external\ndaemon:!::\nnew:!::operator\n",
        )
        .expect("gshadow fixture is written");

        reconcile_owned_memberships(
            root.path(),
            &[("new".to_string(), "daemon".to_string())],
            &[("old".to_string(), "daemon".to_string())],
        )
        .expect("membership is reconciled");
        let groups = fs::read_to_string(root.path().join("group"))
            .expect("reconciled group database is read");
        assert!(groups.contains("old:x:455:external"));
        assert!(groups.contains("new:x:457:daemon,operator"));

        let principal = Desired::Principal(PrincipalDesired {
            name: "daemon".to_string(),
            allocation: Allocation::Managed,
            requested_id: Some(123),
            description: None,
            home_directory: None,
            login_access: None,
            primary_group: Some("daemon".to_string()),
            supplementary_groups: None,
        });
        assert!(
            remove_identity(root.path(), &principal, "daemon", 123)
                .expect("owned principal is removed")
        );
        let passwd =
            fs::read_to_string(root.path().join("passwd")).expect("passwd database is read");
        let groups = fs::read_to_string(root.path().join("group")).expect("group database is read");
        assert!(!passwd.contains("daemon:x:"));
        assert!(passwd.contains("operator:x:"));
        assert!(!groups.contains(":daemon,"));
        assert!(groups.contains("new:x:457:operator"));
    }
}
