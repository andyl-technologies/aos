//! Authenticated registry-snapshot evidence for configuration evaluation.
//!
//! Registry synchronization owns the cache transition. This terminal observes
//! the exact synchronized authority after that transition, authenticates every
//! enabled registry receipt and the immutable image contract, and emits a
//! bounded snapshot commitment. Package selection remains the evaluator's
//! responsibility so there is only one resolver for the final module set.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use anyhow::{bail, ensure, Context as _, Result};
use aos_ability_model::{
    AbilityValue, ArtifactReference, LocalKey, ResourceReference, ABILITY_LIMITS_V1,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts, AdmissionDisposition, AdmissionRequest, AdmissionResult,
    AdmissionRevision, Invocation, InvocationDisposition, InvocationPurpose, InvocationResult,
    ResourceContext, SupportedPurposes, ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA,
    HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, RESULT_SCHEMA,
};
use serde::{Deserialize, Serialize};

use super::static_packages::checked_host_selection;
use crate::config::ApmConfig;
use crate::registry::RegistrySet;
use crate::types::ProfileScope;

const INTERFACE: &str = "aos.registry.synchronized-snapshot";
const SNAPSHOT_SCHEMA: &str = "aos.registry.synchronized-snapshot/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.registry-snapshot-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.registry.synchronized-snapshot-context/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    scope: String,
    controller: ResourceReference,
    handoff: ResourceReference,
    synchronization: ResourceReference,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentity {
    registry: String,
    release_tag: String,
    commit: String,
    tag_signer_key: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCommitment<'a> {
    schema: &'static str,
    scope: &'a str,
    controller: &'a ResourceReference,
    handoff: &'a ResourceReference,
    synchronization: &'a ResourceReference,
    static_contract: &'a ArtifactReference,
    releases: &'a [ReleaseIdentity],
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SynchronizedSnapshot {
    schema: &'static str,
    scope: String,
    controller: ResourceReference,
    handoff: ResourceReference,
    synchronization: ResourceReference,
    static_contract: ArtifactReference,
    releases: Vec<ReleaseIdentity>,
    snapshot_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotObservation<'a> {
    schema: &'static str,
    expected: &'a SnapshotRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_sha256: Option<&'a str>,
    state: &'static str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    request: SnapshotRequest,
}

/// Runs one synchronized-registry snapshot handler call from process streams.
///
/// # Errors
///
/// Returns an error when the invocation authority, synchronized registry
/// receipts, immutable image contract, or canonical result is invalid.
pub fn run_provider_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 2 && arguments[0] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "protocol input exceeds the canonical document bound"
    );

    let value = match arguments[1].as_str() {
        "admit" => {
            let request =
                aos_contract::canonical::from_slice(&input, "registry snapshot admission")?;
            serde_json::to_value(admit(request)?)?
        }
        "effect" | "reconcile" | "cancel" => {
            let invocation =
                aos_contract::canonical::from_slice(&input, "registry snapshot invocation")?;
            serde_json::to_value(invoke(invocation, &arguments[1])?)?
        }
        purpose => bail!("unsupported registry snapshot provider purpose {purpose:?}"),
    };
    let output = aos_contract::canonical::canonical_json(&value)?;
    ensure!(
        output.len() <= aos_provider_protocol::MAX_HANDLER_RESULT_BYTES,
        "registry snapshot provider result exceeds the handler bound"
    );
    io::stdout().write_all(&output)?;
    Ok(())
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "unsupported admission schema"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    validate_method(
        request.method.interface.name.as_str(),
        request.method.method.as_str(),
    )?;

    let expected: SnapshotRequest = decode(&request.resource_spec.value)?;
    validate_request(&expected, &request.resources)?;
    let observation = snapshot_observation(&expected, None, "unavailable")?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT_SCHEMA.into(),
            request: expected,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("constructing registry snapshot provider purpose set")?,
    })
}

fn invoke(invocation: Invocation, purpose: &str) -> Result<InvocationResult> {
    ensure!(
        invocation.schema == INVOCATION_SCHEMA && purpose == purpose_name(invocation.purpose),
        "invocation envelope differs from the selected ABI"
    );
    ensure!(
        invocation.method_is_bound(),
        "invocation method is not durably bound"
    );
    validate_resource_contexts(&invocation.request.resources)?;
    ensure!(
        resource_set_digest(&invocation.request.resources)?
            == invocation.request.native_context_digest,
        "resource contexts differ from their authenticated digest"
    );
    validate_method(
        invocation.method.interface.name.as_str(),
        invocation.method.method.as_str(),
    )?;

    let target = exact_context(&invocation.request.target, &invocation.request.resources)?;
    let bound = validate_resource_context(target)?;
    let expected: SnapshotRequest = decode(&bound.resource_spec.value)?;
    let inputs: SnapshotRequest = decode(&invocation.request.inputs)?;
    ensure!(
        inputs == expected,
        "snapshot inputs differ from the checked resource"
    );
    validate_request(&expected, &invocation.request.resources)?;

    let provider_context: ProviderContext = decode(&bound.provider_context)?;
    ensure!(
        provider_context.schema == PROVIDER_CONTEXT_SCHEMA && provider_context.request == expected,
        "registry snapshot provider context differs from admission"
    );

    if invocation.control.cancelled || invocation.purpose == InvocationPurpose::Cancel {
        return invocation_result(
            &invocation,
            InvocationDisposition::RejectedBeforeEffect,
            snapshot_observation(&expected, None, "unavailable")?,
            BTreeMap::new(),
        );
    }
    ensure!(
        matches!(
            invocation.purpose,
            InvocationPurpose::Effect | InvocationPurpose::Reconcile
        ),
        "registry snapshot observation does not support compensation"
    );

    let snapshot = observe_snapshot(&expected)?;
    let digest = snapshot.snapshot_sha256.clone();
    invocation_result(
        &invocation,
        InvocationDisposition::Completed,
        snapshot_observation(&expected, Some(&digest), "ready")?,
        method_outputs([(
            "registry-snapshot",
            ability_value(serde_json::to_value(snapshot)?)?,
        )])?,
    )
}

fn observe_snapshot(request: &SnapshotRequest) -> Result<SynchronizedSnapshot> {
    let config = ApmConfig::load(ProfileScope::System)
        .context("loading the system registry configuration")?;
    let registries = RegistrySet::load_for_config_evaluation(
        &config.cache_path(),
        &config.enabled_registries(),
        &crate::platform::native_platform(),
    )
    .context("loading the exact synchronized registry authority")?;
    let releases = registries
        .registries()
        .iter()
        .map(|registry| {
            let receipt = registry
                .release_trust()
                .context("synchronized registry has no authenticated release receipt")?;
            Ok(ReleaseIdentity {
                registry: receipt.registry.clone(),
                release_tag: receipt.release_tag.clone(),
                commit: receipt.commit.clone(),
                tag_signer_key: receipt.tag_signer_key.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let releases = canonical_releases(releases)?;

    let (static_contract, _) =
        checked_host_selection().context("authenticating the immutable image package contract")?;
    let commitment = SnapshotCommitment {
        schema: SNAPSHOT_SCHEMA,
        scope: &request.scope,
        controller: &request.controller,
        handoff: &request.handoff,
        synchronization: &request.synchronization,
        static_contract: &static_contract,
        releases: &releases,
    };
    let snapshot_sha256 = Sha256Digest::of_canonical(SNAPSHOT_SCHEMA, &commitment)?.to_string();

    Ok(SynchronizedSnapshot {
        schema: SNAPSHOT_SCHEMA,
        scope: request.scope.clone(),
        controller: request.controller.clone(),
        handoff: request.handoff.clone(),
        synchronization: request.synchronization.clone(),
        static_contract,
        releases,
        snapshot_sha256,
    })
}

fn canonical_releases(releases: Vec<ReleaseIdentity>) -> Result<Vec<ReleaseIdentity>> {
    let mut encoded_releases = releases
        .into_iter()
        .map(|release| Ok((aos_contract::canonical::to_vec(&release)?, release)))
        .collect::<Result<Vec<_>>>()?;
    encoded_releases.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        encoded_releases
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0),
        "synchronized registry receipts are not unique"
    );
    Ok(encoded_releases
        .into_iter()
        .map(|(_, release)| release)
        .collect())
}

fn validate_request(request: &SnapshotRequest, resources: &[ResourceContext]) -> Result<()> {
    ensure!(
        request.scope == "system",
        "unsupported registry snapshot scope"
    );
    let references = std::iter::once(&request.controller)
        .chain(std::iter::once(&request.handoff))
        .chain(std::iter::once(&request.synchronization))
        .chain(request.prerequisites.iter());
    for reference in references {
        validate_resource_context(exact_context(reference, resources)?)?;
    }
    let prerequisite_bytes = request
        .prerequisites
        .iter()
        .map(aos_contract::canonical::to_vec)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        prerequisite_bytes.windows(2).all(|pair| pair[0] < pair[1]),
        "registry snapshot prerequisites are not in strict canonical order"
    );
    Ok(())
}

fn validate_method(interface: &str, method: &str) -> Result<()> {
    ensure!(
        interface == INTERFACE && method == "observe",
        "unsupported registry snapshot method"
    );
    Ok(())
}

fn exact_context<'a>(
    reference: &ResourceReference,
    resources: &'a [ResourceContext],
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "resource reference has no unique runtime context"
    );
    Ok(matches[0])
}

fn snapshot_observation(
    expected: &SnapshotRequest,
    snapshot_sha256: Option<&str>,
    state: &'static str,
) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(SnapshotObservation {
        schema: OBSERVATION_SCHEMA,
        expected,
        snapshot_sha256,
        state,
    })?)
}

fn invocation_result(
    invocation: &Invocation,
    disposition: InvocationDisposition,
    evidence: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
) -> Result<InvocationResult> {
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn method_outputs<const N: usize>(
    entries: [(&str, AbilityValue); N],
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    entries
        .into_iter()
        .map(|(name, value)| Ok((LocalKey::new(name)?, value)))
        .collect()
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).map_err(anyhow::Error::msg)
}

fn decode<T: serde::de::DeserializeOwned>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).map_err(anyhow::Error::from)
}

fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_releases, ReleaseIdentity};

    fn release(registry: &str) -> ReleaseIdentity {
        ReleaseIdentity {
            registry: registry.into(),
            release_tag: "stable".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            tag_signer_key: "release-key".into(),
        }
    }

    #[test]
    fn release_evidence_is_canonical_and_unique() {
        let releases = canonical_releases(vec![release("zeta"), release("alpha")])
            .expect("canonical release evidence");

        assert_eq!(releases[0].registry, "alpha");
        assert_eq!(releases[1].registry, "zeta");
        assert!(canonical_releases(vec![release("same"), release("same")]).is_err());
    }
}
