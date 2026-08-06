//! Reproduction artifact schema, codec, identity, and validation.

use super::*;
#[derive(Clone, Debug)]
pub(super) struct CliReproductionArtifact {
    pub(super) seed: u64,
    pub(super) identity: CliIdentity,
    pub(super) scenario: CliComponent,
    pub(super) components: Vec<CliComponent>,
    pub(super) payloads: Vec<CliPayload>,
    pub(super) schedule_digest: String,
    pub(super) decisions: Vec<CliDecision>,
    pub(super) fingerprints: Vec<CliFingerprint>,
    pub(super) sampling: CliSamplingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CliIdentity {
    pub(super) engine_version: String,
    pub(super) engine_abi: String,
    pub(super) artifact_abi: String,
    pub(super) qemu_build_id: String,
    pub(super) qemu_patch_series_hash: String,
    pub(super) shmem_abi_version: String,
    pub(super) guest_host_protocol_version: String,
    pub(super) rpc_abi_version: String,
    pub(super) rpc_abi_build: String,
    pub(super) plugin_abi: String,
}

pub(super) fn validate_replayable_reproduction_artifact(
    cli: &Cli,
    bytes: &[u8],
) -> Result<CliReproductionArtifact, CliError> {
    let mut artifact = decode_reproduction_artifact(bytes)?;
    verify_replay_identity(&artifact.identity, &expected_replay_identity(cli)?)?;
    hydrate_replay_artifact_components(&mut artifact, &default_run_store_root(cli))?;
    Ok(artifact)
}

pub(super) fn hydrate_replay_artifact_components(
    artifact: &mut CliReproductionArtifact,
    store_root: &Path,
) -> Result<(), CliError> {
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    for component in artifact.components.clone() {
        let embedded = artifact
            .payloads
            .iter()
            .find(|payload| payload.digest == component.digest);
        let Some(bytes) = replay_component_payload_bytes(&store, &component, embedded)? else {
            continue;
        };
        let actual_digest = content_address_bytes(&bytes);
        if actual_digest != component.digest {
            return Err(artifact_error(format!(
                "component `{}` resolved payload digest {} did not match artifact digest {}",
                component.name, actual_digest, component.digest
            )));
        }
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| {
            artifact_error(format!(
                "component `{}` resolved payload size cannot be represented",
                component.name
            ))
        })?;
        if size_bytes != component.size_bytes {
            return Err(artifact_error(format!(
                "component `{}` declared {} bytes but DAG store resolved {} bytes",
                component.name, component.size_bytes, size_bytes
            )));
        }
        if embedded.is_none() {
            artifact.payloads.push(CliPayload {
                digest: component.digest,
                bytes,
            });
        }
    }
    Ok(())
}

pub(super) fn replay_component_payload_bytes(
    store: &crucible::LocalDagStore,
    component: &CliComponent,
    embedded: Option<&CliPayload>,
) -> Result<Option<Vec<u8>>, CliError> {
    if component.store_uri == format!("cas:{}", component.digest) {
        return Ok(embedded.map(|payload| payload.bytes.clone()));
    }
    let key = parse_blake3_content_hash("component store URI", &component.store_uri)?;
    let bytes = store.get(&key).map_err(|error| {
        artifact_error(format!(
            "component `{}` ({}) could not be resolved from DAG store {}: {error}",
            component.name,
            component.store_uri,
            store.root().display()
        ))
    })?;
    if let Some(payload) = embedded
        && payload.bytes != bytes
    {
        return Err(artifact_error(format!(
            "component `{}` inline payload does not match DAG store object {}",
            component.name, component.store_uri
        )));
    }
    Ok(Some(bytes))
}

pub(super) fn verify_replay_identity(
    actual: &CliIdentity,
    expected: &CliIdentity,
) -> Result<(), CliError> {
    if actual != expected {
        return Err(CliError::Identity(format!(
            "reproduction build identity mismatch: expected engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` patch-series `{}` shmem `{}` guest-host `{}` RPC `{}+{}` plugin `{}`, got engine `{}` ABI `{}` artifact ABI `{}` QEMU `{}` patch-series `{}` shmem `{}` guest-host `{}` RPC `{}+{}` plugin `{}`",
            expected.engine_version,
            expected.engine_abi,
            expected.artifact_abi,
            expected.qemu_build_id,
            expected.qemu_patch_series_hash,
            expected.shmem_abi_version,
            expected.guest_host_protocol_version,
            expected.rpc_abi_version,
            expected.rpc_abi_build,
            expected.plugin_abi,
            actual.engine_version,
            actual.engine_abi,
            actual.artifact_abi,
            actual.qemu_build_id,
            actual.qemu_patch_series_hash,
            actual.shmem_abi_version,
            actual.guest_host_protocol_version,
            actual.rpc_abi_version,
            actual.rpc_abi_build,
            actual.plugin_abi
        )));
    }
    Ok(())
}

pub(super) fn expected_replay_identity(cli: &Cli) -> Result<CliIdentity, CliError> {
    let backend_plan = plan_backend_selection(cli)?;
    if let Some(plan) = backend_plan.as_ref()
        && plan.target == BackendExecutionTarget::RemoteDaemon
    {
        return Err(CliError::Identity(
            "remote daemon replay cannot validate reproduction artifacts without producer build provenance; run replay without --daemon or select a local backend".to_string(),
        ));
    }
    let resolved_backend = backend_plan
        .as_ref()
        .and_then(|plan| plan.resolved_backend.as_ref());
    Ok(expected_replay_identity_for_backend(resolved_backend))
}

pub(super) fn expected_replay_identity_for_backend(
    backend: Option<&ResolvedLocalBackend>,
) -> CliIdentity {
    let (qemu_build_id, qemu_patch_series_hash, shmem_abi_version, plugin_abi) = match backend {
        Some(ResolvedLocalBackend::Qemu {
            qemu_build_id,
            qemu_patch_series_hash,
            plugin_abi,
            shmem_abi_version,
            ..
        }) => (
            qemu_build_id.clone(),
            qemu_patch_series_hash.clone(),
            shmem_abi_version.clone(),
            plugin_abi.clone(),
        ),
        #[cfg(any(test, feature = "test-double"))]
        Some(ResolvedLocalBackend::Double) | None => (
            content_address_bytes(b"mock-backend-source-v1"),
            content_address_bytes(b"mock-qemu-patch-series-v1"),
            crucible::SHMEM_ABI_VERSION.to_string(),
            String::from("simdouble-mock-plugin-abi"),
        ),
        #[cfg(not(any(test, feature = "test-double")))]
        None => (
            content_address_bytes(b"unresolved-backend-source-v1"),
            content_address_bytes(b"unresolved-qemu-patch-series-v1"),
            crucible::SHMEM_ABI_VERSION.to_string(),
            String::from("unresolved-plugin-abi"),
        ),
    };
    CliIdentity {
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_abi: String::from("crucible-harness-e2e-v1"),
        artifact_abi: REPRODUCTION_ARTIFACT_SCHEMA.to_string(),
        qemu_build_id,
        qemu_patch_series_hash,
        shmem_abi_version,
        guest_host_protocol_version: current_guest_host_protocol_version(),
        rpc_abi_version: current_rpc_abi_version(),
        rpc_abi_build: current_rpc_abi_build(),
        plugin_abi,
    }
}

#[derive(Clone, Debug)]
pub(super) struct CliComponent {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) digest: String,
    pub(super) store_uri: String,
    pub(super) media_type: String,
    pub(super) size_bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct CliPayload {
    pub(super) digest: String,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CliDecision {
    pub(super) sequence: u64,
    pub(super) virtual_time_ticks: u64,
    pub(super) node: String,
    pub(super) kind: String,
    pub(super) payload_digest: String,
}

pub(super) fn cli_decisions_from_canonical_log(
    canonical_log: &[CanonicalLogEntry],
) -> Vec<CliDecision> {
    canonical_log
        .iter()
        .map(|entry| CliDecision {
            sequence: entry.sequence,
            virtual_time_ticks: entry.virtual_time_ticks,
            node: entry.node.clone(),
            kind: entry.kind.clone(),
            payload_digest: content_address_bytes(entry.summary.as_bytes()),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReproductionArtifactComponentPayload {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) media_type: String,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct CliFingerprint {
    pub(super) index: u64,
    pub(super) instruction: u64,
    pub(super) node: String,
    pub(super) digest: String,
}

#[derive(Clone, Debug)]
pub(super) struct CliSamplingConfig {
    pub(super) fine: String,
    pub(super) coarse: String,
    pub(super) regions: Vec<String>,
}

pub(super) fn decode_reproduction_artifact(
    bytes: &[u8],
) -> Result<CliReproductionArtifact, CliError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("artifact is not UTF-8: {error}")))?;
    let mut schema_version = None;
    let mut seed = None;
    let mut identity = None;
    let mut scenario = None;
    let mut components = Vec::new();
    let mut payloads = Vec::new();
    let mut schedule_digest = None;
    let mut schedule_len = None;
    let mut decisions = Vec::new();
    let mut fingerprints = Vec::new();
    let mut sampling = None;

    for (line_index, line_text) in text.lines().enumerate() {
        let fields = parse_artifact_fields(line_text)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "schema" => {
                require_field_count(line_index, tag, &fields, 2)?;
                set_once(&mut schema_version, line_index, tag, fields[1].clone())?;
            }
            "seed" => {
                require_field_count(line_index, tag, &fields, 2)?;
                let parsed = parse_u64(line_index, tag, &fields[1])?;
                set_once(&mut seed, line_index, tag, parsed)?;
            }
            "identity" => {
                require_field_count(line_index, tag, &fields, 11)?;
                validate_required_field("identity.engine_version", &fields[1])?;
                validate_required_field("identity.engine_abi", &fields[2])?;
                if fields[3] != REPRODUCTION_ARTIFACT_SCHEMA {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "artifact ABI does not match supported schema",
                    ));
                }
                validate_digest("identity.qemu_build_id", &fields[4])?;
                validate_required_field("identity.qemu_patch_series_hash", &fields[5])?;
                validate_required_field("identity.shmem_abi_version", &fields[6])?;
                validate_required_field("identity.guest_host_protocol_version", &fields[7])?;
                validate_required_field("identity.rpc_abi_version", &fields[8])?;
                validate_required_field("identity.rpc_abi_build", &fields[9])?;
                validate_required_field("identity.plugin_abi", &fields[10])?;
                set_once(
                    &mut identity,
                    line_index,
                    tag,
                    CliIdentity {
                        engine_version: fields[1].clone(),
                        engine_abi: fields[2].clone(),
                        artifact_abi: fields[3].clone(),
                        qemu_build_id: fields[4].clone(),
                        qemu_patch_series_hash: fields[5].clone(),
                        shmem_abi_version: fields[6].clone(),
                        guest_host_protocol_version: fields[7].clone(),
                        rpc_abi_version: fields[8].clone(),
                        rpc_abi_build: fields[9].clone(),
                        plugin_abi: fields[10].clone(),
                    },
                )?;
            }
            "scenario" => {
                let parsed = parse_component(line_index, tag, &fields)?;
                if parsed.kind != "scenario_def" {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "scenario component kind must be scenario_def",
                    ));
                }
                set_once(&mut scenario, line_index, tag, parsed)?;
            }
            "component" => {
                components.push(parse_component(line_index, tag, &fields)?);
            }
            "payload" => {
                require_field_count(line_index, tag, &fields, 3)?;
                let payload = CliPayload {
                    digest: fields[1].clone(),
                    bytes: parse_hex_bytes(line_index, tag, &fields[2])?,
                };
                validate_digest("payload.digest", &payload.digest)?;
                let actual = content_address_bytes(&payload.bytes);
                if payload.digest != actual {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "payload digest does not match bytes",
                    ));
                }
                payloads.push(payload);
            }
            "schedule" => {
                require_field_count(line_index, tag, &fields, 3)?;
                validate_digest("schedule.digest", &fields[1])?;
                let parsed_len = parse_usize(line_index, tag, &fields[2])?;
                set_once(&mut schedule_digest, line_index, tag, fields[1].clone())?;
                set_once(&mut schedule_len, line_index, tag, parsed_len)?;
            }
            "decision" => {
                require_field_count(line_index, tag, &fields, 6)?;
                let decision = CliDecision {
                    sequence: parse_u64(line_index, tag, &fields[1])?,
                    virtual_time_ticks: parse_u64(line_index, tag, &fields[2])?,
                    node: fields[3].clone(),
                    kind: fields[4].clone(),
                    payload_digest: fields[5].clone(),
                };
                validate_required_field("decision.node", &decision.node)?;
                validate_required_field("decision.kind", &decision.kind)?;
                validate_digest("decision.payload_digest", &decision.payload_digest)?;
                decisions.push(decision);
            }
            "fingerprint" => {
                require_field_count(line_index, tag, &fields, 5)?;
                let index = parse_u64(line_index, tag, &fields[1])?;
                let instruction = parse_u64(line_index, tag, &fields[2])?;
                validate_required_field("fingerprint.node", &fields[3])?;
                validate_digest("fingerprint.digest", &fields[4])?;
                fingerprints.push(CliFingerprint {
                    index,
                    instruction,
                    node: fields[3].clone(),
                    digest: fields[4].clone(),
                });
            }
            "sampling" => {
                if fields.len() < 4 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "expected at least 4 fields",
                    ));
                }
                validate_required_field("sampling.fine", &fields[1])?;
                validate_required_field("sampling.coarse", &fields[2])?;
                let region_count = parse_usize(line_index, tag, &fields[3])?;
                if region_count == 0 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "sampling must name at least one region",
                    ));
                }
                if fields.len() != region_count + 4 {
                    return Err(artifact_line_error(
                        line_index,
                        tag,
                        "region count does not match fields",
                    ));
                }
                for region in &fields[4..] {
                    validate_required_field("sampling.region", region)?;
                }
                set_once(
                    &mut sampling,
                    line_index,
                    tag,
                    CliSamplingConfig {
                        fine: fields[1].clone(),
                        coarse: fields[2].clone(),
                        regions: fields[4..].to_vec(),
                    },
                )?;
            }
            _ => return Err(artifact_line_error(line_index, tag, "unknown line tag")),
        }
    }

    let schema_version = schema_version.ok_or_else(|| missing_line("schema"))?;
    if schema_version != REPRODUCTION_ARTIFACT_SCHEMA {
        return Err(artifact_error(format!(
            "unsupported reproduction artifact schema `{schema_version}`"
        )));
    }
    let identity = identity.ok_or_else(|| missing_line("identity"))?;
    let scenario = scenario.ok_or_else(|| missing_line("scenario"))?;
    let schedule_digest = schedule_digest.ok_or_else(|| missing_line("schedule"))?;
    let schedule_len = schedule_len.ok_or_else(|| missing_line("schedule"))?;
    if schedule_len != decisions.len() {
        return Err(artifact_error(format!(
            "schedule declared {schedule_len} decisions but encoded {}",
            decisions.len()
        )));
    }
    validate_schedule(&decisions, &schedule_digest)?;
    if !components.iter().any(|component| {
        component.kind == "scenario_def"
            && component.digest == scenario.digest
            && component.store_uri == scenario.store_uri
    }) {
        return Err(artifact_error(format!(
            "scenario component `{}` is missing from artifact component references",
            scenario.digest
        )));
    }
    for payload in &payloads {
        if !components
            .iter()
            .any(|component| component.digest == payload.digest)
            && scenario.digest != payload.digest
        {
            return Err(artifact_error(format!(
                "component payload `{}` is missing from artifact component references",
                payload.digest
            )));
        }
    }
    let sampling = sampling.ok_or_else(|| missing_line("sampling"))?;

    let artifact = CliReproductionArtifact {
        seed: seed.ok_or_else(|| missing_line("seed"))?,
        identity,
        scenario,
        components,
        payloads,
        schedule_digest,
        decisions,
        fingerprints,
        sampling,
    };
    if canonical_artifact_text(&artifact) != text {
        return Err(artifact_error("non-canonical artifact encoding"));
    }

    Ok(artifact)
}

pub(super) fn parse_component(
    line_index: usize,
    tag: &str,
    fields: &[String],
) -> Result<CliComponent, CliError> {
    require_field_count(line_index, tag, fields, 7)?;
    let component = CliComponent {
        kind: fields[1].clone(),
        name: fields[2].clone(),
        digest: fields[3].clone(),
        store_uri: fields[4].clone(),
        media_type: fields[5].clone(),
        size_bytes: parse_u64(line_index, tag, &fields[6])?,
    };
    validate_required_field("component.name", &component.name)?;
    validate_required_field("component.media_type", &component.media_type)?;
    validate_digest("component.digest", &component.digest)?;
    if component.store_uri != format!("cas:{}", component.digest)
        && crucible::ContentAddressedBlobRef::parse("component store_uri", &component.store_uri)
            .is_err()
    {
        return Err(artifact_line_error(
            line_index,
            tag,
            "component store URI must either match the digest or be a blake3 DAG-store reference",
        ));
    }
    Ok(component)
}

pub(super) fn validate_schedule(decisions: &[CliDecision], digest: &str) -> Result<(), CliError> {
    if decisions.is_empty() {
        return Err(artifact_error("reproduction schedule is empty"));
    }
    for (expected, decision) in decisions.iter().enumerate() {
        if decision.sequence != expected as u64 {
            return Err(artifact_error(format!(
                "schedule decision sequence out of order: expected {expected}, got {}",
                decision.sequence
            )));
        }
    }
    let expected = schedule_digest(decisions);
    if digest != expected {
        return Err(artifact_error(format!(
            "schedule digest mismatch: expected {expected}, got {digest}"
        )));
    }
    Ok(())
}

pub(super) fn canonical_artifact_text(artifact: &CliReproductionArtifact) -> String {
    let mut text = String::new();
    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &artifact.seed.to_string()]);
    artifact_line(
        &mut text,
        &[
            "identity",
            &artifact.identity.engine_version,
            &artifact.identity.engine_abi,
            &artifact.identity.artifact_abi,
            &artifact.identity.qemu_build_id,
            &artifact.identity.qemu_patch_series_hash,
            &artifact.identity.shmem_abi_version,
            &artifact.identity.guest_host_protocol_version,
            &artifact.identity.rpc_abi_version,
            &artifact.identity.rpc_abi_build,
            &artifact.identity.plugin_abi,
        ],
    );
    artifact_component_line(&mut text, "scenario", &artifact.scenario);
    for component in &artifact.components {
        artifact_component_line(&mut text, "component", component);
    }
    for payload in &artifact.payloads {
        artifact_line(
            &mut text,
            &["payload", &payload.digest, &hex_bytes(&payload.bytes)],
        );
    }
    artifact_line(
        &mut text,
        &[
            "schedule",
            &artifact.schedule_digest,
            &artifact.decisions.len().to_string(),
        ],
    );
    for decision in &artifact.decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    for fingerprint in &artifact.fingerprints {
        artifact_line(
            &mut text,
            &[
                "fingerprint",
                &fingerprint.index.to_string(),
                &fingerprint.instruction.to_string(),
                &fingerprint.node,
                &fingerprint.digest,
            ],
        );
    }
    let mut sampling_fields = vec![
        String::from("sampling"),
        artifact.sampling.fine.clone(),
        artifact.sampling.coarse.clone(),
        artifact.sampling.regions.len().to_string(),
    ];
    sampling_fields.extend(artifact.sampling.regions.iter().cloned());
    artifact_line(
        &mut text,
        &sampling_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    text
}

pub(super) fn artifact_component_line(text: &mut String, tag: &str, component: &CliComponent) {
    artifact_line(
        text,
        &[
            tag,
            &component.kind,
            &component.name,
            &component.digest,
            &component.store_uri,
            &component.media_type,
            &component.size_bytes.to_string(),
        ],
    );
}

#[cfg(test)]
pub(super) fn mock_failure_reproduction_artifact_bytes(
    cli: &Cli,
    seed: u64,
) -> Result<Vec<u8>, CliError> {
    let backend_plan = plan_backend_selection(cli)?;
    let resolved_backend = backend_plan
        .as_ref()
        .and_then(|plan| plan.resolved_backend.as_ref());
    mock_failure_reproduction_artifact_bytes_for_backend(seed, resolved_backend)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn mock_failure_reproduction_artifact_bytes_for_backend(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
) -> Result<Vec<u8>, CliError> {
    let scenario_material = b"scenario\tmock-failure\nnode\tnode-a\tserver\n";
    let scenario_digest = content_address_bytes(scenario_material);
    let identity = expected_replay_identity_for_backend(backend);
    let payload = b"mock-failure-decision";
    let payload_digest = content_address_bytes(payload);
    let fingerprint_digest = content_address_bytes(b"mock-failure-fingerprint");
    let decisions = vec![CliDecision {
        sequence: 0,
        virtual_time_ticks: 1,
        node: String::from("node-a"),
        kind: String::from("property_observation"),
        payload_digest: payload_digest.clone(),
    }];
    let schedule_digest = schedule_digest(&decisions);
    let scenario_size = scenario_material.len().to_string();
    let seed_text = seed.to_string();
    let schedule_len = decisions.len().to_string();
    let store_uri = format!("cas:{scenario_digest}");
    let mut text = String::new();

    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &seed_text]);
    artifact_line(
        &mut text,
        &[
            "identity",
            &identity.engine_version,
            &identity.engine_abi,
            &identity.artifact_abi,
            &identity.qemu_build_id,
            &identity.qemu_patch_series_hash,
            &identity.shmem_abi_version,
            &identity.guest_host_protocol_version,
            &identity.rpc_abi_version,
            &identity.rpc_abi_build,
            &identity.plugin_abi,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "scenario",
            "scenario_def",
            "mock-failure.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.mock-scenario+text",
            &scenario_size,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "scenario_def",
            "mock-failure.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.mock-scenario+text",
            &scenario_size,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "other",
            "decision-0-payload",
            &payload_digest,
            &format!("cas:{payload_digest}"),
            RECORDED_DECISION_PAYLOAD_MEDIA_TYPE,
            &payload.len().to_string(),
        ],
    );
    artifact_line(
        &mut text,
        &["payload", &scenario_digest, &hex_bytes(scenario_material)],
    );
    artifact_line(
        &mut text,
        &["payload", &payload_digest, &hex_bytes(payload)],
    );
    artifact_line(&mut text, &["schedule", &schedule_digest, &schedule_len]);
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    artifact_line(
        &mut text,
        &["fingerprint", "0", "1", "node-a", &fingerprint_digest],
    );
    artifact_line(
        &mut text,
        &[
            "sampling",
            "every-decision",
            "final",
            "1",
            "canonical-log-tail",
        ],
    );

    let bytes = text.into_bytes();
    let artifact = decode_reproduction_artifact(&bytes)?;
    verify_replay_identity(&artifact.identity, &identity)?;
    Ok(bytes)
}

pub(super) fn schedule_digest(decisions: &[CliDecision]) -> String {
    let mut material = String::new();
    for decision in decisions {
        artifact_line(
            &mut material,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

pub(super) fn content_address_bytes(bytes: &[u8]) -> String {
    format!(
        "{}{}",
        CONTENT_ADDRESS_PREFIX,
        hex_bytes(&stable_digest(bytes))
    )
}

pub(super) fn is_content_address(digest: &str) -> bool {
    digest
        .strip_prefix(CONTENT_ADDRESS_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(super) fn stable_digest(material: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in b"crucible.reproduction.hash.v1"
            .iter()
            .copied()
            .chain([0xff])
            .chain(material.iter().copied())
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        output[lane as usize * 8..lane as usize * 8 + 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

pub(super) fn artifact_line(text: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            text.push('\t');
        }
        text.push_str(&escape_artifact_field(field));
    }
    text.push('\n');
}

pub(super) fn escape_artifact_field(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'%' => escaped.push_str("%25"),
            b'\t' => escaped.push_str("%09"),
            b'\n' => escaped.push_str("%0A"),
            b'\r' => escaped.push_str("%0D"),
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

pub(super) fn parse_artifact_fields(line_text: &str) -> Result<Vec<String>, CliError> {
    line_text.split('\t').map(unescape_artifact_field).collect()
}

pub(super) fn unescape_artifact_field(value: &str) -> Result<String, CliError> {
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(artifact_error(format!("truncated escape in `{value}`")));
        }
        let escape = &value[index + 1..index + 3];
        match escape {
            "25" => output.push('%'),
            "09" => output.push('\t'),
            "0A" => output.push('\n'),
            "0D" => output.push('\r'),
            _ => {
                return Err(artifact_error(format!(
                    "unknown escape %{escape} in `{value}`"
                )));
            }
        }
        index += 3;
    }
    Ok(output)
}

pub(super) fn require_field_count(
    line_index: usize,
    tag: &str,
    fields: &[String],
    expected: usize,
) -> Result<(), CliError> {
    if fields.len() == expected {
        return Ok(());
    }
    Err(artifact_line_error(
        line_index,
        tag,
        &format!("expected {expected} fields, got {}", fields.len()),
    ))
}

pub(super) fn set_once<T>(
    slot: &mut Option<T>,
    line_index: usize,
    tag: &str,
    value: T,
) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(artifact_line_error(
            line_index,
            tag,
            "duplicate singleton line",
        ));
    }
    *slot = Some(value);
    Ok(())
}

pub(super) fn parse_u64(line_index: usize, tag: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|error| {
        artifact_line_error(line_index, tag, &format!("invalid u64 `{value}`: {error}"))
    })
}

pub(super) fn parse_usize(line_index: usize, tag: &str, value: &str) -> Result<usize, CliError> {
    value.parse::<usize>().map_err(|error| {
        artifact_line_error(
            line_index,
            tag,
            &format!("invalid usize `{value}`: {error}"),
        )
    })
}

pub(super) fn parse_hex_bytes(
    line_index: usize,
    tag: &str,
    value: &str,
) -> Result<Vec<u8>, CliError> {
    if !value.len().is_multiple_of(2) {
        return Err(artifact_line_error(
            line_index,
            tag,
            "hex payload has odd length",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0])
            .ok_or_else(|| artifact_line_error(line_index, tag, "hex payload is malformed"))?;
        let low = hex_nibble(chunk[1])
            .ok_or_else(|| artifact_line_error(line_index, tag, "hex payload is malformed"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

pub(super) fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn validate_required_field(field: &'static str, value: &str) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(artifact_error(format!("required field `{field}` is empty")));
    }
    Ok(())
}

pub(super) fn validate_digest(field: &'static str, digest: &str) -> Result<(), CliError> {
    if !is_content_address(digest) {
        return Err(artifact_error(format!(
            "field `{field}` is not a content address: `{digest}`"
        )));
    }
    Ok(())
}

#[path = "artifact/errors.rs"]
mod errors;

pub(super) use errors::*;

#[path = "artifact/live_qemu.rs"]
mod live_qemu;
pub(crate) use live_qemu::*;

#[path = "artifact/reports.rs"]
mod reports;

pub(super) use reports::*;

#[path = "artifact/materialization_proof.rs"]
mod materialization_proof;
