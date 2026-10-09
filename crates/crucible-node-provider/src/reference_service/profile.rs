//! Immutable content and bindings for the controlled checksum provider.
//!
//! Profiles describe a bounded quantized application process. They do not claim
//! physical suspension, state capture, native CPU timing, or authenticated
//! execution authority. The service obtains live authority from its private
//! host bootstrap and verifies it independently of these content identities.

use std::collections::BTreeMap;

use crucible_node_contract::{
    ArtifactIdentity, BindingCompatibility, CapabilityProfile, CaptureScope, ContentRef,
    Continuation, Direction, Extensions, FacetSelection, GuaranteeProfile, Id,
    ImplementationIdentity, LaneDescriptor, LiveAuthority, NodeBinding, NodeBindingRef,
    NodeDescriptor, NodeManifest, OperatingContract, OperatingMode, OwnerBinding, OwnerRef,
    PortDescriptor, ProviderManifest, Repeatability, SchedulingRole, SchemaRef, U64, Validate,
    canonical,
};
use serde::Serialize;
use serde_json::json;

use crate::{ProviderError, reference_device::MAX_INPUT_BYTES};

/// Retains one complete immutable profile object and its exact bytes.
#[derive(Clone, Debug)]
pub struct ProfileContent {
    /// Commits to the bytes, length and media type.
    pub reference: ContentRef,
    /// Contains the canonical JSON or UTF-8 semantic specification.
    pub bytes: Vec<u8>,
}

/// Contains the complete immutable checksum model and selected capabilities.
///
/// Executable content references must be measured by the launcher against the
/// actual processes. Building this value does not qualify those executables.
#[derive(Clone, Debug)]
pub struct ReferenceProfile {
    /// Defines immutable node identity and ports.
    pub descriptor: NodeDescriptor,
    /// Binds both actual provider and companion implementations.
    pub implementation: ImplementationIdentity,
    /// Selects the quantized execution facet.
    pub operating_contract: OperatingContract,
    /// Declares realized limited capabilities.
    pub capabilities: CapabilityProfile,
    /// Declares conservative execution and preservation guarantees.
    pub guarantees: GuaranteeProfile,
    /// Defines the sole owner of all child and protocol state.
    pub owner: OwnerRef,
    /// Advertises only the actually selected bounded child-process profile.
    pub node_manifest: NodeManifest,
    /// Advertises the measured implementation without native qualification claims.
    pub provider_manifest: ProviderManifest,
    /// Binds all resolved operational and checksum parameters.
    pub configuration_ref: ContentRef,
    /// Retains profile content by digest for bounded blob resolution.
    pub contents: BTreeMap<String, (ContentRef, Vec<u8>)>,
    profile_ref: ContentRef,
    capabilities_ref: ContentRef,
    guarantees_ref: ContentRef,
    ownership_ref: ContentRef,
    content: Vec<ProfileContent>,
}

impl ReferenceProfile {
    /// Builds a bounded phase-zero quantized checksum profile.
    ///
    /// All input is frozen before execution. The child publishes one cumulative
    /// checksum record at the window's end. Its application-level park does not
    /// certify physical suspension. No preservation operation is selected.
    ///
    /// # Errors
    /// Rejects invalid artifact references, zero budgets or quantum duration,
    /// identifier overflow, malformed portable records, or serialization errors.
    pub fn build(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
    ) -> Result<Self, ProviderError> {
        provider_executable.validate()?;
        device_executable.validate()?;
        if quantum_ps.get() == 0 || host_budget_ns.get() == 0 {
            return Err(ProviderError::Frame(
                "reference profile requires positive budgets",
            ));
        }

        let mut content = Vec::new();
        let model = put_text(&mut content, MODEL_SPECIFICATION)?;
        let limitations = put_json(
            &mut content,
            &json!({
                "schema_version":1,
                "application_park":"private protocol acknowledgement only",
                "capture_scope":"none",
                "continuation":"unsupported",
                "physical_pause":"unknown",
                "repeatability":"nondeterministic",
                "host_budget":"elapsed host time is operational and can fail differently between runs",
                "state_ownership":"all child, staged input, output and retry state belongs to one owner"
            }),
        )?;
        let guarantees = GuaranteeProfile {
            schema_version: 1,
            repeatability: Repeatability::Nondeterministic,
            capture_scope: CaptureScope::None,
            continuation: Continuation::Unsupported,
            durable_restart: false,
            isolated_fork: false,
            conditional_replay: false,
            limitations_ref: limitations.clone(),
            extensions: Extensions::new(),
        };
        let guarantees_ref = put_json(&mut content, &guarantees)?;
        let window = put_text(&mut content, WINDOW_SPECIFICATION)?;
        let policy = put_json(
            &mut content,
            &json!({
                "schema_version":1,"mode":"quantized","quantum_ps":quantum_ps,
                "phase_ps":"0","host_budget_ns":host_budget_ns,"window_proof_ref":window
            }),
        )?;
        let configuration = put_json(
            &mut content,
            &json!({
                "schema_version":1,"quantum_ps":quantum_ps,"phase_ps":"0",
                "host_budget_ns":host_budget_ns,"maximum_input_bytes":U64::new(MAX_INPUT_BYTES as u64),
                "ordering_profile":"superdense-v1","window_semantics_ref":window,
                "checksum_multiplier":"257","checksum_modulus":"18446744073709551616"
            }),
        )?;
        let facet = FacetSelection {
            id: id("reference-device/quantized-v1")?,
            version: 1,
            configuration_ref: configuration.clone(),
            guarantees_ref: guarantees_ref.clone(),
            extensions: Extensions::new(),
        };
        let operating_contract = OperatingContract {
            schema_version: 1,
            mode: OperatingMode::Quantized,
            scheduling_role: SchedulingRole::Active,
            ordering_profile: "superdense-v1".into(),
            policy_ref: policy,
            resolution_ps: Some(quantum_ps),
            phase_ps: Some(U64::new(0)),
            facets: vec![facet.clone()],
            extensions: Extensions::new(),
        };
        let devices = put_json(
            &mut content,
            &json!({
                "schema_version":1,"device":"rolling-checksum",
                "input":"immutable raw byte batch","output":"one cumulative checksum record",
                "queues":"one staged input and one unacknowledged output per owner",
                "dma":false,"irq":false,"reset":"fresh realization only","capture":false
            }),
        )?;
        let requirements = put_json(
            &mut content,
            &json!({
                "schema_version":1,"platform":"linux","transport":"private Unix stream",
                "peer_identity":"SO_PEERCRED and measured running executable",
                "threading":"single owner; serialized resource effects",
                "supervision":"finite reserved custody slot before child creation",
                "modes":["quantized"],"capture_modes":[]
            }),
        )?;
        let capabilities = CapabilityProfile {
            schema_version: 1,
            facets: vec![facet],
            devices_ref: devices,
            requirements_ref: requirements,
            extensions: Extensions::new(),
        };
        let capabilities_ref = put_json(&mut content, &capabilities)?;
        let initialization = put_json(
            &mut content,
            &json!({
                "schema_version":1,"quantum":"0","bytes_processed":"0",
                "checksum":"0","input":"empty"
            }),
        )?;

        let input_schema = schema(&mut content, "reference-device/input-v1", INPUT_SCHEMA)?;
        let output_schema = schema(&mut content, "reference-device/output-v1", OUTPUT_SCHEMA)?;
        let domains = vec![Id::new(format!("{owner}/state"))?];
        let ownership_ref = put_json(
            &mut content,
            &json!({
                "schema_version":1,"owner_id":owner,"participant_ids":[node],
                "state_domain_ids":domains,
                "indivisible_resources":["child-process","input-batch","output-custody","request-journal"],
                "capture":"unsupported"
            }),
        )?;
        let port_policy = put_json(
            &mut content,
            &json!({
                "schema_version":1,
                "lanes":[
                    lane_policy("input", quantum_ps, &window, MAX_INPUT_BYTES as u64),
                    lane_policy("output", quantum_ps, &window, 4096)
                ],
                "maximum_producers":"1","maximum_consumers":"1",
                "arbitration_ref":window,"execution_owner_id":owner,
                "state_domain_ids":domains,"internal":false
            }),
        )?;
        let descriptor = NodeDescriptor {
            schema_version: 1,
            id: node.clone(),
            roles: vec![id("external_device")?],
            model_ref: model.clone(),
            configuration_ref: configuration.clone(),
            initialization_ref: initialization,
            ports: vec![PortDescriptor {
                id: id("data")?,
                lanes: vec![
                    lane(
                        "input",
                        Direction::Input,
                        input_schema.clone(),
                        MAX_INPUT_BYTES as u64,
                    )?,
                    lane("output", Direction::Output, output_schema.clone(), 4096)?,
                ],
                interface_id: id("reference-device/bytes-and-checksum-v1")?,
                features: Vec::new(),
                configuration_ref: port_policy,
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let implementation = ImplementationIdentity {
            schema_version: 1,
            implementation_id: id("crucible-reference-device")?,
            artifacts: vec![
                artifact("device", "device-executable", device_executable)?,
                artifact("provider", "provider-executable", provider_executable)?,
            ],
            model_definitions: vec![model],
            formats: vec![input_schema, output_schema],
            extensions: Extensions::new(),
        };
        let profile_ref = put_json(
            &mut content,
            &json!({
                "schema_version":1,"descriptor":descriptor,"implementation":implementation,
                "operating_contract":operating_contract,"capabilities":capabilities,"guarantees":guarantees
            }),
        )?;
        descriptor.validate()?;
        implementation.validate()?;
        operating_contract.validate()?;
        capabilities.validate()?;
        guarantees.validate()?;

        let configuration_schema = schema(
            &mut content,
            "reference-device/configuration-v1",
            CONFIGURATION_SCHEMA,
        )?;
        let allowed_combinations_ref = put_json(
            &mut content,
            &json!({
                "schema_version":1,"modes":["quantized"],"devices":["rolling-checksum"],
                "facets":operating_contract.facets,"capture":"none","continuation":"unsupported"
            }),
        )?;
        let port_templates_ref = put_json(&mut content, &descriptor.ports)?;
        let node_manifest = NodeManifest {
            schema_version: 1,
            profile_id: id("reference-device/quantized-v1")?,
            roles: descriptor.roles.clone(),
            configuration_schema,
            allowed_combinations_ref,
            port_templates_ref,
            state_formats: Vec::new(),
            operation_facets: operating_contract.facets.clone(),
            extensions: Extensions::new(),
        };
        let provider_manifest = ProviderManifest {
            schema_version: 1,
            provider_id: id("crucible-reference-provider")?,
            implementation: implementation.clone(),
            protocol_versions: vec![id("CNP/1")?],
            supported_profiles: vec![node_manifest.clone()],
            extensions_supported: Vec::new(),
            qualification_refs: Vec::new(),
            extensions: Extensions::new(),
        };
        node_manifest.validate()?;
        provider_manifest.validate()?;
        put_json(&mut content, &provider_manifest)?;
        let contents = content
            .iter()
            .map(|entry| {
                (
                    entry.reference.hash.digest.clone(),
                    (entry.reference.clone(), entry.bytes.clone()),
                )
            })
            .collect();

        Ok(Self {
            descriptor,
            implementation,
            operating_contract,
            capabilities,
            guarantees,
            owner: OwnerRef {
                id: owner,
                participant_ids: vec![node],
                state_domain_ids: domains,
            },
            node_manifest,
            provider_manifest,
            configuration_ref: configuration,
            contents,
            profile_ref,
            capabilities_ref,
            guarantees_ref,
            ownership_ref,
            content,
        })
    }

    /// Returns immutable objects required to resolve this profile's closure.
    ///
    /// Executable bytes remain in the launcher's installed artifact store.
    pub fn content_objects(&self) -> &[ProfileContent] {
        &self.content
    }

    /// Resolves exactly one immutable object in the selected profile.
    ///
    /// # Errors
    /// Rejects absent content and mismatched length, media type or hash domain.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        let (original, bytes) = self
            .contents
            .get(&reference.hash.digest)
            .ok_or(ProviderError::Frame("profile content absent"))?;
        if original != reference {
            return Err(ProviderError::Conflict(
                "profile reference differs from original content",
            ));
        }
        Ok(bytes)
    }

    /// Binds separately supplied live custody without manufacturing qualification.
    ///
    /// The caller authenticates `authority` against the actual prepared process
    /// and a private host admission record. No qualification reference is added
    /// by this method and no native effect is performed.
    ///
    /// # Errors
    /// Rejects invalid live authority or portable binding records.
    pub fn bind(
        &self,
        authority: LiveAuthority,
    ) -> Result<(NodeBinding, OwnerBinding), ProviderError> {
        authority.validate()?;
        let binding = NodeBinding {
            compatibility: BindingCompatibility {
                schema_version: 1,
                node_id: self.descriptor.id.clone(),
                descriptor_hash: self.descriptor.identity()?,
                implementation: self.implementation.clone(),
                profile_ref: self.profile_ref.clone(),
                configuration_ref: self.descriptor.configuration_ref.clone(),
                operating_contract: self.operating_contract.clone(),
                execution_owner: self.owner.clone(),
                capture_owner: self.owner.clone(),
                capabilities_ref: self.capabilities_ref.clone(),
                guarantees_ref: self.guarantees_ref.clone(),
                qualification_refs: Vec::new(),
                extensions: Extensions::new(),
            },
            authority,
            extensions: Extensions::new(),
        };
        binding.validate()?;
        let owner = OwnerBinding {
            schema_version: 1,
            owner: self.owner.clone(),
            owner_roles: vec![id("capture")?, id("execution")?],
            node_bindings: vec![NodeBindingRef {
                node_id: self.descriptor.id.clone(),
                binding_hash: binding.identity()?,
                extensions: Extensions::new(),
            }],
            ownership_ref: self.ownership_ref.clone(),
            extensions: Extensions::new(),
        };
        owner.validate()?;
        Ok((binding, owner))
    }
}

fn id(value: &str) -> Result<Id, ProviderError> {
    Ok(Id::new(value)?)
}

fn put_json(
    content: &mut Vec<ProfileContent>,
    value: &impl Serialize,
) -> Result<ContentRef, ProviderError> {
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    put(
        content,
        canonical::canonical_json(&value)?,
        "application/json",
    )
}

fn put_text(content: &mut Vec<ProfileContent>, text: &str) -> Result<ContentRef, ProviderError> {
    put(
        content,
        text.as_bytes().to_vec(),
        "text/plain; charset=utf-8",
    )
}

fn put(
    content: &mut Vec<ProfileContent>,
    bytes: Vec<u8>,
    media_type: &str,
) -> Result<ContentRef, ProviderError> {
    let reference = canonical::content_ref(&bytes, media_type)?;
    if !content.iter().any(|entry| entry.reference == reference) {
        content.push(ProfileContent {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(reference)
}

fn schema(
    content: &mut Vec<ProfileContent>,
    name: &str,
    specification: &str,
) -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: id(name)?,
        version: 1,
        definition: put_text(content, specification)?,
        extensions: Extensions::new(),
    })
}

fn artifact(
    name: &str,
    role: &str,
    content: ContentRef,
) -> Result<ArtifactIdentity, ProviderError> {
    Ok(ArtifactIdentity {
        id: id(name)?,
        role: id(role)?,
        content,
        extensions: Extensions::new(),
    })
}

fn lane(
    name: &str,
    direction: Direction,
    payload_schema: SchemaRef,
    maximum: u64,
) -> Result<LaneDescriptor, ProviderError> {
    Ok(LaneDescriptor {
        id: id(name)?,
        direction,
        payload_schema,
        maximum_payload_bytes: maximum.into(),
        maximum_pending_events: 1.into(),
        extensions: Extensions::new(),
    })
}

fn lane_policy(name: &str, quantum: U64, window: &ContentRef, maximum: u64) -> serde_json::Value {
    json!({ "lane_id":name,"ordering_ref":window,"correlation_ref":window,
        "flow_control":"credit","maximum_pending_bytes":U64::new(maximum),
        "visibility":{"kind":"quantized","quantum_ps":quantum,"phase_ps":"0","contract_ref":window},
        "effect_phases":[1],"minimum_lookahead_ps":"0" })
}

const MODEL_SPECIFICATION: &str = "Controlled checksum model, edition 1. Initial quantum and checksum are zero. For each byte b in frozen input order, checksum becomes (checksum * 257 + b) modulo 2^64. bytes_processed equals this window's input length. Exactly one JSON output record is published per closed window, including empty input. An identical operation retry returns original custody; changed material conflicts. Native process state is not exportable in this profile.";

const WINDOW_SPECIFICATION: &str = "Quantized checksum window, edition 1. The controller authenticates one fixed input batch and closed prefix before begin. Staging consumes no bytes. Execution consumes exactly the staged batch once, with a finite host-time budget. Output remains invisible until the controller closes the original window. Publication is at (window_end_ps,0,Publication), without an evaluation coordinate. The parked child acknowledges closure and retains its output until acknowledgement. A lost response does not authorize reexecution. Budget failure retains original native custody under supervision. Application park makes no physical suspension claim. Each input and output is bounded by its lane credits. No captures, forks, reset or continuation are supported.";

const INPUT_SCHEMA: &str = "reference-device/input-v1: arbitrary octets in one immutable content reference, length 0 through MAX_INPUT_BYTES. Multiple admitted events are concatenated in coordinator order before begin. No textual decoding, implicit separators, or host arrival ordering is applied.";

const OUTPUT_SCHEMA: &str = "reference-device/output-v1: closed JSON object with required bytes_processed and checksum fields. Each field is a canonical decimal u64 string, never a JSON number. bytes_processed equals the original frozen input length for this window; checksum is cumulative across windows. There are no additional fields. The original grant carries the quantum identity separately. Serialized bytes are preserved exactly in output custody.";

const CONFIGURATION_SCHEMA: &str = "reference-device/configuration-v1: closed JSON object, required schema_version integral JSON value 1, positive canonical decimal u64 quantum_ps and host_budget_ns, phase_ps string 0, maximum_input_bytes decimal u64 equal to the installed implementation limit, ordering_profile string superdense-v1, window_semantics_ref complete CNP ContentRef, checksum_multiplier string 257, checksum_modulus string 18446744073709551616. No additional fields or extensions are accepted. Native admission also verifies the original configured profile and separately authenticated owner/world custody.";

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
