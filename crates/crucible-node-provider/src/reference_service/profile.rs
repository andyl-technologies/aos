//! Immutable content and bindings for the controlled checksum provider.
//!
//! Profiles describe a bounded quantized application process. They do not claim
//! physical suspension, state capture, native CPU timing, or authenticated
//! execution authority. The service obtains live authority from its private
//! host bootstrap and verifies it independently of these content identities.

#[path = "profile/lineage.rs"]
mod lineage;

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

use super::bootstrap::PublicReferenceProfile;

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
    /// Defines inert verified-byte possession without granting model effects.
    pub content_possession_schema: SchemaRef,
    /// Retains profile content by digest for bounded blob resolution.
    pub contents: BTreeMap<String, (ContentRef, Vec<u8>)>,
    profile_ref: ContentRef,
    capabilities_ref: ContentRef,
    guarantees_ref: ContentRef,
    ownership_ref: ContentRef,
    content: Vec<ProfileContent>,
    selection: ProfileSelection,
}

#[derive(Clone, Copy, Debug)]
enum ProfileSelection {
    Cnp,
    Closed,
    Linked { closed_ingress: bool },
    PublicLinked { closed_ingress: bool },
    PublicLineage { closed_ingress: bool },
    PublicProgress { closed_ingress: bool },
}

impl ReferenceProfile {
    /// Builds a separate qualification-only positive-work latch profile.
    ///
    /// The input-capable companion holds quantum one's completion after one
    /// actual byte. The closed source never reaches that input-bearing target.
    /// This model selects a distinct implementation, configuration and facet;
    /// ordinary public launch records cannot select it.
    ///
    /// # Errors
    /// Rejects invalid measured artifacts, zero budgets, malformed portable
    /// records, or unrepresentable profile content.
    pub fn build_public_progress(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
        closed_ingress: bool,
    ) -> Result<Self, ProviderError> {
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::PublicProgress { closed_ingress },
        )
    }

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
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::Cnp,
        )
    }

    /// Builds an output-only checksum profile with permanently closed ingress.
    ///
    /// The owning adapter exclusively controls the private companion and accepts
    /// only an authenticated empty original input cut. The descriptor exposes no
    /// input lane; input schema and profile/configuration identities differ from
    /// [`Self::build`]. This declaration does not itself authenticate deployment.
    ///
    /// # Errors
    /// Rejects invalid artifacts, zero quantum/budget, malformed records, or
    /// serialization failure. Native admission separately verifies the closed
    /// descriptor and actual exclusive child custody before any effects.
    pub fn build_closed(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
    ) -> Result<Self, ProviderError> {
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::Closed,
        )
    }

    /// Builds an actor-native checksum profile for lossless opaque-byte links.
    ///
    /// Original checksum JSON output is carried as opaque octets. A connected
    /// consumer intentionally checksums those exact octets; no semantic JSON or
    /// Ethernet conversion is implied. A closed source exposes output only.
    /// Otherwise every input lane needs an authenticated admitted causal source.
    /// No public CNP endpoint, capture, or physical suspension is advertised.
    ///
    /// # Errors
    /// Rejects invalid references, zero quantum/budget, malformed records, and
    /// serialization failure. Native custody and complete graph closure remain
    /// independently authenticated before effects.
    pub fn build_native_linked(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
        closed_ingress: bool,
    ) -> Result<Self, ProviderError> {
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::Linked { closed_ingress },
        )
    }

    /// Builds a public CNP profile for lossless opaque-byte connections.
    ///
    /// The provider retains its public protocol, authenticated native admission
    /// and dedicated resource ceilings. Original checksum output bytes use the
    /// same octet schema as connected input. No conversion, capture, physical
    /// suspension or repeatability guarantee is introduced.
    ///
    /// # Errors
    /// Rejects invalid references, zero budgets, malformed records or failed
    /// serialization. A closed source has no input lane and rejects ingress.
    pub fn build_public_linked(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
        closed_ingress: bool,
    ) -> Result<Self, ProviderError> {
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::PublicLinked { closed_ingress },
        )
    }

    /// Builds the distinct source-owned ordered-consumption public candidate.
    ///
    /// Exact input event boundaries, native state ancestry and paired provenance
    /// are selected separately from baseline same-time scalar parent semantics.
    /// This profile declaration grants no source qualification or preservation.
    ///
    /// # Errors
    /// Refuses malformed measured artifacts, zero bounds or invalid records.
    pub fn build_public_lineage(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
        closed_ingress: bool,
    ) -> Result<Self, ProviderError> {
        Self::build_selected(
            node,
            owner,
            provider_executable,
            device_executable,
            quantum_ps,
            host_budget_ns,
            ProfileSelection::PublicLineage { closed_ingress },
        )
    }

    pub(crate) fn is_lineage(&self) -> bool {
        matches!(self.selection, ProfileSelection::PublicLineage { .. })
    }

    /// Returns the selected public launch profile without granting authority.
    ///
    /// # Errors
    /// Refuses actor-native profiles and the separate progress fixture, which
    /// requires its own explicit launch edition.
    pub fn public_profile(&self) -> Result<PublicReferenceProfile, ProviderError> {
        match self.selection {
            ProfileSelection::Cnp => Ok(PublicReferenceProfile::ChecksumJsonV1),
            ProfileSelection::PublicLinked { closed_ingress } => {
                Ok(PublicReferenceProfile::ByteLinkedV1 { closed_ingress })
            }
            ProfileSelection::PublicProgress { .. } => Err(ProviderError::Frame(
                "progress fixture requires explicit launch edition five",
            )),
            ProfileSelection::Closed
            | ProfileSelection::Linked { .. }
            | ProfileSelection::PublicLineage { .. } => Err(ProviderError::Frame(
                "actor-native reference profile has no public launch selection",
            )),
        }
    }

    pub(super) fn output_media_type(&self) -> &'static str {
        if matches!(
            self.selection,
            ProfileSelection::PublicLinked { .. }
                | ProfileSelection::PublicLineage { .. }
                | ProfileSelection::PublicProgress { .. }
        ) {
            "application/octet-stream"
        } else {
            "application/json"
        }
    }

    fn build_selected(
        node: Id,
        owner: Id,
        provider_executable: ContentRef,
        device_executable: ContentRef,
        quantum_ps: U64,
        host_budget_ns: U64,
        selection: ProfileSelection,
    ) -> Result<Self, ProviderError> {
        let closed_ingress = matches!(
            selection,
            ProfileSelection::Closed
                | ProfileSelection::Linked {
                    closed_ingress: true
                }
                | ProfileSelection::PublicLinked {
                    closed_ingress: true
                }
                | ProfileSelection::PublicLineage {
                    closed_ingress: true
                }
                | ProfileSelection::PublicProgress {
                    closed_ingress: true
                }
        );
        let native_linked = matches!(selection, ProfileSelection::Linked { .. });
        let public_lineage = matches!(selection, ProfileSelection::PublicLineage { .. });
        let progress_latch = matches!(selection, ProfileSelection::PublicProgress { .. });
        let public_linked = matches!(selection, ProfileSelection::PublicLinked { .. })
            || public_lineage
            || progress_latch;
        let byte_linked = native_linked || public_linked;
        let native_adapter = matches!(
            selection,
            ProfileSelection::Closed | ProfileSelection::Linked { .. }
        );
        provider_executable.validate()?;
        device_executable.validate()?;
        if quantum_ps.get() == 0 || host_budget_ns.get() == 0 {
            return Err(ProviderError::Frame(
                "reference profile requires positive budgets",
            ));
        }

        let mut content = Vec::new();
        let model = put_text(
            &mut content,
            if progress_latch {
                PROGRESS_MODEL_SPECIFICATION
            } else if public_lineage {
                lineage::MODEL_SPECIFICATION
            } else if public_linked {
                PUBLIC_LINKED_MODEL_SPECIFICATION
            } else if native_linked {
                LINKED_MODEL_SPECIFICATION
            } else if closed_ingress {
                CLOSED_MODEL_SPECIFICATION
            } else {
                MODEL_SPECIFICATION
            },
        )?;
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
                "native_resource_limits": if native_adapter {
                    "The actor-native adapter bounds original windows, staged/output bytes, retained operations and world custody; finite wall-time control and window budgets contain this fixed measured no-fork child. Dedicated CNP-provider RLIMIT partitioning is not selected or claimed by this actor profile."
                } else {
                    "dedicated provider and fixed measured companion inherit half of admitted RLIMIT_AS, RLIMIT_NOFILE, RLIMIT_FSIZE and integral-second RLIMIT_CPU hard ceilings; smaller CPU allowances are refused"
                },
                "process_limit":"the measured no-fork companion is the sole child; this profile does not sandbox arbitrary external executables",
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
        let window = put_text(
            &mut content,
            if progress_latch {
                PROGRESS_WINDOW_SPECIFICATION
            } else if public_lineage {
                lineage::WINDOW_SPECIFICATION
            } else if public_linked {
                PUBLIC_LINKED_WINDOW_SPECIFICATION
            } else if native_linked {
                LINKED_WINDOW_SPECIFICATION
            } else if closed_ingress {
                CLOSED_WINDOW_SPECIFICATION
            } else {
                WINDOW_SPECIFICATION
            },
        )?;
        let policy = put_json(
            &mut content,
            &json!({
                "schema_version":1,"mode":"quantized","quantum_ps":quantum_ps,
                "phase_ps":"0","host_budget_ns":host_budget_ns,"window_proof_ref":window
            }),
        )?;
        let mut configuration_value = json!({
            "schema_version":1,"quantum_ps":quantum_ps,"phase_ps":"0",
            "host_budget_ns":host_budget_ns,"maximum_input_bytes":U64::new(MAX_INPUT_BYTES as u64),
            "ordering_profile":"superdense-v1","window_semantics_ref":window,
            "checksum_multiplier":"257","checksum_modulus":"18446744073709551616"
        });
        if closed_ingress {
            configuration_value["input_policy"] = json!("closed-no-ingress");
        }
        if byte_linked {
            configuration_value["byte_interface"] = json!("opaque-octets");
            if !closed_ingress {
                configuration_value["input_policy"] = json!("admitted-causal-source");
            }
        }
        if public_lineage {
            configuration_value["native_dialect"] = json!(crate::reference_lineage::DIALECT);
            configuration_value["native_consumption_schema"] =
                json!("crucible.reference.consumption-relation.v1");
            configuration_value["maximum_input_events"] = json!("64");
            configuration_value["maximum_native_windows"] = json!("64");
            configuration_value["maximum_native_commands"] = json!("512");
            configuration_value["maximum_native_journal_bytes"] = json!("8388608");
            configuration_value["relation_reserved_bytes"] = json!("614400");
        }
        if progress_latch {
            configuration_value["native_fault_fixture"] = json!({
                "schema":"crucible.reference.native-progress.v1",
                "target_quantum":"1","consumed_prefix":"1",
                "completion_latch":"separate-private-stream-release-byte-1",
                "closed_ingress_target":"never-selected"
            });
        }
        let configuration = put_json(&mut content, &configuration_value)?;
        let facet = FacetSelection {
            id: id(if progress_latch {
                "reference-device/quantized-progress-v1"
            } else if public_lineage {
                "reference-device/quantized-lineage-v1"
            } else {
                "reference-device/quantized-v1"
            })?,
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
                "input": if closed_ingress { "permanently closed; authenticated empty batch only" } else { "immutable raw byte batch" },
                "output":"one cumulative checksum record",
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

        let input_schema = if byte_linked {
            schema(
                &mut content,
                NATIVE_OCTET_SCHEMA_ID,
                NATIVE_OCTET_SPECIFICATION,
            )?
        } else {
            schema(&mut content, "reference-device/input-v1", INPUT_SCHEMA)?
        };
        let output_schema = if byte_linked {
            input_schema.clone()
        } else {
            schema(&mut content, "reference-device/output-v1", OUTPUT_SCHEMA)?
        };
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
        let mut lane_policies = Vec::new();
        let mut lanes = Vec::new();
        if !closed_ingress {
            lane_policies.push(lane_policy(
                "input",
                quantum_ps,
                &window,
                MAX_INPUT_BYTES as u64,
            ));
            lanes.push(lane(
                "input",
                Direction::Input,
                input_schema.clone(),
                MAX_INPUT_BYTES as u64,
            )?);
        }
        lane_policies.push(lane_policy("output", quantum_ps, &window, 4096));
        lanes.push(lane(
            "output",
            Direction::Output,
            output_schema.clone(),
            4096,
        )?);
        let port_policy = put_json(
            &mut content,
            &json!({
                "schema_version":1,"lanes":lane_policies,
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
                lanes,
                interface_id: id(if byte_linked {
                    NATIVE_OCTET_INTERFACE_ID
                } else if closed_ingress {
                    "reference-device/checksum-only-v1"
                } else {
                    "reference-device/bytes-and-checksum-v1"
                })?,
                features: Vec::new(),
                configuration_ref: port_policy,
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let content_possession_schema = schema(
            &mut content,
            "reference-device/content-possession-v1",
            r#"{"schema":"reference-device/content-possession-v1","semantics":"Verified bounded content remains inert. A selected consuming schema and native authority are required before effects."}"#,
        )?;
        let mut formats = vec![output_schema, content_possession_schema.clone()];
        if !closed_ingress && !formats.contains(&input_schema) {
            formats.push(input_schema);
        }
        if public_lineage {
            lineage::add_formats(&mut content, &mut formats)?;
        }
        formats.sort_by(|left, right| (&left.id, left.version).cmp(&(&right.id, right.version)));
        let implementation = ImplementationIdentity {
            schema_version: 1,
            implementation_id: id(if progress_latch {
                "crucible-reference-progress-device"
            } else if public_lineage {
                "crucible-reference-lineage"
            } else {
                "crucible-reference-device"
            })?,
            artifacts: vec![
                artifact("device", "device-executable", device_executable)?,
                artifact("provider", "provider-executable", provider_executable)?,
            ],
            model_definitions: vec![model],
            formats,
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
            if progress_latch {
                "reference-device/configuration-progress-v1"
            } else if public_lineage {
                "reference-device/configuration-public-lineage-v1"
            } else if public_linked {
                "reference-device/configuration-public-linked-v1"
            } else if native_linked {
                "reference-device/configuration-linked-v1"
            } else if closed_ingress {
                "reference-device/configuration-closed-v1"
            } else {
                "reference-device/configuration-v1"
            },
            if progress_latch {
                PROGRESS_CONFIGURATION_SCHEMA
            } else if public_lineage {
                lineage::CONFIGURATION_SCHEMA
            } else if public_linked {
                PUBLIC_LINKED_CONFIGURATION_SCHEMA
            } else if native_linked {
                LINKED_CONFIGURATION_SCHEMA
            } else if closed_ingress {
                CLOSED_CONFIGURATION_SCHEMA
            } else {
                CONFIGURATION_SCHEMA
            },
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
            profile_id: id(if progress_latch {
                if closed_ingress {
                    "reference-device/progress-source-v1"
                } else {
                    "reference-device/progress-consumer-v1"
                }
            } else if public_lineage {
                if closed_ingress {
                    "reference-device/cnp-lineage-source-v1"
                } else {
                    "reference-device/cnp-lineage-consumer-v1"
                }
            } else if public_linked {
                if closed_ingress {
                    "reference-device/cnp-linked-source-v1"
                } else {
                    "reference-device/cnp-linked-consumer-v1"
                }
            } else if native_linked {
                if closed_ingress {
                    "reference-device/linked-source-v1"
                } else {
                    "reference-device/linked-consumer-v1"
                }
            } else if closed_ingress {
                "reference-device/closed-quantized-v1"
            } else {
                "reference-device/quantized-v1"
            })?,
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
            provider_id: id(if public_lineage {
                "crucible-reference-lineage-provider"
            } else if native_adapter {
                "crucible-host-reference-adapter"
            } else {
                "crucible-reference-provider"
            })?,
            implementation: implementation.clone(),
            // The closed actor profile selects the local native adapter, not
            // the independently launched public CNP provider endpoint.
            protocol_versions: if native_adapter {
                Vec::new()
            } else {
                vec![id("CNP/1")?]
            },
            supported_profiles: vec![node_manifest.clone()],
            extensions_supported: if native_adapter {
                Vec::new()
            } else if public_linked {
                vec![
                    id("cnp.control-evidence/1")?,
                    id("cnp.resume/1")?,
                    id(if progress_latch {
                        "reference-device/quantized-progress-v1"
                    } else if public_lineage {
                        "reference-device/quantized-lineage-v1"
                    } else {
                        "reference-device/quantized-v1"
                    })?,
                ]
            } else {
                vec![id("cnp.resume/1")?, id("reference-device/quantized-v1")?]
            },
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
            content_possession_schema,
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
            selection,
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
        self.bind_qualified(authority, &[])
    }

    /// Commits caller-supplied host qualification references to immutable bindings.
    ///
    /// This method validates data only. The installation registry must separately
    /// authenticate the exact evidence, actual native custody and permitted
    /// claims; a provider cannot qualify itself by constructing these references.
    /// Empty references retain the original unqualified binding exactly.
    ///
    /// # Errors
    /// Rejects invalid authority, unsorted or duplicate references, excessive
    /// qualification bounds or invalid resulting portable bindings.
    pub fn bind_qualified(
        &self,
        authority: LiveAuthority,
        qualifications: &[ContentRef],
    ) -> Result<(NodeBinding, OwnerBinding), ProviderError> {
        validate_qualifications(qualifications)?;
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
                qualification_refs: qualifications.to_vec(),
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

pub(super) fn validate_qualifications(qualifications: &[ContentRef]) -> Result<(), ProviderError> {
    if qualifications.len() > 4096
        || qualifications.windows(2).any(|pair| {
            (&pair[0].hash.domain, &pair[0].hash.digest)
                >= (&pair[1].hash.domain, &pair[1].hash.digest)
        })
    {
        return Err(ProviderError::Frame(
            "installed qualifications exceed bounds or change canonical order",
        ));
    }
    for reference in qualifications {
        reference.validate()?;
    }
    Ok(())
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

const PROGRESS_MODEL_SPECIFICATION: &str = "reference-device/native-progress-v1: separately measured qualification-only rolling-checksum process. Original ordered input bytes update cumulative checksum by wrapping multiplier257. Quantum0 normally closes and acknowledges; input-bearing quantum1 consumes exactly its first byte, sends the original Initialize/Ready, Stage/Activate and preceding Close/ACK ledger on a distinct private source-owned stream, and holds its ordinary completion until release byte1. The ledger is positive partial work, never a complete-window receipt, source-class claim or capture. Empty quantum1 completes normally without a progress ledger. Closed-ingress sources have no positive-input target. All records and stream state belong to the original owner; native deadlines/loss retain Unknown without replacement execution.";

const PROGRESS_WINDOW_SPECIFICATION: &str = "reference-device/native-progress-window-v1: unchanged opaque-octet boundary sampling and cumulative checksum output on successful completion. A distinct declared fault fixture holds input-bearing quantum1 after consumed-prefix1 and before completion publication; a source actor may terminate the original provider only after authenticating the actual progress peer, original input/grant/predecessor and ledger. Positive partial progress cannot authorize Close/publication/ACK or establish full quantum completion. The first original request and missing response remain owned on loss. Native modeled timing, repeatability and preservation remain unqualified.";

const PROGRESS_CONFIGURATION_SCHEMA: &str = "reference-device/configuration-progress-v1: the closed public-linked base configuration plus native_fault_fixture object with exactly schema crucible.reference.native-progress.v1, target_quantum string1, consumed_prefix string1, completion_latch separate-private-stream-release-byte-1, closed_ingress_target never-selected. No implicit environment switch or ordinary launch record may enable the fault. The explicit edition5 launch carries a separately private progress endpoint whose path is operational launch scope, not reusable model identity.";

const OUTPUT_SCHEMA: &str = "reference-device/output-v1: closed JSON object with required bytes_processed and checksum fields. Each field is a canonical decimal u64 string, never a JSON number. bytes_processed equals the original frozen input length for this window; checksum is cumulative across windows. There are no additional fields. The original grant carries the quantum identity separately. Serialized bytes are preserved exactly in output custody.";

const CONFIGURATION_SCHEMA: &str = "reference-device/configuration-v1: closed JSON object, required schema_version integral JSON value 1, positive canonical decimal u64 quantum_ps and host_budget_ns, phase_ps string 0, maximum_input_bytes decimal u64 equal to the installed implementation limit, ordering_profile string superdense-v1, window_semantics_ref complete CNP ContentRef, checksum_multiplier string 257, checksum_modulus string 18446744073709551616. No additional fields or extensions are accepted. Native admission also verifies the original configured profile and separately authenticated owner/world custody.";

const CLOSED_MODEL_SPECIFICATION: &str = "Controlled checksum model, closed-ingress edition 1. Initial quantum and checksum are zero. No public input lane or independent ingress source exists. The exclusive native adapter accepts only an authenticated empty original input cut. Every window preserves checksum zero, reports bytes_processed zero, and publishes one original JSON checksum record. The child process and retry/output custody remain owned. Native state export, fork and continuation are unsupported.";

const CLOSED_WINDOW_SPECIFICATION: &str = "Closed-ingress quantized checksum window, edition 1. No public input lane or side ingress exists. The exclusive measured controller freezes an authenticated empty cut before begin. Exactly one bounded empty-input window executes with a finite host-time budget. Original output remains invisible until authentic controller close, then publishes at (window_end_ps,0,Publication), without evaluation coordinates. Original retry and output custody persist until acknowledgement; lost responses never authorize reexecution. The native adapter rejects nonempty input before staging or execution. Application park does not certify physical suspension. Capture, fork, reset and continuation are unsupported.";

const CLOSED_CONFIGURATION_SCHEMA: &str = "reference-device/configuration-closed-v1: closed JSON object with schema_version integral 1, positive canonical decimal u64 quantum_ps and host_budget_ns, phase_ps string 0, maximum_input_bytes equal to the installed companion ceiling, ordering_profile string superdense-v1, window_semantics_ref complete CNP ContentRef for closed ingress, checksum_multiplier string 257, checksum_modulus string 18446744073709551616, and input_policy string closed-no-ingress. No extensions, side-input source, or public input lane exists. The exclusive native adapter accepts authenticated empty original input cuts only. Other fields are refused.";

/// Names the installed bounded lossless byte interface for native model links.
pub const NATIVE_OCTET_INTERFACE_ID: &str = "crucible/octet-stream-v1";
/// Names the shared inert octet payload schema used by native model links.
pub const NATIVE_OCTET_SCHEMA_ID: &str = "crucible/octet-stream-v1";
/// Defines byte-preserving payload semantics; lane credits bound actual length.
pub const NATIVE_OCTET_SPECIFICATION: &str = "crucible/octet-stream-v1: exactly the original immutable octets in a hash-checked CNP ContentRef. Length is bounded by the admitted lane and connection credits. No text, JSON, Ethernet, address, framing or timing conversion is implied. Media type remains original metadata and does not change the octets. Consuming model semantics and original native input authority are separate from inert byte possession.";

const LINKED_MODEL_SPECIFICATION: &str = "Controlled checksum model, native byte-linked edition 1. Initial quantum/checksum are zero. A linked consumer consumes only the original authenticated causal input cut, concatenated in coordinator order, applying checksum=(checksum*257+b) modulo 2^64 per octet. A source with closed-no-ingress exposes no input lane and accepts only an empty cut. Every original window publishes one original checksum JSON record as opaque octets, without semantic conversion. Native retry/output custody persists. No captures, forks or continuation are supported.";
const LINKED_WINDOW_SPECIFICATION: &str = "Native byte-linked quantized checksum window, edition 1. Exclusive measured adapter freezes a complete authenticated original input prefix before execution. Exactly that byte sequence is consumed once under the selected finite host budget. Original checksum JSON output becomes visible only at authentic close, at (window_end_ps,0,Publication), without evaluation coordinates. Original retries retain custody, never reexecute. Admitted temporal connections preserve byte order and explicit causal provenance. Closed sources reject every nonempty input before staging. Application park makes no physical suspension claim.";
const LINKED_CONFIGURATION_SCHEMA: &str = "reference-device/configuration-linked-v1: closed JSON object with the base quantized checksum configuration fields, positive quantum_ps/host_budget_ns, phase_ps 0, installed maximum_input_bytes, ordering_profile superdense-v1, native-linked window_semantics_ref, multiplier257 and modulus2^64, byte_interface opaque-octets, and input_policy either closed-no-ingress or admitted-causal-source. The former selects no input lane; the latter requires complete admitted causal source for its shared bounded octet lane. No implicit side ingress, extensions or conversion is accepted.";

const PUBLIC_LINKED_MODEL_SPECIFICATION: &str = concat!(
    "Public CNP byte-linked checksum model, edition 1. The measured provider and ",
    "its sole companion retain complete original request, input and output custody ",
    "under dedicated native resource ceilings. Each frozen input byte updates the ",
    "rolling checksum modulo 2^64. Exactly one original canonical checksum JSON ",
    "record is published as unchanged opaque octets. A closed source exposes no ",
    "input lane and consumes only authenticated empty cuts. This profile does not ",
    "select the actor-native adapter, capture, fork, replay or physical suspension."
);

const PUBLIC_LINKED_WINDOW_SPECIFICATION: &str = concat!(
    "Public CNP byte-linked quantized checksum window, edition 1. Private host ",
    "admission binds measured provider/companion artifacts and hard resource ",
    "ceilings. A complete immutable original input cut is staged once before ",
    "execution under a finite host budget. The original checksum JSON octets ",
    "remain invisible until authentic window close and publish at ",
    "(window_end_ps,0,Publication), without an evaluation coordinate. Original ",
    "retry, reconnect and consumption acknowledgement preserve native custody ",
    "without reexecution. Closed sources reject nonempty input before effects. ",
    "Application park makes no physical suspension or repeatability claim."
);

const PUBLIC_LINKED_CONFIGURATION_SCHEMA: &str = concat!(
    "reference-device/configuration-public-linked-v1: closed base quantized ",
    "checksum configuration with schema_version 1, positive quantum_ps and ",
    "host_budget_ns, phase_ps 0, installed maximum_input_bytes, ordering_profile ",
    "superdense-v1, public-linked window_semantics_ref, checksum_multiplier 257, ",
    "checksum_modulus 18446744073709551616, byte_interface opaque-octets and ",
    "input_policy closed-no-ingress or admitted-causal-source. Public CNP/1 ",
    "transport and dedicated resource ceilings remain selected. No additional ",
    "fields, side ingress or implicit byte conversion are accepted."
);

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
