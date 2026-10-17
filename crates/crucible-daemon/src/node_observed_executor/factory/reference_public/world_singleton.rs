//! Defines the exact source-owned ordinary singleton collecting world.

use super::*;

impl CandidateWorldDefinition {
    /// Builds the closed ordinary one-owner fixture without granting acceptance.
    ///
    /// # Errors
    /// Refuses malformed local nonce, unavailable installed source, invalid
    /// immutable profiles, or unrepresentable complete world objects.
    pub(in super::super) fn build_singleton(
        package: Rc<InstalledPublicReferencePackage>,
        quantum_ps: U64,
        host_budget_ns: U64,
        nonce: Bytes,
    ) -> Result<Self, ProviderError> {
        if nonce.as_slice().len() != 32 {
            return Err(ProviderError::Frame(
                "singleton requires fresh 32-byte local nonce",
            ));
        }
        let nonce = nonce
            .as_slice()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let profile = package
            .profile(
                id("singleton")?,
                id("singleton-owner")?,
                quantum_ps,
                host_budget_ns,
                true,
            )
            .map_err(package_error)?;
        let mechanism_bytes = canonical::canonical_json(&serde_json::json!({
            "schema": "crucible.reference.singleton-collecting-mechanism.v1",
            "implementation": package.identity(),
            "profile": "ordinary-public-byte-linked-closed-ingress-v1",
            "quantum_ps": quantum_ps,
            "host_budget_ns": host_budget_ns,
            "owner_inventory": "one-original-provider-companion-group-and-complete-common-coordinator",
            "connections": "none",
            "capture": "none",
            "repeatability": "nondeterministic",
            "qualification": "collecting-only; no ordinary Accepted or Ready is issued by these mechanism bytes",
        }))?;
        let artifacts = ["provider", "device"]
            .into_iter()
            .map(|role| {
                Ok((
                    package
                        .artifact_content(role)
                        .map_err(package_error)?
                        .clone(),
                    package
                        .executable(role)
                        .map_err(package_error)?
                        .to_path_buf(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ProviderError>>()?;
        let mut content = BTreeMap::new();
        for object in profile.content_objects() {
            content.insert(object.reference.clone(), object.bytes.clone());
        }
        let qualification = put(&mut content, mechanism_bytes, "application/json")?;
        let requirements = ScenarioRequirements {
            accepted_quantized_nodes: vec![profile.descriptor.id.clone()],
            accepted_nondeterministic_nodes: vec![profile.descriptor.id.clone()],
            accepted_limited_state_nodes: vec![profile.descriptor.id.clone()],
            ..ScenarioRequirements::default()
        };
        let authority = initial_authority(&profile.descriptor.id, &qualification, &nonce)?;
        let (binding, _) =
            profile.bind_qualified(authority, std::slice::from_ref(&qualification))?;
        let [domain] = profile.owner.state_domain_ids.as_slice() else {
            return Err(ProviderError::Correlation(
                "singleton source domain roster differs",
            ));
        };
        let ownership = OwnershipPolicy {
            schema_version: 1,
            domains: vec![StateDomain {
                id: domain.clone(),
                capture_owner_id: profile.owner.id.clone(),
                execution_owner_ids: vec![profile.owner.id.clone()],
                future_affecting: true,
            }],
            objects: vec![StateObject {
                id: profile.descriptor.id.clone(),
                node_ids: vec![profile.descriptor.id.clone()],
                future_affecting: true,
                state: ObjectState::Mutable {
                    domain_id: domain.clone(),
                },
            }],
            internal_dependencies: Vec::new(),
            capture_owners: vec![OwnerCapturePolicy {
                owner_id: profile.owner.id.clone(),
                complete_model: false,
                unchanged_cut: false,
                exact_continuation: false,
                durable_restart: false,
                isolated_fork: false,
                dependencies: Vec::new(),
                cut_procedure_ref: qualification.clone(),
            }],
            inventory_proof_ref: qualification.clone(),
        };
        let coordinator = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: qualification.clone(),
            maximum_microsteps_per_instant: U64::new(1024),
            same_time_closure: Vec::new(),
            operational_policy_ref: qualification.clone(),
            external_inputs: Vec::new(),
        };
        let ownership_ref = put_json(&mut content, &ownership)?;
        let coordinator_ref = put_json(&mut content, &coordinator)?;
        let scenario_ref = put_json(&mut content, &requirements)?;
        let initialization_ref = put_json(
            &mut content,
            &vec![(
                &profile.descriptor.id,
                &profile.descriptor.initialization_ref,
            )],
        )?;
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref,
            node_bindings: vec![NodeBindingRef {
                node_id: profile.descriptor.id.clone(),
                binding_hash: binding.identity()?,
                extensions: Extensions::new(),
            }],
            connections: Vec::new(),
            ownership_ref,
            coordinator_contract_ref: coordinator_ref,
            ordering_profile: "superdense-v1".into(),
            initialization_ref,
            extensions: Extensions::new(),
        };
        Ok(Self {
            topology: CandidateTopology::OrdinarySingleton,
            world,
            descriptors: vec![profile.descriptor.clone()],
            requirements,
            content,
            artifacts,
            qualification,
            profiles: vec![profile],
            nonce,
        })
    }
}
