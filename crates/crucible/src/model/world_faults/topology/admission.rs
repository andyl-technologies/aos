//! Canonical world-fault ownership and cross-reference admission.

use super::*;

impl WorldFaultTopology {
    /// Validates and canonicalizes a complete world fault registry.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] for duplicate IDs, excessive
    /// collections, dangling references, self-references, invalid geometry, or
    /// a sensor-backed field which is specification-only in schema v3.
    pub fn admit(mut self, world: &World) -> Result<Self, WorldFaultTopologyError> {
        hard_count(&self.fault_domains, "fault domains", 65_536)?;
        hard_count(&self.network_interfaces, "network interfaces", 65_536)?;
        hard_count(&self.network_segments, "network segments", 262_144)?;
        hard_count(&self.network_media, "network media", 16_384)?;
        hard_count(&self.network_forwarders, "network forwarders", 32_768)?;
        hard_count(&self.network_queues, "network queues", 262_144)?;
        expand_direct_segment_paths(&mut self, world)?;
        hard_count(&self.network_paths, "network paths", 262_144)?;
        hard_count(&self.network_attachments, "network attachments", 65_536)?;
        hard_count(&self.network_contact_plans, "network contact plans", 65_536)?;
        hard_count(
            &self.network_policy_artifacts,
            "network policy artifacts",
            HARD_NETWORK_POLICY_ARTIFACTS,
        )?;
        hard_count(&self.mobile_endpoints, "mobile endpoints", 65_536)?;
        hard_count(&self.storage_devices, "storage devices", 16_384)?;
        hard_count(&self.storage_controllers, "storage controllers", 16_384)?;
        hard_count(&self.storage_arrays, "storage arrays", 16_384)?;
        hard_count(
            &self.storage_policy_artifacts,
            "storage policy artifacts",
            HARD_STORAGE_POLICY_ARTIFACTS,
        )?;
        hard_count(&self.node_capabilities, "node capabilities", 16_384)?;
        canonicalize_by_id(&mut self.fault_domains, WorldFaultDomain::id)?;
        canonicalize_by_id(&mut self.network_interfaces, WorldNetworkInterface::id)?;
        canonicalize_by_id(&mut self.network_segments, WorldNetworkSegment::id)?;
        canonicalize_by_id(&mut self.network_media, WorldNetworkMedium::id)?;
        canonicalize_by_id(&mut self.network_forwarders, WorldNetworkForwarder::id)?;
        canonicalize_by_id(&mut self.network_queues, WorldNetworkQueue::id)?;
        canonicalize_by_id(&mut self.network_paths, WorldNetworkPath::id)?;
        canonicalize_by_id(&mut self.network_attachments, WorldNetworkAttachment::id)?;
        canonicalize_by_id(&mut self.network_contact_plans, WorldNetworkContactPlan::id)?;
        self.network_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        require(
            !self
                .network_policy_artifacts
                .windows(2)
                .any(|pair| pair[0].id == pair[1].id),
            "network policy artifact identity",
        )?;
        for artifact in &self.network_policy_artifacts {
            artifact.validate()?;
        }
        for artifact in &self.network_policy_artifacts {
            match &artifact.artifact {
                NetworkPolicyArtifactKind::ContactPlan { intervals } => {
                    for interval in intervals {
                        require(
                            self.network_policy_artifact(&interval.capacity_profile)
                                .is_some_and(|capacity| {
                                    capacity.artifact.class()
                                        == NetworkPolicyArtifactClass::ServiceCurve
                                }),
                            "network contact capacity profile",
                        )?;
                    }
                }
                NetworkPolicyArtifactKind::MediumAccess(policy) => {
                    if let Some(key) = &policy.arbitration_key {
                        require(
                            self.network_policy_artifact(key).is_some_and(|key| {
                                key.artifact.class() == NetworkPolicyArtifactClass::PacketKey
                            }),
                            "network medium arbitration key",
                        )?;
                    }
                    if let Some(transform) = policy
                        .contention
                        .as_ref()
                        .and_then(|contention| contention.undetected_transform.as_ref())
                    {
                        require(
                            self.network_policy_artifact(transform)
                                .is_some_and(|transform| {
                                    matches!(
                                        &transform.artifact,
                                        NetworkPolicyArtifactKind::ByteTemplate { bytes }
                                            if !bytes.is_empty()
                                    )
                                }),
                            "network medium undetected transform",
                        )?;
                    }
                }
                NetworkPolicyArtifactKind::Overflow {
                    typed_error: Some(typed_error),
                    ..
                } => {
                    require(
                        self.network_policy_artifact(typed_error)
                            .is_some_and(|result| {
                                matches!(
                                    result.artifact.class(),
                                    NetworkPolicyArtifactClass::ControlResult
                                        | NetworkPolicyArtifactClass::TypedResponse
                                )
                            }),
                        "network overflow typed error",
                    )?;
                }
                _ => {}
            }
        }
        canonicalize_by_id(&mut self.mobile_endpoints, WorldMobileEndpoint::id)?;
        canonicalize_by_id(&mut self.storage_devices, WorldStorageFaultDevice::id)?;
        canonicalize_by_id(&mut self.storage_controllers, WorldStorageController::id)?;
        canonicalize_by_id(&mut self.storage_arrays, WorldStorageArray::id)?;
        self.storage_policy_artifacts
            .sort_by(|left, right| left.id.cmp(&right.id));
        require(
            !self
                .storage_policy_artifacts
                .windows(2)
                .any(|pair| pair[0].id == pair[1].id),
            "storage policy artifact identity",
        )?;
        for artifact in &self.storage_policy_artifacts {
            artifact.validate()?;
        }
        for artifact in &self.storage_policy_artifacts {
            match &artifact.artifact {
                StoragePolicyArtifactKind::Cache(StoragePolicyCache {
                    dirty_eviction: StoragePolicyDirtyEviction::Fail { result },
                    ..
                }) => {
                    validate_storage_policy_reference(
                        &self,
                        result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage nested typed result",
                    )?;
                    require(
                        self.storage_policy_artifact(result)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block { result }
                                    ) if result != StoragePolicyResult::Success
                                )
                            }),
                        "storage cache failure result",
                    )?;
                }
                StoragePolicyArtifactKind::DuplicateCompletion(
                    StoragePolicyDuplicateCompletion::ProtocolError { result },
                ) => {
                    validate_storage_policy_reference(
                        &self,
                        result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage nested typed result",
                    )?;
                    require(
                        self.storage_policy_artifact(result)
                            .is_some_and(|artifact| {
                                !matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block {
                                            result: StoragePolicyResult::Success
                                        }
                                    )
                                )
                            }),
                        "storage duplicate protocol error result",
                    )?;
                }
                StoragePolicyArtifactKind::DuplicateCompletion(
                    StoragePolicyDuplicateCompletion::Reset { transition_policy },
                ) => {
                    validate_storage_policy_reference(
                        &self,
                        transition_policy,
                        StoragePolicyArtifactClass::ControllerTransition,
                        "storage duplicate controller reset",
                    )?;
                    require(
                        self.storage_policy_artifact(transition_policy)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::ControllerTransition(
                                        StoragePolicyControllerTransition {
                                            transition: StorageControllerTransition::Reset,
                                            ..
                                        }
                                    )
                                )
                            }),
                        "storage duplicate reset transition policy",
                    )?;
                }
                StoragePolicyArtifactKind::ControllerTransition(policy) => {
                    validate_storage_policy_reference(
                        &self,
                        &policy.failure_result,
                        StoragePolicyArtifactClass::TypedResult,
                        "storage reset failure result",
                    )?;
                    require(
                        self.storage_policy_artifact(&policy.failure_result)
                            .is_some_and(|artifact| {
                                matches!(
                                    artifact.artifact,
                                    StoragePolicyArtifactKind::TypedResult(
                                        StoragePolicyTypedResult::Block { result }
                                    ) if result != StoragePolicyResult::Success
                                )
                            }),
                        "storage reset failure result",
                    )?;
                }
                _ => {}
            }
        }
        canonicalize_by_id(&mut self.node_capabilities, WorldNodeFaultCapabilities::id)?;

        for domain in &mut self.fault_domains {
            canonicalize_set(&mut domain.targets, "fault domain targets")?;
        }
        for interface in &mut self.network_interfaces {
            canonicalize_set(&mut interface.addresses, "network interface addresses")?;
            canonicalize_set(
                &mut interface.fault_domains,
                "network interface fault domains",
            )?;
        }
        for segment in &mut self.network_segments {
            canonicalize_set(&mut segment.forwarders, "network segment forwarders")?;
            canonicalize_set(&mut segment.fault_domains, "network segment fault domains")?;
        }
        for medium in &mut self.network_media {
            canonicalize_set(&mut medium.resources, "network medium resources")?;
            canonicalize_set(&mut medium.fault_domains, "network medium fault domains")?;
        }
        for forwarder in &mut self.network_forwarders {
            canonicalize_set(&mut forwarder.ports, "network forwarder ports")?;
            canonicalize_set(
                &mut forwarder.fault_domains,
                "network forwarder fault domains",
            )?;
        }
        for queue in &mut self.network_queues {
            canonicalize_set(&mut queue.fault_domains, "network queue fault domains")?;
        }
        for attachment in &mut self.network_attachments {
            canonicalize_set(&mut attachment.candidates, "network attachment candidates")?;
        }
        for storage in &mut self.storage_devices {
            canonicalize_set(&mut storage.fault_domains, "storage device fault domains")?;
        }
        for controller in &mut self.storage_controllers {
            canonicalize_by_id(&mut controller.namespaces, WorldStorageNamespace::id)?;
            canonicalize_by_id(&mut controller.paths, WorldStoragePath::id)?;
            canonicalize_set(
                &mut controller.fault_domains,
                "storage controller fault domains",
            )?;
        }
        for array in &mut self.storage_arrays {
            canonicalize_by_id(&mut array.members, WorldStorageArrayMember::id)?;
            canonicalize_by_id(&mut array.paths, WorldStoragePath::id)?;
            canonicalize_set(&mut array.fault_domains, "storage array fault domains")?;
        }
        for capabilities in &mut self.node_capabilities {
            canonicalize_by_id(&mut capabilities.registers, WorldNodeRegister::id)?;
            for register in &mut capabilities.registers {
                canonicalize_set(&mut register.model_phases, "register model phases")?;
                canonicalize_set(&mut register.side_effects, "register side effects")?;
            }
            canonicalize_by_id(&mut capabilities.address_spaces, WorldNodeAddressSpace::id)?;
            canonicalize_by_id(&mut capabilities.interrupts, WorldNodeInterrupt::id)?;
            canonicalize_by_id(&mut capabilities.clock_sources, WorldNodeClockSource::id)?;
            canonicalize_by_id(&mut capabilities.accelerators, WorldNodeAccelerator::id)?;
            for interrupt in &mut capabilities.interrupts {
                canonicalize_set(&mut interrupt.target_vcpus, "interrupt target vCPUs")?;
            }
        }

        let mut vm_nodes = BTreeSet::new();
        for node in world.vm_nodes() {
            crate::owned_decode::charge_btree_set_entry::<&str>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            vm_nodes.insert(node.id.name.as_str());
        }
        let mut io_nodes = BTreeMap::new();
        for node in world.io_nodes() {
            crate::owned_decode::charge_btree_entry::<&str, WorldDeviceKind>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            io_nodes.insert(node.id.name.as_str(), node.kind.family());
        }
        let interfaces = ids(&self.network_interfaces)?;
        let segments = ids(&self.network_segments)?;
        let media = ids(&self.network_media)?;
        let forwarders = ids(&self.network_forwarders)?;
        let queues = ids(&self.network_queues)?;
        let fault_domains = ids(&self.fault_domains)?;

        for interface in &self.network_interfaces {
            require_all(
                &interface.fault_domains,
                &fault_domains,
                "network interface fault domain",
            )?;
        }

        for interface in &self.network_interfaces {
            require(
                vm_nodes.contains(interface.endpoint.as_str())
                    || forwarders.contains(&interface.endpoint),
                "network interface endpoint",
            )?;
        }
        for segment in &self.network_segments {
            require_all(
                &segment.fault_domains,
                &fault_domains,
                "network segment fault domain",
            )?;
            require(
                segment.interface_a != segment.interface_b,
                "network segment self-loop",
            )?;
            require(
                interfaces.contains(&segment.interface_a),
                "network segment interface_a",
            )?;
            require(
                interfaces.contains(&segment.interface_b),
                "network segment interface_b",
            )?;
            require(
                segment.minimum_latency_nanos > 0,
                "network segment minimum latency",
            )?;
            require(segment.mtu_bytes > 0, "network segment MTU")?;
            if let Some(reference) = &segment.medium {
                require(media.contains(reference), "network segment medium")?;
            }
            require_all(
                &segment.forwarders,
                &forwarders,
                "network segment forwarder",
            )?;
        }
        for medium in &self.network_media {
            require_all(
                &medium.fault_domains,
                &fault_domains,
                "network medium fault domain",
            )?;
            require(!medium.resources.is_empty(), "network medium resources")?;
            hard_count(&medium.resources, "network medium resources", 16_384)?;
            require(
                self.network_policy_artifacts.iter().any(|artifact| {
                    artifact.id.as_str() == medium.access_policy.as_str()
                        && artifact.artifact.class() == NetworkPolicyArtifactClass::MediumAccess
                }),
                "network medium access policy",
            )?;
        }
        for forwarder in &self.network_forwarders {
            require_all(
                &forwarder.fault_domains,
                &fault_domains,
                "network forwarder fault domain",
            )?;
            require(!forwarder.ports.is_empty(), "network forwarder ports")?;
            require_all(&forwarder.ports, &interfaces, "network forwarder port")?;
            require(
                forwarder.table_capacity > 0,
                "network forwarder table capacity",
            )?;
        }
        for queue in &self.network_queues {
            require_all(
                &queue.fault_domains,
                &fault_domains,
                "network queue fault domain",
            )?;
            require(queue.capacity_packets > 0, "network queue capacity")?;
            require(
                interfaces.contains(&queue.owner)
                    || media.contains(&queue.owner)
                    || forwarders.contains(&queue.owner),
                "network queue owner",
            )?;
        }
        for path in &self.network_paths {
            require(!path.hops.is_empty(), "network path hops")?;
            require(path.mtu_bytes > 0, "network path MTU")?;
            require(
                matches!(path.direction, FaultDirection::AToB | FaultDirection::BToA),
                "network path direction",
            )?;
            hard_count(&path.hops, "network path hops", 1_024)?;
            let mut previous_exit: Option<&SignalId> = None;
            let mut first_entry: Option<&SignalId> = None;
            let mut forwarding_ports: Option<&[SignalId]> = None;
            for hop in &path.hops {
                match hop {
                    WorldNetworkPathHop::Segment { segment, direction } => {
                        let declaration = self
                            .network_segments
                            .iter()
                            .find(|candidate| &candidate.id == segment)
                            .ok_or_else(|| invalid("network path segment"))?;
                        let (entry, exit) = match direction {
                            FaultDirection::AToB => {
                                (&declaration.interface_a, &declaration.interface_b)
                            }
                            FaultDirection::BToA => {
                                (&declaration.interface_b, &declaration.interface_a)
                            }
                            _ => return Err(invalid("network path direction")),
                        };
                        first_entry.get_or_insert(entry);
                        if let Some(ports) = forwarding_ports.take() {
                            require(ports.contains(entry), "network path forwarder egress")?;
                        } else if let Some(previous) = previous_exit {
                            require(previous == entry, "network path continuity")?;
                        }
                        previous_exit = Some(exit);
                    }
                    WorldNetworkPathHop::Forwarder { forwarder } => {
                        require(
                            forwarding_ports.is_none(),
                            "network path adjacent forwarders",
                        )?;
                        let declaration = self
                            .network_forwarders
                            .iter()
                            .find(|candidate| &candidate.id == forwarder)
                            .ok_or_else(|| invalid("network path forwarder"))?;
                        if let Some(previous) = previous_exit {
                            require(
                                declaration.ports.contains(previous),
                                "network path forwarder ingress",
                            )?;
                        }
                        forwarding_ports = Some(&declaration.ports);
                    }
                    WorldNetworkPathHop::Queue { queue } => {
                        require(queues.contains(queue), "network path queue")?;
                    }
                }
            }
            require(
                forwarding_ports.is_none(),
                "network path trailing forwarder",
            )?;
            let entry = first_entry.ok_or_else(|| invalid("network path entry"))?;
            let exit = previous_exit.ok_or_else(|| invalid("network path exit"))?;
            let entry_owner = self
                .network_interfaces
                .iter()
                .find(|interface| &interface.id == entry)
                .map(|interface| &interface.endpoint)
                .ok_or_else(|| invalid("network path entry interface"))?;
            let exit_owner = self
                .network_interfaces
                .iter()
                .find(|interface| &interface.id == exit)
                .map(|interface| &interface.endpoint)
                .ok_or_else(|| invalid("network path exit interface"))?;
            require(
                vm_nodes.contains(entry_owner.as_str()) && vm_nodes.contains(exit_owner.as_str()),
                "network path endpoint owner",
            )?;
            require(entry_owner != exit_owner, "network path endpoint self-loop")?;
            let expected_direction = if entry_owner < exit_owner {
                FaultDirection::AToB
            } else {
                FaultDirection::BToA
            };
            require(
                path.direction == expected_direction,
                "network path declared direction",
            )?;
        }
        if !self.network_interfaces.is_empty() || !self.network_segments.is_empty() {
            let mut interface_endpoints = BTreeMap::new();
            for interface in &self.network_interfaces {
                crate::owned_decode::charge_btree_entry::<&SignalId, &SignalId>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                interface_endpoints.insert(&interface.id, &interface.endpoint);
            }
            let mut declared_pairs = BTreeSet::new();
            for segment in &self.network_segments {
                let endpoint_a = interface_endpoints
                    .get(&segment.interface_a)
                    .ok_or_else(|| invalid("network segment interface_a"))?;
                let endpoint_b = interface_endpoints
                    .get(&segment.interface_b)
                    .ok_or_else(|| invalid("network segment interface_b"))?;
                if vm_nodes.contains(endpoint_a.as_str()) && vm_nodes.contains(endpoint_b.as_str())
                {
                    crate::owned_decode::charge_btree_set_entry::<(&str, &str)>()
                        .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                    declared_pairs.insert(canonical_name_pair(
                        endpoint_a.as_str(),
                        endpoint_b.as_str(),
                    ));
                }
            }
            for path in &self.network_paths {
                let (entry, exit) = network_path_endpoint_interfaces(&self, path)?;
                let endpoint_a = interface_endpoints
                    .get(entry)
                    .ok_or_else(|| invalid("network path entry interface"))?;
                let endpoint_b = interface_endpoints
                    .get(exit)
                    .ok_or_else(|| invalid("network path exit interface"))?;
                crate::owned_decode::charge_btree_set_entry::<(&str, &str)>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                declared_pairs.insert(canonical_name_pair(
                    endpoint_a.as_str(),
                    endpoint_b.as_str(),
                ));
            }
            require(
                world.links().iter().all(|link| {
                    let (left, right) = link.endpoints();
                    declared_pairs.contains(&canonical_name_pair(&left.name, &right.name))
                }),
                "network path and world link correspondence",
            )?;
        }
        for attachment in &self.network_attachments {
            require(
                interfaces.contains(&attachment.interface),
                "network attachment interface",
            )?;
            require(
                !attachment.candidates.is_empty(),
                "network attachment candidates",
            )?;
            require_all(
                &attachment.candidates,
                &segments,
                "network attachment candidate",
            )?;
            require(
                attachment.semantic_version == 1,
                "network attachment semantic version",
            )?;
            require(
                FaultObjectId::parse(attachment.technology.as_str().to_owned()).is_ok(),
                "network attachment technology",
            )?;
        }
        for plan in &self.network_contact_plans {
            require(
                vm_nodes.contains(plan.endpoint_a.as_str()),
                "contact endpoint_a",
            )?;
            require(
                vm_nodes.contains(plan.endpoint_b.as_str()),
                "contact endpoint_b",
            )?;
            require(
                plan.endpoint_a < plan.endpoint_b,
                "contact plan endpoint order",
            )?;
            require(!plan.contacts.is_empty(), "contact plan contacts")?;
            hard_count(&plan.contacts, "network contact entries", 16_777_216)?;
            let mut previous_end = 0;
            let mut contact_ids = BTreeSet::new();
            for contact in &plan.contacts {
                crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                require(contact_ids.insert(&contact.id), "duplicate contact ID")?;
                require(contact.start_ticks < contact.end_ticks, "contact interval")?;
                require(contact.start_ticks >= previous_end, "contact ordering")?;
                previous_end = contact.end_ticks;
            }
        }
        let mut mobile_nodes = BTreeSet::new();
        for endpoint in &self.mobile_endpoints {
            crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            require(
                vm_nodes.contains(endpoint.node.as_str()),
                "mobile endpoint node",
            )?;
            require(
                mobile_nodes.insert(&endpoint.node),
                "duplicate mobile endpoint node",
            )?;
        }
        let mut declared_storage_devices = BTreeSet::new();
        for storage in &self.storage_devices {
            crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            require(
                declared_storage_devices.insert(&storage.device),
                "duplicate storage device contract",
            )?;
            require_all(
                &storage.fault_domains,
                &fault_domains,
                "storage device fault domain",
            )?;
            let family = io_nodes
                .get(storage.device.as_str())
                .ok_or_else(|| invalid("storage device"))?;
            require(
                matches!(
                    (family, storage.kind),
                    (WorldDeviceKind::Block, WorldStorageKind::Block)
                        | (WorldDeviceKind::NineP, WorldStorageKind::NineP)
                ),
                "storage device kind",
            )?;
            let node = world
                .io_nodes()
                .find(|node| node.id.name == storage.device.as_str())
                .ok_or_else(|| invalid("storage device"))?;
            if let WorldIoNodeKind::Block { base_length, .. } = &node.kind {
                require(
                    storage.persistence.length_bytes == *base_length,
                    "storage device length",
                )?;
            }
            storage.validate()?;
            if let WorldStorageMedia::Remote { protocol } = &storage.media {
                require(
                    self.storage_policy_artifacts.iter().any(|artifact| {
                        artifact.id.as_str() == protocol.as_str()
                            && artifact.artifact.class()
                                == StoragePolicyArtifactClass::RemoteProtocol
                    }),
                    "storage remote media protocol",
                )?;
            }
        }
        let storage_devices = declared_storage_devices;
        let mut storage_device_contracts = BTreeMap::new();
        for item in &self.storage_devices {
            crate::owned_decode::charge_btree_entry::<&str, &WorldStorageFaultDevice>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            storage_device_contracts.insert(item.device.as_str(), item);
        }
        let path_policy_exists = |policy: &SignalId| {
            self.storage_policy_artifacts.iter().any(|artifact| {
                artifact.id.as_str() == policy.as_str()
                    && artifact.artifact.class() == StoragePolicyArtifactClass::Path
            })
        };
        for controller in &self.storage_controllers {
            require(
                controller.semantic_version == 1,
                "storage controller semantic version",
            )?;
            require_all(
                &controller.fault_domains,
                &fault_domains,
                "storage controller fault domain",
            )?;
            require(
                !controller.namespaces.is_empty(),
                "storage controller namespaces",
            )?;
            for namespace in &controller.namespaces {
                require(
                    storage_devices.contains(&namespace.device),
                    "storage controller namespace device",
                )?;
                let device = storage_device_contracts
                    .get(namespace.device.as_str())
                    .ok_or_else(|| invalid("storage controller namespace device"))?;
                require(
                    device.kind == WorldStorageKind::Block
                        && namespace.capacity_bytes > 0
                        && namespace.capacity_bytes <= device.persistence.length_bytes
                        && namespace
                            .capacity_bytes
                            .is_multiple_of(u64::from(device.persistence.logical_block_bytes)),
                    "storage namespace capacity and geometry",
                )?;
            }
            require(!controller.paths.is_empty(), "storage controller paths")?;
            for path in &controller.paths {
                require(path.queue_depth > 0, "storage controller path queue depth")?;
                require(
                    path_policy_exists(&path.policy),
                    "storage controller path policy",
                )?;
            }
        }
        let mut array_logical_devices = BTreeSet::new();
        let mut array_member_devices = BTreeSet::new();
        for array in &self.storage_arrays {
            crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            require(
                array.semantic_version == 1,
                "storage array semantic version",
            )?;
            require_all(
                &array.fault_domains,
                &fault_domains,
                "storage array fault domain",
            )?;
            require(
                storage_device_contracts
                    .get(array.device.as_str())
                    .is_some_and(|device| device.kind == WorldStorageKind::Block),
                "storage array logical device",
            )?;
            require(
                array_logical_devices.insert(&array.device),
                "storage array logical device ownership",
            )?;
            require(!array.members.is_empty(), "storage array members")?;
            hard_count(&array.members, "storage array members", 4_096)?;
            let minimum_members = match array.layout {
                WorldStorageArrayLayout::Mirror | WorldStorageArrayLayout::Stripe => 1,
                WorldStorageArrayLayout::SingleParity => 3,
                WorldStorageArrayLayout::DualParity => 4,
            };
            require(
                array.members.len() >= minimum_members,
                "storage array layout member count",
            )?;
            require(
                array.chunk_bytes.is_power_of_two(),
                "storage array chunk geometry",
            )?;
            require(array.read_quorum > 0, "storage array read quorum")?;
            require(array.write_quorum > 0, "storage array write quorum")?;
            require(
                usize::from(array.read_quorum) <= array.members.len()
                    && usize::from(array.write_quorum) <= array.members.len(),
                "storage array quorum",
            )?;
            let mut member_devices = BTreeSet::new();
            for member in &array.members {
                crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                member_devices.insert(&member.device);
            }
            require(
                member_devices.len() == array.members.len(),
                "storage array backing devices",
            )?;
            require(
                member_devices
                    .iter()
                    .all(|device| array_member_devices.insert(*device)),
                "storage array backing device ownership",
            )?;
            for member in &array.members {
                require(
                    member.device != array.device
                        && storage_devices.contains(&member.device)
                        && storage_device_contracts
                            .get(member.device.as_str())
                            .is_some_and(|device| device.kind == WorldStorageKind::Block),
                    "storage array member device",
                )?;
            }
            let mut ordinals = BTreeSet::new();
            for member in &array.members {
                crate::owned_decode::charge_btree_set_entry::<u16>()
                    .map_err(WorldFaultTopologyError::OriginalAdmission)?;
                ordinals.insert(member.ordinal);
            }
            require(
                ordinals.len() == array.members.len()
                    && ordinals
                        .iter()
                        .enumerate()
                        .all(|(expected, ordinal)| usize::from(*ordinal) == expected),
                "storage array member ordinal",
            )?;
            let logical_length = storage_device_contracts
                .get(array.device.as_str())
                .map(|device| device.persistence.length_bytes)
                .ok_or_else(|| invalid("storage array logical capacity"))?;
            let minimum_member_length = array
                .members
                .iter()
                .filter_map(|member| storage_device_contracts.get(member.device.as_str()))
                .map(|device| device.persistence.length_bytes)
                .min()
                .ok_or_else(|| invalid("storage array member capacity"))?;
            let data_members = match array.layout {
                WorldStorageArrayLayout::Mirror => 1_u64,
                WorldStorageArrayLayout::Stripe => array.members.len() as u64,
                WorldStorageArrayLayout::SingleParity => array.members.len() as u64 - 1,
                WorldStorageArrayLayout::DualParity => array.members.len() as u64 - 2,
            };
            let stripe_capacity = minimum_member_length
                .checked_div(array.chunk_bytes)
                .and_then(|chunks| chunks.checked_mul(array.chunk_bytes))
                .and_then(|member_bytes| member_bytes.checked_mul(data_members))
                .ok_or_else(|| invalid("storage array capacity overflow"))?;
            require(
                logical_length <= stripe_capacity,
                "storage array logical capacity",
            )?;
            for path in &array.paths {
                require(path.queue_depth > 0, "storage array path queue depth")?;
                require(
                    path_policy_exists(&path.policy),
                    "storage array path policy",
                )?;
            }
            let state = self
                .storage_policy_artifact(&array.member_path_state)
                .ok_or_else(|| invalid("storage array member/path state"))?;
            let StoragePolicyArtifactKind::ArrayState { members, paths } = &state.artifact else {
                return Err(invalid("storage array member/path state"));
            };
            require(
                members
                    .iter()
                    .map(|member| member.member.as_str())
                    .eq(array.members.iter().map(|member| member.id.as_str()))
                    && paths
                        .iter()
                        .map(|path| path.path.as_str())
                        .eq(array.paths.iter().map(|path| path.id.as_str())),
                "storage array complete member/path state",
            )?;
            require(
                self.storage_policy_artifact(&array.selection_policy)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::ArraySelection(_)
                        )
                    }),
                "storage array selection policy",
            )?;
            require(
                self.storage_policy_artifact(&array.rebuild_service)
                    .is_some_and(|artifact| {
                        matches!(artifact.artifact, StoragePolicyArtifactKind::Rebuild(_))
                    }),
                "storage array rebuild service",
            )?;
            require(
                self.storage_policy_artifact(&array.consistency_policy)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::ArrayConsistency(_)
                        )
                    }),
                "storage array consistency policy",
            )?;
            require(
                self.storage_policy_artifact(&array.failure_result)
                    .is_some_and(|artifact| {
                        matches!(
                            artifact.artifact,
                            StoragePolicyArtifactKind::TypedResult(
                                StoragePolicyTypedResult::Block { result }
                            ) if result != StoragePolicyResult::Success
                        )
                    }),
                "storage array failure result",
            )?;
        }
        require(
            array_logical_devices.is_disjoint(&array_member_devices),
            "storage array logical and backing device roles",
        )?;
        let mut declared_node_capabilities = BTreeSet::new();
        for capabilities in &self.node_capabilities {
            crate::owned_decode::charge_btree_set_entry::<&SignalId>()
                .map_err(WorldFaultTopologyError::OriginalAdmission)?;
            require(
                declared_node_capabilities.insert(&capabilities.node),
                "duplicate node capability contract",
            )?;
            let node = world
                .vm_nodes()
                .iter()
                .find(|node| node.id.name == capabilities.node.as_str())
                .ok_or_else(|| invalid("node capability node"))?;
            require(
                capabilities.architecture.matches_vm(node.arch),
                "node capability architecture",
            )?;
            capabilities.validate()?;
            for interrupt in &capabilities.interrupts {
                require(
                    interrupt
                        .target_vcpus
                        .iter()
                        .all(|vcpu| *vcpu < u32::from(node.smp_vcpus)),
                    "node interrupt target vCPU",
                )?;
            }
        }

        let targets = self.all_target_refs()?;
        for domain in &self.fault_domains {
            require(!domain.targets.is_empty(), "fault domain targets")?;
            bounded(&domain.targets, "fault domain targets")?;
            for target in &domain.targets {
                require(targets.contains(target), "fault domain target")?;
                require(
                    self.target_fault_domains(target).contains(&domain.id),
                    "fault domain inverse membership",
                )?;
            }
        }
        for target in targets {
            for domain in self.target_fault_domains(&target) {
                let declaration = self
                    .fault_domain(domain)
                    .ok_or_else(|| invalid("fault domain membership"))?;
                require(
                    declaration
                        .targets
                        .iter()
                        .any(|declared| same_target_object(declared, &target)),
                    "fault domain inverse target",
                )?;
            }
        }
        let _ = queues;
        Ok(self)
    }
}
