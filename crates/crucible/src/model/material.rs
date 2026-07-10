// Serialized identity checks, parsing, and canonical material helpers.
fn validate_world_serialized_identity(world: &World) -> Result<(), EngineError> {
    validate_serialized_id("world", world.id(), serialized_world_identity(world))
}

fn validate_serialized_id(
    component: &'static str,
    expected: ContentHash,
    actual: ContentHash,
) -> Result<(), EngineError> {
    if expected == actual {
        Ok(())
    } else {
        Err(EngineError::ScenarioSerializedIdMismatch {
            component,
            expected,
            actual,
        })
    }
}

fn validate_no_host_path_image_refs_in_toml(value: &str) -> Result<(), EngineError> {
    let value = toml::from_str::<toml::Value>(value).map_err(|source| {
        scenario_serialization_error(format!("parse TOML before image-ref validation: {source}"))
    })?;
    validate_toml_image_refs_value(&value)
}

fn validate_plan_entries_in_toml(value: &str) -> Result<(), EngineError> {
    let value = toml::from_str::<toml::Value>(value).map_err(|source| {
        scenario_serialization_error(format!("parse TOML before plan validation: {source}"))
    })?;
    let Some(plan) = toml_plan_table(&value) else {
        return Ok(());
    };
    for key in ["entry", "fault_entry"] {
        let Some(entries) = plan.get(key) else {
            continue;
        };
        let Some(entries) = entries.as_array() else {
            return Err(scenario_serialization_error(format!(
                "serialized plan {key} list must be an array"
            )));
        };

        for (index, entry) in entries.iter().enumerate() {
            validate_plan_entry_toml_value(index, entry)?;
        }
    }

    Ok(())
}

fn toml_plan_table(value: &toml::Value) -> Option<&toml::map::Map<String, toml::Value>> {
    let table = value.as_table()?;
    match table.get("plan") {
        Some(plan) => plan.as_table(),
        None => Some(table),
    }
}

fn validate_plan_entry_toml_value(index: usize, entry: &toml::Value) -> Result<(), EngineError> {
    let Some(entry) = entry.as_table() else {
        return Err(scenario_serialization_error(
            "serialized plan entry must be a table",
        ));
    };
    if let Some(at_ticks) = entry
        .get("at_ticks")
        .and_then(toml::Value::as_integer)
        .filter(|at_ticks| *at_ticks < 0)
    {
        return Err(EngineError::PlanNegativeTime {
            entry: index,
            at_ticks,
        });
    }
    if entry.get("kind").and_then(toml::Value::as_str) != Some("activate") {
        return Ok(());
    }
    let Some(fault) = entry.get("fault") else {
        return Ok(());
    };
    validate_membership_fault_toml_value(index, fault)
}

fn validate_membership_fault_toml_value(
    index: usize,
    fault: &toml::Value,
) -> Result<(), EngineError> {
    let Some(fault) = fault.as_table() else {
        return Err(scenario_serialization_error(
            "serialized membership fault must be a table",
        ));
    };
    let Some(kind) = fault.get("kind").and_then(toml::Value::as_str) else {
        return Ok(());
    };
    let allowed = match kind {
        "crash" => &["kind", "node", "restart"][..],
        "partition" => &["kind", "endpoint_a", "endpoint_b", "direction"][..],
        "isolate" | "not_yet_joined" => &["kind", "node"][..],
        _ => return Ok(()),
    };
    for field in fault.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(EngineError::PlanFaultUnsupportedParam {
                entry: index,
                field: field.clone(),
            });
        }
    }
    if kind == "partition" {
        validate_partition_direction_toml_value(index, fault)?;
    }
    Ok(())
}

fn validate_partition_direction_toml_value(
    index: usize,
    fault: &toml::map::Map<String, toml::Value>,
) -> Result<(), EngineError> {
    let Some(direction) = fault.get("direction").and_then(toml::Value::as_str) else {
        return Ok(());
    };
    if matches!(
        direction,
        "bidirectional" | "endpoint_a_to_endpoint_b" | "endpoint_b_to_endpoint_a"
    ) {
        Ok(())
    } else {
        Err(EngineError::PlanFaultUnknownDirection {
            entry: index,
            direction: direction.to_owned(),
        })
    }
}

fn validate_toml_image_refs_value(value: &toml::Value) -> Result<(), EngineError> {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if let Some(field) = image_ref_field(key) {
                    let Some(reference) = value.as_str() else {
                        return Err(scenario_serialization_error(format!(
                            "{field} image reference must be a string"
                        )));
                    };
                    let _ = ContentAddressedBlobRef::parse(field, reference)?;
                }
                validate_toml_image_refs_value(value)?;
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                validate_toml_image_refs_value(value)?;
            }
        }
        toml::Value::String(_)
        | toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
    Ok(())
}

fn image_ref_field(key: &str) -> Option<&'static str> {
    ["kernel", "root_image", "initrd"]
        .into_iter()
        .find(|field| key == *field)
}

fn parse_content_addressed_blob_ref(
    field: &'static str,
    value: &str,
) -> Result<ContentAddressedBlobRef, EngineError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(EngineError::ScenarioImageReferenceNotContentAddressed {
            field,
            value: value.to_owned(),
        });
    };
    let hash = parse_content_hash_hex(hex).map_err(|_| {
        EngineError::ScenarioImageReferenceNotContentAddressed {
            field,
            value: value.to_owned(),
        }
    })?;
    Ok(ContentAddressedBlobRef::from_hash(hash))
}

fn parse_optional_blob_ref(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<ContentAddressedBlobRef>, EngineError> {
    value
        .as_deref()
        .map(|reference| ContentAddressedBlobRef::parse(field, reference))
        .transpose()
}

fn parse_content_hash_ref(value: &str) -> Result<ContentHash, EngineError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(scenario_serialization_error(
            "content hash reference must start with blake3:",
        ));
    };
    parse_content_hash_hex(hex)
}

fn parse_content_hash_hex(hex: &str) -> Result<ContentHash, EngineError> {
    let bytes = parse_fixed_hex_32(hex, "content hash")?;
    Ok(ContentHash { bytes })
}

fn parse_seed_ref(value: &str) -> Result<Seed, EngineError> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(scenario_serialization_error(
            "seed must start with 0x and contain 64 lowercase hex characters",
        ));
    };
    Ok(Seed::from_bytes(parse_fixed_hex_32(hex, "seed")?))
}

fn parse_fixed_hex_32(hex: &str, label: &'static str) -> Result<[u8; 32], EngineError> {
    if hex.len() != 64 {
        return Err(scenario_serialization_error(format!(
            "{label} must contain 64 lowercase hex characters"
        )));
    }
    let mut bytes = [0; 32];
    let raw = hex.as_bytes();
    for index in 0..32 {
        let high = hex_value(raw[index * 2]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        let low = hex_value(raw[index * 2 + 1]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn parse_hex_bytes(label: &'static str, hex: &str) -> Result<Vec<u8>, EngineError> {
    if !hex.len().is_multiple_of(2) {
        return Err(scenario_serialization_error(format!(
            "{label} must contain an even number of lowercase hex characters"
        )));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    for index in 0..bytes.capacity() {
        let high = hex_value(raw[index * 2]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        let low = hex_value(raw[index * 2 + 1]).ok_or_else(|| {
            scenario_serialization_error(format!("{label} contains non-lowercase-hex character"))
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn format_content_hash_ref(hash: ContentHash) -> String {
    format!("blake3:{}", content_hash_hex(hash))
}

fn parse_guest_workload_parameter(cmdline: &str) -> Option<GuestWorkloadBinary> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadBinary::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_seed_parameter(cmdline: &str) -> Option<GuestWorkloadSeed> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_SEED_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadSeed::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_scalar_parameters(
    cmdline: &str,
) -> BTreeMap<GuestWorkloadParameterKey, String> {
    let mut parameters = BTreeMap::new();
    for token in cmdline.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let Some(parameter) = GuestWorkloadParameterKey::from_cmdline_key(key) else {
            continue;
        };
        if valid_guest_workload_parameter_value(value) {
            parameters
                .entry(parameter)
                .or_insert_with(|| value.to_owned());
        }
    }
    parameters
}

fn parse_guest_workload_config_tree_parameter(cmdline: &str) -> Option<GuestWorkloadConfigTreeRef> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadConfigTreeRef::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_pattern_parameter(cmdline: &str) -> Option<GuestWorkloadPattern> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadPattern::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_spike_mode_parameter(cmdline: &str) -> Option<GuestWorkloadSpikeMode> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadSpikeMode::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_time_source_parameter(cmdline: &str) -> Option<GuestWorkloadTimeSource> {
    cmdline.split_whitespace().find_map(|token| {
        token
            .strip_prefix(WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER_PREFIX)
            .and_then(GuestWorkloadTimeSource::from_scenario_parameter_value)
    })
}

fn parse_guest_workload_config_tree_value(value: &str) -> Option<GuestWorkloadConfigTreeRef> {
    let mut parts = value.split(',');
    let delivery = parts
        .next()
        .and_then(GuestWorkloadConfigTreeDelivery::from_scenario_parameter_value)?;
    let export = parts
        .next()
        .and_then(|part| part.strip_prefix("export="))
        .and_then(|part| ContentAddressedBlobRef::parse("wcfg.export", part).ok())?;
    let mount = parts.next().and_then(|part| part.strip_prefix("mount="))?;
    if parts.next().is_some() || !valid_guest_mount_path(mount) {
        return None;
    }
    Some(GuestWorkloadConfigTreeRef {
        delivery,
        export,
        mount: mount.to_owned(),
    })
}

fn valid_guest_workload_parameter_value(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_whitespace)
}

fn valid_guest_mount_path(mount: &str) -> bool {
    if !mount.starts_with('/')
        || mount.is_empty()
        || mount.contains(',')
        || mount.chars().any(char::is_whitespace)
    {
        return false;
    }
    if mount != "/" && mount.ends_with('/') {
        return false;
    }
    mount
        .split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn cmdline_with_guest_workload(cmdline: &str, workload: GuestWorkloadBinary) -> String {
    let selection = workload.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_seed(cmdline: &str, seed: GuestWorkloadSeed) -> String {
    let selection = seed.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_SEED_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_scalar_parameter(
    cmdline: &str,
    parameter: &GuestWorkloadScalarParameter,
) -> String {
    let selection = parameter.scenario_parameter();
    let key = parameter.key().cmdline_key();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| match token.split_once('=') {
            Some((existing_key, _value)) => existing_key != key,
            None => true,
        })
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_config_tree(
    cmdline: &str,
    config: &GuestWorkloadConfigTreeRef,
) -> String {
    let selection = config.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_pattern(cmdline: &str, pattern: GuestWorkloadPattern) -> String {
    let selection = pattern.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_spike_mode(cmdline: &str, mode: GuestWorkloadSpikeMode) -> String {
    let selection = mode.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn cmdline_with_guest_workload_time_source(
    cmdline: &str,
    source: GuestWorkloadTimeSource,
) -> String {
    let selection = source.scenario_parameter();
    let mut rendered = String::new();
    for token in cmdline
        .split_whitespace()
        .filter(|token| !token.starts_with(WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER_PREFIX))
    {
        push_cmdline_token(&mut rendered, token);
    }
    push_cmdline_token(&mut rendered, &selection);
    rendered
}

fn workload_pattern_cmdline(
    base_cmdline: &str,
    pattern: GuestWorkloadPattern,
    spike_mode: Option<GuestWorkloadSpikeMode>,
    time_source: Option<GuestWorkloadTimeSource>,
) -> String {
    let cmdline = GuestWorkloadBinary::ClientLoop.selected_cmdline(base_cmdline);
    let cmdline = pattern.selected_cmdline(&cmdline);
    let cmdline = match spike_mode {
        Some(mode) => mode.selected_cmdline(&cmdline),
        None => cmdline,
    };
    match time_source {
        Some(source) => source.selected_cmdline(&cmdline),
        None => cmdline,
    }
}

fn workload_pattern_node(name: &str, cmdline: String) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from(name),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline,
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn workload_pattern_link_id(link: &LinkDef) -> LinkId {
    let (left, right) = link.endpoints();
    LinkId::from_name(format!("{}--{}", left.name, right.name))
}

fn push_cmdline_token(cmdline: &mut String, token: &str) {
    if !cmdline.is_empty() {
        cmdline.push(' ');
    }
    cmdline.push_str(token);
}

fn format_seed_ref(seed: Seed) -> String {
    format!("0x{}", seed.to_hex())
}

fn scenario_serialization_error(reason: impl Into<String>) -> EngineError {
    EngineError::ScenarioSerialization {
        reason: reason.into(),
    }
}

fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode> {
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    nodes
}

fn canonical_world_node_defs(nodes: &[WorldNodeDef]) -> Vec<WorldNodeDef> {
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| left.id().cmp(right.id()));
    nodes
}

fn world_vm_node_projection(nodes: &[WorldNodeDef]) -> Vec<WorldNode> {
    nodes
        .iter()
        .filter_map(|node| match node {
            WorldNodeDef::Vm(node) => Some(node.clone()),
            WorldNodeDef::Io(_) => None,
        })
        .collect()
}

fn canonical_world_links(links: &[LinkDef]) -> Vec<LinkDef> {
    let mut links = links.to_vec();
    links.sort_by(|left, right| {
        let (left_a, left_b) = left.endpoints();
        let (right_a, right_b) = right.endpoints();
        left_a
            .cmp(right_a)
            .then_with(|| left_b.cmp(right_b))
            .then_with(|| left.latency().cmp(&right.latency()))
            .then_with(|| left.jitter().cmp(&right.jitter()))
            .then_with(|| left.loss().cmp(&right.loss()))
            .then_with(|| left.bandwidth_bps().cmp(&right.bandwidth_bps()))
    });
    links
}

fn world_participants(world: &World) -> Vec<NodeId> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| node.id)
        .collect()
}

fn world_scheduling_nodes(world: &World) -> Vec<SchedulerNodeId> {
    let mut nodes = canonical_world_node_defs(&world.topology_nodes)
        .into_iter()
        .map(|node| match node {
            WorldNodeDef::Vm(node) => SchedulerNodeId {
                node: node.id,
                kind: SchedulingNodeKind::Vm,
            },
            WorldNodeDef::Io(node) => node.scheduler_node_id(),
        })
        .collect::<Vec<_>>();
    nodes.extend(
        canonical_world_links(&world.links)
            .iter()
            .map(LinkDef::scheduler_node_id),
    );
    nodes.sort();
    nodes
}

fn world_rng_streams(world: &World) -> Vec<RngStreamId> {
    let mut streams = Vec::with_capacity(
        world
            .nodes
            .len()
            .saturating_add(world.links.len())
            .saturating_add(world.io_nodes().count()),
    );
    for node in canonical_world_nodes(&world.nodes) {
        streams.push(RngStreamId::for_node(node.id.name));
    }
    for link in canonical_world_links(&world.links) {
        streams.push(RngStreamId::for_link(world_link_stream_name(&link)));
    }
    for node in canonical_world_node_defs(&world.topology_nodes) {
        if let WorldNodeDef::Io(node) = node {
            streams.push(RngStreamId::for_device(node.device_id().name));
        }
    }
    streams.sort();
    streams.dedup();
    streams
}

fn world_lookahead_edges(world: &World) -> Vec<WorldLookaheadEdge> {
    let mut edges = Vec::with_capacity(world.links.len().saturating_mul(2));
    for link in canonical_world_links(&world.links) {
        let (left, right) = link.endpoints();
        edges.push(WorldLookaheadEdge {
            from: left.clone(),
            to: right.clone(),
            minimum_latency: link_minimum_latency(&link),
        });
        edges.push(WorldLookaheadEdge {
            from: right.clone(),
            to: left.clone(),
            minimum_latency: link_minimum_latency(&link),
        });
    }
    edges.sort();
    edges
}

fn world_bake_nodes(world: &World) -> Vec<NodeId> {
    world_participants(world)
}

fn world_link_stream_name(link: &LinkDef) -> String {
    let (left, right) = link.endpoints();
    format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        left.name.len(),
        left.name,
        right.name.len(),
        right.name
    )
}

fn link_minimum_latency(link: &LinkDef) -> SimDuration {
    SimDuration {
        nanos: link.latency().nanos.saturating_sub(link.jitter().nanos),
    }
}

fn derive_family_seed(meta_seed: Seed, index: u64) -> Seed {
    let hash = ContentHash::from_canonical_material(
        "crucible.model.scenario-family.seed.v1",
        &format!("{}\nseed_index={index}", seed_material(meta_seed)),
    );
    Seed::from_bytes(hash.bytes)
}

fn family_node_id(index: u32) -> NodeId {
    NodeId {
        name: format!("node-{index}"),
    }
}

fn family_links(params: FamilyParams) -> Result<Vec<LinkDef>, EngineError> {
    let mut pairs = BTreeSet::new();
    match params.topology_shape {
        TopologyShape::Ring => {
            if params.topology_size > 1 {
                for left in 0..params.topology_size {
                    add_family_link_pair(&mut pairs, left, (left + 1) % params.topology_size);
                }
            }
        }
        TopologyShape::Star => {
            for node in 1..params.topology_size {
                add_family_link_pair(&mut pairs, 0, node);
            }
        }
        TopologyShape::Mesh => {
            for left in 0..params.topology_size {
                for right in (left + 1)..params.topology_size {
                    add_family_link_pair(&mut pairs, left, right);
                }
            }
        }
        TopologyShape::Random => {
            for left in 0..params.topology_size.saturating_sub(1) {
                add_family_link_pair(&mut pairs, left, left + 1);
            }

            let mut stream = params.seed.decision_rng().fork_in_domain(
                "crucible.model.scenario-family.random-topology.v1",
                &format!(
                    "topology_shape=random\ntopology_size={}",
                    params.topology_size
                ),
            );
            for left in 0..params.topology_size {
                for right in (left + 1)..params.topology_size {
                    if pairs.contains(&(left, right)) {
                        continue;
                    }
                    if stream.next_u64() & 1 == 1 {
                        add_family_link_pair(&mut pairs, left, right);
                    }
                }
            }
        }
    }

    pairs
        .into_iter()
        .map(|(left, right)| LinkDef::new(family_node_id(left), family_node_id(right)))
        .collect()
}

fn add_family_link_pair(pairs: &mut BTreeSet<(u32, u32)>, left: u32, right: u32) {
    if left == right {
        return;
    }
    let pair = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    pairs.insert(pair);
}

fn family_fault_candidates(world: &World) -> Vec<FamilyFaultCandidate> {
    let mut candidates =
        Vec::with_capacity(world.links().len().saturating_add(world.vm_nodes().len()));
    for link in world.links() {
        let (endpoint_a, endpoint_b) = link.endpoints();
        candidates.push(FamilyFaultCandidate::Partition {
            endpoint_a: endpoint_a.clone(),
            endpoint_b: endpoint_b.clone(),
        });
    }
    for node in world.vm_nodes() {
        candidates.push(FamilyFaultCandidate::Crash(node.id.clone()));
    }
    candidates
}

fn baked_node_blobs(world: &World) -> BTreeMap<NodeId, NodeBlobRef> {
    let world_identity = canonical_world_identity(world);
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let blob = ContentHash::from_canonical_material(
                "crucible.model.node-baked-blob.v1",
                &format!(
                    "world_id={}\n{}",
                    content_hash_hex(world_identity),
                    world_node_material(&node)
                ),
            );
            (node.id, NodeBlobRef::baked(blob))
        })
        .collect()
}

fn baked_node_icounts(world: &World) -> BTreeMap<NodeId, Icount> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let icount = match node.ready_point {
                ReadyPoint::FixedIcount { icount } => icount,
                ReadyPoint::NetworkIdle { .. }
                | ReadyPoint::ConsoleMarker { .. }
                | ReadyPoint::AgentSignal => Icount::default(),
            };
            (node.id, icount)
        })
        .collect()
}

fn canonical_world_identity(world: &World) -> ContentHash {
    let nodes = canonical_world_node_defs(&world.topology_nodes);
    let links = canonical_world_links(&world.links);
    if nodes.is_empty() && links.is_empty() {
        return world.id;
    }

    ContentHash::from_canonical_material(
        world_identity_domain(&nodes),
        &world_material(&nodes, &links),
    )
}

fn serialized_world_identity(world: &World) -> ContentHash {
    let nodes = canonical_world_node_defs(&world.topology_nodes);
    ContentHash::from_canonical_material(
        world_identity_domain(&nodes),
        &world_material(&nodes, &canonical_world_links(&world.links)),
    )
}

fn scenario_world_plan_properties_seed_material(
    world: &World,
    plan: &Plan,
    properties: &Properties,
    seed: Seed,
) -> String {
    scenario_world_plan_properties_seed_app_random_cap_material(
        world,
        plan,
        properties,
        seed,
        DEFAULT_APP_RANDOM_DRAW_CAP,
    )
}

fn scenario_world_plan_properties_seed_app_random_cap_material(
    world: &World,
    plan: &Plan,
    properties: &Properties,
    seed: Seed,
    app_random_draw_cap: u64,
) -> String {
    format!(
        "world_ref={}\nplan_ref={}\nproperties_ref={}\n{}\n{}",
        content_hash_hex(canonical_world_identity(world)),
        content_hash_hex(plan.content_hash()),
        content_hash_hex(properties.content_hash()),
        seed_material(seed),
        app_random_draw_cap_material(app_random_draw_cap)
    )
}

fn world_material(nodes: &[WorldNodeDef], links: &[LinkDef]) -> String {
    if nodes.iter().all(|node| matches!(node, WorldNodeDef::Vm(_))) {
        let vm_nodes = world_vm_node_projection(nodes);
        format!(
            "min_link_latency_ns={}\n{}\n{}",
            MIN_LINK_LATENCY.nanos,
            world_nodes_material(&vm_nodes),
            world_links_material(links),
        )
    } else {
        format!(
            "min_link_latency_ns={}\n{}\n{}",
            MIN_LINK_LATENCY.nanos,
            world_node_defs_material(nodes),
            world_links_material(links),
        )
    }
}

fn world_identity_domain(nodes: &[WorldNodeDef]) -> &'static str {
    if nodes.iter().any(|node| matches!(node, WorldNodeDef::Io(_))) {
        "crucible.model.world.v2"
    } else {
        "crucible.model.world.v1"
    }
}

fn world_nodes_material(nodes: &[WorldNode]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(5) + 1);
    lines.push(format!("nodes={}", nodes.len()));
    for node in nodes {
        lines.push(world_node_material(node));
    }
    lines.join("\n")
}

fn world_links_material(links: &[LinkDef]) -> String {
    let mut lines = Vec::with_capacity(links.len().saturating_mul(8) + 1);
    lines.push(format!("links={}", links.len()));
    for link in links {
        lines.push(world_link_material(link));
    }
    lines.join("\n")
}

fn world_node_defs_material(nodes: &[WorldNodeDef]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(8) + 1);
    lines.push(format!("nodes={}", nodes.len()));
    for node in nodes {
        lines.push(match node {
            WorldNodeDef::Vm(node) => format!("node_kind=vm\n{}", world_node_material(node)),
            WorldNodeDef::Io(node) => world_io_node_material(node),
        });
    }
    lines.join("\n")
}

fn world_io_node_material(node: &WorldIoNode) -> String {
    let kind = match &node.kind {
        WorldIoNodeKind::Block {
            base_image,
            base_length,
            latency,
        } => format!(
            "node_kind=block\nartifact={}\nartifact_length={}\nlatency.read_base_ns={}\nlatency.write_base_ns={}\nlatency.flush_ns={}\nlatency.get_length_ns={}\nlatency.per_byte_ns={}",
            base_image.to_uri(),
            base_length,
            latency.read_base_ns,
            latency.write_base_ns,
            latency.flush_ns,
            latency.get_length_ns,
            latency.per_byte_ns,
        ),
        WorldIoNodeKind::NineP { tree, latency } => format!(
            "node_kind=9p\nartifact={}\nlatency.control_ns={}\nlatency.data_ns={}\nlatency.per_byte_ns={}",
            tree.to_uri(),
            latency.control_ns,
            latency.data_ns,
            latency.per_byte_ns,
        ),
    };
    format!(
        "node_id_len={}\nnode_id={}\nowner_id_len={}\nowner_id={}\ncore.shift_bits={}\n{}",
        node.id.name.len(),
        node.id.name,
        node.owner.name.len(),
        node.owner.name,
        node.core.shift_bits,
        kind,
    )
}

fn world_node_material(node: &WorldNode) -> String {
    format!(
        "node_id_len={}\nnode_id={}\narch={}\nmemory_mib={}\ncmdline_len={}\ncmdline={}\nsmp_vcpus={}\nicount_shift={}\nkernel_ref={}\nroot_image_ref={}\ninitrd_ref={}\n{}\nwhite_box={}",
        node.id.name.len(),
        node.id.name,
        node.arch.material(),
        node.memory_mib,
        node.cmdline.len(),
        node.cmdline,
        node.smp_vcpus,
        node.icount_shift,
        optional_blob_ref_material(node.kernel),
        optional_blob_ref_material(node.root_image),
        optional_blob_ref_material(node.initrd),
        ready_point_material(&node.ready_point),
        white_box_material(node.white_box)
    )
}

fn world_link_material(link: &LinkDef) -> String {
    let (left, right) = link.endpoints();
    format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}\nlink_latency_ns={}\nlink_jitter_ns={}\nlink_loss_millionths={}\nlink_bandwidth_bps={}",
        left.name.len(),
        left.name,
        right.name.len(),
        right.name,
        link.latency().nanos,
        link.jitter().nanos,
        link.loss().millionths(),
        link.bandwidth_bps()
            .map_or_else(|| String::from("none"), |bandwidth| bandwidth.to_string())
    )
}

fn plan_material(plan: &Plan) -> String {
    plan_kind_material(&plan.kind)
}

fn plan_kind_material(kind: &PlanKind) -> String {
    match kind {
        PlanKind::ScheduledEntries { entries } => scheduled_plan_material(entries),
        PlanKind::FaultPlan { plan } => fault_plan_material(plan.entries()),
        PlanKind::EventGraph { graph } => event_graph_plan_material(graph),
    }
}

fn scheduled_plan_material(entries: &[PlanEntry]) -> String {
    let mut lines = Vec::with_capacity(entries.len().saturating_mul(12) + 1);
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        lines.push(plan_entry_material(entry));
    }
    lines.join("\n")
}

fn fault_plan_material(entries: &[FaultPlanEntry]) -> String {
    event_graph_plan_material_from_events(&fault_plan_material_events(entries))
}

fn event_graph_plan_material(graph: &EventGraph) -> String {
    event_graph_plan_material_from_events(graph.events())
}

fn event_graph_plan_material_from_events(events: &[Event]) -> String {
    let mut lines = Vec::with_capacity(events.len().saturating_mul(16) + 2);
    lines.push(String::from("plan=event-graph"));
    lines.push(format!("events={}", events.len()));
    for event in events {
        lines.push(event_material(event));
    }
    lines.join("\n")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultPlanMaterialAction {
    at: VirtualTime,
    kind: &'static str,
    kind_order: u8,
    tag: FaultTag,
    material: String,
    action: Action,
}

fn fault_plan_material_events(entries: &[FaultPlanEntry]) -> Vec<Event> {
    fault_plan_material_actions(entries)
        .iter()
        .enumerate()
        .map(|(index, action)| {
            Event::once(
                fault_plan_material_event_id(index, action.kind, &action.tag),
                Some(Predicate::At { at: action.at }),
                action.action.clone(),
            )
        })
        .collect()
}

fn fault_plan_material_actions(entries: &[FaultPlanEntry]) -> Vec<FaultPlanMaterialAction> {
    let mut actions = Vec::new();
    for entry in entries {
        match entry {
            FaultPlanEntry::At {
                at,
                duration,
                tag,
                fault,
            } => {
                actions.push(fault_plan_material_inject_action(*at, tag, fault));
                if let Some(heal_at) = at.ticks.checked_add(duration.nanos()) {
                    actions.push(fault_plan_material_heal_action(
                        VirtualTime { ticks: heal_at },
                        tag,
                    ));
                }
            }
            FaultPlanEntry::PermanentAt { at, tag, fault } => {
                actions.push(fault_plan_material_inject_action(*at, tag, fault));
            }
            FaultPlanEntry::Heal { at, tag } => {
                actions.push(fault_plan_material_heal_action(*at, tag));
            }
        }
    }
    actions.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.kind_order.cmp(&right.kind_order))
            .then_with(|| left.material.cmp(&right.material))
    });
    actions
}

fn fault_plan_material_inject_action(
    at: VirtualTime,
    tag: &FaultTag,
    fault: &Fault,
) -> FaultPlanMaterialAction {
    FaultPlanMaterialAction {
        at,
        kind: "inject",
        kind_order: 0,
        tag: tag.clone(),
        material: format!(
            "inject\n{}\n{}",
            fault_tag_material(tag),
            fault.canonical_material()
        ),
        action: Action::InjectFault {
            tag: tag.clone(),
            fault: MembershipFault::taxonomy(fault.clone()),
        },
    }
}

fn fault_plan_material_heal_action(at: VirtualTime, tag: &FaultTag) -> FaultPlanMaterialAction {
    FaultPlanMaterialAction {
        at,
        kind: "heal",
        kind_order: 1,
        tag: tag.clone(),
        material: format!("heal\n{}", fault_tag_material(tag)),
        action: Action::HealFault { tag: tag.clone() },
    }
}

fn fault_plan_material_event_id(index: usize, kind: &str, tag: &FaultTag) -> EventId {
    EventId::from_name(format!("plan:{index:016}:{kind}:{}", tag.name))
}

fn event_material(event: &Event) -> String {
    let trigger = match &event.trigger {
        Some(trigger) => format!("trigger=some\n{}", predicate_material(trigger)),
        None => String::from("trigger=entrypoint"),
    };
    format!(
        "{}\npolicy={}\n{}\naction:\n{}",
        event_id_material(&event.id),
        fire_policy_label(event.policy),
        trigger,
        action_material(&event.action)
    )
}

fn fault_plan_entry_material(entry: &FaultPlanEntry) -> String {
    match entry {
        FaultPlanEntry::At {
            at,
            duration,
            tag,
            fault,
        } => {
            format!(
                "fault_plan_entry=at\nplan_at_ticks={}\nduration_nanos={}\n{}\n{}",
                at.ticks,
                duration.nanos(),
                fault_tag_material(tag),
                fault.canonical_material()
            )
        }
        FaultPlanEntry::PermanentAt { at, tag, fault } => {
            format!(
                "fault_plan_entry=permanent-at\nplan_at_ticks={}\n{}\n{}",
                at.ticks,
                fault_tag_material(tag),
                fault.canonical_material()
            )
        }
        FaultPlanEntry::Heal { at, tag } => {
            format!(
                "fault_plan_entry=heal\nplan_at_ticks={}\n{}",
                at.ticks,
                fault_tag_material(tag)
            )
        }
    }
}

fn plan_entry_material(entry: &PlanEntry) -> String {
    match entry {
        PlanEntry::Activate { at, tag, fault } => {
            format!(
                "plan_entry=activate\nplan_at_ticks={}\n{}\n{}",
                at.ticks,
                fault_tag_material(tag),
                membership_fault_material(fault)
            )
        }
        PlanEntry::Heal { at, tag } => {
            format!(
                "plan_entry=heal\nplan_at_ticks={}\n{}",
                at.ticks,
                fault_tag_material(tag)
            )
        }
    }
}

fn action_material(action: &Action) -> String {
    match action {
        Action::InjectFault { tag, fault } => {
            format!(
                "action=inject-fault\n{}\n{}",
                fault_tag_material(tag),
                membership_fault_material(fault)
            )
        }
        Action::HealFault { tag } => {
            format!("action=heal-fault\n{}", fault_tag_material(tag))
        }
        Action::ArmTimer { name, after } => {
            format!(
                "action=arm-timer\n{}\nafter_nanos={}",
                timer_id_material(name),
                after.nanos
            )
        }
        Action::CancelTimer { name } => {
            format!("action=cancel-timer\n{}", timer_id_material(name))
        }
        Action::StartNode { node } => {
            format!("action=start-node\n{}", node_ref_material("node", node))
        }
        Action::StopNode { node } => {
            format!("action=stop-node\n{}", node_ref_material("node", node))
        }
        Action::CreateSavepoint { label } => {
            format!(
                "action=create-savepoint\n{}",
                optional_label_material("label", label.as_deref())
            )
        }
        Action::Fork { label } => {
            format!(
                "action=fork\n{}",
                optional_label_material("label", label.as_deref())
            )
        }
        Action::Pass => String::from("action=pass"),
        Action::Fail { reason } => {
            format!("action=fail\nreason_len={}\nreason={reason}", reason.len())
        }
        Action::Log { level, message } => {
            format!(
                "action=log\nlevel={}\nmessage_len={}\nmessage={}",
                log_level_label(*level),
                message.len(),
                message
            )
        }
        Action::Group(actions) => {
            let mut lines = Vec::with_capacity(actions.len().saturating_mul(8) + 2);
            lines.push(String::from("action=group"));
            lines.push(format!("actions={}", actions.len()));
            for action in actions {
                lines.push(action_material(action));
            }
            lines.join("\n")
        }
    }
}

fn membership_fault_material(fault: &MembershipFault) -> String {
    match fault {
        MembershipFault::Crash { node, restart } => {
            format!(
                "fault=crash\n{}\nrestart={}",
                node_ref_material("node", node),
                restart_policy_label(*restart)
            )
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            format!(
                "fault=partition\n{}\n{}\ndirection={}",
                node_ref_material("endpoint_a", endpoint_a),
                node_ref_material("endpoint_b", endpoint_b),
                partition_direction_label(*direction)
            )
        }
        MembershipFault::Isolate { node } => {
            format!("fault=isolate\n{}", node_ref_material("node", node))
        }
        MembershipFault::NotYetJoined { node } => {
            format!("fault=not-yet-joined\n{}", node_ref_material("node", node))
        }
        MembershipFault::Taxonomy { fault } => {
            format!("fault=taxonomy\n{}", fault.canonical_material())
        }
    }
}

fn fault_tag_material(tag: &FaultTag) -> String {
    format!("tag_len={}\ntag={}", tag.name.len(), tag.name)
}

fn properties_material(assertions: &[AssertionDef]) -> String {
    let mut lines = Vec::with_capacity(assertions.len().saturating_mul(16) + 1);
    lines.push(format!("assertions={}", assertions.len()));
    for assertion in assertions {
        lines.push(assertion_material(assertion));
    }
    lines.join("\n")
}

fn assertion_material(assertion: &AssertionDef) -> String {
    format!(
        "{}\nmessage_len={}\nmessage={}\n{}",
        assertion_id_material(&assertion.id),
        assertion.message.len(),
        assertion.message,
        property_material(&assertion.property)
    )
}

fn property_material(property: &Property) -> String {
    match property {
        Property::Always { predicate } => {
            format!(
                "property={}\n{}",
                property.kind().canonical_label(),
                predicate_material(predicate)
            )
        }
        Property::Sometimes { predicate } => {
            format!(
                "property={}\n{}",
                property.kind().canonical_label(),
                predicate_material(predicate)
            )
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            format!(
                "property={}\ndeadline_ticks={}\ntrigger:\n{}\nproperty_predicate:\n{}",
                PropertyKind::Eventually.canonical_label(),
                deadline.ticks,
                predicate_material(trigger),
                predicate_material(property)
            )
        }
        Property::AfterQuiescence { predicate } => {
            format!(
                "property={}\n{}",
                property.kind().canonical_label(),
                predicate_material(predicate)
            )
        }
        Property::Reachable {
            predicate,
            expectation,
        } => {
            let expectation_material = match expectation {
                ReachabilityExpectation::Reachable { on_unreached } => {
                    format!(
                        "expectation=reachable\non_unreached={}",
                        reachable_disposition_label(*on_unreached)
                    )
                }
                ReachabilityExpectation::Unreachable => String::from("expectation=unreachable"),
            };
            format!(
                "property={}\n{}\n{}",
                property.kind().canonical_label(),
                expectation_material,
                predicate_material(predicate)
            )
        }
    }
}

fn predicate_material(predicate: &Predicate) -> String {
    match predicate {
        Predicate::At { at } => {
            format!("predicate=at\nat_ticks={}", at.ticks)
        }
        Predicate::After { duration, of } => {
            format!(
                "predicate=after\nduration_nanos={}\n{}",
                duration.nanos,
                event_id_material(of)
            )
        }
        Predicate::Timer { name } => {
            format!("predicate=timer\n{}", timer_id_material(name))
        }
        Predicate::NetworkMatch { link, predicate } => {
            let link_material = match link {
                Some(link) => format!("network_link=some\n{}", link_id_material(link)),
                None => String::from("network_link=any"),
            };
            format!(
                "predicate=network-match\n{}\n{}",
                link_material,
                frame_predicate_material(predicate)
            )
        }
        Predicate::ConsoleMatch { node, regex } => {
            format!(
                "predicate=console-match\n{}\n{}",
                node_ref_material("console_node", node),
                regex_program_material(regex)
            )
        }
        Predicate::CoveragePoint { node, point } => {
            format!(
                "predicate=coverage-point\n{}\n{}",
                node_ref_material("coverage_node", node),
                code_point_material(point)
            )
        }
        Predicate::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => {
            format!(
                "predicate=memory-predicate\n{}\n{}\nmemory_cmp={}\nmemory_value={value}",
                node_ref_material("memory_node", node),
                mem_place_material(place),
                memory_cmp_label(*cmp)
            )
        }
        Predicate::IoPattern { node, kind } => {
            format!(
                "predicate=io-pattern\n{}\nio_kind={}",
                node_ref_material("io_node", node),
                io_event_kind_label(*kind)
            )
        }
        Predicate::NodeState { node, state } => {
            format!(
                "predicate=node-state\n{}\nnode_lifecycle={}",
                node_ref_material("lifecycle_node", node),
                node_lifecycle_label(*state)
            )
        }
        Predicate::AssertionState { name, state } => {
            format!(
                "predicate=assertion-state\n{}\nassertion_phase={}",
                assertion_id_material(name),
                assertion_phase_label(*state)
            )
        }
        Predicate::Quiescent => String::from("predicate=quiescent"),
        Predicate::FaultActive { tag } => {
            format!("predicate=fault-active\n{}", fault_tag_material(tag))
        }
        Predicate::Named { name, nodes } => {
            format!(
                "predicate=named\npredicate_name_len={}\npredicate_name={}\n{}",
                name.len(),
                name,
                predicate_nodes_material(nodes)
            )
        }
        Predicate::GuestMarker { marker } => {
            format!("predicate=guest-marker\n{}", marker_id_material(marker))
        }
        Predicate::AllOf { predicates } => {
            format!("predicate=all-of\n{}", predicate_list_material(predicates))
        }
        Predicate::AnyOf { predicates } => {
            format!("predicate=any-of\n{}", predicate_list_material(predicates))
        }
        Predicate::Once { predicate } => {
            format!("predicate=once\n{}", predicate_material(predicate))
        }
        Predicate::Not { predicate } => {
            format!("predicate=not\n{}", predicate_material(predicate))
        }
    }
}

fn predicate_nodes_material(nodes: &[NodeId]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(2) + 1);
    lines.push(format!("predicate_nodes={}", nodes.len()));
    for node in nodes {
        lines.push(node_ref_material("predicate_node", node));
    }
    lines.join("\n")
}

fn predicate_list_material(predicates: &[Predicate]) -> String {
    let mut lines = Vec::with_capacity(predicates.len().saturating_mul(8) + 1);
    lines.push(format!("predicates={}", predicates.len()));
    for predicate in predicates {
        lines.push(predicate_material(predicate));
    }
    lines.join("\n")
}

fn event_id_material(id: &EventId) -> String {
    format!("event_id_len={}\nevent_id={}", id.name.len(), id.name)
}

fn timer_id_material(id: &TimerId) -> String {
    format!("timer_id_len={}\ntimer_id={}", id.name.len(), id.name)
}

fn link_id_material(id: &LinkId) -> String {
    format!("link_id_len={}\nlink_id={}", id.name.len(), id.name)
}

fn frame_predicate_material(predicate: &FramePredicate) -> String {
    match predicate {
        FramePredicate::Any => String::from("frame_predicate=any"),
        FramePredicate::Exact(bytes) => format!(
            "frame_predicate=exact\nframe_bytes_len={}\nframe_bytes={}",
            bytes.len(),
            bytes_hex(bytes)
        ),
        FramePredicate::Contains(bytes) => format!(
            "frame_predicate=contains\nframe_needle_len={}\nframe_needle={}",
            bytes.len(),
            bytes_hex(bytes)
        ),
        FramePredicate::Prefix(bytes) => format!(
            "frame_predicate=prefix\nframe_prefix_len={}\nframe_prefix={}",
            bytes.len(),
            bytes_hex(bytes)
        ),
    }
}

fn regex_program_material(regex: &RegexProgram) -> String {
    format!("regex_len={}\nregex={}", regex.pattern.len(), regex.pattern)
}

fn code_point_material(point: &CodePoint) -> String {
    match point {
        CodePoint::GuestAddress { address } => {
            format!("code_point=guest-address\ncode_address={address}")
        }
        CodePoint::Symbol { name } => {
            format!(
                "code_point=symbol\nsymbol_len={}\nsymbol={}",
                name.len(),
                name
            )
        }
    }
}

fn mem_place_material(place: &MemPlace) -> String {
    match place {
        MemPlace::PhysicalAddress { address, width } => format!(
            "mem_place=physical-address\nmem_address={address}\nmem_width={}",
            memory_width_label(*width)
        ),
        MemPlace::VirtualAddress { address, width } => format!(
            "mem_place=virtual-address\nmem_address={address}\nmem_width={}",
            memory_width_label(*width)
        ),
        MemPlace::Symbol { name, width } => format!(
            "mem_place=symbol\nsymbol_len={}\nsymbol={}\nmem_width={}",
            name.len(),
            name,
            memory_width_label(*width)
        ),
        MemPlace::Register { name, width } => format!(
            "mem_place=register\nregister_len={}\nregister={}\nmem_width={}",
            name.len(),
            name,
            memory_width_label(*width)
        ),
    }
}

fn memory_width_label(width: MemoryWidth) -> &'static str {
    match width {
        MemoryWidth::U8 => "u8",
        MemoryWidth::U16 => "u16",
        MemoryWidth::U32 => "u32",
        MemoryWidth::U64 => "u64",
    }
}

fn memory_cmp_label(cmp: MemoryCmp) -> &'static str {
    match cmp {
        MemoryCmp::Eq => "eq",
        MemoryCmp::Ne => "ne",
        MemoryCmp::Lt => "lt",
        MemoryCmp::Le => "le",
        MemoryCmp::Gt => "gt",
        MemoryCmp::Ge => "ge",
    }
}

fn io_event_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "ninep",
        IoEventKind::Network => "network",
    }
}

fn node_lifecycle_label(state: NodeLifecycle) -> &'static str {
    match state {
        NodeLifecycle::Started => "started",
        NodeLifecycle::Crashed => "crashed",
        NodeLifecycle::Hung => "hung",
        NodeLifecycle::Exited => "exited",
    }
}

fn assertion_phase_label(state: AssertionPhase) -> &'static str {
    match state {
        AssertionPhase::Satisfied => "satisfied",
        AssertionPhase::Violated => "violated",
    }
}

fn assertion_id_material(id: &AssertionId) -> String {
    format!(
        "assertion_id_len={}\nassertion_id={}",
        id.name.len(),
        id.name
    )
}

fn marker_id_material(id: &MarkerId) -> String {
    format!("marker_id_len={}\nmarker_id={}", id.name.len(), id.name)
}

fn seed_material(seed: Seed) -> String {
    format!("seed_bytes={}", seed.to_hex())
}

fn app_random_draw_cap_material(app_random_draw_cap: u64) -> String {
    format!("app_random_draw_cap={app_random_draw_cap}")
}

fn optional_label_material(prefix: &str, label: Option<&str>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}=some\n{prefix}_len={}\n{prefix}={label}",
            label.len()
        ),
        None => format!("{prefix}=none"),
    }
}

fn optional_blob_ref_material(reference: Option<ContentAddressedBlobRef>) -> String {
    reference.map_or_else(|| String::from("none"), ContentAddressedBlobRef::to_uri)
}

fn node_ref_material(prefix: &str, node: &NodeId) -> String {
    format!("{prefix}_len={}\n{prefix}={}", node.name.len(), node.name)
}

fn restart_policy_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

fn partition_direction_label(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

fn reachable_disposition_label(disposition: ReachableDisposition) -> &'static str {
    match disposition {
        ReachableDisposition::Warn => "warn",
        ReachableDisposition::Fail => "fail",
    }
}

fn fire_policy_label(policy: FirePolicy) -> &'static str {
    match policy {
        FirePolicy::Once => "once",
        FirePolicy::Repeatable => "repeatable",
    }
}

fn log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn ready_point_material(ready_point: &ReadyPoint) -> String {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            format!("ready_point=fixed-icount\nready_icount={}", icount.retired)
        }
        ReadyPoint::NetworkIdle { window } => {
            format!("ready_point=network-idle\nidle_window_ns={}", window.nanos)
        }
        ReadyPoint::ConsoleMarker { marker } => format!(
            "ready_point=console-marker\nmarker_len={}\nmarker={marker}",
            marker.len()
        ),
        ReadyPoint::AgentSignal => String::from("ready_point=agent-signal"),
    }
}

fn white_box_material(policy: WhiteBoxPolicy) -> &'static str {
    match policy {
        WhiteBoxPolicy::Disabled => "disabled",
        WhiteBoxPolicy::Enabled => "enabled",
    }
}
