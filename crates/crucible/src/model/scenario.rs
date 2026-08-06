//! Scenario and World construction plus immutable launch identity.

use super::*;

/// A handle to an immutable scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// The content address of the scenario definition.
    pub(super) id: ContentHash,
    /// The root entropy carried by this scenario definition.
    pub(super) seed: Seed,
    /// The maximum number of app-random decisions admitted for one run.
    pub(super) app_random_draw_cap: u64,
}

impl ScenarioDef {
    /// Returns the content address of this scenario definition.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the root entropy carried by this scenario definition.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns the configured app-random draw cap for this scenario.
    #[must_use]
    pub fn app_random_draw_cap(&self) -> u64 {
        self.app_random_draw_cap
    }

    /// Rebuilds a scenario definition handle from trusted content-addressed identity fields.
    ///
    /// This is a transport and artifact decoding helper for cases that already
    /// received a validated scenario definition elsewhere and only need to
    /// rehydrate the identity-bearing execution handle. Scenario authors should
    /// use [`ScenarioDefForm`] or the builder APIs instead so component hashes
    /// are derived from canonical scenario content.
    #[must_use]
    pub const fn from_trusted_identity(
        id: ContentHash,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        Self {
            id,
            seed,
            app_random_draw_cap,
        }
    }

    /// Builds a scenario definition from canonical material.
    ///
    /// This helper is the engine-side content-addressing entry point for
    /// backend-produced canonical material.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        Self::from_canonical_material_with_seed(domain, material, Seed::default())
    }

    /// Builds a scenario definition from canonical material and root seed.
    ///
    /// This helper is the compatibility entry point for backend-produced
    /// canonical material when the caller also has the scenario seed component.
    /// The seed is included in the returned content address so it cannot drift
    /// from scenario identity.
    #[must_use]
    pub fn from_canonical_material_with_seed(domain: &str, material: &str, seed: Seed) -> Self {
        Self::from_canonical_material_with_seed_and_app_random_draw_cap(
            domain,
            material,
            seed,
            DEFAULT_APP_RANDOM_DRAW_CAP,
        )
    }

    /// Builds a scenario definition from canonical material, root seed, and
    /// app-random draw cap.
    ///
    /// The cap is included in the returned content address so app-random policy
    /// cannot drift from scenario identity.
    #[must_use]
    pub fn from_canonical_material_with_seed_and_app_random_draw_cap(
        domain: &str,
        material: &str,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        let material = format!(
            "{material}\n{}\n{}",
            seed_material(seed),
            app_random_draw_cap_material(app_random_draw_cap)
        );
        Self {
            id: ContentHash::from_canonical_material(domain, &material),
            seed,
            app_random_draw_cap,
        }
    }

    /// Builds an opaque scenario definition from already-addressed components.
    ///
    /// This is the compatibility path for API adapters that receive an inline
    /// scenario handle over a transport before the full scenario form lands on
    /// the wire. Callers are responsible for supplying the content address that
    /// corresponds to the seed and app-random policy.
    #[must_use]
    pub fn from_content_hash_seed_and_app_random_draw_cap(
        id: ContentHash,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> Self {
        Self {
            id,
            seed,
            app_random_draw_cap,
        }
    }
}

impl World {
    /// Builds an opaque world handle from an already-computed content address.
    ///
    /// This is the compatibility path for backend tests and adapters that do
    /// not yet carry full spatial-graph node material.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self {
            id,
            topology_nodes: Vec::new(),
            nodes: Vec::new(),
            links: Vec::new(),
            fault_topology: WorldFaultTopology::default(),
            fault_topology_id: ContentHash::default(),
            fault_topology_wire: Vec::new(),
        }
    }

    /// Builds a world from an already-recorded identity and validated topology.
    ///
    /// This compatibility path lets adapters preserve an external world handle
    /// while still enforcing the same static topology invariants as
    /// [`World::from_nodes_and_links`]. Non-empty logical worlds derive
    /// [`ScenarioDef`] and bake identity from their heterogeneous node/link material rather
    /// than this recorded handle.
    ///
    /// # Errors
    ///
    /// Returns the same topology, ready-point, and launch-input validation
    /// errors as [`World::from_nodes_and_links`].
    pub fn from_recorded_parts(
        id: ContentHash,
        nodes: Vec<WorldNode>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        Self::from_recorded_node_defs_and_links(
            id,
            nodes.into_iter().map(WorldNodeDef::Vm).collect(),
            links,
        )
    }

    /// Builds a world from a recorded identity and heterogeneous logical topology.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`World::from_node_defs_and_links`].
    pub fn from_recorded_node_defs_and_links(
        id: ContentHash,
        topology_nodes: Vec<WorldNodeDef>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        let topology_nodes = canonical_world_node_defs(&topology_nodes);
        let nodes = world_vm_node_projection(&topology_nodes);
        let links = canonical_world_links(&links);
        validate_world_nodes(&nodes)?;
        validate_world_node_defs(&topology_nodes)?;
        validate_world_links_for_node_defs(&topology_nodes, &links)?;
        Ok(Self {
            id,
            topology_nodes,
            nodes,
            links,
            fault_topology: WorldFaultTopology::default(),
            fault_topology_id: ContentHash::default(),
            fault_topology_wire: Vec::new(),
        })
    }

    /// Returns the world content address carried by this handle.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the world's canonical heterogeneous logical node collection.
    ///
    /// This is the RFC-0010 `World.nodes` contract: VM and I/O sub-nodes share
    /// one namespace and one canonical collection. Callers that specifically
    /// launch QEMU guests use [`World::vm_nodes`] instead.
    #[must_use]
    pub fn nodes(&self) -> &[WorldNodeDef] {
        &self.topology_nodes
    }

    /// Returns the derived VM-only compatibility projection.
    ///
    /// This is not a third logical World collection and is never serialized or
    /// hashed independently. Constructors rebuild it from [`World::nodes`].
    #[must_use]
    pub fn vm_nodes(&self) -> &[WorldNode] {
        &self.nodes
    }

    /// Returns the canonical heterogeneous logical node topology.
    ///
    /// This compatibility spelling is equivalent to [`World::nodes`]. New code
    /// should use `nodes` to match the public RFC vocabulary.
    #[must_use]
    pub fn topology_nodes(&self) -> &[WorldNodeDef] {
        self.nodes()
    }

    /// Iterates the world's first-class deterministic I/O sub-nodes.
    pub fn io_nodes(&self) -> impl Iterator<Item = &WorldIoNode> {
        self.topology_nodes.iter().filter_map(|node| match node {
            WorldNodeDef::Vm(_) => None,
            WorldNodeDef::Io(node) => Some(node),
        })
    }

    /// Returns the declared I/O sub-node with `id`, if present.
    #[must_use]
    pub fn io_node(&self, id: &NodeId) -> Option<&WorldIoNode> {
        self.io_nodes().find(|node| &node.id == id)
    }

    /// Returns this world's immutable logical links.
    #[must_use]
    pub fn links(&self) -> &[LinkDef] {
        &self.links
    }

    /// Returns the immutable hardware and link registry used by fault selectors.
    #[must_use]
    pub const fn fault_topology(&self) -> &WorldFaultTopology {
        &self.fault_topology
    }

    /// Attaches and content-addresses the complete executable fault topology.
    ///
    /// # Errors
    ///
    /// Returns [`WorldFaultTopologyError`] when a declaration is malformed,
    /// references an absent world object, exceeds a hard bound, or cannot be
    /// encoded into canonical identity material.
    pub fn with_fault_topology(
        mut self,
        topology: WorldFaultTopology,
    ) -> Result<Self, WorldFaultTopologyError> {
        let topology = topology.admit(&self)?;
        let (topology_id, topology_wire) = if topology.is_empty() {
            (ContentHash::default(), Vec::new())
        } else {
            (topology.content_hash()?, topology.canonical_bytes()?)
        };
        self.fault_topology = topology;
        self.fault_topology_id = topology_id;
        self.fault_topology_wire = topology_wire;
        self.id = canonical_world_identity(&self);
        Ok(self)
    }

    /// Returns the workload config-tree exports declared by world nodes.
    ///
    /// The declarations are derived from validated `wcfg=...` scenario
    /// parameters in node command lines, so the returned config-tree refs are
    /// part of the world's content-addressed material. Rootfs-backed entries are
    /// additionally validated to match the node's read-only `root_image`.
    #[must_use]
    pub fn workload_config_trees(&self) -> Vec<WorldWorkloadConfigTree> {
        self.nodes
            .iter()
            .filter_map(|node| {
                node.guest_workload_config_tree()
                    .map(|config| WorldWorkloadConfigTree {
                        node: node.id.clone(),
                        config,
                    })
            })
            .collect()
    }

    /// Builds a canonical world from node ready-point configuration.
    ///
    /// Nodes are sorted by [`NodeId`] before hashing so authoring order does not
    /// affect the world identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`],
    /// [`EngineError::ReadyPointNetworkIdleWindowZero`] when a node selects an
    /// empty network-idle window,
    /// [`EngineError::ReadyPointNetworkIdleWithoutLinks`] when a node selects
    /// network-idle readiness without any incident links,
    /// [`EngineError::ReadyPointConsoleMarkerEmpty`] when a node selects an
    /// empty console marker. Returns
    /// [`EngineError::WorldNodeSmpVcpuCountZero`],
    /// [`EngineError::WorldNodeMemoryMibZero`], or
    /// [`EngineError::WorldNodeIcountShiftTooLarge`] when a node's fixed launch
    /// fields are invalid. Returns workload scenario-parameter validation errors
    /// when reserved workload, seed, scalar-parameter, config-tree, load-pattern,
    /// spike-mode, or time-source command-line config is malformed, duplicated,
    /// unsupported, or inconsistent with its declared delivery surface.
    pub fn from_nodes(nodes: Vec<WorldNode>) -> Result<Self, EngineError> {
        Self::from_nodes_and_links(nodes, Vec::new())
    }

    /// Builds a canonical world from node and link topology.
    ///
    /// Nodes are sorted by [`NodeId`] and links are sorted by endpoint pair
    /// before hashing so authoring order does not affect world identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`],
    /// [`EngineError::ReadyPointNetworkIdleWindowZero`] when a node selects an
    /// empty network-idle window,
    /// [`EngineError::ReadyPointNetworkIdleWithoutLinks`] when a node selects
    /// network-idle readiness without any incident links,
    /// [`EngineError::ReadyPointConsoleMarkerEmpty`] when a node selects an
    /// empty console marker,
    /// [`EngineError::WorldNodeSmpVcpuCountZero`],
    /// [`EngineError::WorldNodeMemoryMibZero`], or
    /// [`EngineError::WorldNodeIcountShiftTooLarge`] when a node's fixed launch
    /// fields are invalid, workload scenario-parameter validation errors when
    /// reserved workload, seed, scalar-parameter, config-tree, load-pattern,
    /// spike-mode, or time-source command-line config is malformed, duplicated,
    /// unsupported, or inconsistent with its declared delivery surface,
    /// [`EngineError::WorldLinkUnknownNode`] when a
    /// link references an undeclared node, [`EngineError::WorldLinkSelfLoop`]
    /// when a link's endpoints are equal, or [`EngineError::DuplicateWorldLink`]
    /// when a canonical endpoint pair appears more than once. Returns
    /// [`EngineError::WorldLinkLatencyBelowFloor`] or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when a link's
    /// transport configuration violates the latency floor.
    pub fn from_nodes_and_links(
        nodes: Vec<WorldNode>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        Self::from_node_defs_and_links(nodes.into_iter().map(WorldNodeDef::Vm).collect(), links)
    }

    /// Builds a canonical world from heterogeneous VM/I/O nodes and logical links.
    ///
    /// Every I/O node belongs to one declared VM node. Node identifiers are unique
    /// across both VM and I/O kinds, and derived device targets are unique across
    /// both block and 9p families. Nodes and links are canonicalized before
    /// content addressing.
    ///
    /// # Errors
    ///
    /// Returns the same VM/link errors as [`World::from_nodes_and_links`],
    /// [`EngineError::WorldIoNodeUnknownOwner`] when an I/O node names an
    /// undeclared/non-VM owner, or an I/O-core configuration error.
    pub fn from_node_defs_and_links(
        topology_nodes: Vec<WorldNodeDef>,
        links: Vec<LinkDef>,
    ) -> Result<Self, EngineError> {
        let topology_nodes = canonical_world_node_defs(&topology_nodes);
        let nodes = world_vm_node_projection(&topology_nodes);
        let links = canonical_world_links(&links);
        validate_world_nodes(&nodes)?;
        validate_world_node_defs(&topology_nodes)?;
        validate_world_links_for_node_defs(&topology_nodes, &links)?;
        let fault_topology_id = ContentHash::default();
        let material = format!(
            "{}\nfault-topology={}",
            world_material(&topology_nodes, &links),
            fault_topology_id.to_hex()
        );
        Ok(Self {
            id: ContentHash::from_canonical_material("crucible.model.world.v3", &material),
            topology_nodes,
            nodes,
            links,
            fault_topology: WorldFaultTopology::default(),
            fault_topology_id,
            fault_topology_wire: Vec::new(),
        })
    }

    /// Validates the world's ready-point policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`],
    /// [`EngineError::ReadyPointNetworkIdleWindowZero`] when a node selects an
    /// empty network-idle window,
    /// [`EngineError::ReadyPointNetworkIdleWithoutLinks`] when a node selects
    /// network-idle readiness without any incident links,
    /// [`EngineError::ReadyPointConsoleMarkerEmpty`] when a node selects an
    /// empty console marker,
    /// [`EngineError::WorldNodeSmpVcpuCountZero`],
    /// [`EngineError::WorldNodeMemoryMibZero`], or
    /// [`EngineError::WorldNodeIcountShiftTooLarge`] when a node's fixed launch
    /// fields are invalid, workload scenario-parameter validation errors when
    /// reserved workload, seed, scalar-parameter, config-tree, load-pattern,
    /// spike-mode, or time-source command-line config is malformed, duplicated,
    /// unsupported, or inconsistent with its declared delivery surface, or a link
    /// validation error from [`World::validate_topology`].
    pub fn validate_ready_point_policies(&self) -> Result<(), EngineError> {
        self.validate_topology()
    }

    /// Validates the world's canonical heterogeneous-node and link topology.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when a
    /// node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`],
    /// [`EngineError::ReadyPointNetworkIdleWindowZero`] when a node selects an
    /// empty network-idle window,
    /// [`EngineError::ReadyPointNetworkIdleWithoutLinks`] when a node selects
    /// network-idle readiness without any incident links,
    /// [`EngineError::ReadyPointConsoleMarkerEmpty`] when a node selects an
    /// empty console marker,
    /// [`EngineError::WorldNodeSmpVcpuCountZero`],
    /// [`EngineError::WorldNodeMemoryMibZero`], or
    /// [`EngineError::WorldNodeIcountShiftTooLarge`] when a node's fixed launch
    /// fields are invalid, workload scenario-parameter validation errors when
    /// reserved workload, seed, scalar-parameter, config-tree, load-pattern,
    /// spike-mode, or time-source command-line config is malformed, duplicated,
    /// unsupported, or inconsistent with its declared delivery surface,
    /// [`EngineError::WorldLinkUnknownNode`] when a
    /// link references an undeclared node, [`EngineError::WorldLinkSelfLoop`]
    /// when a link's endpoints are equal, or [`EngineError::DuplicateWorldLink`]
    /// when a canonical endpoint pair appears more than once. Returns
    /// [`EngineError::WorldLinkLatencyBelowFloor`] or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when a link's
    /// transport configuration violates the latency floor, or an I/O-node owner
    /// or static-core configuration is invalid.
    pub fn validate_topology(&self) -> Result<(), EngineError> {
        validate_world_nodes(&self.nodes)?;
        validate_world_node_defs(&self.topology_nodes)?;
        validate_world_links_for_node_defs(&self.topology_nodes, &self.links)
    }

    /// Derives the static topology products that are fixed by this world.
    ///
    /// The returned participant set, per-entity decision-RNG streams,
    /// scheduler-lookahead graph, and bake-node set are functions only of the
    /// world's heterogeneous node/link topology. They do not take a [`Schedule`] and therefore
    /// cannot vary with a schedule prefix.
    #[must_use]
    pub fn static_topology(&self) -> WorldStaticTopology {
        WorldStaticTopology {
            participants: world_participants(self),
            scheduling_nodes: world_scheduling_nodes(self),
            rng_streams: world_rng_streams(self),
            lookahead_graph: world_lookahead_edges(self),
            bake_nodes: world_bake_nodes(self),
        }
    }

    /// Builds the canonical genesis scenario definition for this world, empty plan,
    /// empty properties, and the default seed.
    ///
    /// Later builder work provides the explicit authoring surface; until then
    /// this helper composes the independently hashed `World`, empty [`Plan`],
    /// empty [`Properties`], and default [`Seed`] components.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.scenario_def_from_components(&Plan::empty(), &Properties::empty(), Seed::default())
    }

    /// Builds the canonical scenario definition for this world, plan, and empty
    /// properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`],
    /// [`EngineError::PlanFaultUnknownLink`],
    /// [`EngineError::PlanHealUnknownTag`],
    /// [`EngineError::PlanHealBeforeActivate`], or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when `plan` cannot be
    /// layered over this world's static topology.
    pub fn scenario_def_with_plan(&self, plan: &Plan) -> Result<ScenarioDef, EngineError> {
        plan.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(plan, &Properties::empty(), Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, empty plan, and
    /// properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`],
    /// [`EngineError::PropertyPredicateUnknownNode`], or
    /// [`EngineError::PropertyPredicateEmptyCompound`], or
    /// [`EngineError::PropertyPredicateTriggerOnly`] when `properties` cannot be
    /// layered over this world's static topology.
    pub fn scenario_def_with_properties(
        &self,
        properties: &Properties,
    ) -> Result<ScenarioDef, EngineError> {
        let plan = Plan::empty();
        let properties = resolve_properties_dsl_for_context(self, &plan, properties)?;
        properties.validate_for_world(self)?;
        Ok(self.scenario_def_from_components(&plan, &properties, Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, plan, and
    /// properties, using the default seed.
    ///
    /// # Errors
    ///
    /// Returns a plan validation error when `plan` cannot be layered over this
    /// world's static topology, or a property validation error when `properties`
    /// names undeclared predicate nodes or otherwise violates the declarative
    /// property model.
    pub fn scenario_def_with_plan_and_properties(
        &self,
        plan: &Plan,
        properties: &Properties,
    ) -> Result<ScenarioDef, EngineError> {
        let properties = resolve_properties_dsl_for_context(self, plan, properties)?;
        properties.validate_for_world(self)?;
        plan.validate_for_world_with_properties(self, &properties)?;
        Ok(self.scenario_def_from_components(plan, &properties, Seed::default()))
    }

    /// Builds the canonical scenario definition for this world, empty plan,
    /// empty properties, and `seed`.
    #[must_use]
    pub fn scenario_def_with_seed(&self, seed: Seed) -> ScenarioDef {
        self.scenario_def_from_components(&Plan::empty(), &Properties::empty(), seed)
    }

    /// Builds the canonical scenario definition for this world, empty plan,
    /// empty properties, `seed`, and app-random draw cap.
    #[must_use]
    pub fn scenario_def_with_seed_and_app_random_draw_cap(
        &self,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> ScenarioDef {
        self.scenario_def_from_components_with_app_random_draw_cap(
            &Plan::empty(),
            &Properties::empty(),
            seed,
            app_random_draw_cap,
        )
    }

    /// Builds the canonical scenario definition for this world, plan,
    /// properties, and seed.
    ///
    /// # Errors
    ///
    /// Returns a plan validation error when `plan` cannot be layered over this
    /// world's static topology, or a property validation error when `properties`
    /// names undeclared predicate nodes or otherwise violates the declarative
    /// property model.
    pub fn scenario_def_with_plan_properties_and_seed(
        &self,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> Result<ScenarioDef, EngineError> {
        let properties = resolve_properties_dsl_for_context(self, plan, properties)?;
        properties.validate_for_world(self)?;
        plan.validate_for_world_with_properties(self, &properties)?;
        Ok(self.scenario_def_from_components(plan, &properties, seed))
    }

    /// Derives this world's per-entity decision-RNG stream seeds from `seed`.
    #[must_use]
    pub fn seeded_rng_streams(&self, seed: Seed) -> Vec<SeededRngStream> {
        self.static_topology()
            .rng_streams
            .into_iter()
            .map(|stream| SeededRngStream {
                seed: seed.stream_seed(&stream),
                stream,
            })
            .collect()
    }

    /// Serializes this world component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&world_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize world TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML world component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, or a world validation error for invalid topology, launch fields,
    /// ready points, or workload scenario-parameter delivery.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        validate_scenario_toml_size(input)?;
        validate_no_host_path_image_refs_in_toml(input)?;
        let toml = toml::from_str::<WorldToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse world TOML: {source}"))
        })?;
        world_from_toml(toml)
    }

    /// Serializes this world component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(WORLD_BINARY_MAGIC_V3);
        write_world_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary world component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a world validation error for invalid topology,
    /// launch fields, ready points, or workload scenario-parameter delivery.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, WORLD_BINARY_MAGIC_V3)?;
        let world = read_world_binary(&mut reader)?;
        reader.finish()?;
        Ok(world)
    }

    /// Returns the canonical bytes used to compute this world's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut material = world_material(
            &canonical_world_node_defs(&self.topology_nodes),
            &canonical_world_links(&self.links),
        );
        material.push_str("\nfault-topology=");
        material.push_str(&self.fault_topology_id.to_hex());
        material.into_bytes()
    }

    fn scenario_def_from_components(
        &self,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
    ) -> ScenarioDef {
        let material = scenario_world_plan_properties_seed_material(self, plan, properties, seed);
        ScenarioDef {
            id: ContentHash::from_canonical_material(
                "crucible.model.world-plan-properties-seed-scenario.v1",
                &material,
            ),
            seed,
            app_random_draw_cap: DEFAULT_APP_RANDOM_DRAW_CAP,
        }
    }

    pub(super) fn scenario_def_from_components_with_app_random_draw_cap(
        &self,
        plan: &Plan,
        properties: &Properties,
        seed: Seed,
        app_random_draw_cap: u64,
    ) -> ScenarioDef {
        let material = scenario_world_plan_properties_seed_app_random_cap_material(
            self,
            plan,
            properties,
            seed,
            app_random_draw_cap,
        );
        ScenarioDef {
            id: ContentHash::from_canonical_material(
                "crucible.model.world-plan-properties-seed-scenario.v1",
                &material,
            ),
            seed,
            app_random_draw_cap,
        }
    }
}
