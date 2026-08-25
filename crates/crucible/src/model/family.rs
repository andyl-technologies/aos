//! Code-first scenario builders, family generation, and reproduction artifacts.

use super::*;

/// Reusable node settings for code-first scenario authoring.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeTemplate {
    pub(super) arch: VmArchitecture,
    pub(super) memory_mib: u32,
    pub(super) cmdline: String,
    pub(super) ready_point: ReadyPoint,
    pub(super) white_box: WhiteBoxPolicy,
    pub(super) smp_vcpus: u16,
    pub(super) icount_shift: u8,
    pub(super) kernel: Option<ContentAddressedBlobRef>,
    pub(super) root_image: Option<ContentAddressedBlobRef>,
    pub(super) initrd: Option<ContentAddressedBlobRef>,
}

impl NodeTemplate {
    /// The default virtual-machine architecture for a world node.
    pub const DEFAULT_ARCH: VmArchitecture = VmArchitecture::X86_64;
    /// The default virtual-machine memory size in MiB.
    pub const DEFAULT_MEMORY_MIB: u32 = 512;
    /// The default fixed vCPU count for a world node.
    pub const DEFAULT_SMP_VCPUS: u16 = 1;
    /// The default fixed icount shift for a world node.
    pub const DEFAULT_ICOUNT_SHIFT: u8 = 0;

    /// Builds a node template with the supplied ready point and white-box disabled.
    #[must_use]
    pub fn new(ready_point: ReadyPoint) -> Self {
        Self {
            arch: Self::DEFAULT_ARCH,
            memory_mib: Self::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point,
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: Self::DEFAULT_SMP_VCPUS,
            icount_shift: Self::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    /// Builds a template for a fixed-instruction ready point.
    #[must_use]
    pub fn fixed_icount(icount: Icount) -> Self {
        Self::new(ReadyPoint::FixedIcount { icount })
    }

    /// Builds a template for a network-idle ready point.
    #[must_use]
    pub fn network_idle(window: SimDuration) -> Self {
        Self::new(ReadyPoint::NetworkIdle { window })
    }

    /// Builds a template for a console-marker ready point.
    #[must_use]
    pub fn console_marker(marker: impl Into<String>) -> Self {
        Self::new(ReadyPoint::ConsoleMarker {
            marker: marker.into(),
        })
    }

    /// Builds a template for an agent-signal ready point with white-box opt-in.
    #[must_use]
    pub fn agent_signal() -> Self {
        Self {
            arch: Self::DEFAULT_ARCH,
            memory_mib: Self::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::AgentSignal,
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: Self::DEFAULT_SMP_VCPUS,
            icount_shift: Self::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }
    }

    /// Builds a node template by copying another world node's settings.
    #[must_use]
    pub fn from_world_node(node: &WorldNode) -> Self {
        Self {
            arch: node.arch,
            memory_mib: node.memory_mib,
            cmdline: node.cmdline.clone(),
            ready_point: node.ready_point.clone(),
            white_box: node.white_box,
            smp_vcpus: node.smp_vcpus,
            icount_shift: node.icount_shift,
            kernel: node.kernel,
            root_image: node.root_image,
            initrd: node.initrd,
        }
    }

    /// Replaces the template ready point.
    #[must_use]
    pub fn ready_point(mut self, ready_point: ReadyPoint) -> Self {
        self.ready_point = ready_point;
        self
    }

    /// Replaces the template white-box policy.
    #[must_use]
    pub fn white_box(mut self, white_box: WhiteBoxPolicy) -> Self {
        self.white_box = white_box;
        self
    }

    /// Replaces the virtual-machine architecture.
    #[must_use]
    pub fn arch(mut self, arch: VmArchitecture) -> Self {
        self.arch = arch;
        self
    }

    /// Replaces the virtual-machine memory size in MiB.
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Replaces the guest kernel command line.
    #[must_use]
    pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = cmdline.into();
        self
    }

    /// Selects a supported in-guest workload binary by scenario parameter.
    ///
    /// The selected workload is encoded as `crucible.workload=...` in the guest
    /// command line, which is already part of the content-addressed world and
    /// scenario identity. This helper does not install an agent or create a
    /// host-side application traffic source.
    #[must_use]
    pub fn guest_workload(mut self, workload: GuestWorkloadBinary) -> Self {
        self.cmdline = workload.selected_cmdline(&self.cmdline);
        self
    }

    /// Delivers an explicit workload seed through black-box scenario config.
    ///
    /// The seed is encoded as `wseed=0x...` in the guest command line, which is
    /// already part of the content-addressed world and scenario identity. This
    /// path does not require [`WhiteBoxPolicy::Enabled`].
    #[must_use]
    pub fn guest_workload_seed(mut self, seed: GuestWorkloadSeed) -> Self {
        self.cmdline = seed.selected_cmdline(&self.cmdline);
        self
    }

    /// Delivers a scalar workload parameter through black-box scenario config.
    ///
    /// The parameter is encoded as a stable `key=value` token in the guest
    /// command line, which is already part of the content-addressed world and
    /// scenario identity.
    #[must_use]
    pub fn guest_workload_scalar_parameter(
        mut self,
        parameter: &GuestWorkloadScalarParameter,
    ) -> Self {
        self.cmdline = parameter.selected_cmdline(&self.cmdline);
        self
    }

    /// Delivers a structured workload config tree through immutable scenario config.
    ///
    /// The tree reference is encoded as `wcfg=...` in the guest command line. A
    /// rootfs-backed config also selects the same content-addressed blob as the
    /// node's read-only root image, so the structured config is represented in
    /// both the delivery surface and the world's canonical material.
    #[must_use]
    pub fn guest_workload_config_tree(mut self, config: &GuestWorkloadConfigTreeRef) -> Self {
        self.cmdline = config.selected_cmdline(&self.cmdline);
        if config.delivery() == GuestWorkloadConfigTreeDelivery::ReadOnlyRootfs {
            self.root_image = Some(config.export());
        }
        self
    }

    /// Selects an in-guest load pattern by scenario parameter.
    ///
    /// The pattern is encoded as `load_pattern=...` in the guest command line,
    /// keeping the load shape in the content-addressed world instead of a
    /// host-side load-generation subsystem.
    #[must_use]
    pub fn guest_workload_pattern(mut self, pattern: GuestWorkloadPattern) -> Self {
        self.cmdline = pattern.selected_cmdline(&self.cmdline);
        self
    }

    /// Selects the spike-pattern mode by scenario parameter.
    ///
    /// The mode is encoded as `spike_mode=...` in the guest command line and is
    /// consumed by the selected in-guest workload.
    #[must_use]
    pub fn guest_workload_spike_mode(mut self, mode: GuestWorkloadSpikeMode) -> Self {
        self.cmdline = mode.selected_cmdline(&self.cmdline);
        self
    }

    /// Selects the time source for a time-varying load pattern by scenario parameter.
    ///
    /// The only supported source is virtual time. The source is encoded as
    /// `load_time_source=virtual_time` in the guest command line.
    #[must_use]
    pub fn guest_workload_time_source(mut self, source: GuestWorkloadTimeSource) -> Self {
        self.cmdline = source.selected_cmdline(&self.cmdline);
        self
    }

    /// Replaces the fixed vCPU count.
    #[must_use]
    pub fn smp_vcpus(mut self, smp_vcpus: u16) -> Self {
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Replaces the fixed icount shift.
    #[must_use]
    pub fn icount_shift(mut self, icount_shift: u8) -> Self {
        self.icount_shift = icount_shift;
        self
    }

    /// Replaces the template kernel blob reference.
    #[must_use]
    pub fn kernel(mut self, kernel: ContentAddressedBlobRef) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Replaces the template root-image blob reference.
    #[must_use]
    pub fn root_image(mut self, root_image: ContentAddressedBlobRef) -> Self {
        self.root_image = Some(root_image);
        self
    }

    /// Replaces the template initrd blob reference.
    #[must_use]
    pub fn initrd(mut self, initrd: ContentAddressedBlobRef) -> Self {
        self.initrd = Some(initrd);
        self
    }

    fn instantiate(&self, id: NodeId) -> WorldNode {
        WorldNode {
            id,
            arch: self.arch,
            memory_mib: self.memory_mib,
            cmdline: self.cmdline.clone(),
            ready_point: self.ready_point.clone(),
            white_box: self.white_box,
            smp_vcpus: self.smp_vcpus,
            icount_shift: self.icount_shift,
            kernel: self.kernel,
            root_image: self.root_image,
            initrd: self.initrd,
        }
    }
}

impl From<WorldNode> for NodeTemplate {
    fn from(node: WorldNode) -> Self {
        Self::from_world_node(&node)
    }
}

/// Code-first scenario authoring surface for the four orthogonal scenario layers.
#[derive(Clone, Debug, Default)]
pub struct ScenarioBuilder {
    pub(super) nodes: Vec<PendingScenarioNode>,
    pub(super) links: Vec<PendingScenarioLink>,
    pub(super) plan: Option<Plan>,
    pub(super) properties: Option<Properties>,
    pub(super) assertions: Vec<AssertionDef>,
    pub(super) seed: Seed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum PendingScenarioNode {
    Concrete(WorldNode),
    Like { id: NodeId, template: NodeId },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum PendingScenarioLink {
    Default {
        left: NodeId,
        right: NodeId,
    },
    Transport {
        left: NodeId,
        right: NodeId,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    },
    Concrete(LinkDef),
}

impl ScenarioBuilder {
    /// Starts an empty scenario builder with empty plan/properties and default seed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies a complete world into the builder's world layer.
    #[must_use]
    pub fn world(mut self, world: &World) -> Self {
        self.nodes.extend(
            world
                .vm_nodes()
                .iter()
                .cloned()
                .map(PendingScenarioNode::Concrete),
        );
        self.links.extend(
            world
                .links()
                .iter()
                .cloned()
                .map(PendingScenarioLink::Concrete),
        );
        self
    }

    /// Adds a concrete node from a reusable node template.
    #[must_use]
    pub fn node(mut self, name: impl Into<String>, template: NodeTemplate) -> Self {
        let id = NodeId { name: name.into() };
        self.nodes
            .push(PendingScenarioNode::Concrete(template.instantiate(id)));
        self
    }

    /// Adds a node by copying another declared node's template settings at build time.
    #[must_use]
    pub fn node_like(mut self, name: impl Into<String>, template: impl Into<String>) -> Self {
        self.nodes.push(PendingScenarioNode::Like {
            id: NodeId { name: name.into() },
            template: NodeId {
                name: template.into(),
            },
        });
        self
    }

    /// Adds a default logical world link between two node names.
    #[must_use]
    pub fn link(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        self.links.push(PendingScenarioLink::Default {
            left: NodeId { name: left.into() },
            right: NodeId { name: right.into() },
        });
        self
    }

    /// Adds a logical world link with explicit transport characteristics.
    #[must_use]
    pub fn link_with_transport(
        mut self,
        left: impl Into<String>,
        right: impl Into<String>,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    ) -> Self {
        self.links.push(PendingScenarioLink::Transport {
            left: NodeId { name: left.into() },
            right: NodeId { name: right.into() },
            latency,
            jitter,
            loss,
            bandwidth_bps,
        });
        self
    }

    /// Adds an already-constructed logical world link.
    #[must_use]
    pub fn link_def(mut self, link: LinkDef) -> Self {
        self.links.push(PendingScenarioLink::Concrete(link));
        self
    }

    /// Sets the complete plan layer.
    #[must_use]
    pub fn plan(mut self, plan: Plan) -> Self {
        self.plan = Some(plan);
        self
    }

    /// Sets the complete properties layer.
    #[must_use]
    pub fn properties(mut self, properties: Properties) -> Self {
        self.properties = Some(properties);
        self.assertions.clear();
        self
    }

    /// Adds one assertion to the properties layer.
    #[must_use]
    pub fn property(mut self, assertion: AssertionDef) -> Self {
        self.properties = None;
        self.assertions.push(assertion);
        self
    }

    /// Sets the scenario root entropy.
    #[must_use]
    pub fn seed(mut self, seed: Seed) -> Self {
        self.seed = seed;
        self
    }

    /// Builds, validates, canonicalizes, and content-addresses the scenario.
    ///
    /// # Errors
    ///
    /// Returns world validation errors for invalid node/link topology, plan
    /// validation errors when plan entries cannot layer over the static world,
    /// property validation errors when assertions reference undeclared nodes or
    /// malformed compound predicates, or
    /// [`EngineError::ScenarioBuilderUnknownNodeTemplate`] when a `node_like`
    /// entry names no concrete node template.
    pub fn build(self) -> Result<ScenarioDef, EngineError> {
        let world = World::from_nodes_and_links(self.build_nodes()?, self.build_links()?)?;
        let plan = self.build_plan(&world)?;
        let properties = self.build_properties(&world)?;
        world.scenario_def_with_plan_properties_and_seed(&plan, &properties, self.seed)
    }

    fn build_nodes(&self) -> Result<Vec<WorldNode>, EngineError> {
        let mut templates = BTreeMap::new();
        let mut nodes = Vec::with_capacity(self.nodes.len());

        for pending in &self.nodes {
            if let PendingScenarioNode::Concrete(node) = pending {
                templates.insert(node.id.clone(), NodeTemplate::from_world_node(node));
                nodes.push(node.clone());
            }
        }

        for pending in &self.nodes {
            if let PendingScenarioNode::Like { id, template } = pending {
                let node_template = templates.get(template).ok_or_else(|| {
                    EngineError::ScenarioBuilderUnknownNodeTemplate {
                        node: id.clone(),
                        template: template.clone(),
                    }
                })?;
                nodes.push(node_template.instantiate(id.clone()));
            }
        }

        Ok(nodes)
    }

    fn build_links(&self) -> Result<Vec<LinkDef>, EngineError> {
        self.links
            .iter()
            .map(|pending| match pending {
                PendingScenarioLink::Default { left, right } => {
                    LinkDef::new(left.clone(), right.clone())
                }
                PendingScenarioLink::Transport {
                    left,
                    right,
                    latency,
                    jitter,
                    loss,
                    bandwidth_bps,
                } => LinkDef::with_transport(
                    left.clone(),
                    right.clone(),
                    *latency,
                    *jitter,
                    *loss,
                    *bandwidth_bps,
                ),
                PendingScenarioLink::Concrete(link) => Ok(link.clone()),
            })
            .collect()
    }

    fn build_plan(&self, _world: &World) -> Result<Plan, EngineError> {
        if let Some(plan) = &self.plan {
            return Ok(plan.clone());
        }

        Ok(Plan::empty())
    }

    fn build_properties(&self, world: &World) -> Result<Properties, EngineError> {
        if let Some(properties) = &self.properties {
            properties.validate_for_world(world)?;
            return Ok(properties.clone());
        }

        if self.assertions.is_empty() {
            Ok(Properties::empty())
        } else {
            Properties::from_assertions_for_world(world, self.assertions.clone())
        }
    }
}

/// Inclusive finite range of generated family topology sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TopologySizeRange {
    pub(super) min: u32,
    pub(super) max: u32,
}

impl TopologySizeRange {
    /// Builds an inclusive topology-size range.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when the range is empty,
    /// starts at zero, or exceeds the implementation's bounded generation limit.
    pub fn new(min: u32, max: u32) -> Result<Self, EngineError> {
        if min == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range must start above zero",
            });
        }
        if min > max {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range minimum exceeds maximum",
            });
        }
        if max > MAX_SCENARIO_FAMILY_TOPOLOGY_SIZE {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology size range exceeds family generation limit",
            });
        }

        Ok(Self { min, max })
    }

    /// Returns the minimum generated node count.
    #[must_use]
    pub fn min(self) -> u32 {
        self.min
    }

    /// Returns the maximum generated node count.
    #[must_use]
    pub fn max(self) -> u32 {
        self.max
    }

    /// Returns whether `size` is in this range.
    #[must_use]
    pub fn contains(self, size: u32) -> bool {
        self.min <= size && size <= self.max
    }

    fn len(self) -> u64 {
        u64::from(self.max - self.min) + 1
    }

    fn at(self, index: u64) -> Result<u32, EngineError> {
        if index >= self.len() {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_size",
            });
        }
        Ok(self.min + index as u32)
    }
}

/// Topology shape axis for [`ScenarioFamily`] generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyShape {
    /// Connect each node to its successor, wrapping the last node to the first.
    Ring,
    /// Connect every non-center node to `node-0`.
    Star,
    /// Connect every node pair.
    Mesh,
    /// Build a deterministic seed-derived connected graph.
    Random,
}

/// Finite seed axis for [`ScenarioFamily`] generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SeedSpace {
    pub(super) kind: SeedSpaceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum SeedSpaceKind {
    Explicit(Vec<Seed>),
    Generated { meta_seed: Seed, count: u32 },
}

impl SeedSpace {
    /// Builds a seed space from an explicit set of seeds.
    ///
    /// The stored set is sorted for deterministic sampling.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `seeds` is empty,
    /// too large, or contains duplicates.
    pub fn explicit(seeds: Vec<Seed>) -> Result<Self, EngineError> {
        if seeds.is_empty() {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space must not be empty",
            });
        }
        if seeds.len() > MAX_SCENARIO_FAMILY_SEEDS as usize {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space exceeds family generation limit",
            });
        }

        let mut seeds = seeds;
        seeds.sort();
        if seeds.windows(2).any(|window| window[0] == window[1]) {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space contains duplicate seeds",
            });
        }

        Ok(Self {
            kind: SeedSpaceKind::Explicit(seeds),
        })
    }

    /// Builds a finite seed space deterministically derived from `meta_seed`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `count` is zero or
    /// exceeds the implementation's bounded generation limit.
    pub fn generated(meta_seed: Seed, count: u32) -> Result<Self, EngineError> {
        if count == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "generated seed space must not be empty",
            });
        }
        if count > MAX_SCENARIO_FAMILY_SEEDS {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "seed space exceeds family generation limit",
            });
        }

        Ok(Self {
            kind: SeedSpaceKind::Generated { meta_seed, count },
        })
    }

    /// Returns the number of seeds in this finite seed space.
    #[must_use]
    pub fn len(&self) -> u64 {
        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => seeds.len() as u64,
            SeedSpaceKind::Generated { count, .. } => u64::from(*count),
        }
    }

    /// Returns whether this seed space is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the seed at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `index` is
    /// outside this finite seed space.
    pub fn seed_at(&self, index: u64) -> Result<Seed, EngineError> {
        if index >= self.len() {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter: "seed" });
        }

        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => Ok(seeds[index as usize]),
            SeedSpaceKind::Generated { meta_seed, .. } => Ok(derive_family_seed(*meta_seed, index)),
        }
    }

    fn contains(&self, seed: Seed) -> bool {
        match &self.kind {
            SeedSpaceKind::Explicit(seeds) => seeds.binary_search(&seed).is_ok(),
            SeedSpaceKind::Generated { count, meta_seed } => {
                (0..u64::from(*count)).any(|index| derive_family_seed(*meta_seed, index) == seed)
            }
        }
    }
}

/// The deterministic parameter space a [`ScenarioFamily`] ranges over.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FamilySpace {
    pub(super) seeds: SeedSpace,
    pub(super) topology_size: TopologySizeRange,
    pub(super) topology_shapes: Vec<TopologyShape>,
}

impl FamilySpace {
    /// Builds a finite family parameter space.
    ///
    /// Shapes are sorted and deduplicated so sampling is deterministic regardless
    /// of authoring order.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when `topology_shapes`
    /// is empty.
    pub fn new(
        seeds: SeedSpace,
        topology_size: TopologySizeRange,
        topology_shapes: Vec<TopologyShape>,
    ) -> Result<Self, EngineError> {
        if topology_shapes.is_empty() {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "topology shape set must not be empty",
            });
        }

        let mut topology_shapes = topology_shapes;
        topology_shapes.sort();
        topology_shapes.dedup();

        Ok(Self {
            seeds,
            topology_size,
            topology_shapes,
        })
    }

    /// Returns this space's seed axis.
    #[must_use]
    pub fn seeds(&self) -> &SeedSpace {
        &self.seeds
    }

    /// Returns this space's topology-size axis.
    #[must_use]
    pub fn topology_size(&self) -> TopologySizeRange {
        self.topology_size
    }

    /// Returns this space's canonical topology-shape axis.
    #[must_use]
    pub fn topology_shapes(&self) -> &[TopologyShape] {
        &self.topology_shapes
    }

    /// Returns whether `params` lies inside this space.
    #[must_use]
    pub fn contains(&self, params: FamilyParams) -> bool {
        self.seeds.contains(params.seed)
            && self.topology_size.contains(params.topology_size)
            && self
                .topology_shapes
                .binary_search(&params.topology_shape)
                .is_ok()
    }

    /// Returns the finite cardinality of this family space.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] if the finite space size
    /// overflows `u64`.
    pub fn cardinality(&self) -> Result<u64, EngineError> {
        let seed_count = self.seeds.len();
        let shape_count = self.topology_shapes.len() as u64;
        let size_count = self.topology_size.len();
        let total = seed_count
            .checked_mul(shape_count)
            .and_then(|count| count.checked_mul(size_count))
            .ok_or(EngineError::ScenarioFamilyInvalidSpace {
                reason: "family space cardinality overflows u64",
            })?;
        if total == 0 {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "family space must not be empty",
            });
        }

        Ok(total)
    }

    /// Deterministically samples one parameter point by cartesian index.
    ///
    /// The finite axes are traversed in seed, shape, then size order.
    /// Callers that want an unbounded fuzz counter should explicitly wrap by
    /// [`Self::cardinality`] so exhaustive enumeration can still reject an
    /// out-of-space index.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `index` is
    /// greater than or equal to [`Self::cardinality`].
    pub fn sample(&self, index: u64) -> Result<FamilyParams, EngineError> {
        let total = self.cardinality()?;
        if index >= total {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "sample_index",
            });
        }

        let seed_count = self.seeds.len();
        let shape_count = self.topology_shapes.len() as u64;
        let size_count = self.topology_size.len();
        let mut index = index;
        let seed = self.seeds.seed_at(index % seed_count)?;
        index /= seed_count;
        let topology_shape = self.topology_shapes[(index % shape_count) as usize];
        index /= shape_count;
        let topology_size = self.topology_size.at(index % size_count)?;

        Ok(FamilyParams {
            seed,
            topology_size,
            topology_shape,
        })
    }

    fn validate_params(&self, params: FamilyParams) -> Result<(), EngineError> {
        if !self.seeds.contains(params.seed) {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter: "seed" });
        }
        if !self.topology_size.contains(params.topology_size) {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_size",
            });
        }
        if self
            .topology_shapes
            .binary_search(&params.topology_shape)
            .is_err()
        {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "topology_shape",
            });
        }

        Ok(())
    }
}

/// One concrete point sampled from a [`ScenarioFamily`] parameter space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FamilyParams {
    /// Concrete root seed for the pinned scenario.
    pub seed: Seed,
    /// Concrete generated node count.
    pub topology_size: u32,
    /// Concrete generated topology shape.
    pub topology_shape: TopologyShape,
}

/// Parametric generator over concrete, validated scenario definitions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioFamily {
    pub(super) space: FamilySpace,
    pub(super) node_template: NodeTemplate,
    pub(super) assertions: Vec<AssertionDef>,
}

impl ScenarioFamily {
    /// Builds a scenario family from a parameter space and reusable node template.
    #[must_use]
    pub fn new(space: FamilySpace, node_template: NodeTemplate) -> Self {
        Self {
            space,
            node_template,
            assertions: Vec::new(),
        }
    }

    /// Returns the parameter space this family ranges over.
    #[must_use]
    pub fn space(&self) -> &FamilySpace {
        &self.space
    }

    /// Adds one assertion to every generated scenario's properties layer.
    #[must_use]
    pub fn property(mut self, assertion: AssertionDef) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Instantiates a concrete validated scenario at `params`.
    ///
    /// The returned [`PinnedScenario`] contains the concrete [`ScenarioDefForm`]
    /// used by execution and reproduction. It carries no reference back to this
    /// family, so callers can only run the pinned scenario definition.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyParameterOutOfSpace`] when `params`
    /// does not lie in the family space, or the usual world/plan/properties
    /// validation errors if the generated scenario is invalid.
    pub fn instantiate(&self, params: FamilyParams) -> Result<PinnedScenario, EngineError> {
        self.space.validate_params(params)?;
        let world = self.build_world(params)?;
        let plan = self.build_plan(&world, params)?;
        let properties = Properties::from_assertions_for_world(&world, self.assertions.clone())?;
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, params.seed)?;
        Ok(PinnedScenario { params, form })
    }

    /// Samples and instantiates one deterministic parameter point.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`FamilySpace::sample`] or [`Self::instantiate`].
    pub fn instantiate_sample(&self, index: u64) -> Result<PinnedScenario, EngineError> {
        let params = self.space.sample(index)?;
        self.instantiate(params)
    }

    /// Samples and mutates concrete scenarios using event-log coverage feedback.
    ///
    /// Each iteration chooses one family parameter point, pins that point to a
    /// concrete [`ScenarioDef`], and appends a schedule mutation encoded as
    /// [`Decision::Override`]. Coverage influences only which deterministic
    /// samples are explored and how the returned candidates are ordered; it never
    /// changes the reduced execution semantics of a candidate.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] when the family space
    /// cannot be counted, [`EngineError::ScenarioFamilyParameterOutOfSpace`] when
    /// a sampled point is invalid, or any validation error from
    /// [`Self::instantiate`] or [`try_step`].
    pub fn fuzz_coverage_guided(
        &self,
        config: CoverageGuidedFuzzConfig,
        feedback: &[EventLogCoverageFeedback],
    ) -> Result<CoverageGuidedFuzzRun, EngineError> {
        run_coverage_guided_fuzz(self, config, feedback)
    }

    /// Runs coverage-guided fuzzing with a durable content-addressed corpus.
    ///
    /// The corpus stores every retained input as a self-contained
    /// [`ReproductionArtifact`] in `store`. Admission is coverage-driven: a
    /// candidate is retained only when its coverage fingerprint has no existing
    /// corpus owner. Rejected duplicate coverage is reported as deterministic
    /// subsumption pruning rather than stored as a corpus entry.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageGuidedCorpusError::Engine`] when sampling, mutation,
    /// artifact capture, or replay validation fails. Returns
    /// [`CoverageGuidedCorpusError::Store`] when `store` cannot persist an
    /// admitted reproduction artifact.
    pub fn fuzz_coverage_guided_corpus<S>(
        &self,
        store: &S,
        config: CoverageGuidedFuzzConfig,
        corpus_config: CoverageGuidedCorpusConfig,
        feedback: &[EventLogCoverageFeedback],
    ) -> Result<CoverageGuidedCorpusRun, CoverageGuidedCorpusError>
    where
        S: DagStore + ?Sized,
    {
        run_coverage_guided_fuzz_corpus(self, store, config, corpus_config, feedback)
    }

    fn build_world(&self, params: FamilyParams) -> Result<World, EngineError> {
        let nodes = (0..params.topology_size)
            .map(|index| self.node_template.instantiate(family_node_id(index)))
            .collect::<Vec<_>>();
        let links = family_links(params)?;
        World::from_nodes_and_links(nodes, links)
    }

    fn build_plan(&self, _world: &World, _params: FamilyParams) -> Result<Plan, EngineError> {
        Ok(Plan::empty())
    }
}

/// A concrete scenario pinned from a [`ScenarioFamily`] parameter point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedScenario {
    pub(super) params: FamilyParams,
    pub(super) form: ScenarioDefForm,
}

impl PinnedScenario {
    /// Returns the family parameters that produced this pinned instance.
    #[must_use]
    pub fn params(&self) -> FamilyParams {
        self.params
    }

    /// Returns the materialized concrete scenario form.
    #[must_use]
    pub fn form(&self) -> &ScenarioDefForm {
        &self.form
    }

    /// Consumes this pinned instance and returns its concrete scenario form.
    #[must_use]
    pub fn into_form(self) -> ScenarioDefForm {
        self.form
    }

    /// Reconstructs the concrete scenario definition used by execution.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.form.scenario_def()
    }

    /// Builds the genesis execution configuration while retaining the concrete form.
    #[must_use]
    pub fn genesis_configuration(&self) -> PinnedConfiguration {
        PinnedConfiguration {
            scenario: self.form.clone(),
            configuration: Configuration::genesis(self.scenario_def()),
        }
    }

    /// Returns the concrete scenario id.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.form.id()
    }
}

/// A run configuration pinned to a concrete materialized scenario form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedConfiguration {
    pub(super) scenario: ScenarioDefForm,
    pub(super) configuration: Configuration,
}

impl PinnedConfiguration {
    /// Returns the concrete materialized scenario form for reproduction.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the executable configuration handle for the pinned scenario.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Consumes this pinned configuration into its concrete parts.
    #[must_use]
    pub fn into_parts(self) -> (ScenarioDefForm, Configuration) {
        (self.scenario, self.configuration)
    }
}

/// A self-contained `(seed, scenario, schedule)` reproduction bundle.
///
/// The seed is not stored as a drifting side channel: it is the embedded
/// [`ScenarioDefForm`]'s own seed. The artifact carries only the complete
/// validated scenario form and recorded schedule, so its identity is exactly the
/// RFC tuple `(seed, scenario, schedule)` without a parent family or host path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReproductionArtifact {
    pub(super) id: ContentHash,
    pub(super) scenario: ScenarioDefForm,
    pub(super) schedule: Schedule,
}

impl ReproductionArtifact {
    /// Captures an artifact by reducing `schedule` from `scenario`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the supplied
    /// scenario/schedule pair.
    pub fn capture(scenario: &ScenarioDefForm, schedule: &Schedule) -> Result<Self, EngineError> {
        let artifact = Self::from_recorded_parts(scenario.clone(), schedule.clone());
        let _ = artifact.replay()?;
        Ok(artifact)
    }

    /// Captures an artifact from an executable pinned configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if replaying the pinned configuration's scenario
    /// and schedule cannot derive a reduced state.
    pub fn from_pinned_configuration(pinned: &PinnedConfiguration) -> Result<Self, EngineError> {
        Self::capture(pinned.scenario_form(), &pinned.configuration().schedule)
    }

    /// Rebuilds an artifact from already-recorded self-contained parts.
    #[must_use]
    pub fn from_recorded_parts(scenario: ScenarioDefForm, schedule: Schedule) -> Self {
        let id =
            ContentHash::from_bytes(&reproduction_artifact_canonical_bytes(&scenario, &schedule));
        Self {
            id,
            scenario,
            schedule,
        }
    }

    /// Parses a compact canonical artifact representation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed artifact,
    /// scenario, or schedule bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let outer_v7 = bytes.starts_with(REPRODUCTION_ARTIFACT_BINARY_MAGIC_V7);
        let outer_v6 = bytes.starts_with(REPRODUCTION_ARTIFACT_BINARY_MAGIC_V6);
        let mut reader = if outer_v7 {
            ScenarioBinaryReader::new(bytes, REPRODUCTION_ARTIFACT_BINARY_MAGIC_V7)?
        } else if outer_v6 {
            ScenarioBinaryReader::new(bytes, REPRODUCTION_ARTIFACT_BINARY_MAGIC_V6)?
        } else {
            ScenarioBinaryReader::new(bytes, REPRODUCTION_ARTIFACT_BINARY_MAGIC_V5)?
        };
        let scenario_bytes = reader.read_binary_blob_bounded(
            "reproduction-artifact.scenario",
            MAX_REPRODUCTION_SCENARIO_BLOB_BYTES,
        )?;
        let schedule_bytes = reader.read_binary_blob("reproduction-artifact.schedule")?;
        reader.finish()?;
        let scenario_version_matches = if outer_v7 {
            scenario_bytes.starts_with(SCENARIO_FORM_BINARY_MAGIC_V7)
        } else if outer_v6 {
            scenario_bytes.starts_with(SCENARIO_FORM_BINARY_MAGIC_V6)
        } else {
            scenario_bytes.starts_with(SCENARIO_FORM_BINARY_MAGIC_V5)
        };
        if !scenario_version_matches {
            return Err(scenario_serialization_error(
                "reproduction-artifact scenario version does not match its outer version",
            ));
        }

        let scenario = ScenarioDefForm::from_compact_binary(scenario_bytes)?;
        let schedule = Schedule::from_compact_binary(schedule_bytes)?;
        Ok(Self::from_recorded_parts(scenario, schedule))
    }

    /// Returns the BLAKE3 content address over this artifact's canonical bytes.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the concrete serialized scenario form carried by this artifact.
    #[must_use]
    pub fn scenario_form(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Reconstructs the immutable scenario definition carried by this artifact.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        self.scenario.scenario_def()
    }

    /// Returns the scenario definition's root seed.
    #[must_use]
    pub fn seed(&self) -> Seed {
        self.scenario.seed()
    }

    /// Returns the recorded schedule carried by this artifact.
    #[must_use]
    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// Returns the canonical byte serialization hashed by [`Self::id`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        reproduction_artifact_canonical_bytes(&self.scenario, &self.schedule)
    }

    /// Serializes this artifact as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    /// Replays the artifact through the reduction oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the reduction function rejects the embedded
    /// scenario/schedule pair.
    pub fn replay(&self) -> Result<ReproductionReplay, EngineError> {
        let state = reduce(&self.scenario_def(), &self.schedule)?;
        Ok(ReproductionReplay {
            artifact: self.id,
            scenario: self.scenario.id(),
            schedule: self.schedule.content_hash(),
            state: state.id,
        })
    }

    /// Replays the artifact and compares the result with an external target state.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionArtifactReplayMismatch`] when the
    /// embedded scenario and schedule reduce to a state other than `expected`.
    /// Returns other [`EngineError`] variants if the reduction itself fails.
    pub fn verify_replay(&self, expected: ContentHash) -> Result<ReproductionReplay, EngineError> {
        let replay = self.replay()?;
        if replay.state != expected {
            return Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: self.id,
                expected,
                actual: replay.state,
            });
        }
        Ok(replay)
    }

    /// Captures the event-log debug/fork metadata for this reproduction artifact.
    ///
    /// The returned value records the causal-subsequence digest and fork-point
    /// index, not the full event log. Replaying the artifact can therefore
    /// recompute the log and compare against this compact record.
    #[must_use]
    pub fn event_log_debug_artifact(
        &self,
        fork_point: EventLogOffset,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> ReproductionEventLogArtifact {
        self.event_log_debug_artifact_with_segments(fork_point, entries, Vec::new())
    }

    /// Captures event-log debug/fork metadata with shared-store segment keys.
    ///
    /// `shared_store_segments` are optional content-addressed event-log segment
    /// keys. They let a shared store fetch retained log bytes, but replay
    /// correctness still comes from recomputing the log from the embedded
    /// scenario and schedule.
    #[must_use]
    pub fn event_log_debug_artifact_with_segments<I>(
        &self,
        fork_point: EventLogOffset,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
        shared_store_segments: I,
    ) -> ReproductionEventLogArtifact
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let projection = crate::scheduler::event_log_causal_projection(entries);
        let coverage_fingerprint = coverage_fingerprint_from_event_log(entries);
        ReproductionEventLogArtifact::from_causal_projection(
            self.id,
            fork_point,
            projection.content_hash(),
            projection.canonical_bytes().len(),
            projection.len(),
            coverage_fingerprint,
            shared_store_segments,
        )
    }

    /// Replays the artifact and checks a reconstructed event log against metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if replaying this artifact's scenario/schedule or
    /// reconstructing the replay log fails before comparison.
    pub fn verify_event_log_replay_with<F>(
        &self,
        event_log: &ReproductionEventLogArtifact,
        replay_log: F,
    ) -> Result<ReproductionEventLogReplay, EngineError>
    where
        F: FnOnce(
            &ReproductionArtifact,
            &ReproductionReplay,
        ) -> Result<Vec<crate::scheduler::SchedulerEventLogEntry>, EngineError>,
    {
        let reduction = self.replay()?;
        let reproduced_entries = replay_log(self, &reduction)?;
        let reproduced = crate::scheduler::event_log_causal_projection(&reproduced_entries);
        let reproduced_coverage_fingerprint =
            coverage_fingerprint_from_event_log(&reproduced_entries);
        Ok(ReproductionEventLogReplay {
            reduction,
            event_log_artifact: event_log.id(),
            artifact_matches: event_log.reproduction_artifact == self.id,
            fork_point: event_log.fork_point,
            expected_causal_subsequence: event_log.causal_subsequence,
            reproduced_causal_subsequence: reproduced.content_hash(),
            expected_causal_bytes: event_log.causal_subsequence_bytes,
            reproduced_causal_bytes: reproduced.canonical_bytes().len(),
            expected_causal_events: event_log.causal_subsequence_events,
            reproduced_causal_events: reproduced.len(),
            expected_coverage_fingerprint: event_log.coverage_fingerprint,
            reproduced_coverage_fingerprint,
            shared_store_segments: event_log.shared_store_segments.clone(),
        })
    }
}
