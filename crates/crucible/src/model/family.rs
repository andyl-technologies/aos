//! Code-first scenario builders, family generation, and reproduction artifacts.

use super::*;

mod instances;

pub use instances::*;

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
    Default { left: NodeId, right: NodeId },
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
    pub(super) fault_densities: Vec<u32>,
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
            fault_densities: vec![0],
        })
    }

    /// Sets the finite number of fault bindings retained from a family plan.
    ///
    /// Density zero pins an empty fault layer. Nonzero densities require a
    /// [`ScenarioFamily::with_fault_plan`] template with enough bindings.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioFamilyInvalidSpace`] for an empty axis or
    /// a density beyond the admitted fault-binding limit.
    pub fn with_fault_densities(mut self, mut densities: Vec<u32>) -> Result<Self, EngineError> {
        if densities.is_empty()
            || densities.iter().any(|density| {
                usize::try_from(*density).map_or(true, |value| value > HARD_FAULT_BINDING_LIMIT)
            })
        {
            return Err(EngineError::ScenarioFamilyInvalidSpace {
                reason: "fault-density axis is empty or exceeds the fault-binding limit",
            });
        }
        densities.sort_unstable();
        densities.dedup();
        self.fault_densities = densities;
        self.cardinality()?;
        Ok(self)
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

    /// Returns the canonical fault-density axis.
    #[must_use]
    pub fn fault_densities(&self) -> &[u32] {
        &self.fault_densities
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
            && self
                .fault_densities
                .binary_search(&params.fault_density)
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
            .and_then(|count| count.checked_mul(self.fault_densities.len() as u64))
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
    /// The finite axes are traversed in seed, shape, size, then fault-density order.
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
        index /= size_count;
        let fault_density = self.fault_densities[index as usize];

        Ok(FamilyParams {
            seed,
            topology_size,
            topology_shape,
            fault_density,
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
        if self
            .fault_densities
            .binary_search(&params.fault_density)
            .is_err()
        {
            return Err(EngineError::ScenarioFamilyParameterOutOfSpace {
                parameter: "fault_density",
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
    /// Number of admitted fault bindings selected from the family plan.
    pub fault_density: u32,
}
