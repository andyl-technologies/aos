//! Concrete five-link World and primary/backup fault domains for Envoy.

use super::*;

// Keep the modeled three-hop route within guest request and health timeouts
// while giving each network-safe scheduler RUN useful instruction progress.
const BASELINE_LINK_LATENCY_NANOS: u64 = 10_000_000;

pub(super) fn worked_network_world(boot: Option<WorkedNetworkBoot>) -> Result<World, CliError> {
    let nodes = [
        ("router-a", "router"),
        ("router-b", "router"),
        ("router-c", "router"),
        ("traffic-west", "endpoint"),
        ("traffic-east", "endpoint"),
    ]
    .into_iter()
    .map(|(name, role)| WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: if boot.is_some() {
            format!("root=/dev/vda init=/init console=ttyS0 network.role={name}")
        } else {
            format!("console=ttyS0 quiet network.role={role} network.fixture=worked-recovery")
        },
        ready_point: ReadyPoint::AgentSignal,
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: boot.map(|assets| assets.kernel),
        root_image: boot.map(|assets| assets.root_image),
        initrd: None,
    })
    .collect::<Vec<_>>();
    let links = WORKED_NETWORK_LINKS
        .into_iter()
        .map(|(left, right, _)| {
            LinkDef::with_transport(
                node(left),
                node(right),
                SimDuration {
                    nanos: BASELINE_LINK_LATENCY_NANOS,
                },
                SimDuration { nanos: 100_000 },
                LinkLossProbability::ZERO,
                Some(10_000_000_000),
            )
            .map_err(|error| fixture_error(format!("build {left}-{right} link: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    World::from_nodes_and_links(nodes, links)
        .map_err(|error| fixture_error(format!("build worked-network world: {error}")))?
        .with_fault_topology(worked_network_fault_topology()?)
        .map_err(|error| fixture_error(format!("build worked-network fault topology: {error}")))
}

fn worked_network_fault_topology() -> Result<WorldFaultTopology, CliError> {
    let mut topology = WorldFaultTopology::default();
    let mut domain_targets = BTreeMap::<&str, Vec<WorldFaultTargetRef>>::new();
    for (left, right, domain) in WORKED_NETWORK_LINKS {
        let segment = signal_id(&format!("segment-{left}-{right}"))?;
        let interface_a = signal_id(&format!("interface-{left}-{right}-a"))?;
        let interface_b = signal_id(&format!("interface-{left}-{right}-b"))?;
        let fault_domains = domain
            .map(signal_id)
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();

        for (id, endpoint) in [(interface_a.clone(), left), (interface_b.clone(), right)] {
            topology.network_interfaces.push(WorldNetworkInterface {
                id,
                endpoint: signal_id(endpoint)?,
                technology: WorldNetworkTechnology::Ethernet,
                addresses: Vec::new(),
                fault_domains: Vec::new(),
            });
        }
        topology.network_segments.push(WorldNetworkSegment {
            id: segment.clone(),
            kind: WorldNetworkSegmentKind::Ethernet,
            interface_a,
            interface_b,
            minimum_latency_nanos: BASELINE_LINK_LATENCY_NANOS,
            mtu_bytes: 1500,
            medium: None,
            forwarders: Vec::new(),
            fault_domains,
        });
        for (from, to, direction) in [
            (left, right, FaultDirection::AToB),
            (right, left, FaultDirection::BToA),
        ] {
            topology.network_paths.push(WorldNetworkPath {
                id: signal_id(&format!("path-{from}-{to}"))?,
                direction,
                hops: vec![WorldNetworkPathHop::Segment {
                    segment: segment.clone(),
                    direction,
                }],
                mtu_bytes: 1500,
            });
        }
        if let Some(domain) = domain {
            for direction in [FaultDirection::AToB, FaultDirection::BToA] {
                domain_targets.entry(domain).or_default().push(
                    WorldFaultTargetRef::NetworkSegment {
                        segment: segment.clone(),
                        direction,
                    },
                );
            }
        }
    }
    topology.fault_domains = domain_targets
        .into_iter()
        .map(|(name, targets)| {
            Ok(WorldFaultDomain {
                id: signal_id(name)?,
                targets,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(topology)
}

fn signal_id(name: &str) -> Result<SignalId, CliError> {
    SignalId::parse(name)
        .map_err(|error| fixture_error(format!("invalid worked-network signal {name}: {error}")))
}
