//! Runs a two-node Nginx/Curl scenario through the production QEMU lifecycle.

use std::error::Error;
use std::fs;
use std::time::Duration;

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, ContentAddressedBlobRef, ContentHash,
    EventGraph, GuestWorkloadBinary, Icount, LinkDef, LinkLossProbability, NodeId, NodeLifecycle,
    NodeTemplate, Plan, Predicate, Properties, Property, QuantumLoop, QuantumRequest,
    QuantumTerminalVerdict, ReadyPoint, RegexProgram, ScenarioDefForm, Seed, SimDuration,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{
    ProductionRootImageFormat, ProductionVmLifecycleConfig, build_production_vm_lifecycle_loop,
};

const MAX_QUANTA: u64 = 10_000;
const QUANTUM_BUDGET: u64 = 4_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunEvidence {
    final_configuration: ContentHash,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--emit-scenario" {
        print!("{}", nginx_curl_scenario()?.to_canonical_toml()?);
        return Ok(());
    }
    let [qemu, plugin, kernel, root_image, scenario_path] = args.as_slice() else {
        return Err("usage: crucible-nginx-curl-http-200 --emit-scenario | \
             QEMU PLUGIN KERNEL ROOT SCENARIO"
            .into());
    };

    let scenario_text = fs::read_to_string(scenario_path)?;
    let source = ScenarioDefForm::from_canonical_toml(&scenario_text)?;
    let authored = nginx_curl_scenario()?;
    if source != authored {
        return Err("scenario fixture differs from its canonical Rust builder".into());
    }

    let config = ProductionVmLifecycleConfig::new(qemu, plugin, kernel, root_image)
        .with_root_image_format(ProductionRootImageFormat::Raw)
        .with_kernel_cmdline_prefix("console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init")
        .with_run_ceiling_icount(40_000_000_000)
        .with_quantum_budget(QUANTUM_BUDGET)
        .with_completion_timeout(Duration::from_secs(300));

    let result = run_once(&source, &config)?;

    println!("PASS");
    println!("scenario=nginx-curl-http-200");
    println!("backend=production-qemu-lifecycle");
    println!("topology=two-vm-hostless-world-link");
    println!("server_workload=nginx");
    println!("client_workload=curl");
    println!("http_status=200");
    println!("assertion=curl-receives-http-200:satisfied");
    println!(
        "final_configuration={}",
        result.final_configuration.to_hex()
    );
    Ok(())
}

fn run_once(
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<RunEvidence, Box<dyn Error>> {
    let scenario = source.scenario_def();
    let mut lifecycle = build_production_vm_lifecycle_loop(&scenario, source, config)?;
    let mut configuration = crucible::Configuration::genesis(scenario);
    let mut advanced_quanta = 0_u64;
    let mut resolved_events = 0_usize;
    let mut decisions = 0_usize;
    let mut frontier = VirtualTime { ticks: 0 };

    for _quantum in 0..MAX_QUANTA {
        let outcome = lifecycle.drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })?;
        frontier = outcome.frontier;
        advanced_quanta =
            advanced_quanta.saturating_add(u64::from(outcome.advanced_node.is_some()));
        resolved_events = resolved_events.saturating_add(outcome.resolved_events.len());
        decisions = decisions.saturating_add(outcome.decisions.len());
        configuration = outcome.configuration;
        match lifecycle.take_terminal_verdict() {
            Some(QuantumTerminalVerdict::Passed) => {
                lifecycle.shutdown()?;
                return Ok(RunEvidence {
                    final_configuration: configuration.id(),
                });
            }
            Some(QuantumTerminalVerdict::Failed(violations)) => {
                lifecycle.shutdown()?;
                return Err(format!("scenario failed: {}", violations.join("; ")).into());
            }
            None => {}
        }
    }

    lifecycle.shutdown()?;
    Err(format!(
        "scenario did not pass within {MAX_QUANTA} scheduler quanta: \
         frontier={} advanced_quanta={advanced_quanta} resolved_events={resolved_events} \
         decisions={decisions}",
        frontier.ticks
    )
    .into())
}

fn nginx_curl_scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let nginx = node(
        "nginx",
        GuestWorkloadBinary::Httpd.selected_cmdline("console=ttyS0 address=10.0.0.2 port=8080"),
    );
    let curl = node(
        "curl",
        GuestWorkloadBinary::ClientLoop
            .selected_cmdline("console=ttyS0 address=10.0.0.3 target=10.0.0.2:8080 count=1"),
    );
    let link = LinkDef::with_transport(
        node_id("curl"),
        node_id("nginx"),
        SimDuration {
            nanos: 5_000_000_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::ZERO,
        None,
    )?;
    let world = World::from_nodes_and_links(vec![nginx, curl], vec![link])?;
    let assertion = AssertionDef {
        id: AssertionId::from_name("curl-receives-http-200"),
        message: String::from("Curl receives an HTTP 200 response from Nginx"),
        property: Property::Sometimes {
            predicate: Predicate::console_match(
                node_id("curl"),
                RegexProgram::from_pattern("(^|\\n)CURL_STATUS=200(\\r?\\n|$)"),
            ),
        },
    };
    let no_crashes = AssertionDef {
        id: AssertionId::from_name("no-crashes"),
        message: String::from("Nginx and Curl must not crash"),
        property: Property::Always {
            predicate: Predicate::not(Predicate::any_of(vec![
                Predicate::node_state(node_id("nginx"), NodeLifecycle::Crashed),
                Predicate::node_state(node_id("curl"), NodeLifecycle::Crashed),
            ])),
        },
    };
    let properties = Properties::from_assertions_for_world(&world, vec![assertion, no_crashes])?;
    let assertion_ids = properties
        .assertions()
        .iter()
        .map(|assertion| assertion.id.clone())
        .collect::<Vec<_>>();
    let graph = EventGraph::builder()
        .event("pass-on-http-200")
        .when(Predicate::assertion_state(
            AssertionId::from_name("curl-receives-http-200"),
            AssertionPhase::Satisfied,
        ))
        .action(Action::pass())
        .build_with_assertions_for_world(assertion_ids.clone(), &world)?;
    let plan = Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)?;
    Ok(ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0x200),
        10,
    )?)
}

fn node(name: &str, cmdline: String) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 256,
        cmdline,
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: Some(blob("aos-linux-crucible")),
        root_image: Some(blob("aos-nginx-curl-root-image")),
        initrd: None,
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn blob(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.nginx-curl-http-200.asset.v1",
        name,
    ))
}
