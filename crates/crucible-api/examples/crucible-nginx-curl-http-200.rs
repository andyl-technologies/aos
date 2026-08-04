//! Runs a two-node Nginx/Curl scenario through the production QEMU lifecycle.

use std::error::Error;
use std::fs;
use std::time::Duration;

use crucible::{
    Action, AssertionDef, AssertionId, ContentAddressedBlobRef, ContentHash, EventGraph,
    FramePredicate, GuestWorkloadBinary, Icount, LinkDef, LinkId, LinkLossProbability, NodeId,
    NodeLifecycle, NodeTemplate, Plan, Predicate, Properties, Property, QuantumLoop,
    QuantumRequest, QuantumTerminalVerdict, ReadyPoint, ScenarioDefForm, ScheduledEventPayload,
    Seed, SimDuration, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{
    ProductionRootImageFormat, ProductionVmLifecycleConfig, build_production_vm_lifecycle_loop,
};

const HTTP_OK: &[u8] = b"HTTP/1.1 200";
const HTTP_GET: &[u8] = b"GET /";
const MAX_QUANTA: u64 = 10_000;
const QUANTUM_BUDGET: u64 = MAX_QUANTA;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunEvidence {
    response_at: VirtualTime,
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
    println!("response_delivery_ticks={}", result.response_at.ticks);
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
    let mut response_at = None;
    let mut advanced_quanta = 0_u64;
    let mut resolved_events = 0_usize;
    let mut decisions = 0_usize;
    let mut frontier = VirtualTime { ticks: 0 };
    let mut frame_previews = Vec::new();

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
        for event in &outcome.resolved_events {
            let ScheduledEventPayload::BackendInput(input) = &event.payload else {
                continue;
            };
            if frame_previews.len() < 16 {
                frame_previews.push(hex_preview(&input.payload));
            }
            if contains(&input.payload, HTTP_OK) {
                response_at.get_or_insert_with(|| event.key.virtual_time());
            }
        }
        match lifecycle.take_terminal_verdict() {
            Some(QuantumTerminalVerdict::Passed) => {
                let response_at = response_at
                    .ok_or("scenario passed without a delivered HTTP/1.1 200 response frame")?;
                lifecycle.shutdown()?;
                return Ok(RunEvidence {
                    response_at,
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
         decisions={decisions} frame_previews={}",
        frontier.ticks,
        frame_previews.join(",")
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
            nanos: 1_048_576_000,
        },
        SimDuration { nanos: 0 },
        LinkLossProbability::ZERO,
        None,
    )?;
    let world = World::from_nodes_and_links(vec![nginx, curl], vec![link])?;
    let assertion = AssertionDef {
        id: AssertionId::from_name("curl-receives-http-200"),
        message: String::from("Curl receives an HTTP 200 response from Nginx"),
        property: Property::Eventually {
            trigger: Predicate::once(Predicate::network_match(
                Some(LinkId::from_name("curl--nginx")),
                FramePredicate::contains(HTTP_GET.to_vec()),
            )),
            property: Predicate::network_match(
                Some(LinkId::from_name("curl--nginx")),
                FramePredicate::contains(HTTP_OK.to_vec()),
            ),
            deadline: VirtualTime {
                ticks: 600_000_000_000,
            },
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
        .when(Predicate::all_of(vec![
            Predicate::once(Predicate::network_match(
                Some(LinkId::from_name("curl--nginx")),
                FramePredicate::contains(HTTP_GET.to_vec()),
            )),
            Predicate::network_match(
                Some(LinkId::from_name("curl--nginx")),
                FramePredicate::contains(HTTP_OK.to_vec()),
            ),
        ]))
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(96)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
