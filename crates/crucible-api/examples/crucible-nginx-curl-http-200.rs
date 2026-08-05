//! Runs a two-node Nginx/Curl scenario through the production QEMU lifecycle.
//!
//! This example is a small, complete tour of Crucible's main building blocks:
//!
//! 1. `nginx_curl_scenario` describes two virtual machines, the simulated
//!    network link between them, and the properties the run must satisfy.
//! 2. `main` checks that the checked-in TOML scenario is the canonical form of
//!    that Rust description and configures the production QEMU backend.
//! 3. `run_once` advances the deterministic scheduler one quantum at a time
//!    until the scenario passes, fails, or exhausts its budget.
//!
//! The `nginx` guest serves HTTP on `10.0.0.2:8080`. The `curl` guest makes one
//! request and emits the `curl-receives-http-200` guest assertion through the
//! white-box doorbell after observing status 200. Crucible records that typed
//! marker and turns the satisfied assertion into the terminal pass action.
//!
//! Run the binary with `--emit-scenario` to print the canonical TOML fixture.
//! The production run instead expects paths to QEMU, the Crucible QEMU plugin,
//! a kernel, a raw root image, and that generated scenario fixture, in that
//! order. These artifacts are normally supplied by the repository's Nix build;
//! the example does not discover or download host tools.

use std::error::Error;
use std::fs;
use std::time::Duration;

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, ContentAddressedBlobRef, ContentHash,
    EventGraph, GuestWorkloadBinary, Icount, LinkDef, LinkLossProbability, NodeId, NodeLifecycle,
    NodeTemplate, Plan, Predicate, Properties, Property, QuantumLoop, QuantumRequest,
    QuantumTerminalVerdict, ReadyPoint, ScenarioDefForm, Seed, SimDuration, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_api::{
    ProductionRootImageFormat, ProductionVmLifecycleConfig, build_production_vm_lifecycle_loop,
};

const MAX_QUANTA: u64 = 30_000;

/// Limits the number of authoritative scheduler quanta admitted for this run.
///
/// Keeping this equal to [`MAX_QUANTA`] makes the outer driver loop and the
/// backend enforce the same upper bound.
const QUANTUM_BUDGET: u64 = MAX_QUANTA;

/// Records the stable evidence reported after a successful run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunEvidence {
    /// Identifies the final immutable Crucible configuration.
    final_configuration: ContentHash,
}

/// Parses the command line, validates the scenario fixture, and runs it.
///
/// # Errors
///
/// Returns an error when arguments are invalid, the fixture cannot be read or
/// parsed, the fixture and Rust builder disagree, or the production lifecycle
/// cannot complete successfully.
fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    // Scenario emission and execution deliberately share one builder. This
    // prevents the human-readable fixture from drifting away from the scenario
    // that developers review in Rust.
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
    // Equality here compares the parsed definitions, not incidental whitespace
    // in the TOML file.
    if source != authored {
        return Err("scenario fixture differs from its canonical Rust builder".into());
    }

    // `ProductionVmLifecycleConfig` supplies real VM artifacts while the
    // scenario remains content-addressed and portable. The synthetic blob
    // references below therefore identify roles; this configuration resolves
    // those roles to the files used by the production backend.
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

/// Drives one deterministic lifecycle run to a terminal verdict.
///
/// A quantum is Crucible's unit of scheduler progress. Each call consumes the
/// previous immutable [`crucible::Configuration`] and returns its successor,
/// together with the decisions and scheduled events that produced it.
///
/// # Errors
///
/// Returns an error when lifecycle construction or execution fails, an
/// assertion fails, shutdown fails, or no terminal verdict is reached before
/// [`MAX_QUANTA`].
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

    // The counters are diagnostic only. If the budget is exhausted, they make
    // it easier to distinguish a scheduler that never advanced from a workload
    // that advanced but never produced the expected event or decision.
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
        // Verdicts are reported separately from `drive_quantum` so every
        // returned configuration can still be inspected or persisted.
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

/// Builds the canonical two-node HTTP scenario.
///
/// The returned form contains the world (machines and links), plan (event
/// graph), properties (assertions), and deterministic random seed. Keeping all
/// four together is what makes the emitted TOML reproducible.
///
/// # Errors
///
/// Returns an error when a link, world, property set, event graph, plan, or
/// canonical scenario violates Crucible's validation rules.
fn nginx_curl_scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    // `GuestWorkloadBinary` selects one of the purpose-built programs already
    // installed in the root image. Its command-line fragment is appended to
    // the common kernel command line configured in `main`.
    let nginx = node(
        "nginx",
        GuestWorkloadBinary::Httpd.selected_cmdline("console=ttyS0 address=10.0.0.2 port=8080"),
        WhiteBoxPolicy::Disabled,
    );
    let curl = node(
        "curl",
        GuestWorkloadBinary::ClientLoop
            .selected_cmdline("console=ttyS0 address=10.0.0.3 target=10.0.0.2:8080 count=1"),
        WhiteBoxPolicy::Enabled,
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
    // `guest_sometimes` declares an eventual-success property whose truth must
    // arrive as a typed assertion marker from a white-box-enabled guest. The
    // Curl workload emits that marker only after observing HTTP status 200.
    let assertion = AssertionDef::guest_sometimes(
        AssertionId::from_name("curl-receives-http-200"),
        "Curl receives an HTTP 200 response from Nginx",
    );
    // `Always` is a safety property. It is violated immediately if either node
    // enters the crashed lifecycle state.
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
    // Assertions describe truth over time; the event graph decides what to do
    // when that truth changes. Here, satisfying the HTTP assertion emits the
    // explicit terminal pass action.
    let graph = EventGraph::builder()
        .event("pass-on-http-200")
        .when(Predicate::assertion_state(
            AssertionId::from_name("curl-receives-http-200"),
            AssertionPhase::Satisfied,
        ))
        .action(Action::pass())
        .build_with_assertions_for_world(assertion_ids.clone(), &world)?;
    let plan = Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)?;
    // The seed makes all pseudo-random choices repeatable. A draw cap of zero
    // rejects application-random requests because neither workload needs them.
    Ok(ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0x200),
        0,
    )?)
}

/// Creates one x86_64 VM description for the shared test image.
///
/// Both guests boot the same kernel and root image; `cmdline` selects their
/// workload and network identity. `white_box` controls whether the guest may
/// send typed observations through the Crucible doorbell: the Curl node needs
/// it for its assertion marker, while the Nginx node does not. A ready point of
/// zero requests a snapshot after the guest has retired zero instructions.
fn node(name: &str, cmdline: String, white_box: WhiteBoxPolicy) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 256,
        cmdline,
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: Some(blob("aos-linux-crucible")),
        root_image: Some(blob("aos-nginx-curl-root-image")),
        initrd: None,
    }
}

/// Creates a node identifier from a readable scenario-local name.
fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

/// Creates a deterministic placeholder reference for a production artifact.
///
/// The namespace string versions the hashing scheme so a future incompatible
/// asset convention can use a new namespace without silently reusing IDs.
fn blob(name: &str) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
        "crucible.nginx-curl-http-200.asset.v1",
        name,
    ))
}
