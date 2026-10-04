//! Three-guest proxy topology, routed completion, and setup admission checks.

use super::*;
use crucible_core::{ConditionEvaluationPass, ConditionLeaf, ObservableEvent};

#[test]
fn proxy_profile_roundtrips_with_only_the_two_world_mediated_legs() -> Result<(), Box<dyn Error>> {
    let kernel = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"kernel"));
    let root = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"root"));
    let form = http_scenario(HttpServer::EnvoyProxy, kernel, root)?;
    let restored = ScenarioDefForm::from_canonical_toml(&form.to_canonical_toml()?)?;
    assert_eq!(restored, form);

    let world = restored.world();
    let nodes = world.vm_nodes().to_vec();
    assert_eq!(nodes.len(), 3);
    assert_eq!(world.nodes().len(), 3);
    assert_eq!(world.links().len(), 2);
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.id.name.as_str())
            .collect::<Vec<_>>(),
        vec!["curl", "envoy", "nginx"]
    );
    for node in &nodes {
        assert_eq!(node.smp_vcpus, 1);
        assert_eq!(node.memory_mib, 256);
        assert_eq!(node.white_box, WhiteBoxPolicy::Enabled);
        assert_eq!(node.kernel, Some(kernel));
        assert_eq!(node.root_image, Some(root));
    }
    assert!(nodes[0].cmdline.ends_with("crucible.workload=httpget"));
    assert!(
        nodes[1]
            .cmdline
            .ends_with("crucible.workload=httpd crucible.http.role=proxy")
    );
    assert!(
        nodes[2]
            .cmdline
            .ends_with("crucible.workload=httpd crucible.http.role=upstream")
    );

    let endpoints = world
        .links()
        .iter()
        .map(|link| {
            assert_eq!(link.latency().ticks, 250_000_000);
            assert_eq!(link.jitter().ticks, 0);
            assert_eq!(link.loss(), LinkLossProbability::ZERO);
            let (a, b) = link.endpoints();
            (a.name.clone(), b.name.clone())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        endpoints,
        BTreeSet::from([
            ("curl".to_owned(), "envoy".to_owned()),
            ("envoy".to_owned(), "nginx".to_owned()),
        ])
    );
    assert_eq!(
        HttpServer::EnvoyProxy.response(),
        HttpServer::Nginx.response()
    );
    Ok(())
}

#[test]
fn proxy_completion_requires_request_and_exact_body_on_both_legs() -> Result<(), Box<dyn Error>> {
    let asset = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"asset"));
    let form = http_scenario(HttpServer::EnvoyProxy, asset, asset)?;
    let lowered = form.plan().lower_to_event_graph_for_world(form.world())?;
    let condition = lowered.event_graph().events()[0]
        .trigger
        .as_ref()
        .ok_or("proxy completion must have an explicit trigger")?;
    let node = |name: &str| NodeId {
        name: name.to_owned(),
    };
    let client_leg = LinkId::for_endpoints(&node("curl"), &node("envoy"));
    let upstream_leg = LinkId::for_endpoints(&node("envoy"), &node("nginx"));
    let at = VirtualTime { ticks: 10 };
    let request = |link| {
        ObservableEvent::network_delivered(at, Some(link), b"GET / HTTP/1.1\r\n\r\n".to_vec())
    };
    let body = |link| {
        ObservableEvent::network_delivered(
            at,
            Some(link),
            HttpServer::EnvoyProxy.response().to_vec(),
        )
    };
    let evidence = vec![
        request(client_leg.clone()),
        body(client_leg.clone()),
        request(upstream_leg.clone()),
        body(upstream_leg.clone()),
        ObservableEvent::guest_marker(
            Icount { retired: 10 },
            node("curl"),
            MarkerId::from_name(HTTP_MARKER),
        ),
    ];
    let evaluate = |events| -> Result<bool, Box<dyn Error>> {
        let prefix = crucible_core::test_support::condition_prefix_from_observable_events_for_test(
            at.ticks, events,
        )?;
        let mut pass =
            ConditionEvaluationPass::from_log_prefix(prefix, |_: ConditionLeaf<'_>| false)
                .with_world_white_box_policies(form.world());
        Ok(pass.evaluate_assertion_condition(condition))
    };

    assert!(evaluate(evidence.clone())?);
    for missing in 0..evidence.len() {
        let mut incomplete = evidence.clone();
        incomplete.remove(missing);
        assert!(!evaluate(incomplete)?);
    }
    let mut wrong_upstream_body = evidence.clone();
    wrong_upstream_body[3] = ObservableEvent::network_delivered(
        at,
        Some(upstream_leg.clone()),
        HttpServer::EnvoyDirect.response().to_vec(),
    );
    assert!(!evaluate(wrong_upstream_body)?);
    let mut bypassed_upstream = evidence;
    bypassed_upstream[2] = request(client_leg.clone());
    bypassed_upstream[3] = body(client_leg);
    assert!(!evaluate(bypassed_upstream)?);
    Ok(())
}

#[test]
fn proxy_application_phase_requires_all_three_authenticated_setup_receipts() {
    let began = Instant::now();
    let receipt = "CRUCIBLE-RUNTIME-BOOT-V1 stage=after-quantum node=\"curl\" guest_stage=setup-complete stage_icount=42 setup_receipts=1";
    let envoy = receipt.replace("node=\"curl\"", "node=\"envoy\"");
    let nginx = receipt.replace("node=\"curl\"", "node=\"nginx\"");
    let mut watchdog = HttpHostWatchdog::new(began, HttpServer::EnvoyProxy);

    watchdog.observe(receipt, began + Duration::from_secs(10));
    watchdog.observe(&envoy, began + Duration::from_secs(20));
    watchdog.observe(
        &nginx.replace("setup_receipts=1", "setup_receipts=0"),
        began + Duration::from_secs(25),
    );
    watchdog.observe(
        &receipt.replace("node=\"curl\"", "node=\"other\""),
        began + Duration::from_secs(25),
    );
    assert_eq!(watchdog.phase(), "startup");
    assert_eq!(watchdog.setup_nodes.len(), 2);

    watchdog.observe(&nginx, began + Duration::from_secs(30));
    assert_eq!(watchdog.phase(), "application");
    assert_eq!(watchdog.setup_nodes.len(), 3);
    assert!(!watchdog.expired(began + Duration::from_secs(209)));
    assert!(watchdog.expired(began + Duration::from_secs(210)));
}
