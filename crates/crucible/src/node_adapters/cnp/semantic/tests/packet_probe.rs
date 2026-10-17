//! Drives the installed source through the independent protocol-only runner.
//!
//! The actual kernel/ELF and closed-gate bytes are observed independently. These
//! cases do not cover a complete behavioral class or authorize host admission.

#![cfg(test)]

use super::*;
use crucible_node_provider::conformance::*;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

struct ProbeSource(SpawnedFixture);

impl ProbeSource {
    fn launch() -> Self {
        let executable = std::env::var_os("CRUCIBLE_INSTALLED_PACKET_SOURCE")
            .map(std::path::PathBuf::from)
            .unwrap();
        let mut source = Self(Fixture::spawn_transport_configured(
            false,
            false,
            true,
            None,
            false,
            false,
            Some(executable),
        ));
        super::super::operational_poll::original_poll(|| {
            assert!(source.0.child.try_wait().unwrap().is_none());
            std::fs::metadata(&source.0.socket)
                .ok()
                .filter(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
                .map(|_| ())
        });
        source
    }

    fn run(&self, plan: &ProbePlan) -> ConformanceReport {
        self.run_original(plan, None).0
    }

    fn run_original(
        &self,
        plan: &ProbePlan,
        credit: Option<usize>,
    ) -> (ConformanceReport, Option<OriginalProbeResponses>) {
        let mut connector = UnixProbeConnector::new(
            self.0.socket.clone(),
            rustix::process::geteuid().as_raw(),
            &self.0.executable,
            Duration::from_secs(3),
        )
        .unwrap();
        let originals =
            credit.map(|maximum| connector.retain_original_responses(64, maximum).unwrap());
        let report = run(
            plan,
            &mut connector,
            BTreeMap::from([
                (
                    "launch-token".into(),
                    serde_json::to_value(Bytes::new(vec![7; 32])).unwrap(),
                ),
                (
                    "hello-challenge".into(),
                    serde_json::to_value(Bytes::new(vec![3; 32])).unwrap(),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(
            report.endpoints[0].peer_pid,
            U64::new(u64::from(self.0.child.id()))
        );
        assert_eq!(
            report.endpoints[0].executable,
            self.0.bootstrap.protocol.executable
        );
        let mut byte = [0; 1025];
        assert_eq!(
            self.0.effects.recv(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        (report, originals)
    }
}

impl Drop for ProbeSource {
    fn drop(&mut self) {
        if self.0.child.try_wait().unwrap().is_none() {
            self.0.child.kill().unwrap();
        }
        self.0.child.wait().unwrap();
        std::fs::remove_dir_all(&self.0.directory).unwrap();
    }
}

fn binding(name: &str) -> Value {
    serde_json::json!({"$binding":name})
}

fn oracle(pointer: &str, value: impl Serialize) -> ReplyAssertion {
    ReplyAssertion {
        pointer: pointer.into(),
        equals: serde_json::to_value(value).unwrap(),
    }
}

fn exchange(request: &str, method: Method, check: CheckKind, body: impl Serialize) -> ProbeStep {
    let envelope = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(id("packet-session"))),
        incarnation_id: Nullable(Some(id("packet-incarnation"))),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(id(request))),
        sequence: U64::new(2),
        method,
        body: object(body),
        extensions: Extensions::new(),
    };
    let mut request_value = serde_json::to_value(envelope).unwrap();
    request_value["sequence"] = serde_json::json!({"$sequence":"outgoing"});
    ProbeStep::Exchange {
        id: id(request),
        check,
        request: request_value,
        expected: Expectation::Completed,
        assertions: vec![],
        captures: BTreeMap::new(),
    }
}

fn original_gate_plan(source: &ProbeSource) -> ProbePlan {
    let bootstrap = &source.0.bootstrap;
    let mut hello = serde_json::to_value(bootstrap.protocol.hello()).unwrap();
    hello["body"]["admission_token"] = binding("launch-token");
    hello["body"]["controller_nonce"] = binding("hello-challenge");
    let mut discover = exchange(
        "probe-discover",
        Method::Discover,
        CheckKind::DescriptorBinding,
        DiscoverRequest {
            profile_ids: vec![
                bootstrap.selection.provider.supported_profiles[0]
                    .profile_id
                    .clone(),
            ],
            cursor: None,
            extensions: Extensions::new(),
        },
    );
    if let ProbeStep::Exchange { assertions, .. } = &mut discover {
        assertions.push(oracle(
            "/body/result/provider_manifest",
            &bootstrap.selection.provider,
        ));
        assertions.push(oracle(
            "/body/result/profiles",
            &bootstrap.selection.provider.supported_profiles,
        ));
    }
    let mut realize = exchange(
        "probe-realize",
        Method::Realize,
        CheckKind::PausedActivation,
        &bootstrap.selection.realize,
    );
    if let ProbeStep::Exchange {
        assertions,
        captures,
        ..
    } = &mut realize
    {
        assertions.push(oracle(
            "/body/result/realization_manifest",
            &bootstrap.selection.realization,
        ));
        captures.insert(
            "original-gate-root".into(),
            "/body/result/closed_gate_receipt".into(),
        );
    }
    ProbePlan {
        schema_version: 1,
        fixture: id("installed-finite-packet-source.gate-protocol-v1"),
        required_checks: BTreeSet::from([
            CheckKind::Hello,
            CheckKind::DescriptorBinding,
            CheckKind::PausedActivation,
        ]),
        steps: vec![
            ProbeStep::Exchange {
                id: id("probe-hello"),
                check: CheckKind::Hello,
                request: hello,
                expected: Expectation::Completed,
                assertions: vec![
                    oracle("/body/result/limits", bootstrap.protocol.limits()),
                    oracle(
                        "/body/result/provider_identity",
                        &bootstrap.selection.provider,
                    ),
                ],
                captures: BTreeMap::new(),
            },
            discover,
            realize,
            ProbeStep::ReceiveBlob {
                id: id("probe-receive-original-gate"),
                reference: binding("original-gate-root"),
                maximum_chunks: 16,
                reference_binding: id("retained-gate-root"),
                bytes_binding: id("retained-gate-bytes"),
            },
            ProbeStep::InspectContent {
                id: id("probe-inspect-original-gate"),
                reference: binding("retained-gate-root"),
                bytes: binding("retained-gate-bytes"),
                assertions: vec![
                    oracle("/schema", "source-owned.packet-native/2"),
                    oracle("/native_pid", U64::new(u64::from(source.0.child.id()))),
                    oracle("/original/method", "realize"),
                    oracle("/inventory/gate_closed", true),
                    oracle("/inventory/private_mutations", U64::new(0)),
                    oracle("/inventory/packet_effects", U64::new(0)),
                    oracle("/inventory/pending", &bootstrap.events),
                    oracle("/inventory/retained_outputs", Vec::<Id>::new()),
                ],
                captures: BTreeMap::new(),
            },
        ],
    }
}

#[test]
fn installed_packet_peer_protocol_runner_retains_actual_closed_gate_without_class_authority() {
    let source = ProbeSource::launch();
    let plan = original_gate_plan(&source);
    let report = source.run(&plan);
    assert!(report.passed(), "{report:?}");
    assert!(report.protocol_only);
    if let Some(destination) = std::env::var_os("CRUCIBLE_PACKET_PROBE_DIRECTORY") {
        let directory = std::path::PathBuf::from(destination);
        assert!(directory.is_dir());
        std::fs::write(directory.join("original-gate-plan.json"), bytes(&plan)).unwrap();
        std::fs::write(
            directory.join("original-gate-report.json"),
            report.canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("original-source-scope.json"), bytes(serde_json::json!({
            "schema":"packet.protocol-collection-scope.v1", "authority":"none: protocol-only collection",
            "selection":source.0.bootstrap.selection, "program":source.0.bootstrap.events,
            "initial_coordinator":{"schema":"packet.native-lifecycle-test.v1","world":source.0.bootstrap.selection.world},
        }))).unwrap();
    }
}

#[test]
fn installed_packet_peer_wrong_gate_oracle_retains_failure_and_unexecuted_case() {
    let source = ProbeSource::launch();
    let mut plan = original_gate_plan(&source);
    let ProbeStep::InspectContent { assertions, .. } = plan.steps.last_mut().unwrap() else {
        panic!("original gate inspection absent")
    };
    assertions.push(oracle("/inventory/gate_closed", false));
    plan.steps.push(exchange(
        "dependent-discover",
        Method::Discover,
        CheckKind::DescriptorBinding,
        DiscoverRequest {
            profile_ids: vec![],
            cursor: None,
            extensions: Extensions::new(),
        },
    ));
    let report = source.run(&plan);
    assert!(!report.passed());
    assert_eq!(report.results[4].disposition, CheckDisposition::Failed);
    assert_eq!(report.results[5].disposition, CheckDisposition::NotExecuted);
    assert!(report.protocol_only);
}

#[test]
fn installed_packet_original_response_journal_reopens_complete_native_gate() {
    let source = ProbeSource::launch();
    let plan = original_gate_plan(&source);
    let (report, originals) = source.run_original(&plan, Some(32 * 1024 * 1024));
    assert!(report.passed(), "{report:?}");
    let originals = originals.unwrap();
    let program = PacketProgramDefinition {
        schema: "source-owned.packet-program.v1".into(),
        events: source.0.bootstrap.events.clone(),
    };
    let gate =
        crucible_node_provider::reference_packet::original_gate::inspect_original_packet_gate(
            &originals,
            &source.0.bootstrap.selection,
            &program,
            &report,
        )
        .unwrap();
    assert_eq!(gate.peer(), &report.endpoints[0]);
    gate.reference().verify(gate.bytes()).unwrap();
    assert_eq!(
        gate.native().native_pid.get(),
        u64::from(source.0.child.id())
    );

    let mut changed = program.clone();
    changed.events[1].payload = Some(Bytes::new(b"changed".to_vec()));
    assert!(
        crucible_node_provider::reference_packet::original_gate::inspect_original_packet_gate(
            &originals,
            &source.0.bootstrap.selection,
            &changed,
            &report,
        )
        .is_err()
    );
    let mut foreign = report.clone();
    foreign.endpoints[0].peer_pid = U64::new(u64::from(source.0.child.id()) + 1);
    assert!(
        crucible_node_provider::reference_packet::original_gate::inspect_original_packet_gate(
            &originals,
            &source.0.bootstrap.selection,
            &program,
            &foreign,
        )
        .is_err()
    );

    let rows = originals.records().unwrap();
    assert!(rows.len() > 3);

    let mut transfer = None;
    let mut reference = None;
    let mut body = Vec::new();
    let mut finished = false;
    for row in rows.iter() {
        assert_eq!(row.state(), OriginalProbeResponseState::Received);
        assert_eq!(row.peer(), &report.endpoints[0]);
        row.reference().unwrap().verify(row.bytes()).unwrap();
        let value = canonical::parse_json(row.bytes(), 65536).unwrap();
        assert!(value.pointer("/body/admission_token").is_none());
        let original: Envelope = serde_json::from_value(value).unwrap();
        if original.message != MessageKind::Request {
            continue;
        }
        match decode_request(original.method, &original.body).unwrap() {
            RequestBody::BlobBegin(begin) => {
                assert!(transfer.is_none());
                transfer = Some(begin.transfer_id);
                reference = Some(begin.content);
            }
            RequestBody::BlobChunk(chunk) => {
                assert!(!finished);
                assert_eq!(Some(chunk.transfer_id), transfer);
                assert_eq!(chunk.offset.get(), body.len() as u64);
                body.extend_from_slice(chunk.bytes.as_slice());
            }
            RequestBody::BlobFinish(finish) => {
                assert_eq!(Some(finish.transfer_id), transfer);
                assert!(!finished);
                reference.as_ref().unwrap().verify(&body).unwrap();
                finished = true;
            }
            _ => panic!("unexpected source-origin request"),
        }
    }
    assert!(finished);
    let native: crucible_node_provider::reference_packet::control::PacketNativeRecord =
        serde_json::from_value(canonical::parse_json(&body, 65536).unwrap()).unwrap();
    assert_eq!(native.native_pid.get(), u64::from(source.0.child.id()));
    assert!(native.inventory.gate_closed);
    assert_eq!(native.inventory.pending, source.0.bootstrap.events);
    assert_eq!(native.inventory.private_mutations, U64::new(0));
    assert_eq!(native.inventory.packet_effects, U64::new(0));
    assert!(native.inventory.retained_outputs.is_empty());
    assert!(report.protocol_only);
}

#[test]
fn installed_packet_original_response_undercredit_retains_failed_population() {
    let source = ProbeSource::launch();
    let plan = original_gate_plan(&source);
    // The runner's initial unnegotiated incoming allowance is 16 MiB. A smaller
    // journal must fence before its first receive rather than trust peer limits
    // that have not yet been authenticated by the original Hello reply.
    let (report, originals) = source.run_original(&plan, Some(65536));
    assert_eq!(report.results[0].disposition, CheckDisposition::Failed);
    assert!(
        report.results[1..]
            .iter()
            .all(|row| { row.disposition == CheckDisposition::NotExecuted })
    );
    assert!(originals.unwrap().records().unwrap().is_empty());
    assert!(!report.passed());
    assert!(report.protocol_only);
}
