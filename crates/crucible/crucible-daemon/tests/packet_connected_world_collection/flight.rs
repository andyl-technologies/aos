//! Drives original connected custody, full-position grants and durable ACK roots.

use super::{id, schedule, setup};
use crucible_daemon::{
    node_observed_executor::StoredWorldActivationPublisher, node_qualification::*,
};
use crucible_engine::{
    node_admission::AdmissionLimits,
    node_contract::{
        BeginResult, OperationRequest, OperationToken, RuntimeError, RuntimeLimits,
        RuntimePollFailure,
    },
    node_scheduling::SchedulingError,
};
use crucible_node_format::{Phase, canonical};
use crucible_store::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

struct Ticket {
    case: String,
    grant: usize,
    member: usize,
    after: bool,
    original: Option<OriginalRealizedCaseReservation>,
}

// Physical watchdog time bounds this native fixture only. Every grant shares
// the same unchanged sixty-second transaction deadline; it is never renewed.
#[allow(clippy::disallowed_methods)]
fn await_progress<T>(deadline: Instant, mut action: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
    let mut context = Context::from_waker(Waker::noop());
    loop {
        assert!(
            Instant::now() < deadline,
            "original connected lifecycle exceeded its sixty-second deadline"
        );
        match action(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn assert_producer_blocked<T>(
    result: Result<T, RuntimePollFailure>,
    producer: &crucible_node_format::Id,
) {
    let expected = SchedulingError::InputBlocked(producer.clone()).to_string();
    match result {
        Err(RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(reason))) => {
            assert_eq!(reason, expected, "cut must wait for its actual producer");
        }
        _ => panic!("cut did not receive the original producer-frontier refusal"),
    }
}

#[allow(clippy::disallowed_methods)]
pub(super) fn run() {
    let installed = setup::install();
    assert!(Rc::ptr_eq(
        &installed.scene.host_owner.source(),
        &installed.scene.host_source
    ));
    eprintln!(
        "original connected evidence directory: {}",
        installed.directory.display()
    );
    let authority = &installed.authority;
    let plan = Rc::new(authority.collection_plan().unwrap());
    let schedule = authority.schedule();
    assert_eq!(schedule.grants.len(), schedule::GRANT_COUNT);
    assert_eq!(
        schedule
            .grants
            .iter()
            .filter(|grant| grant.node != schedule::node(0))
            .count(),
        schedule::INPUT_STAGE_COUNT,
        "every reactive grant has its own retained input stage"
    );
    let runtime_limits = RuntimeLimits {
        maximum_nodes: 4,
        maximum_owners: 4,
        maximum_operations: schedule::RETAINED_OPERATION_CAPACITY,
        maximum_retained_outputs: 3,
    };
    let supervisor = PacketWorldHostSupervisor::new().unwrap();
    let reservations = supervisor
        .reserve_connected_original(
            &installed.scene.activation,
            &installed.scene.coordinator,
            runtime_limits,
        )
        .unwrap();
    let mut runners: [Option<ProductionConformanceRunner<'_>>; 3] = std::array::from_fn(|member| {
        let node = &schedule.nodes[member];
        Some(
            ProductionConformanceRunner::new(
                authority.as_ref(),
                node.clone(),
                authority.binding(node).unwrap().identity().unwrap(),
                authority.plan_bytes(),
                authority.plan_reference(),
                installed.qualification_limits,
            )
            .unwrap(),
        )
    });
    let mut tickets = Vec::with_capacity(schedule.cases.len());
    for case in &schedule.cases {
        let Some(operation) = &case.operation else {
            continue;
        };
        let grant = schedule
            .grants
            .iter()
            .position(|grant| &grant.operation == operation)
            .unwrap();
        let member = schedule
            .nodes
            .iter()
            .position(|node| node == &case.node)
            .unwrap();
        let oracle = &authority
            .witness_plan()
            .cases
            .iter()
            .find(|row| row.id == case.id)
            .unwrap()
            .oracle;
        tickets.push(Ticket {
            case: case.id.clone(),
            grant,
            member,
            after: case.kind == PacketConnectedCaseKind::AfterRetirement,
            original: Some(
                runners[member]
                    .as_mut()
                    .unwrap()
                    .reserve_exact_case(&case.id, oracle, 8 * 1024 * 1024)
                    .unwrap(),
            ),
        });
    }
    let result_references: Vec<RefName> = (0..schedule.grants.len())
        .map(|index| {
            RefName::new(format!(
                "node-packet-collecting-results/connected/original-{index:02}"
            ))
            .unwrap()
        })
        .collect();
    let mut results =
        StoredPacketConnectedResultPublisher::new(PacketConnectedPublicationRequest {
            authority: authority.clone(),
            plan: plan.clone(),
            requirements: installed.scene.requirements.clone(),
            blobs: installed.blobs.clone(),
            refs: installed.refs.clone(),
            references: result_references.clone(),
            maximum_each_bytes: 8 * 1024 * 1024,
            maximum_total_bytes: schedule::GRANT_COUNT * 8 * 1024 * 1024,
        })
        .unwrap();
    let activation_reference =
        RefName::new("node-world-activations/packet-connected-original").unwrap();
    let mut activation = StoredWorldActivationPublisher::new(
        installed.blobs.clone(),
        installed.refs.clone(),
        activation_reference.clone(),
    )
    .unwrap();
    let peers = installed.peers(reservations.native, reservations.journal);
    let mut holder = match authority.prepare_connected_host(PacketConnectedHostRequest {
        peers,
        plan,
        requirements: installed.scene.requirements.clone(),
        activation: installed.scene.activation.clone(),
        runtime_custody: reservations.runtime,
        admission_limits: AdmissionLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            ..AdmissionLimits::default()
        },
        runtime_limits,
    }) {
        Ok(holder) => holder,
        Err(failure) => {
            let original = failure.original;
            panic!(
                "original connected pre-Child holder refused: {:?}; {:?}",
                failure.error,
                original.start_error()
            );
        }
    };
    let mut tokens: Vec<OperationToken> = Vec::with_capacity(schedule.grants.len());
    let mut host_witness = None;
    let mut nonempty_host_witness = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    let execution = catch_unwind(AssertUnwindSafe(|| {
        holder.start().unwrap_or_else(|_| {
            panic!(
                "original connected start refused: {:?}",
                holder.start_error()
            )
        });
        let runtime = holder.runtime().unwrap();
        runtime.arm_all().unwrap();
        runtime.activate_initial(&mut activation, 131072).unwrap();

        // There is no empty-queue exemption: the producer has not closed six
        // picoseconds, so the relay cannot stage that cut yet.
        let slow = runtime.stage_exact_inputs(
            &schedule::node(1),
            id("slow-producer-stage"),
            id("slow-producer-batch"),
            schedule::position(6, 0, Phase::Reaction),
        );
        assert_producer_blocked(slow, &schedule::node(0));
        // This observation borrows the actual initialized scheduler after the
        // real slow-producer refusal, before any execution grant is submitted.
        let cut = schedule::position(0, 0, Phase::BoundaryControl);
        let ordinal = crucible_node_format::U64::new(0);
        let credit = 64 * 1024 * 1024;
        let observation = runtime
            .host_scheduling_observation(&installed.scene.host_source)
            .unwrap();
        let (common, scheduling) = observation.snapshots(cut, ordinal, credit).unwrap();
        let limits = crucible_engine::node_contract::HostSchedulingContinuationLimits {
            maximum_record_bytes: credit,
            lineage: crucible_engine::node_contract::OriginalInputLineageLimits::default(),
        };
        let original_host = observation.continuation_v2(cut, ordinal, limits).unwrap();
        assert_eq!(
            original_host.record().source,
            *installed.scene.host_source.selection()
        );
        assert_eq!(original_host.record().scheduling, scheduling);
        let crucible_engine::node_contract::HostSchedulingRuntimeRecord::Legacy(record) =
            &original_host.record().runtime
        else {
            panic!("pre-Begin original host ledger changed its codec");
        };
        assert_eq!(**record, common);
        original_host
            .encoded()
            .reference
            .verify(&original_host.encoded().bytes)
            .unwrap();
        let decoded = crucible_engine::node_contract::HostSchedulingContinuationRecord::decode(
            &original_host.encoded().bytes,
            limits,
        )
        .unwrap();
        assert_eq!(&decoded, original_host.record());
        std::fs::write(
            installed
                .directory
                .join("original-host-continuation-before-begin.json"),
            &original_host.encoded().bytes,
        )
        .unwrap();
        let commitment = canonical::canonical_json(
            &serde_json::to_value(&original_host.encoded().reference).unwrap(),
        )
        .unwrap();
        std::fs::write(
            installed
                .directory
                .join("original-host-continuation-before-begin-ref.json"),
            commitment,
        )
        .unwrap();
        let expected_coordinator =
            canonical::canonical_json(&installed.scene.coordinator.template).unwrap();
        std::fs::write(
            installed
                .directory
                .join("original-installed-coordinator-template.json"),
            expected_coordinator,
        )
        .unwrap();
        host_witness = Some(original_host);
        eprintln!(
            "original host continuation witness: same active four-owner runtime before first Begin"
        );
        let mut blocked_zero_delay = false;
        for (index, grant) in schedule.grants.iter().enumerate() {
            let member = schedule
                .nodes
                .iter()
                .position(|node| node == &grant.node)
                .unwrap();
            let limit = match grant.request {
                OperationRequest::ExactRun { limit, .. }
                | OperationRequest::BoundarySettle { limit, .. } => limit,
                _ => panic!("connected schedule substituted timing family"),
            };
            if member != 0 {
                runtime
                    .stage_exact_inputs(
                        &grant.node,
                        id(&format!("connected-stage-{index}")),
                        id(&format!("connected-batch-{index}")),
                        limit,
                    )
                    .unwrap();
            }
            if grant.operation.as_str() == "relay-delivery" {
                nonempty_host_witness =
                    Some(super::host_witness::retain_nonempty(runtime, &installed));
            }
            let token = match runtime
                .begin_exact_position(&grant.node, grant.operation.clone(), limit)
                .unwrap()
            {
                BeginResult::Accepted(token) => token,
                BeginResult::Uncertain { token, effects } => {
                    tokens.push(token);
                    assert!(
                        runtime
                            .host_scheduling_observation(&installed.scene.host_source)
                            .is_err()
                    );
                    let retained = host_witness.as_ref().unwrap();
                    retained
                        .encoded()
                        .reference
                        .verify(&retained.encoded().bytes)
                        .unwrap();
                    panic!(
                        "original connected Begin {index} is uncertain: {effects:?}; original host witness retained, whole-world observation refused"
                    );
                }
                BeginResult::Refused(refusal) => {
                    panic!("original connected Begin refused: {refusal:?}")
                }
            };
            tokens.push(token);
            let token = &tokens[index];
            await_progress(deadline, |context| runtime.poll(token, context)).unwrap();
            let original = runtime.original_completed_operation(token).unwrap();
            if member != 0 {
                let staged = original.staged_inputs().unwrap().unwrap();
                let count = staged.batch().deliveries().len();
                assert_eq!(
                    count,
                    usize::from(matches!(
                        grant.operation.as_str(),
                        "relay-delivery" | "sink-delivery"
                    )),
                    "exclusive full-cut delivery inventory"
                );
                assert!(
                    staged.committed() && staged.coordinator_commit().is_some(),
                    "source consumption must precede every grant, including empty cuts"
                );
            }

            for after in [false, true] {
                for ticket in tickets
                    .iter_mut()
                    .filter(|ticket| ticket.grant == index && ticket.after == after)
                {
                    let expected = authority.expected_completion(&ticket.case).unwrap();
                    let original = ticket.original.take().unwrap();
                    let mut witness = runtime.original_witness().unwrap();
                    let runner = runners[ticket.member].as_mut().unwrap();
                    if member == 0 {
                        runner
                            .collect_exact_witness_reserved(original, expected, &mut witness, token)
                            .unwrap();
                    } else {
                        runner
                            .collect_exact_input_witness_reserved(
                                expected,
                                &mut witness,
                                token,
                                original,
                            )
                            .unwrap();
                    }
                }
                if !after {
                    runtime
                        .publish_and_acknowledge(token, &mut results)
                        .unwrap();
                }
            }
            if grant.operation.as_str() == "relay-delivery" {
                let blocked = runtime.stage_exact_inputs(
                    &schedule::node(2),
                    id("slow-relay-stage"),
                    id("slow-relay-batch"),
                    schedule::position(6, 1, Phase::Reaction),
                );
                assert_producer_blocked(blocked, &schedule::node(1));
                blocked_zero_delay = true;
            }
            eprintln!("original connected grant {index}: {}", grant.operation);
        }
        assert!(blocked_zero_delay);
        assert!(tickets.iter().all(|ticket| ticket.original.is_none()));
        assert_eq!(tokens.len(), schedule::GRANT_COUNT);
        for runner in &mut runners {
            let collected = runner.take().unwrap().finish();
            assert!(!collected.attempts.authenticated_cases().is_empty());
            let issued = collected.issued.as_ref().unwrap();
            let claim: QualificationClaim = serde_json::from_value(
                canonical::parse_json(
                    issued.bytes(),
                    installed.qualification_limits.maximum_claim_bytes,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(claim.requirements.len(), 382);
            assert!(
                claim
                    .requirements
                    .iter()
                    .all(|row| row.disposition == RequirementDisposition::NotExecuted)
            );
            assert!(
                accept_claim(
                    issued.bytes(),
                    issued.reference(),
                    &authority.witness_plan().unit,
                    &authority.witness_plan().classes,
                    authority.as_ref(),
                    installed.qualification_limits
                )
                .is_err()
            );
            for observed in collected.exact_observations.values() {
                observed
                    .snapshot_ref
                    .verify(observed.snapshot.as_slice())
                    .unwrap();
                for body in &observed.objects {
                    body.reference.verify(&body.bytes).unwrap();
                }
            }
        }
        for reference in &result_references {
            let root = installed.refs.read_ref(reference).unwrap().unwrap();
            let bytes = installed
                .blobs
                .read(root, None)
                .unwrap()
                .read_all(8 * 1024 * 1024)
                .unwrap();
            assert_eq!(
                canonical::parse_json(&bytes, 8 * 1024 * 1024).unwrap()["version"],
                4
            );
        }
        assert!(
            installed
                .refs
                .read_ref(&activation_reference)
                .unwrap()
                .is_some()
        );
        assert!(
            installed
                .incidents
                .iter()
                .all(|incident| incident.is_empty())
        );
        println!(
            "original connected completion: three native peers, four owners, thirteen grants, two nonempty deliveries, genuine empty commits, separated zero-delay phases, thirteen durable roots; normative382 remain NotExecuted"
        );
    }));

    // The complete same holder and original supervisor remain outside the
    // unwind boundary. Reclamation never launches replacement children.
    holder.retire_original().unwrap();
    let cleanup_deadline = Instant::now() + Duration::from_secs(60);
    await_progress(cleanup_deadline, |context| {
        supervisor.poll_reclamation(context)
    })
    .unwrap_or_else(|_| panic!("original connected kernel reclamation failed"));
    let reclaimed = supervisor.observation();
    assert_eq!(reclaimed.runtime_worlds, 0);
    assert!(reclaimed.peers.iter().all(|peer| peer.native_returned
        && peer.kernel_reclaimed
        && peer.journal_retained
        && !peer.containment_fault));
    if let Some(original) = &nonempty_host_witness {
        original
            .encoded()
            .reference
            .verify(&original.encoded().bytes)
            .unwrap();
    }
    if let Err(failure) = execution {
        std::panic::resume_unwind(failure);
    }
}
