//! Verifies exported campaign save closures and boundary proofs.

use super::*;

pub(super) fn assert_campaign_save_exports_closure(
    boundary_arguments: &[&str],
    stop: StopCondition,
    with_selection: bool,
) {
    let CampaignSaveCapture {
        temporary,
        output,
        cli,
        save_plan,
        campaign,
    } = capture_campaign_save(boundary_arguments, stop.clone());
    let report = campaign_save_workflow_report(&save_plan, &campaign, &stop)
        .or_panic("project campaign capture into the save command contract");
    let thin_plan = plan_cli_invocation(&cli);
    let backend_plan = plan_backend_selection(&cli)
        .or_panic("backend plan")
        .or_panic("save requires a backend");
    let mut outcome =
        finish_save_workflow_outcome(&thin_plan, &backend_plan, None, &save_plan, report)
            .or_panic("finish projected save workflow");
    export_savepoint_handle(&save_plan, &mut outcome)
        .or_panic("export versioned handle and DAG closure");

    match &stop {
        StopCondition::NamedBoundary(name) => {
            assert_eq!(campaign.terminal_configuration().schedule.len(), 0);
            let boundary = outcome
                .save_boundary_evidence
                .as_ref()
                .or_panic("marker save boundary evidence");
            assert_eq!(
                boundary.selector,
                Some(SaveAtSelector::Marker { name: name.clone() })
            );
            let SaveBoundaryProof::CampaignMarkerEvent {
                sequence,
                content_hash,
                node: proved_node,
                retired_icount,
                marker: proved_marker,
            } = &boundary.proof
            else {
                panic!("expected authenticated campaign marker event proof");
            };
            let marker_entry = campaign
                .evidence()
                .event_log_entries()
                .iter()
                .find(|entry| entry.sequence() == *sequence)
                .or_panic("retained marker proof entry");
            assert_eq!(*content_hash, marker_entry.content_hash());
            assert_eq!(proved_marker, &crucible::MarkerId::from_name(name));
            assert_eq!(marker_entry.event_payload().kind(), "guest_marker");
            assert_eq!(marker_entry.event_payload().node("node"), Some(proved_node));
            assert_eq!(
                marker_entry.event_payload().icount("retired_icount"),
                Some(crucible::Icount {
                    retired: *retired_icount,
                })
            );
            assert_eq!(
                marker_entry.event_payload().string("marker"),
                Some(proved_marker.name.as_str())
            );
            let handle = std::fs::read_to_string(&output).or_panic("marker v6 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v6\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            assert!(handle.contains("boundary-proof\tcampaign-marker-event\t"));
            assert!(handle.contains("boundary-predicate\t"));
            let decoded = decode_savepoint_handle(handle.as_bytes())
                .or_panic("decode authenticated campaign marker handle");
            assert!(matches!(
                decoded.boundary_proof,
                Some(SavepointBoundaryProof::CampaignMarkerEvent {
                    event_sequence,
                    event_content_hash,
                    node,
                    retired_icount: decoded_retired_icount,
                    frontier_ticks,
                    quanta,
                }) if event_sequence == *sequence
                    && event_content_hash == *content_hash
                    && node == *proved_node
                    && decoded_retired_icount == *retired_icount
                    && frontier_ticks == campaign.evidence().frontier().ticks
                    && quanta == campaign.evidence().quanta()
            ));
            assert_eq!(
                decoded.boundary_predicate,
                Some(crucible::Predicate::guest_marker(proved_marker.clone()))
            );
            let wrong_hash = handle.replace(
                &format_content_hash_ref(*content_hash),
                &format_content_hash_ref(crucible::ContentHash::default()),
            );
            let error = decode_savepoint_handle(wrong_hash.as_bytes())
                .error_or_panic("campaign marker hash must bind its canonical event");
            assert!(error.to_string().contains("canonical event"));

            let wrong_predicate = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-predicate\t") {
                        String::from("boundary-predicate\tnone")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(wrong_predicate.as_bytes()).is_err());

            let coordinate_proof = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-proof\t") {
                        format!(
                            "boundary-proof\tcoordinate\t{}\t{}",
                            campaign.evidence().frontier().ticks,
                            campaign.evidence().quanta()
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(coordinate_proof.as_bytes()).is_err());

            let missing_node = crucible::NodeId {
                name: String::from("missing-campaign-marker-node"),
            };
            let missing_node_event = crucible::SchedulerEventLogEntry::guest_marker_observation(
                *sequence,
                crucible::Icount {
                    retired: *retired_icount,
                },
                missing_node.clone(),
                proved_marker.clone(),
            );
            let missing_source = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-proof\t") {
                        format!(
                            "boundary-proof\tcampaign-marker-event\t{}\t{}\t{}\t{}\t{}\t{}",
                            sequence,
                            format_content_hash_ref(missing_node_event.content_hash()),
                            missing_node.name,
                            retired_icount,
                            campaign.evidence().frontier().ticks,
                            campaign.evidence().quanta()
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let missing_source = decode_savepoint_handle(missing_source.as_bytes())
                .or_panic("structurally valid v6 event record");
            let error = savepoint_handle_evidence("resume", &missing_source)
                .error_or_panic("v6 source node must belong to the embedded scenario");
            assert!(error.to_string().contains("not declared"));
        }
        StopCondition::VirtualTimePicoseconds(_) => {
            assert_eq!(
                outcome
                    .save_boundary_evidence
                    .as_ref()
                    .or_panic("virtual-time boundary evidence")
                    .proof,
                SaveBoundaryProof::Coordinate
            );
            let handle = std::fs::read_to_string(&output).or_panic("virtual-time v6 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v6\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            decode_savepoint_handle(handle.as_bytes())
                .or_panic("v6 decoder accepts campaign coordinate proof");
        }
        StopCondition::Observation(condition) => {
            let boundary = outcome
                .save_boundary_evidence
                .as_ref()
                .or_panic("observation save boundary evidence");
            let SaveBoundaryProof::CampaignObservation { proof, evidence } = &boundary.proof else {
                panic!("expected authenticated campaign observation proof");
            };
            let retained_evidence =
                crucible_daemon::CrucibleMeasurementReplayEvidence::from_canonical_bytes(evidence)
                    .or_panic("decode retained campaign observation evidence");
            assert_eq!(proof.condition(), condition);
            assert_eq!(proof.child(), campaign.terminal().observation().child());
            assert_eq!(
                proof.boundary().frontier_picoseconds(),
                campaign.evidence().frontier().ticks
            );
            assert_eq!(
                campaign.terminal().observation().stop(),
                &StopOutcome::ObservationReached(proof.clone())
            );

            let handle = std::fs::read_to_string(&output).or_panic("observation v6 handle");
            assert!(handle.contains("schema\tcrucible.savepoint-handle.v6\n"));
            assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
            assert!(handle.contains("boundary-proof\tcampaign-observation\t"));
            let decoded = decode_savepoint_handle(handle.as_bytes())
                .or_panic("decode authenticated campaign observation handle");
            assert_eq!(
                decoded.boundary_proof,
                Some(SavepointBoundaryProof::CampaignObservation {
                    proof: proof.clone(),
                    evidence: Box::new(retained_evidence.clone()),
                })
            );
            let pending = savepoint_handle_evidence("resume", &decoded)
                .or_panic("campaign observation handle reconstructs its checkpoint");
            assert_eq!(
                pending.source_observation_proof.as_deref(),
                Some(proof.as_ref())
            );
            assert_eq!(
                pending.source_observation_evidence.as_deref(),
                Some(&retained_evidence)
            );

            let unsupported = handle.replace(
                "schema\tcrucible.savepoint-handle.v6",
                "schema\tunsupported.savepoint-handle",
            );
            assert!(decode_savepoint_handle(unsupported.as_bytes()).is_err());

            let wrong_checkpoint = handle
                .lines()
                .map(|line| {
                    if line.starts_with("checkpoint\t") {
                        format!(
                            "checkpoint\t{}",
                            format_content_hash_ref(crucible::ContentHash::default())
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let error = decode_savepoint_handle(wrong_checkpoint.as_bytes())
                .error_or_panic("observation proof child must bind the checkpoint");
            assert!(error.to_string().contains("proof child"));

            let missing_predicate = handle
                .lines()
                .map(|line| {
                    if line.starts_with("boundary-predicate\t") {
                        String::from("boundary-predicate\tnone")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(missing_predicate.as_bytes()).is_err());
        }
        other => panic!("unsupported campaign save test boundary: {other:?}"),
    }

    let checkpoint = outcome
        .terminal_savepoint
        .or_panic("projected save exposes its logical checkpoint");
    let (handle_resume_plan, handle_evidence) =
        resume_plan_and_evidence_from_cli(&output, temporary.path());
    let checkpoint_reference = format_content_hash_ref(checkpoint);
    let bare_hash_cli = Cli::parse_from([
        String::from("crucible"),
        String::from("--store"),
        temporary.path().display().to_string(),
        String::from("resume"),
        checkpoint_reference,
    ]);
    let Commands::Resume(bare_hash_args) = &bare_hash_cli.command else {
        panic!("expected resume command");
    };
    let bare_hash_plan = plan_resume_invocation(bare_hash_args, temporary.path())
        .or_panic("a checkpoint hash parses as a typed resume reference");
    let bare_hash_error = resume_handle_evidence(&bare_hash_plan)
        .error_or_panic("resume must reject an unauthenticated checkpoint hash");
    assert!(matches!(bare_hash_error, CliError::Artifact(_)));
    assert!(
        bare_hash_error
            .to_string()
            .contains("requires an authenticated .crucible-savepoint handle")
    );
    assert_eq!(handle_evidence.checkpoint.id, checkpoint);
    assert!(guarded_campaign_resume_eligible(
        &handle_resume_plan,
        &handle_evidence
    ));
    if let Some(source_proof) = handle_evidence.source_observation_proof.as_deref() {
        assert!(handle_evidence.schedule.is_empty());
        let source_frontier = handle_evidence.checkpoint.virtual_time.ticks;
        let terminal_frontier = source_frontier.saturating_add(1);
        let mut replay_plan = handle_resume_plan.clone();
        replay_plan.terminal_condition = RunTerminalCondition::VirtualTime;
        replay_plan.max_virtual_time = Some(format!("{terminal_frontier}ticks"));
        replay_plan.max_virtual_time_ticks = Some(terminal_frontier);
        let replay = resume_campaign_fixture(
            &temporary,
            &handle_evidence,
            StopCondition::VirtualTimePicoseconds(terminal_frontier),
            true,
        );
        let source = replay
            .campaign
            .resume()
            .or_panic("v6 replay retains its source authentication");
        let accepted_source = replay
            .campaign
            .observations()
            .iter()
            .find(|observation| observation.id() == source.source_observation())
            .or_panic("v6 replay retains its accepted source observation");
        assert!(matches!(
            accepted_source.observation().stop(),
            StopOutcome::ObservationReached(actual) if actual.as_ref() == source_proof
        ));
        assert!(source.source_savepoint().is_some());
        campaign_resume_workflow_report(&replay_plan, &handle_evidence, &replay.campaign)
            .or_panic("v6 source observation is reproduced before continuation");

        let mut remote_plan = handle_resume_plan.clone();
        remote_plan.max_virtual_time = None;
        remote_plan.max_virtual_time_ticks = None;
        remote_plan.terminal_condition = match source_proof.condition() {
            ObservationCondition::SchedulerQuiescent => RunTerminalCondition::Quiescence,
            ObservationCondition::AssertionViolationTransition(_)
            | ObservationCondition::AnyAssertionViolationTransition => {
                RunTerminalCondition::Property
            }
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { .. } => {
                RunTerminalCondition::Quiescence
            }
        };
        let ordinary_starts = Arc::new(AtomicUsize::new(0));
        let counted_ordinary = Arc::clone(&ordinary_starts);
        let observation_calls = Arc::new(AtomicUsize::new(0));
        let selection_applications = Arc::new(AtomicUsize::new(0));
        let continuation_applications = Arc::new(AtomicUsize::new(0));
        let control_plane = LifecycleControlPlane::new(
            "typed-observation-remote-resume",
            Vec::new(),
            move |_scenario: &crucible::ScenarioDef, _seed| {
                counted_ordinary.fetch_add(1, Ordering::SeqCst);
                ResumeRecordingLifecycleLoop::new(VirtualTime {
                    ticks: source_frontier,
                })
            },
        )
        .with_resume_replay_closure_validator(|scenario, configuration, checkpoint, envelope| {
            crucible_daemon::qemu_campaign_lifecycle::validate_remote_resume_replay_closure(
                scenario,
                configuration,
                checkpoint,
                envelope,
            )
            .map_err(|error| {
                crucible_api::ResumeReplayClosureValidationError::new(error.to_string())
            })
        })
        .with_resume_observation_loop_factory(capture_only_remote_observation_factory(
            remote_plan.clone(),
            handle_evidence.clone(),
            Arc::clone(&observation_calls),
            Arc::clone(&selection_applications),
            Arc::clone(&continuation_applications),
        ));
        let client = InProcessLifecycleClient::new(control_plane);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .or_panic("observation remote resume test runtime");
        let remote_report = runtime
            .block_on(
                run_remote_control_client_resume_from_evidence_with_driver_async(
                    &client,
                    &remote_plan,
                    handle_evidence.clone(),
                    ResumeInteractiveCommandDriver::Preparsed(&[]),
                ),
            )
            .or_panic("cold remote session path should authenticate and restore v6 evidence");
        assert_eq!(remote_report.source_checkpoint, checkpoint);
        assert_eq!(runtime.block_on(client.session_count()), 0);
        assert_eq!(ordinary_starts.load(Ordering::SeqCst), 0);
        assert_eq!(observation_calls.load(Ordering::SeqCst), 1);
        assert_eq!(selection_applications.load(Ordering::SeqCst), 0);
        assert_eq!(continuation_applications.load(Ordering::SeqCst), 0);
        match source_proof.condition() {
            ObservationCondition::SchedulerQuiescent
            | ObservationCondition::SchedulerQuiescentOrExecutionQuanta { .. } => {
                assert_eq!(remote_report.run.status, BackendCommandStatus::Passed);
                assert_eq!(remote_report.run.outcome, Some(OutcomeKind::Passed));
                assert_eq!(remote_report.run.final_state, "quiescent");
            }
            ObservationCondition::AssertionViolationTransition(_)
            | ObservationCondition::AnyAssertionViolationTransition => {
                assert_eq!(remote_report.run.status, BackendCommandStatus::Failed);
                assert_eq!(remote_report.run.outcome, Some(OutcomeKind::Failed));
                assert_eq!(remote_report.run.final_state, "property-failed");
            }
        }

        let handle = std::fs::read_to_string(&output).or_panic("read v6 handle for tampering");
        for (mutation, forged) in recomputed_observation_proof_forgeries(
            source_proof,
            campaign.evidence().event_log_entries(),
        ) {
            let forged_handle = handle_with_observation_proof(&handle, &forged);
            let error = decode_savepoint_handle(forged_handle.as_bytes())
                .error_or_panic("proof-only forgery must disagree with retained raw evidence");
            assert!(
                error
                    .to_string()
                    .contains("campaign observation proof and evidence disagree"),
                "{mutation}: {error}"
            );
        }

        let source_evidence = handle_evidence
            .source_observation_evidence
            .as_deref()
            .or_panic("v6 handle retains raw source evidence");
        let crucible_daemon::CrucibleMeasurementStopEvidence::Observation(source_boundary) =
            source_evidence.stop()
        else {
            panic!("v6 raw evidence retains an observation boundary");
        };
        let shifted_boundary = crucible_daemon::CrucibleObservationBoundaryEvidence::new(
            source_boundary.frontier(),
            source_boundary.quantum_start_completed_quanta() + 1,
            source_boundary.completed_quanta() + 1,
            source_boundary.quantum_start_events(),
            source_boundary.event_log_offset(),
            source_boundary.scheduler_quiescent(),
        )
        .or_panic("shifted raw boundary remains structurally valid");
        let shifted_proof = recomputed_observation_proof_forgeries(
            source_proof,
            campaign.evidence().event_log_entries(),
        )
        .into_iter()
        .find_map(|(mutation, proof)| (mutation == "quanta").then_some(proof))
        .or_panic("quantum-coordinate proof forgery");
        let (shifted_evidence, _, _) =
            crucible_daemon::evaluate_crucible_observation_measurement_publication(
                source_evidence.scenario(),
                source_evidence.configuration(),
                handle_evidence.scenario_form.measurements(),
                source_evidence.entries().to_vec(),
                source_evidence.terminal().clone(),
                shifted_boundary,
                crucible_daemon::MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
            )
            .or_panic("build coherent shifted raw evidence")
            .into_parts();
        shifted_evidence
            .verify_observation_stop_proof(&shifted_proof)
            .or_panic("shifted proof and raw evidence agree with each other");
        let forged_handle =
            handle_with_observation_claim(&handle, &shifted_proof, &shifted_evidence);
        let decoded = decode_savepoint_handle(forged_handle.as_bytes())
            .or_panic("coherent proof and raw evidence pass portable structural checks");
        let forged_evidence = savepoint_handle_evidence("resume", &decoded)
            .or_panic("coherent forged claim remains pending until actual replay");
        let error = match try_resume_campaign_fixture(
            &temporary,
            &forged_evidence,
            StopCondition::VirtualTimePicoseconds(terminal_frontier),
            true,
        ) {
            Err(error) => error,
            Ok(_) => panic!("actual source replay accepted coherent portable forgery"),
        };
        assert!(
            error
                .to_string()
                .contains("guarded campaign resume source observation differs"),
            "{error}"
        );
        let remote_error = runtime
            .block_on(
                run_remote_control_client_resume_from_evidence_with_driver_async(
                    &client,
                    &remote_plan,
                    forged_evidence,
                    ResumeInteractiveCommandDriver::Preparsed(&[]),
                ),
            )
            .error_or_panic("cold remote source replay must reject a coherent forged pair");
        assert!(
            remote_error
                .to_string()
                .contains("guarded campaign resume source observation differs"),
            "{remote_error}"
        );
        assert_eq!(runtime.block_on(client.session_count()), 0);
        assert_eq!(ordinary_starts.load(Ordering::SeqCst), 0);
        assert_eq!(observation_calls.load(Ordering::SeqCst), 2);
    }

    if with_selection {
        assert_fixed_typed_choice_replay_closure(&stop);
    }
}
