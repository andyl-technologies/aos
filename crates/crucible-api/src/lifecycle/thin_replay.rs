//! Thin-replay session restoration for production backends.

use super::*;

impl<L, F> LifecycleControlPlane<L, F>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>,
{
    pub(super) async fn resume_session_via_thin_replay(
        &mut self,
        request: ResumeSessionRequest,
    ) -> Result<ResumeSessionResponse, LifecycleApiError> {
        let scenario = request.scenario.scenario_def();
        let target = Configuration {
            def: scenario.clone(),
            schedule: request.schedule.clone(),
        };
        validate_resume_checkpoint_closure(&target, &request.checkpoint)?;

        let graph = graph_with_baked_genesis(&scenario)?;
        let debug_genesis = Some(debug_genesis_checkpoint(
            &Configuration::genesis(scenario.clone()),
            &request.scenario,
        )?);
        let loop_instance = (self.loop_factory)(&scenario, Some(&request.scenario), request.seed)?;
        let white_box_policies =
            self.white_box_policies_for_source(Some(&request.scenario), &scenario);
        let engine = Engine::new(Configuration::genesis(scenario), graph, loop_instance)
            .with_white_box_policies(white_box_policies);
        let (sender, receiver) = mpsc::channel(self.mailbox_capacity);
        let actor = SessionActor::new(engine, receiver).with_terminal_command_keepalive(true);
        let live = actor.live_snapshot();
        let event_log = ControlPlaneEventLog::new(actor.event_log());
        let reproduction_log = actor.reproduction_log();
        let state_transitions = actor.state_transition_bus();
        let actor_task = tokio::spawn(async move { actor.run().await });
        let session_ref = self.next_session_ref(request.seed);
        let runtime = SessionRuntime {
            session: session_ref,
            sender,
            live,
            event_log,
            reproduction_log,
            state_transitions,
            debug_access: DebugCoordinator::new(),
            debug_operation_gate: Arc::new(Mutex::new(())),
            debug_genesis,
            actor_task,
        };

        if let Err(error) = start_runtime(&runtime, true, self.startup_max_actor_yields).await {
            cleanup_runtime(runtime).await;
            return Err(error);
        }

        let mut prefix_ids = Vec::with_capacity(request.schedule.len().saturating_add(1));
        for prefix_len in 0..=request.schedule.len() {
            let prefix = request.schedule.prefix(prefix_len).map_err(|error| {
                LifecycleApiError::ResumeCheckpoint {
                    message: format!("cannot derive replay prefix of length {prefix_len}: {error}"),
                }
            })?;
            prefix_ids.push(
                Configuration {
                    def: target.def.clone(),
                    schedule: prefix,
                }
                .id(),
            );
        }

        let target_id = target.id();
        let target_frontier = request.checkpoint.virtual_time;
        let initial = runtime.live.read();
        let schedule_bound = u64::try_from(request.schedule.len()).unwrap_or(u64::MAX);
        let max_steps = target_frontier
            .ticks
            .saturating_sub(initial.virtual_time.ticks)
            .saturating_add(schedule_bound)
            .saturating_add(1);
        let mut matched =
            initial.configuration == target_id && initial.virtual_time == target_frontier;
        for _ in 0..max_steps {
            if matched {
                break;
            }
            let before = runtime.live.read();
            if before.state_kind == LiveStateKind::Stopped {
                break;
            }
            if !prefix_ids.contains(&before.configuration)
                || before.virtual_time.ticks > target_frontier.ticks
            {
                cleanup_runtime(runtime).await;
                return Err(LifecycleApiError::ResumeCheckpoint {
                    message: format!(
                        "thin replay diverged before checkpoint: configuration={} frontier={} target_configuration={} target_frontier={}",
                        before.configuration.to_hex(),
                        before.virtual_time.ticks,
                        target_id.to_hex(),
                        target_frontier.ticks
                    ),
                });
            }
            if let Err(error) =
                send_runtime_command(&runtime, SessionCommand::step(StepMode::Quantum)).await
            {
                cleanup_runtime(runtime).await;
                return Err(error);
            }
            if let Err(error) = wait_for_replay_boundary(
                &runtime,
                before.quanta_stepped,
                self.startup_max_actor_yields,
            )
            .await
            {
                cleanup_runtime(runtime).await;
                return Err(error);
            }
            let current = runtime.live.read();
            matched = current.configuration == target_id && current.virtual_time == target_frontier;
        }

        if !matched {
            let actual = runtime.live.read();
            cleanup_runtime(runtime).await;
            return Err(LifecycleApiError::ResumeCheckpoint {
                message: format!(
                    "thin replay did not reach checkpoint: configuration={} frontier={} target_configuration={} target_frontier={}",
                    actual.configuration.to_hex(),
                    actual.virtual_time.ticks,
                    target_id.to_hex(),
                    target_frontier.ticks
                ),
            });
        }

        let state = runtime.live.read().state_kind;
        self.sessions.insert(session_ref.id, runtime);
        Ok(ResumeSessionResponse {
            session: session_ref,
            state,
            checkpoint: request.checkpoint.id,
            configuration: target_id,
        })
    }
}

async fn wait_for_replay_boundary(
    runtime: &SessionRuntime,
    prior_quanta: u64,
    max_actor_yields: u64,
) -> Result<(), LifecycleApiError> {
    for _ in 0..max_actor_yields {
        let current = runtime.live.read();
        if current.quanta_stepped > prior_quanta
            && matches!(
                current.state_kind,
                LiveStateKind::Paused | LiveStateKind::Stopped
            )
        {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err(LifecycleApiError::StateDidNotAdvance {
        session_id: runtime.session.id,
        expected: LiveStateKind::Paused,
    })
}
