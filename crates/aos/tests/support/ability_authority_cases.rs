//! Incarnation replacement and runtime failure-control qualification cells.
//!
//! These cases share the checked plan, durable journal, and reservation ledger
//! maintained by the authority audit entry point.

use super::*;

pub(super) fn run_replacement_cell(
    evidence_root: &Path,
    cell_id: &str,
    cell: &Value,
    interface: &InterfaceDocument,
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
    scenario: &str,
) -> Result<AuditCell> {
    let directory =
        evidence_root.join(digest_bytes(cell_id.as_bytes()).trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    let journal_path = directory.join("execution.journal");
    let ledger_path = directory.join("reservation-ledger.json");
    let foreign_path = directory.join("foreign-resource");
    write_durable(&foreign_path, b"independent-foreign-resource\n")?;
    let foreign_before = digest_file(&foreign_path)?;

    let (plan, plan_bundle, operation_key, dependent_key, observation) =
        checked_plan(interface, interfaces, descriptor, matrix_method)?;
    let planned_incarnation = plan
        .operation(&operation_key)
        .and_then(|operation| operation.preconditions.first())
        .and_then(|precondition| precondition.expected_incarnation.clone())
        .context("checked plan lacks its provider-incarnation precondition")?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "replacement-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let mut store = DurableStore {
        directory: directory.clone(),
        plan_bundle,
        bundle_digest: None,
    };
    let mut transaction = Some(ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?);
    let observed_provider_incarnation = match scenario {
        "replace-executor-incarnation" => planned_incarnation,
        "replace-provider-incarnation" => IncarnationId::new("replacement-provider-incarnation")?,
        other => bail!("unknown incarnation-replacement scenario {other}"),
    };
    let mut catalog = DurableCatalog {
        ledger: ledger_path.clone(),
        state: ReservationState::default(),
        fail_releases: 0,
        observed_provider_incarnation: Some(observed_provider_incarnation),
    };
    catalog.persist()?;
    let revoked = Rc::new(Cell::new(None));
    let mut policy = RevocablePolicy { revoked };
    let mut adapter = NoDispatchAdapter::new(observation);
    let clock = AuditClock::new(1);
    let ready = transaction
        .as_mut()
        .context("execution transaction is absent")?
        .schedule_ready(NonZeroUsize::new(2).context("positive batch")?)?;
    ensure!(
        ready.len() == 1 && ready[0].operation() == &operation_key,
        "checked dependency graph did not expose only its source"
    );

    let (runtime_boundary, rejection_kind, expected_releases, expected_owners) = match scenario {
        "replace-executor-incarnation" => {
            let admitted = transaction
                .as_mut()
                .context("execution transaction is absent")?
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            drop(transaction.take());
            let mut replacement = ExecutionTransaction::open(
                &plan,
                transaction_id.clone(),
                &journal_path,
                JournalLimits::default(),
                &mut store,
            )?;
            let error = replacement
                .drive_admitted(
                    &admitted,
                    &mut adapter,
                    &mut policy,
                    &clock,
                    &CancellationToken::default(),
                )
                .expect_err("a replacement executor accepted its predecessor's token");
            ensure!(
                matches!(error, ExecutionError::StaleAdmission),
                "executor replacement produced an unexpected runtime error"
            );
            drop(replacement);
            drop(admitted);

            (
                "ExecutorSessionReplacement",
                "stale-executor-admission",
                0,
                1,
            )
        }
        "replace-provider-incarnation" => {
            let failure = transaction
                .as_mut()
                .context("execution transaction is absent")?
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .expect_err("stale provider incarnation was admitted");
            ensure!(
                matches!(failure.error(), AdmissionError::StalePrecondition(_)),
                "provider replacement produced an unexpected admission error"
            );

            (
                "ProviderCatalogReplacement",
                "resource-provider-incarnation-precondition",
                1,
                0,
            )
        }
        other => bail!("unknown incarnation-replacement scenario {other}"),
    };

    ensure!(
        adapter.calls() == 0,
        "replacement fence allowed adapter dispatch"
    );
    ensure!(
        catalog.state.acquire_calls == 1,
        "replacement did not acquire once"
    );
    ensure!(
        catalog.state.release_calls == expected_releases,
        "replacement release count differs"
    );
    ensure!(catalog.state.max_owners == 1, "ownership was not exclusive");
    ensure!(
        catalog.state.owners == expected_owners,
        "replacement final ownership differs"
    );

    let rejection_path = directory.join("incarnation-rejection.json");
    write_durable(
        &rejection_path,
        &canonical_bytes(&json!({
            "schema": "aos.qualification.native-adapter-incarnation-rejection/v1",
            "cell-id": cell_id,
            "plan": plan.id(),
            "transaction": transaction_id,
            "kind": rejection_kind,
        }))?,
    )?;

    drop(transaction.take());
    let snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    let authority_rejections = count_events(&snapshot, |event| {
        matches!(event, ExecutionEventKind::AuthorityRejected { .. })
    });
    let effect_outcomes = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::EffectCompleted { .. }
                | ExecutionEventKind::EffectRejectedBeforeEffect { .. }
                | ExecutionEventKind::EffectIndeterminate { .. }
        )
    });
    ensure!(
        authority_rejections == 0,
        "replacement invented authority revocation"
    );
    ensure!(
        effect_outcomes == 0,
        "replacement reports an adapter outcome"
    );
    let foreign_after = digest_file(&foreign_path)?;
    ensure!(foreign_before == foreign_after, "foreign sentinel changed");

    let cell_digest = digest_value(cell)?;
    let bundle_digest = store
        .bundle_digest
        .context("plan bundle was not retained")?;
    let subject = json!({
        "schema": REPLACEMENT_SUBJECT_SCHEMA,
        "cell-id": cell_id,
        "cell-digest": cell_digest,
        "interface": interface.interface_key()?,
        "method": matrix_method.method,
        "plan": plan.id(),
        "transaction": transaction_id,
        "primary-operation": plan.operation(&operation_key).context("primary operation vanished")?,
        "dependent-operation": plan.operation(&dependent_key).context("dependent operation vanished")?,
        "dependency-edge": {
            "from": PlanNodeKey::Operation { key: operation_key.clone() },
            "to": PlanNodeKey::Operation { key: dependent_key.clone() },
            "kind": DependencyKind::RequiredSuccess,
        },
    });
    let retained_bundle = fs::read(directory.join("plan-bundle.json"))?;
    let evidence = json!({
        "role": Value::Null,
        "authority-boundary": Value::Null,
        "runtime-boundary": runtime_boundary,
        "rejection": {
            "kind": rejection_kind,
            "digest": digest_file(&rejection_path)?,
        },
        "journal": {
            "digest": digest_file(&journal_path)?,
            "head": snapshot.head_digest(),
            "authority-rejections": authority_rejections,
            "effect-outcomes": effect_outcomes,
        },
        "reservation-ledger": {
            "digest": digest_file(&ledger_path)?,
            "acquire-calls": catalog.state.acquire_calls,
            "release-calls": catalog.state.release_calls,
            "max-owners": catalog.state.max_owners,
            "owners": catalog.state.owners,
        },
        "dispatch-calls": adapter.calls(),
        "initial-ready": [operation_key],
        "blocked-dependent": dependent_key,
        "foreign-before": foreign_before,
        "foreign-after": foreign_after,
    });

    Ok(AuditCell {
        cell_digest,
        subject,
        plan_bundle: json!({
            "schema": PLAN_BUNDLE_SCHEMA,
            "digest": format!("{bundle_digest}"),
            "bytes-sha256": digest_bytes(&retained_bundle),
        }),
        evidence,
    })
}

pub(super) fn run_failure_control_cell(
    evidence_root: &Path,
    cell_id: &str,
    cell: &Value,
    interface: &InterfaceDocument,
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
    descriptor: &MethodDescriptor,
    matrix_method: &MatrixMethod,
    scenario: &str,
) -> Result<AuditCell> {
    use aos_ability_runtime::execution::Boundary;

    let directory =
        evidence_root.join(digest_bytes(cell_id.as_bytes()).trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    let journal_path = directory.join("execution.journal");
    let ledger_path = directory.join("reservation-ledger.json");
    let foreign_path = directory.join("foreign-resource");
    write_durable(&foreign_path, b"independent-foreign-resource\n")?;
    let foreign_before = digest_file(&foreign_path)?;

    let (plan, plan_bundle, operation_key, dependent_key, observation) =
        checked_plan(interface, interfaces, descriptor, matrix_method)?;
    let operation = plan
        .operation(&operation_key)
        .context("checked plan lacks the selected operation")?;
    let planned_incarnation = plan
        .operation(&operation_key)
        .and_then(|operation| operation.preconditions.first())
        .and_then(|precondition| precondition.expected_incarnation.clone())
        .context("checked plan lacks its provider-incarnation precondition")?;
    let transaction_id = TransactionId(LocalKey::new(&format!(
        "control-{}",
        &digest_bytes(cell_id.as_bytes())[7..23]
    ))?);
    let mut store = DurableStore {
        directory: directory.clone(),
        plan_bundle,
        bundle_digest: None,
    };
    let mut transaction = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        &journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    let mut catalog = DurableCatalog {
        ledger: ledger_path.clone(),
        state: ReservationState::default(),
        fail_releases: 0,
        observed_provider_incarnation: Some(planned_incarnation),
    };
    catalog.persist()?;
    let revoked = Rc::new(Cell::new(None));
    let mut policy = RevocablePolicy { revoked };
    let mut adapter = NoDispatchAdapter::new(observation);
    let clock = AuditClock::new(1);
    let cancellation = CancellationToken::default();
    let classification: String;
    let retained_resources: usize;
    let cleanup_errors: usize;
    let owners_at_failure: usize;

    match scenario {
        "expire-attempt-deadline" => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let mut observer = ExpireAtBoundary {
                clock: &clock,
                target: Boundary::EffectIntentDurable,
                advance_by: admitted.operation().deadline.attempt_timeout_millis.get(),
                observed: false,
            };
            let step = transaction.drive_admitted_with_observer(
                &admitted,
                &mut adapter,
                &mut policy,
                &clock,
                &cancellation,
                &mut observer,
            )?;
            ensure!(
                observer.observed && step == ExecutionStep::RejectedBeforeEffect,
                "trusted clock deadline did not abort the durable intent"
            );
            retained_resources = admitted.resources().count();
            owners_at_failure = catalog.state.owners;
            cleanup_errors = 0;
            classification = "trusted-clock-deadline-expired".to_string();
        }
        "fail-cleanup" => {
            catalog.fail_releases = 1;
            let mut observer = FailAtBoundary {
                target: Boundary::ResourcesAcquired,
                observed: false,
            };
            let failure = transaction
                .admit_with_observer(
                    &operation_key,
                    &adapter,
                    &mut catalog,
                    &mut policy,
                    &clock,
                    &mut observer,
                )
                .expect_err("injected admission cleanup must fail");
            ensure!(
                observer.observed,
                "cleanup failure boundary was not observed"
            );
            retained_resources = failure.retained_resources().count();
            cleanup_errors = failure.cleanup_errors().len();
            owners_at_failure = catalog.state.owners;
            ensure!(
                retained_resources == 1 && cleanup_errors == 1 && owners_at_failure == 1,
                "cleanup failure did not retain its exact ownership token"
            );
            failure.retry_cleanup(&mut catalog).map_err(|failure| {
                anyhow::anyhow!("cleanup retry remained failed: {}", failure.error())
            })?;
            classification = "cleanup-failure-retained-then-released".to_string();
        }
        "fail-release" => {
            let admitted = transaction
                .admit(&operation_key, &adapter, &mut catalog, &mut policy, &clock)
                .map_err(|failure| anyhow::anyhow!(failure.error().to_string()))?;
            let step = transaction.drive_admitted(
                &admitted,
                &mut adapter,
                &mut policy,
                &clock,
                &cancellation,
            )?;
            ensure!(
                step == ExecutionStep::RejectedBeforeEffect,
                "release setup did not settle before effect"
            );
            catalog.fail_releases = 1;
            let failure = transaction
                .release_admitted::<NoDispatchAdapter, _, _>(admitted, &mut catalog, &clock)
                .expect_err("injected release must fail");
            ensure!(
                matches!(failure.error(), ResourceReleaseError::Catalog { .. }),
                "release injection produced an unexpected error"
            );
            retained_resources = failure.retained_resources().count();
            owners_at_failure = catalog.state.owners;
            cleanup_errors = 0;
            ensure!(
                retained_resources == 1 && owners_at_failure == 1,
                "release failure did not retain its exact ownership token"
            );
            failure
                .retry(&mut transaction, &mut catalog, &clock)
                .map_err(|failure| anyhow::anyhow!("release retry failed: {}", failure.error()))?;
            transaction
                .settle_failure_before_effect(&operation_key, adapter.observation.clone())?;
            classification = "release-failure-retained-then-released".to_string();
        }
        other => bail!("unknown failure-control scenario {other}"),
    }

    ensure!(catalog.state.max_owners == 1, "ownership was not exclusive");
    ensure!(owners_at_failure == 1, "failure did not retain ownership");
    ensure!(
        retained_resources == 1,
        "failure retained an unexpected resource set"
    );
    let ready = transaction.schedule_ready(
        NonZeroUsize::new(plan.operations().len()).context("plan has no operations")?,
    )?;
    let expected_dependent_settlement = scenario == "fail-release";
    let dependent = ready
        .iter()
        .find(|entry| entry.operation() == &dependent_key);
    if expected_dependent_settlement {
        let dependent = dependent.context("required-success dependent was not durably blocked")?;
        ensure!(
            dependent.action() == &RecoveryAction::SettleFailureBeforeEffect,
            "required-success dependent became externally executable"
        );
        transaction.settle_failure_before_effect(&dependent_key, adapter.observation.clone())?;
    } else {
        ensure!(
            dependent.is_none(),
            "unsettled required-success predecessor exposed its dependent"
        );
    }

    drop(transaction);
    let snapshot =
        CheckedExecutionJournalSnapshot::read(&plan, &journal_path, JournalLimits::default())?;
    let dependent_effect_events = snapshot
        .records()
        .iter()
        .filter(|record| {
            matches!(
                record.body().body(),
                ExecutionEventKind::EffectIntent { operation, .. }
                    | ExecutionEventKind::EffectCompleted { operation, .. }
                    | ExecutionEventKind::EffectRejectedBeforeEffect { operation, .. }
                    | ExecutionEventKind::EffectIndeterminate { operation, .. }
                    if operation.operation == dependent_key
            )
        })
        .count();
    let dependent_settlements = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::OperationSettledFailure { operation, .. }
                if operation.operation == dependent_key
        )
    });
    ensure!(
        dependent_effect_events == 0
            && dependent_settlements == usize::from(expected_dependent_settlement),
        "dependent operation was not blocked before effect"
    );
    let cancellation_requested = count_events(&snapshot, |event| {
        matches!(event, ExecutionEventKind::CancellationRequested { .. })
    });
    let cancellation_observed = count_events(&snapshot, |event| {
        matches!(event, ExecutionEventKind::CancellationObserved { .. })
    });
    let cancellation_interventions = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::OperationInterventionRequired { .. }
        )
    });
    let deadline_aborts = count_events(&snapshot, |event| {
        matches!(
            event,
            ExecutionEventKind::EffectDispatchAborted {
                reason: aos_ability_runtime::execution::DispatchAbortReason::DeadlineExpired,
                ..
            }
        )
    });
    ensure!(
        cancellation_interventions == 0,
        "failure control unexpectedly required operator intervention"
    );
    let foreign_after = digest_file(&foreign_path)?;
    ensure!(foreign_before == foreign_after, "foreign sentinel changed");

    let cell_digest = digest_value(cell)?;
    let bundle_digest = store
        .bundle_digest
        .context("plan bundle was not retained")?;
    let subject = json!({
        "schema": SUBJECT_SCHEMA,
        "cell-id": cell_id,
        "cell-digest": cell_digest,
        "interface": interface.interface_key()?,
        "method": matrix_method.method,
        "plan": plan.id(),
        "transaction": transaction_id,
    });
    let retained_bundle = fs::read(directory.join("plan-bundle.json"))?;
    let evidence = json!({
        "scenario": scenario,
        "classification": classification,
        "operation-recovery": operation.recovery,
        "journal": {
            "digest": digest_file(&journal_path)?,
            "head": snapshot.head_digest(),
            "cancellation-requested": cancellation_requested,
            "cancellation-observed": cancellation_observed,
            "cancellation-interventions": cancellation_interventions,
            "deadline-aborts": deadline_aborts,
            "dependent-effect-events": dependent_effect_events,
            "dependent-settlements": dependent_settlements,
        },
        "reservation-ledger": {
            "digest": digest_file(&ledger_path)?,
            "acquire-calls": catalog.state.acquire_calls,
            "release-calls": catalog.state.release_calls,
            "release-failures": catalog.state.release_failures,
            "max-owners": catalog.state.max_owners,
            "owners-at-failure": owners_at_failure,
            "owners-final": catalog.state.owners,
            "retained-resources": retained_resources,
            "cleanup-errors": cleanup_errors,
        },
        "adapter": {
            "execute-calls": adapter.execute_calls,
            "reconcile-calls": adapter.reconcile_calls,
            "cancel-calls": adapter.cancel_calls,
        },
        "clock": {
            "now-millis": clock.now_millis(),
            "restart-stable-millis": clock.restart_stable_millis(),
        },
        "foreign-before": foreign_before,
        "foreign-after": foreign_after,
    });

    Ok(AuditCell {
        cell_digest,
        subject,
        plan_bundle: json!({
            "schema": PLAN_BUNDLE_SCHEMA,
            "digest": format!("{bundle_digest}"),
            "bytes-sha256": digest_bytes(&retained_bundle),
        }),
        evidence,
    })
}

fn count_events(
    snapshot: &CheckedExecutionJournalSnapshot,
    predicate: impl Fn(&ExecutionEventKind) -> bool,
) -> usize {
    snapshot
        .records()
        .iter()
        .filter(|record| predicate(record.body().body()))
        .count()
}
