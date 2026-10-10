//! Executes one explicitly selected production typed collecting lifecycle.
//!
//! The ignored cohort uses production source installation and owning invocation
//! APIs. It installs no test acceptance policy. Complete public plans/results
//! remain Refused; private Hello and incident journals are never exported. The
//! caller chooses one fresh retention directory and retains it after the run.

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread::{self, Thread},
    time::Duration,
};

use crucible::{node_admission::AdmissionLimits, node_contract::RuntimeLimits};
use crucible_daemon::{
    node_observed_executor::{
        InstalledTypedReaderHostInvocation, SelectedTypedReaderHostSource,
        TypedReaderCustodySupervisor, TypedReaderHostInvocationFailure,
        TypedReaderHostInvocationRequest, TypedReaderHostSourceFailure, TypedReaderLaunchError,
        TypedReaderSessionFailure, TypedReaderWindowDisposition,
    },
    node_qualification::{
        CaseVerdict, QualificationClaim, QualificationLimits, RequirementDisposition,
        WitnessCriterion,
    },
};
use crucible_node_contract::{ResourceLimits, U64};
use crucible_node_provider::{client::ExchangeDeadline, handshake::Limits};
use serde::Serialize;

const MIB: usize = 1024 * 1024;
const SERVICE_CADENCE: Duration = Duration::from_millis(1);

#[test]
#[ignore = "requires reviewed current source gates, selected immutable 4ac source and fresh explicit private retention directory; finite collecting purpose only"]
fn actual_source_installed_typed_lifecycle_retains_nine_windows() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(
        std::env::var_os("CRUCIBLE_TYPED_CONFORMANCE_RETENTION")
            .ok_or_else(|| public_error("fresh explicit retention directory is required"))?,
    );
    if !root.is_absolute() {
        return Err(public_error("retention directory must be absolute").into());
    }
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let private = root.join("private-sessions");
    let public = root.join("public");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&public)?;

    let selected: SelectedTypedReaderHostSource = serde_json::from_str(include_str!(
        "typed_conformance_lifecycle/selected-source.json"
    ))?;
    let invocation =
        InstalledTypedReaderHostInvocation::install(TypedReaderHostInvocationRequest {
            selected: &selected,
            resources: resources(),
            protocol_limits: protocol(),
            qualification_limits: qualification(),
            maximum_snapshot_bytes: 8 * MIB,
        })
        .map_err(|_| public_error("production source installation refused"))?;

    let plan = invocation.plan();
    assert_eq!(plan.requirements.len(), 382);
    assert_eq!(plan.cases.len(), 391);
    assert!(
        plan.requirements
            .values()
            .all(|criterion| matches!(criterion, WitnessCriterion::Applicable { .. }))
    );
    assert_eq!(
        plan.cases
            .iter()
            .filter(|case| case.id.starts_with("unexecuted/"))
            .count(),
        382
    );
    let original: QualificationClaim = serde_json::from_slice(invocation.audit().original_bytes())?;
    assert!(original.requirements.iter().all(|row| {
        row.disposition == RequirementDisposition::NotExecuted
            && row
                .cases
                .iter()
                .all(|case| case.verdict == CaseVerdict::NotExecuted)
    }));
    write_json(&public.join("original-plan.json"), plan)?;
    write_bytes(
        &public.join("original-refused-claim.json"),
        invocation.audit().original_bytes(),
    )?;
    write_json(
        &public.join("original-refused-audit.json"),
        invocation.audit().record(),
    )?;

    // All three sessions, publishers, report holders and failure storage are
    // prepared before any native participant can be created by start.
    let prepared = invocation
        .prepare(
            private,
            public.join("durable-store"),
            Duration::from_secs(60),
            runtime(),
            admission(),
        )
        .map_err(|_| public_error("production original preparation refused"))?;

    // This separate physical wait handle never attaches to a source transport
    // or changes an original session/controller deadline. Reserve it before Child.
    let cadence = ExchangeDeadline::start(SERVICE_CADENCE)?;
    let supervisor = prepared.supervisor().clone();
    let waker = Waker::from(Arc::new(OriginalWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut execution = match prepared.start() {
        Ok(original) => original,
        Err(original) => {
            reclaim_start_failure(original, &supervisor, &mut context, &cadence)?;
            write_bytes(
                &public.join("lifecycle-disposition.txt"),
                b"start_refused\n",
            )?;
            return Err(public_error("original start refused; authentic cleanup completed").into());
        }
    };
    let reclaimed = loop {
        match execution.poll(&mut context) {
            Poll::Ready(original) => break original,
            Poll::Pending => service_pending(&cadence),
        }
    };
    let collection = &reclaimed.collection;
    let reports = &collection.report.collection;

    // Export only public original report bodies after authentic reclamation.
    // Raw incidents, private launch capsules and Hello values stay in original.
    write_json(
        &public.join("quantized-original-observations.json"),
        &reports.quantized_observations,
    )?;
    match &reports.issued {
        Ok(original) => {
            write_bytes(
                &public.join("collected-refused-claim.json"),
                original.bytes(),
            )?;
            write_json(
                &public.join("original-claim-reference.json"),
                original.reference(),
            )?;
            for (index, (reference, body)) in original.objects().iter().enumerate() {
                write_json(
                    &public.join(format!("original-object-{index}.reference.json")),
                    reference,
                )?;
                write_bytes(
                    &public.join(format!("original-object-{index}.body")),
                    body.as_slice(),
                )?;
            }
        }
        Err(_) => {
            write_bytes(
                &public.join("lifecycle-disposition.txt"),
                b"issuance_refused\n",
            )?;
            return Err(public_error("original collection issuance refused after cleanup").into());
        }
    }
    assert!(!collection.callback_unwound);
    assert!(collection.driving_refusal.is_none());
    assert!(collection.reclamation_refusal.is_none());
    assert!(
        collection
            .report
            .windows
            .iter()
            .all(|state| { *state == TypedReaderWindowDisposition::Authenticated })
    );
    assert_eq!(reports.quantized_observations.len(), 9);
    assert_eq!(reports.attempts.attempted_cases().len(), 9);
    assert_eq!(reports.attempts.authenticated_cases().len(), 9);
    let issued = reports
        .issued
        .as_ref()
        .map_err(|_| public_error("issuance absent"))?;
    let claim: QualificationClaim = serde_json::from_slice(issued.bytes())?;
    assert_eq!(claim.requirements.len(), 382);
    assert!(claim.requirements.iter().all(|row| {
        row.disposition == RequirementDisposition::NotExecuted
            && row.cases.iter().any(|case| {
                case.case.starts_with("unexecuted/") && case.verdict == CaseVerdict::NotExecuted
            })
    }));
    write_bytes(
        &public.join("lifecycle-disposition.txt"),
        b"finite_nine_windows_collected;382_normative_obligations_not_executed;no_accepted_class\n",
    )?;
    Ok(())
}

fn reclaim_start_failure(
    original: TypedReaderHostInvocationFailure<'_>,
    supervisor: &TypedReaderCustodySupervisor,
    context: &mut Context<'_>,
    cadence: &ExchangeDeadline,
) -> io::Result<()> {
    let Some(mut original) = original.into_original() else {
        return Err(public_error("original failed custody holder unavailable"));
    };
    {
        let preparation = match original.original.failure() {
            Some(TypedReaderHostSourceFailure::Launch(original)) => matches!(
                &original.launch,
                TypedReaderLaunchError::Original(original) if original.guard.is_some()
            ),
            Some(TypedReaderHostSourceFailure::Realize(original)) => matches!(
                original.as_ref(),
                TypedReaderSessionFailure::Hello { .. }
                    | TypedReaderSessionFailure::Controller { .. }
            ),
            _ => false,
        };
        if preparation {
            loop {
                match original.original.poll_failed_preparation() {
                    Ok(true) => break,
                    Ok(false) | Err(_) => service_pending(cadence),
                }
            }
        }
        // Failed Adoption goes into its reserved supervisor journal mailbox;
        // other originals use their existing source/runtime Drop custody. All
        // original publishers and private services remain owned until transfer.
        drop(original);
    }
    loop {
        match supervisor.poll_reclamation(context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(_)) => service_pending(cadence),
            Poll::Pending => service_pending(cadence),
        }
    }
    Ok(())
}

// Actual typed polling has no readiness registration for the OS cleanup wait.
// This separate predeclared physical cut only throttles repeated Pending/error
// reads; original provider/session/grant deadlines are unchanged. The original
// waker may already have queued a wake or wake again during the wait. Drain the
// queued token, then reread the same cut after every early or spurious return.
// A wake never certifies native progress or permits another poll before expiry.
// Unexpected clock-boundary refusal retains original custody and keeps waiting.
fn service_pending(cadence: &ExchangeDeadline) {
    thread::park_timeout(Duration::ZERO);

    loop {
        match cadence.reset(SERVICE_CADENCE) {
            Ok(()) => break,
            Err(_) => thread::park_timeout(SERVICE_CADENCE),
        }
    }

    loop {
        match cadence.remaining() {
            Ok(remaining) => thread::park_timeout(remaining),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => break,
            Err(_) => thread::park_timeout(SERVICE_CADENCE),
        }
    }
}

struct OriginalWake(Thread);

impl Wake for OriginalWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn resources() -> ResourceLimits {
    ResourceLimits {
        cpu_budget_ns: U64::new(64_000_000_000),
        memory_bytes: U64::new((512 * MIB) as u64),
        writable_bytes: U64::new((64 * MIB) as u64),
        processes: U64::new(2),
        descriptors: U64::new(128),
        pending_events: U64::new(16),
        content_bytes: U64::new((16 * MIB) as u64),
        maximum_operations: U64::new(16),
        extensions: Default::default(),
    }
}

fn protocol() -> Limits {
    Limits {
        frame_bytes: U64::new(MIB as u64),
        nesting: U64::new(32),
        requests: U64::new(128),
        journal_entries: U64::new(512),
        blob_chunk_bytes: U64::new(65_536),
    }
}

fn qualification() -> QualificationLimits {
    QualificationLimits {
        maximum_claim_bytes: MIB,
        maximum_cases: 391,
        maximum_evidence_objects: 4096,
        maximum_evidence_bytes: (16 * MIB) as u64,
        maximum_total_evidence_bytes: (64 * MIB) as u64,
    }
}

fn runtime() -> RuntimeLimits {
    RuntimeLimits {
        maximum_nodes: 3,
        maximum_owners: 3,
        maximum_operations: 64,
        maximum_retained_outputs: 64,
    }
}

fn admission() -> AdmissionLimits {
    AdmissionLimits {
        maximum_nodes: 3,
        maximum_owners: 3,
        maximum_state_objects: 64,
        maximum_connections: 8,
        maximum_ports_or_lanes: 16,
        maximum_content_bytes: 4 * MIB,
        maximum_total_content_bytes: 64 * MIB,
        maximum_core_object_bytes: 4 * MIB,
        maximum_total_core_bytes: 16 * MIB,
        maximum_payload_bytes: 65_536,
        maximum_pending_events: 16,
        maximum_total_pending_bytes: MIB as u64,
        maximum_owner_conflict_pairs: 16,
        maximum_owner_conflict_checks: 64,
    }
}

fn write_json<T: Serialize + ?Sized>(path: &Path, original: &T) -> Result<(), Box<dyn Error>> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&file, original)?;
    file.sync_all()?;
    Ok(())
}

fn write_bytes(path: &Path, original: &[u8]) -> io::Result<()> {
    let mut file: File = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(original)?;
    file.sync_all()
}

fn public_error(reason: &'static str) -> io::Error {
    io::Error::other(reason)
}
