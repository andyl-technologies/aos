//! Offline reconstruction and rendering of checked ability plans.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Take};
use std::num::NonZeroU64;

use anyhow::{Context as _, Result, bail};
use aos_ability_inspect::{
    DiagnosticBundle, DiagnosticBundleAudience, ExecutionTimeline, GraphQuery,
    INSPECTION_BUNDLE_MAX_BYTES, INSPECTION_QUERY_MAX_BYTES, InspectionBundle, InspectionView,
    PendingStateAvailability, ProjectionKind, RenderFormat, TimelineEventInput, TimelineEventKind,
    TimelineProvenance, TimelineTiming, ViewAnchor, render, render_projection, render_slice,
};
use aos_ability_model::{LocalKey, PlanNodeKey, RequiredFeature, TransactionId};
use aos_ability_runtime::execution::{
    CancellationResult, CheckedExecutionJournalSnapshot, DispatchAbortReason, ExecutionEventKind,
    ReconciliationResult,
};
use aos_ability_runtime::journal::{JournalLimits, JournalRecord};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_package::config_eval::ability_store::RetainedAbilityDiagnosticSource;

use crate::cli::{
    AbilityCommand, AbilityDiagnosticArgs, AbilityDiagnosticAudience, AbilityInspectArgs,
    AbilityProjection, AbilityRenderFormat,
};

/// Runs one offline ability inspection command.
///
/// # Errors
///
/// Returns an error if the input cannot be read within its bound, its canonical
/// bundle or external digest is invalid, semantic revalidation fails, or the
/// checked view cannot be rendered.
pub fn run(command: &AbilityCommand, printer: &Printer) -> Result<()> {
    match command {
        AbilityCommand::Inspect(args) => inspect(args, printer),
        AbilityCommand::Diagnostic(args) => diagnostic(args, printer),
    }
}

fn diagnostic(args: &AbilityDiagnosticArgs, printer: &Printer) -> Result<()> {
    let transaction = TransactionId(
        LocalKey::new(args.transaction.clone()).context("parsing ability transaction identity")?,
    );
    let supported_features = BTreeSet::from([
        RequiredFeature::new("abilities-v1").context("constructing ability feature set")?
    ]);
    let source =
        RetainedAbilityDiagnosticSource::load(&args.generation, &transaction, supported_features)
            .context("loading retained ability transaction")?;
    let (plan, plan_bundle, journal_file, journal_path) = source.into_parts();
    let journal = CheckedExecutionJournalSnapshot::read_file(
        &plan,
        journal_file,
        journal_path,
        JournalLimits::default(),
    )
    .context("checking retained execution journal")?;
    if journal.transaction() != &transaction || journal.plan_bundle() != plan_bundle {
        bail!("retained execution journal does not match the selected transaction plan bundle");
    }

    let audience = args.audience.into();
    let provenance = match NonZeroU64::new(journal.incomplete_tail_bytes()) {
        Some(incomplete_tail_bytes) => TimelineProvenance::CallerAssertedJournalPrefix {
            journal: journal.head_digest(),
            incomplete_tail_bytes,
        },
        None => TimelineProvenance::CallerAssertedJournalAnchor {
            journal: journal.head_digest(),
        },
    };
    let events = journal
        .records()
        .iter()
        .map(project_journal_record)
        .collect();
    let timeline = ExecutionTimeline::from_records(
        transaction,
        &plan,
        PendingStateAvailability::Unavailable,
        Vec::new(),
        events,
        provenance,
        audience,
    )
    .context("projecting checked execution timeline")?;
    let inspection = InspectionBundle::from_checked(&plan)?;
    let checked = inspection.check(None)?;
    let diagnostic = DiagnosticBundle::from_checked(&checked, timeline)?;
    let bytes = diagnostic.canonical_bytes()?;
    let output = std::str::from_utf8(&bytes).context("diagnostic JSON is not UTF-8")?;
    printer.raw(output);

    if journal.incomplete_tail_bytes() != 0 {
        printer.warning(&format!(
            "excluded {} bytes from an incomplete final journal frame; the retained file was not modified",
            journal.incomplete_tail_bytes()
        ));
    }
    Ok(())
}

fn inspect(args: &AbilityInspectArgs, printer: &Printer) -> Result<()> {
    let query = args.query.as_deref().map(read_bounded_query).transpose()?;
    let bytes = read_bounded_bundle(args)?;
    let expected_digest = args
        .expected_digest
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()
        .context("parsing --expected-digest")?;
    let checked = InspectionBundle::decode(&bytes)
        .context("decoding canonical ability inspection bundle")?
        .check(expected_digest)
        .context("checking ability inspection bundle semantics")?;
    let view = InspectionView::from_bundle(&checked)
        .context("projecting checked ability inspection view")?;

    let format = args.format.map(Into::into).unwrap_or_else(|| {
        if printer.mode() == OutputMode::Json {
            RenderFormat::Json
        } else {
            RenderFormat::Text
        }
    });
    let projection = args
        .projection
        .map(|kind| view.project(kind.into()))
        .transpose()
        .context("projecting semantic ability graph")?;
    let output = match (projection.as_ref(), query.as_ref()) {
        (Some(projection), Some(query)) => {
            let slice = projection
                .query(query)
                .context("querying projected ability inspection view")?;
            render_slice(&slice, format).context("rendering projected ability graph slice")?
        }
        (Some(projection), None) => render_projection(projection, format)
            .context("rendering projected ability inspection view")?,
        (None, Some(query)) => {
            let slice = view
                .query(query)
                .context("querying checked ability inspection view")?;
            render_slice(&slice, format).context("rendering checked ability graph slice")?
        }
        (None, None) => {
            render(&view, format).context("rendering checked ability inspection view")?
        }
    };
    printer.raw(&output);

    if matches!(view.anchor(), ViewAnchor::UnanchoredBundle { .. }) {
        printer.warning(
            "the bundle was semantically checked without an independent digest; its captured environment and policy are not asserted current",
        );
    }
    Ok(())
}

fn project_journal_record(
    record: &JournalRecord<aos_ability_runtime::execution::ExecutionEvent>,
) -> TimelineEventInput {
    let event = record.body().body();
    let kind = match event {
        ExecutionEventKind::TransactionPlanned { .. } => TimelineEventKind::TransactionPlanned,
        ExecutionEventKind::OperationAdmitted { .. } => TimelineEventKind::OperationAdmitted,
        ExecutionEventKind::RetryBackoffScheduled { .. } => TimelineEventKind::RetryScheduled,
        ExecutionEventKind::RetryBackoffElapsed { .. } => TimelineEventKind::RetryReady,
        ExecutionEventKind::CompensationRequested { .. } => {
            TimelineEventKind::CompensationRequested
        }
        ExecutionEventKind::CompensationAdmitted { .. } => TimelineEventKind::CompensationAdmitted,
        ExecutionEventKind::CompensationIntent { .. } => TimelineEventKind::CompensationStarted,
        ExecutionEventKind::CompensationCompleted { .. } => {
            TimelineEventKind::CompensationCompleted
        }
        ExecutionEventKind::CompensationRejectedBeforeEffect { .. } => {
            TimelineEventKind::CompensationRejectedBeforeEffect
        }
        ExecutionEventKind::CompensationIndeterminate { .. } => {
            TimelineEventKind::CompensationIndeterminate
        }
        ExecutionEventKind::CompensationReconciliationIntent { .. } => {
            TimelineEventKind::CompensationReconciliationStarted
        }
        ExecutionEventKind::CompensationReconciliationObserved { result, .. } => {
            compensation_reconciliation_kind(*result)
        }
        ExecutionEventKind::CompensationInterventionRequired { .. } => {
            TimelineEventKind::CompensationInterventionRequired
        }
        ExecutionEventKind::BranchSelected { .. } => TimelineEventKind::BranchSelected,
        ExecutionEventKind::OperationSkipped { .. } => TimelineEventKind::OperationSkipped,
        ExecutionEventKind::MergeCompleted { .. } => TimelineEventKind::MergeCompleted,
        ExecutionEventKind::EffectIntent { .. } => TimelineEventKind::EffectStarted,
        ExecutionEventKind::EffectCompleted { .. } => TimelineEventKind::EffectCompleted,
        ExecutionEventKind::EffectRejectedBeforeEffect { .. } => {
            TimelineEventKind::RejectedBeforeEffect
        }
        ExecutionEventKind::EffectDispatchAborted { reason, .. } => match reason {
            DispatchAbortReason::Cancelled => TimelineEventKind::DispatchCancelled,
            DispatchAbortReason::DeadlineExpired => TimelineEventKind::DispatchTimedOut,
        },
        ExecutionEventKind::EffectIndeterminate { .. } => TimelineEventKind::EffectIndeterminate,
        ExecutionEventKind::ReconciliationIntent { .. } => TimelineEventKind::ReconciliationStarted,
        ExecutionEventKind::ReconciliationObserved { result, .. } => reconciliation_kind(*result),
        ExecutionEventKind::CancellationRequested { .. } => TimelineEventKind::CancellationStarted,
        ExecutionEventKind::CancellationObserved { result, .. } => match result {
            CancellationResult::RejectedBeforeEffect => {
                TimelineEventKind::CancellationRejectedBeforeEffect
            }
            CancellationResult::Completed => TimelineEventKind::CancellationObservedCompletion,
            CancellationResult::Indeterminate => TimelineEventKind::CancellationIndeterminate,
        },
        ExecutionEventKind::OperationSettledFailure { .. } => TimelineEventKind::SettledFailure,
        ExecutionEventKind::OwnershipTransferred { .. } => TimelineEventKind::OwnershipTransferred,
        ExecutionEventKind::ResourcesReleased { .. } => TimelineEventKind::ResourcesReleased,
    };
    let node = match event {
        ExecutionEventKind::BranchSelected { selection, .. } => Some(PlanNodeKey::Decision {
            key: selection.decision.clone(),
        }),
        ExecutionEventKind::OperationSkipped { skipped, .. } => Some(PlanNodeKey::Operation {
            key: skipped.operation.clone(),
        }),
        ExecutionEventKind::MergeCompleted { merged, .. } => Some(PlanNodeKey::Merge {
            key: merged.merge.clone(),
        }),
        _ => event.operation().map(|operation| PlanNodeKey::Operation {
            key: operation.operation.clone(),
        }),
    };
    let timing = event
        .elapsed_millis()
        .map_or(TimelineTiming::Unavailable, |elapsed_millis| {
            TimelineTiming::OperationRecoveryElapsed { elapsed_millis }
        });
    let selected_alternative = match event {
        ExecutionEventKind::BranchSelected { selection, .. } => Some(selection.alternative.clone()),
        _ => None,
    };

    TimelineEventInput {
        sequence: record.sequence(),
        kind,
        node,
        attempt: event.attempt(),
        selected_alternative,
        timing,
    }
}

const fn reconciliation_kind(result: ReconciliationResult) -> TimelineEventKind {
    match result {
        ReconciliationResult::Completed => TimelineEventKind::ReconciledCompleted,
        ReconciliationResult::RejectedBeforeEffect => {
            TimelineEventKind::ReconciledRejectedBeforeEffect
        }
        ReconciliationResult::SafeToRetry => TimelineEventKind::ReconciledSafeToRetry,
        ReconciliationResult::StillIndeterminate => {
            TimelineEventKind::ReconciliationStillIndeterminate
        }
        ReconciliationResult::InterventionRequired => {
            TimelineEventKind::ReconciliationInterventionRequired
        }
    }
}

const fn compensation_reconciliation_kind(result: ReconciliationResult) -> TimelineEventKind {
    match result {
        ReconciliationResult::Completed => TimelineEventKind::CompensationReconciledCompleted,
        ReconciliationResult::RejectedBeforeEffect => {
            TimelineEventKind::CompensationReconciledRejectedBeforeEffect
        }
        ReconciliationResult::SafeToRetry => TimelineEventKind::CompensationReconciledSafeToRetry,
        ReconciliationResult::StillIndeterminate => {
            TimelineEventKind::CompensationReconciliationStillIndeterminate
        }
        ReconciliationResult::InterventionRequired => {
            TimelineEventKind::CompensationReconciliationInterventionRequired
        }
    }
}

fn read_bounded_bundle(args: &AbilityInspectArgs) -> Result<Vec<u8>> {
    let file = File::open(&args.bundle)
        .with_context(|| format!("opening inspection bundle {}", args.bundle.display()))?;
    let limit = u64::try_from(INSPECTION_BUNDLE_MAX_BYTES)
        .context("inspection bundle byte limit does not fit this platform")?;
    let mut reader: Take<File> = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading inspection bundle {}", args.bundle.display()))?;
    if bytes.len() > INSPECTION_BUNDLE_MAX_BYTES {
        bail!(
            "inspection bundle {} exceeds the {} byte limit",
            args.bundle.display(),
            INSPECTION_BUNDLE_MAX_BYTES
        );
    }
    Ok(bytes)
}

fn read_bounded_query(path: &std::path::Path) -> Result<GraphQuery> {
    let file =
        File::open(path).with_context(|| format!("opening inspection query {}", path.display()))?;
    let limit = u64::try_from(INSPECTION_QUERY_MAX_BYTES)
        .context("inspection query byte limit does not fit this platform")?;
    let mut reader: Take<File> = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading inspection query {}", path.display()))?;
    if bytes.len() > INSPECTION_QUERY_MAX_BYTES {
        bail!(
            "inspection query {} exceeds the {} byte limit",
            path.display(),
            INSPECTION_QUERY_MAX_BYTES
        );
    }
    GraphQuery::decode(&bytes)
        .with_context(|| format!("decoding inspection query {}", path.display()))
}

impl From<AbilityRenderFormat> for RenderFormat {
    fn from(value: AbilityRenderFormat) -> Self {
        match value {
            AbilityRenderFormat::Text => Self::Text,
            AbilityRenderFormat::Json => Self::Json,
            AbilityRenderFormat::Dot => Self::Dot,
            AbilityRenderFormat::Mermaid => Self::Mermaid,
        }
    }
}

impl From<AbilityProjection> for ProjectionKind {
    fn from(value: AbilityProjection) -> Self {
        match value {
            AbilityProjection::Composition => Self::Composition,
            AbilityProjection::BindingAuthority => Self::BindingAuthority,
            AbilityProjection::Activation => Self::Activation,
            AbilityProjection::Retention => Self::Retention,
        }
    }
}

impl From<AbilityDiagnosticAudience> for DiagnosticBundleAudience {
    fn from(value: AbilityDiagnosticAudience) -> Self {
        match value {
            AbilityDiagnosticAudience::Redacted => Self::Redacted,
            AbilityDiagnosticAudience::Deployment => Self::Deployment,
        }
    }
}
