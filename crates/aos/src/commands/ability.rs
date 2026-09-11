//! Checked ability reconstruction, rendering, and loopback operator browsing.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Take};
use std::num::NonZeroU64;

use anyhow::{Context as _, Result, bail};
use aos_ability_inspect::{
    ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES, ArtifactConsumptionExplanation,
    ArtifactConsumptionQuery, CheckedArtifactConsumptionEvidence, DiagnosticBundle,
    DiagnosticBundleAudience, ExecutionTimeline, GraphQuery, INSPECTION_BUNDLE_MAX_BYTES,
    INSPECTION_BUNDLE_SCHEMA, INSPECTION_QUERY_MAX_BYTES, InspectionBundle, InspectionView,
    OPERATOR_OBSERVATION_MAX_BYTES, OPERATOR_QUERY_MAX_BYTES, OperatorObservation, OperatorQuery,
    OperatorView, PendingStateAvailability, ProjectionKind, REFERENCE_INSPECTION_INPUT_SCHEMA,
    ReferenceInspectionAnchor, ReferenceInspectionInput, ReferenceInspectionView, RenderFormat,
    TimelineEventInput, TimelineEventKind, TimelineProvenance, TimelineTiming, ViewAnchor, render,
    render_projection, render_reference, render_reference_slice, render_slice,
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
    AbilityArtifactConsumptionArgs, AbilityCommand, AbilityDiagnosticArgs,
    AbilityDiagnosticAudience, AbilityInspectArgs, AbilityOperatorArgs, AbilityProjection,
    AbilityRenderFormat, ArtifactConsumptionRenderFormat,
};

mod browser;

/// Runs one checked ability inspection or operator-browser command.
///
/// # Errors
///
/// Returns an error if the input cannot be read within its bound, its canonical
/// bundle or external digest is invalid, semantic revalidation fails, or the
/// checked view cannot be rendered.
pub async fn run(command: &AbilityCommand, printer: &Printer) -> Result<()> {
    match command {
        AbilityCommand::Inspect(args) => inspect(args, printer),
        AbilityCommand::ArtifactConsumption(args) => artifact_consumption(args, printer),
        AbilityCommand::Diagnostic(args) => diagnostic(args, printer),
        AbilityCommand::Operator(args) => operator(args, printer).await,
    }
}

async fn operator(args: &AbilityOperatorArgs, printer: &Printer) -> Result<()> {
    let query_bytes = read_bounded_file(
        &args.query,
        u64::try_from(OPERATOR_QUERY_MAX_BYTES)
            .context("operator query byte limit does not fit this platform")?,
        "operator query",
    )?;
    let query = OperatorQuery::decode(&query_bytes).context("decoding canonical operator query")?;
    let observation = args
        .observation
        .as_deref()
        .map(|path| {
            let bytes = read_bounded_file(
                path,
                u64::try_from(OPERATOR_OBSERVATION_MAX_BYTES)
                    .context("operator observation byte limit does not fit this platform")?,
                "operator observation",
            )?;
            OperatorObservation::decode(&bytes).context("decoding canonical operator observation")
        })
        .transpose()?;
    let bundle_bytes = read_bounded_file(
        &args.bundle,
        u64::try_from(INSPECTION_BUNDLE_MAX_BYTES)
            .context("inspection bundle byte limit does not fit this platform")?,
        "inspection bundle",
    )?;
    let expected_digest = args
        .expected_digest
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()
        .context("parsing --expected-digest")?;
    let checked = InspectionBundle::decode(&bundle_bytes)
        .context("decoding canonical ability inspection bundle")?
        .check(expected_digest)
        .context("checking ability inspection bundle semantics")?;
    let view = InspectionView::from_bundle(&checked)
        .context("projecting checked ability inspection view")?;

    if args.serve {
        let listen = args.listen.unwrap_or_else(|| ([127, 0, 0, 1], 0).into());
        return browser::serve(view, query, observation, listen, printer).await;
    }

    let operator = OperatorView::from_view(&view, &query, observation.as_ref())
        .context("building bounded ability operator view")?;
    let bytes = operator.canonical_bytes()?;
    let output = std::str::from_utf8(&bytes).context("operator view JSON is not UTF-8")?;
    printer.raw(output);

    if matches!(view.anchor(), ViewAnchor::UnanchoredBundle { .. }) {
        printer.warning(
            "the bundle was semantically checked without an independent digest; its desired environment and policy are not asserted current",
        );
    }
    Ok(())
}

fn artifact_consumption(args: &AbilityArtifactConsumptionArgs, printer: &Printer) -> Result<()> {
    let bytes = read_bounded_file(
        &args.evidence,
        ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES,
        "artifact-consumption evidence",
    )?;
    let checked = CheckedArtifactConsumptionEvidence::decode(&bytes)
        .context("checking realized artifact-consumption evidence")?;
    let provider_content = args
        .provider_content
        .as_deref()
        .map(Sha256Digest::parse)
        .transpose()
        .context("parsing --provider-content")?;
    let query = ArtifactConsumptionQuery::new(args.consumer.clone(), provider_content);
    let explanation = if let Some(bundle_path) = &args.bundle {
        let bundle_bytes = read_bounded_file(
            bundle_path,
            INSPECTION_BUNDLE_MAX_BYTES as u64,
            "ability inspection bundle",
        )?;
        let expected_digest = args
            .expected_bundle_digest
            .as_deref()
            .map(Sha256Digest::parse)
            .transpose()
            .context("parsing --expected-bundle-digest")?;
        let bundle = InspectionBundle::decode(&bundle_bytes)
            .context("decoding artifact-consumption inspection bundle")?
            .check(expected_digest)
            .context("checking artifact-consumption inspection bundle")?;
        checked
            .query_with_bundle(&query, &bundle)
            .context("joining realized artifact consumption to the checked ability graph")?
    } else {
        checked
            .query(&query)
            .context("querying realized artifact-consumption evidence")?
    };
    let format = args.format.unwrap_or_else(|| {
        if printer.mode() == OutputMode::Json {
            ArtifactConsumptionRenderFormat::Json
        } else {
            ArtifactConsumptionRenderFormat::Text
        }
    });

    match format {
        ArtifactConsumptionRenderFormat::Text => {
            printer.raw(&render_artifact_consumption_text(&explanation));
        }
        ArtifactConsumptionRenderFormat::Json => {
            let bytes = aos_contract::canonical::to_vec(&explanation)
                .context("encoding artifact-consumption explanation")?;
            let output = std::str::from_utf8(&bytes)
                .context("artifact-consumption explanation JSON is not UTF-8")?;
            printer.raw(output);
        }
    }
    Ok(())
}

fn render_artifact_consumption_text(explanation: &ArtifactConsumptionExplanation) -> String {
    let consumer = format!(
        "{}{}",
        explanation.consumer.artifact.store_path, explanation.consumer.path
    );
    let provider = format!(
        "{}{}",
        explanation.provider.artifact.store_path, explanation.provider.path
    );
    let detail = match &explanation.contract {
        aos_ability_model::ArtifactConsumptionContract::ElfStartupLinkage(linkage) => {
            let symbols = linkage
                .symbols
                .iter()
                .map(|symbol| format!("{}@{}", symbol.name, symbol.version))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "  mechanism: ELF startup DT_NEEDED ({})\n  loader: {}\n  search path ({}): {}\n  symbol versions: {symbols}\n  provider ELF compatible: {}\n  loader ELF compatible: {}\n  search resolves exact provider: {}\n",
                linkage.soname,
                linkage.loader,
                match linkage.search_path_kind {
                    aos_ability_model::ElfSearchPathKind::Runpath => "DT_RUNPATH",
                    aos_ability_model::ElfSearchPathKind::Rpath => "DT_RPATH",
                },
                linkage.search_path.join(":"),
                explanation.provider_elf_compatible.unwrap_or(false),
                explanation.loader_elf_compatible.unwrap_or(false),
                explanation.search_resolves_exact_provider.unwrap_or(false),
            )
        }
        aos_ability_model::ArtifactConsumptionContract::ObservedPath(contract) => format!(
            "  mechanism: {:?}\n  arguments: {}\n  output: {}\n  exact provider access observed: {}\n",
            explanation.mechanism,
            contract.arguments.join(" "),
            contract.output_sha256,
            explanation.provider_access_observed.unwrap_or(false),
        ),
    };
    let limitations = explanation
        .limitations
        .iter()
        .map(|limitation| format!("{limitation:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "{consumer}\n  consumes: {provider}\n  exact provider: {}\n{detail}  provider retained by consumer closure: {}\n  provenance: reported realized-build gate observation\n  limits: {limitations}\n",
        explanation.provider.artifact.content, explanation.provider_retained_by_consumer,
    )
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
    let schema = serde_json::from_slice::<serde_json::Value>(&bytes)
        .context("decoding ability inspection input JSON")?
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("ability inspection input has no schema discriminator")?;
    if schema == REFERENCE_INSPECTION_INPUT_SCHEMA {
        return inspect_reference(args, printer, query.as_ref(), &bytes, expected_digest);
    }
    if schema != INSPECTION_BUNDLE_SCHEMA {
        bail!("ability inspection input has an unsupported schema discriminator");
    }
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

fn inspect_reference(
    args: &AbilityInspectArgs,
    printer: &Printer,
    query: Option<&GraphQuery>,
    bytes: &[u8],
    expected_digest: Option<Sha256Digest>,
) -> Result<()> {
    if args.projection.is_some() {
        bail!("semantic plan projections do not apply to public-reference inspection input");
    }
    let checked = ReferenceInspectionInput::decode(bytes)
        .context("decoding canonical public-reference inspection input")?
        .check(expected_digest)
        .context("checking public-reference inspection input")?;
    let view = ReferenceInspectionView::from_checked(&checked)
        .context("projecting checked public-reference inspection view")?;
    let format = args.format.map(Into::into).unwrap_or_else(|| {
        if printer.mode() == OutputMode::Json {
            RenderFormat::Json
        } else {
            RenderFormat::Text
        }
    });
    let output = if let Some(query) = query {
        let slice = view
            .query(query)
            .context("querying checked public-reference inspection view")?;
        render_reference_slice(&slice, format)
            .context("rendering checked public-reference graph slice")?
    } else {
        render_reference(&view, format).context("rendering checked public-reference graph")?
    };
    printer.raw(&output);

    if matches!(
        view.anchor(),
        ReferenceInspectionAnchor::UnanchoredReference { .. }
    ) {
        printer.warning(
            "the public reference was checked without an independent digest; deployment authorization and runtime availability were not evaluated",
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
    read_bounded_file(
        &args.bundle,
        u64::try_from(INSPECTION_BUNDLE_MAX_BYTES)
            .context("inspection bundle byte limit does not fit this platform")?,
        "inspection bundle",
    )
}

fn read_bounded_file(path: &std::path::Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {label} {}", path.display()))?;
    let mut reader: Take<File> = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!(
            "{label} {} exceeds the {} byte limit",
            path.display(),
            limit
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
