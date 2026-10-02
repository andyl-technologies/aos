//! Native declaration, desired effect, and committed-output inspection.
//!
//! Imported documents supply desired declarations. Retained generation results
//! come from checked native journals and are shown separately from desired inputs.

use crate::cli::*;
use crate::commands::input::read_bounded_file;
use anyhow::{Context as _, Result, ensure};
use aos_contract::Sha256Digest;
use aos_core::output::{OutputMode, Printer};
use aos_doc_model::artifact_consumption::{
    ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES, ArtifactConsumptionExplanation,
    ArtifactConsumptionQuery, CheckedArtifactConsumptionEvidence,
};
use aos_doc_model::runtime::RuntimeDocument;
use std::collections::BTreeSet;
mod browser;
mod check_compat;
mod evaluate;

pub(crate) use check_compat::CompatibilityFailure;

/// Runs native inspection or pure source replay without invoking handlers.
///
/// # Errors
/// Returns an error for invalid or oversized native documents, unavailable
/// committed generations, ambiguous graph identities, failed or cancelled source
/// replay, or output failures.
pub async fn run(command: &AbilityCommand, printer: &Printer) -> Result<()> {
    match command {
        AbilityCommand::Evaluate(args) => evaluate::run(args),
        AbilityCommand::CheckCompat(args) => check_compat::run(args, printer),
        AbilityCommand::Journal(args) => {
            let inspection = aos_ability_runtime::activation::inspect(
                &args.journal,
                aos_ability_runtime::journal::JournalLimits::default(),
            )?;
            printer.json(&serde_json::to_value(&inspection)?);
            Ok(())
        }
        AbilityCommand::Inspect(args) => {
            let document = read_document(&args.document, args.expected_digest.as_deref())?;
            let format = args
                .format
                .unwrap_or(if printer.mode() == OutputMode::Json {
                    AbilityRenderFormat::Json
                } else {
                    AbilityRenderFormat::Text
                });
            match format {
                AbilityRenderFormat::Text => printer.raw(&document.render_plain()),
                AbilityRenderFormat::Html => printer.raw(&document.render_html()),
                AbilityRenderFormat::Json => printer.json(document.value()),
            }
            Ok(())
        }
        AbilityCommand::Operator(args) => {
            let document = read_document(&args.document, args.expected_digest.as_deref())?;
            if args.serve {
                browser::serve(
                    document,
                    args.listen.unwrap_or_else(|| ([127, 0, 0, 1], 0).into()),
                    printer,
                )
                .await
            } else {
                printer.json(document.value());
                Ok(())
            }
        }
        AbilityCommand::Compare(args) => {
            let before = read_document(&args.before, args.before_digest.as_deref())?;
            let after = read_document(&args.after, args.after_digest.as_deref())?;
            if let (Some(before_graph), Some(after_graph)) =
                (before.transaction_graph(), after.transaction_graph())
            {
                ensure!(
                    before.value()["scope"] == after.value()["scope"]
                        && before.value()["system"] == after.value()["system"],
                    "transaction comparison requires the same scope and platform"
                );
                let earlier = &before_graph.graph().nodes;
                let later = &after_graph.graph().nodes;
                let added = later
                    .keys()
                    .filter(|id| !earlier.contains_key(*id))
                    .collect::<Vec<_>>();
                let removed = earlier
                    .keys()
                    .filter(|id| !later.contains_key(*id))
                    .collect::<Vec<_>>();
                let mut changed = Vec::new();
                for (id, effect) in later {
                    if let Some(previous) = earlier.get(id) {
                        if previous.revision != effect.revision {
                            changed.push(id);
                        }
                    }
                }
                printer.json(&serde_json::json!({
                    "schema": "aos.package.transaction.comparison",
                    "added": added,
                    "removed": removed,
                    "changed": changed,
                    "desiredOnly": true,
                    "retirementBefore": before.transaction_retirement(),
                    "retirementAfter": after.transaction_retirement(),
                    "orderChanged": before_graph.graph().order != after_graph.graph().order,
                }));
            } else {
                printer.json(&serde_json::to_value(before.compare(&after)?)?);
            }
            Ok(())
        }
        AbilityCommand::RemovalPreview(args) => {
            let document = read_document(&args.document, args.expected_digest.as_deref())?;
            let graph = document
                .transaction_graph()
                .context("removal preview requires a native desired transaction")?
                .graph();
            ensure!(
                graph.nodes.contains_key(&args.effect),
                "selected effect identity is absent"
            );
            ensure!(
                args.max_nodes > 0 && args.max_nodes <= 10000 && args.max_depth <= 10000,
                "invalid removal traversal bounds"
            );
            let mut affected = BTreeSet::from([args.effect.clone()]);
            let mut frontier = affected.clone();
            for _ in 0..args.max_depth {
                let next = graph
                    .nodes
                    .iter()
                    .filter(|(id, effect)| {
                        !affected.contains(*id)
                            && effect
                                .dependencies
                                .iter()
                                .any(|dependency| frontier.contains(dependency))
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<BTreeSet<_>>();
                if next.is_empty() {
                    break;
                }
                ensure!(
                    affected.len() + next.len() <= args.max_nodes,
                    "removal preview exceeds its effect bound"
                );
                affected.extend(next.iter().cloned());
                frontier = next;
            }
            let truncated = graph.nodes.iter().any(|(id, effect)| {
                !affected.contains(id)
                    && effect
                        .dependencies
                        .iter()
                        .any(|dependency| affected.contains(dependency))
            });
            printer.json(&serde_json::json!({
                "schema": "aos.package.transaction.removal-preview",
                "effect": args.effect,
                "affected": affected,
                "truncated": truncated,
                "desiredOnly": true,
            }));
            Ok(())
        }
        AbilityCommand::Diagnostic(args) => {
            let generation = aos_package::profile::deployment::committed_generation(
                &args.profile,
                args.generation,
            )?;
            let desired = RuntimeDocument::from_json(&generation.deployment.canonical_bytes()?)?;
            let value = match args.audience {
                AbilityDiagnosticAudience::Redacted => {
                    serde_json::json!({
                        "schema": "aos.package.generation.inspection",
                        "generation": args.generation,
                        "sequence": generation.sequence,
                        "content": generation.content,
                        "desiredEffectCount": desired.transaction_graph().map(|graph| graph.graph().nodes.len()),
                        "retainedOutputCount": generation.outputs.len(),
                        "audience": "redacted",
                        "liveStateVerified": false,
                    })
                }
                AbilityDiagnosticAudience::Deployment => {
                    serde_json::json!({
                        "schema": "aos.package.generation.inspection",
                        "generation": args.generation,
                        "sequence": generation.sequence,
                        "content": generation.content,
                        "desired": desired.value(),
                        "retainedOutputs": generation.outputs,
                        "audience": "deployment",
                        "liveStateVerified": false,
                    })
                }
            };
            printer.json(&value);
            Ok(())
        }
        AbilityCommand::ArtifactConsumption(args) => {
            let bytes = read_bounded_file(
                &args.evidence,
                ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES,
                "realized artifact evidence",
            )?;
            let evidence = CheckedArtifactConsumptionEvidence::decode(&bytes)?;
            let provider = args
                .provider_content
                .as_deref()
                .map(Sha256Digest::parse)
                .transpose()?;
            let explanation = evidence.query(&ArtifactConsumptionQuery::new(
                args.consumer.clone(),
                provider,
            ))?;
            if matches!(args.format, Some(ArtifactConsumptionRenderFormat::Json))
                || printer.mode() == OutputMode::Json
            {
                printer.json(&serde_json::to_value(&explanation)?);
            } else {
                printer.raw(&render_artifact_consumption_text(&explanation));
            }
            Ok(())
        }
    }
}

fn read_document(path: &std::path::Path, expected_digest: Option<&str>) -> Result<RuntimeDocument> {
    let bytes = read_bounded_file(
        path,
        aos_doc_model::runtime::MAX_RUNTIME_DOCUMENT_BYTES as u64,
        "native runtime document",
    )?;
    if let Some(expected) = expected_digest {
        ensure!(
            Sha256Digest::of_bytes(&bytes) == Sha256Digest::parse(expected)?,
            "native runtime document differs from its independent digest"
        );
    }
    RuntimeDocument::from_json(&bytes).context("checking native runtime document")
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
