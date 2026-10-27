//! Read-only inspection and canonical export of the shared release contract.
//!
//! Without `--to` the command prints the registry tier's destination table
//! (surface, channel, profile, `after`). With `--to <destination>` it prints
//! that destination's profile and the gate identities it derives without a
//! change scope, that is, with every population affecting. Both forms report
//! the platforms whose release the contract defers.

use std::io::Write as _;

use anyhow::{Context as _, Result};
use aos_cli_ui::output::Printer;
use aos_nix::NixRunner;
use aos_release_format::canonical;
use aos_release_format::qualification::{ContractDestination, QualificationContract};
use aos_release_format::registry::{channel_kind, registry_policy};

use crate::cli::ReleaseContractArgs;

pub(super) fn run(args: &ReleaseContractArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let contract: QualificationContract = match &args.input {
        Some(path) => {
            let contract: QualificationContract = canonical::from_slice(
                &super::capture::control_file(path, "qualification contract")?,
                "qualification contract",
            )?;
            contract.validate()?;
            contract
        }
        None => export(nix)?,
    };
    let tier = registry_policy(&args.registry)?.tier();
    let bytes = canonical::to_vec(&contract)?;
    if let Some(path) = &args.output {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file_mut().sync_all()?;
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
    }
    let digest = contract.digest()?;

    let Some(name) = &args.to else {
        let destinations: Vec<&ContractDestination> = contract.destinations_for(tier).collect();
        if printer.json_if_active(&serde_json::json!({
            "schema_version": "aos.release.contract-result/v1",
            "registry": args.registry,
            "public_evidence_policy_digest": digest,
            "deferred_platforms": contract.deferred_platforms,
            "destinations": destinations,
        })) {
            return Ok(());
        }
        printer.success(&format!(
            "{} ({}) policy {}",
            contract.id, args.registry, digest
        ));
        print_deferred_platforms(&contract);
        for destination in destinations {
            println!(
                "{}: profile {}{}",
                destination.name_for(&destination.channel),
                destination.profile,
                if destination.after.is_empty() {
                    String::new()
                } else {
                    format!(
                        " after {}",
                        destination
                            .after
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            );
        }
        return Ok(());
    };

    let (surface, channel) = aos_release_format::plan::parse_destination_name(name)?;
    let cell = contract.destination(tier, surface, channel_kind(channel)?)?;
    let profile = contract.profile(&cell.profile)?;
    let gates = contract.gates(cell, None).or_else(|_| {
        // Change-scoped profiles need a scope; show the fail-closed one.
        contract.gates(
            cell,
            Some(&aos_release_format::qualification::ChangeScope {
                schema_version: aos_release_format::qualification::change_scope::CHANGE_SCOPE
                    .to_owned(),
                predecessor_manifest_digest: None,
                image_affecting: true,
                container_affecting: true,
                changed_package_cells: Vec::new(),
                reason: "contract inspection: every population is affecting".to_owned(),
            }),
        )
    })?;
    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.contract-result/v1",
        "registry": args.registry,
        "destination": name,
        "public_evidence_policy_digest": digest,
        "deferred_platforms": contract.deferred_platforms,
        "profile": profile,
        "profile_digest": profile.digest()?,
        "gates": gates,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "{name} ({}) profile {} policy {}",
        args.registry, profile.name, digest
    ));
    println!("{}", profile.description);
    print_deferred_platforms(&contract);
    println!(
        "claims {:?}, soak {}s, reviews {}, complete matrix {}, transaction review {}",
        profile.claims,
        profile.soak_seconds,
        profile.review_threshold,
        profile.require_complete_matrix,
        profile.review_registry_transaction
    );
    for (ring, policy) in profile.rollout.rings.iter().enumerate() {
        println!(
            "ring {}: {} partitions, observe {}s",
            ring + 1,
            policy.partitions,
            policy.observe_seconds
        );
    }
    for (kind, fitness) in &profile.fitness {
        println!("fitness {kind}: max age {}s", fitness.max_age_seconds);
    }
    for gate in &gates {
        println!(
            "gate {} ({})",
            gate.policy_id,
            if gate.blocking {
                "blocking"
            } else {
                "advisory"
            }
        );
    }
    println!(
        "Qualification status: not evaluated. This contract describes requirements, not passing evidence."
    );
    Ok(())
}

/// Evaluates and validates the repository's exported qualification contract.
///
/// # Errors
/// Returns an error when Nix evaluation fails or the export is not a valid
/// contract.
pub(super) fn export(nix: &NixRunner) -> Result<QualificationContract> {
    let contract: QualificationContract =
        serde_json::from_value(nix.eval_json("releaseQualification")?)
            .context("decoding Nix qualification contract")?;
    contract.validate()?;
    Ok(contract)
}

/// Prints the deferred platforms, which ship nothing in any release.
fn print_deferred_platforms(contract: &QualificationContract) {
    if contract.deferred_platforms.is_empty() {
        return;
    }
    let platforms: Vec<&str> = contract
        .deferred_platforms
        .iter()
        .map(|platform| platform.as_str())
        .collect();
    println!(
        "deferred platforms (no artifacts, targets or claims): {}",
        platforms.join(", ")
    );
}
