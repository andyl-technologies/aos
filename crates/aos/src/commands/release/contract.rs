//! Read-only inspection and canonical export of the shared release contract.

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};
use aos_core::{nix::NixRunner, output::Printer};
use aos_release::qualification::{CONTRACT_V1, QualificationContractV1};
use aos_release::{canonical, digest::Sha256Digest, plan::ReleaseClass};

use crate::cli::ReleaseContractArgs;

pub(super) fn run(args: &ReleaseContractArgs, nix: &NixRunner, printer: &Printer) -> Result<()> {
    let contract: QualificationContractV1 = match &args.input {
        Some(path) => canonical::from_slice(
            &super::capture::control_file(path, "qualification contract")?,
            "qualification contract",
        )?,
        None => serde_json::from_value(nix.eval_json("releaseQualification")?)
            .context("decoding Nix qualification contract")?,
    };
    contract.validate()?;
    let class = match args.release_class.as_str() {
        "edge" => ReleaseClass::Edge,
        "candidate" => ReleaseClass::Candidate,
        "stable" => ReleaseClass::Stable,
        "emergency" => ReleaseClass::Emergency,
        _ => bail!("unknown release class"),
    };
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
    let digest = Sha256Digest::of_canonical(CONTRACT_V1, &contract)?;
    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.contract-result/v1",
        "contract": contract,
        "release_class": class,
        "public_evidence_policy_digest": digest,
        "gates": contract.gates(class)?,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "{} ({}) policy {}",
        contract.id, args.release_class, digest
    ));
    for requirement in contract.selected(class) {
        println!(
            "{:?}: {} ({:?}, {:?})",
            requirement.phase, requirement.id, requirement.scope, requirement.method
        );
        for check in &requirement.checks {
            println!("  [ ] {check}");
        }
    }
    println!(
        "Qualification status: not evaluated. This contract describes requirements, not passing evidence."
    );
    Ok(())
}
