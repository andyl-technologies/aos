//! Current authenticated findings-ledger fixtures for CLI triage tests.

use super::*;

pub(super) fn write_current_triage_findings_ledger(
    dir: &Path,
    store_root: &Path,
    file_name: &str,
    mismatched_signature_material: Option<&str>,
) -> Result<(PathBuf, crucible::FindingReproductionArtifact), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let form = search_frontier_scenario_form()?;
    let configuration = crucible::try_step(
        &crucible::Configuration::genesis(form.scenario_def()),
        search_frontier_decisions()
            .into_iter()
            .nth(1)
            .ok_or_else(|| std::io::Error::other("missing triage fixture decision"))?,
    )?;
    let finding_fingerprint = crucible::ContentHash::from_bytes(b"cli triage signed finding");
    let finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint,
        &form,
        &configuration,
    )?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let artifact = finding.store_artifact(&store)?;
    assert_eq!(artifact, finding.artifact.id());

    let violation = crucible_model::HostAssertionViolation {
        assertion: crucible::AssertionId::from_name("cli-triage-signed-finding"),
        message: String::from("CLI triage signed finding violated"),
        quantifier: crucible::AssertionQuantifierKind::Always,
        event_kind: String::from("assertion_state_changed"),
        at_icount: Some(crucible::Icount { retired: 8 }),
        at_virtual_time: crucible::VirtualTime { ticks: 8 },
        node: Some(crucible::NodeId {
            name: String::from("triage-node"),
        }),
        detail: String::from("synthetic signed finding evidence"),
        reproduction_artifact: finding.artifact.id(),
    };
    let evidence = triage_property_evidence_for_violation(finding.clone(), violation)?;
    let mut ledger = String::from_utf8(reproduction_findings_ledger_bytes(&[evidence])?)?;
    if let Some(material) = mismatched_signature_material {
        let expected = ledger
            .lines()
            .find_map(|line| line.strip_prefix("finding.0.discovery_signature="))
            .ok_or_else(|| std::io::Error::other("missing discovery signature"))?;
        let replacement = crucible::ContentHash::from_bytes(material.as_bytes()).to_hex();
        ledger = ledger.replacen(
            &format!("finding.0.discovery_signature={expected}"),
            &format!("finding.0.discovery_signature={replacement}"),
            1,
        );
    }
    let path = dir.join(file_name);
    fs::write(&path, ledger)?;
    Ok((path, finding))
}
