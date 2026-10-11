//! Exact inventory-to-alert selection projection from a reproduced assessment.

use anyhow::{Context as _, Result};
use aos_assessment::evaluator::evaluate;
use aos_assessment::input::Profile;
use aos_assessment_runtime::alerts::IssueFamily;
use aos_assessment_runtime::attention::project;
use aos_assessment_runtime::attention_selection::SeverityBand;

#[path = "../../aos-assessment/tests/common/mod.rs"]
mod common;

#[test]
fn selection_facts_bind_exact_reproduced_subject_and_source_severity() -> Result<()> {
    let data = common::fixture("1.2.0")?;
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    let attention = project(&input, &data, &assessment)?;
    let issue = attention[0]
        .issues
        .iter()
        .find(|issue| issue.family == IssueFamily::Vulnerability)
        .context("vulnerability attention")?;
    let context = issue
        .selection_context
        .as_ref()
        .context("immutable selection facts")?;
    assert_eq!(
        context.package_coordinate,
        data.inventory.subjects[0].package_coordinate
    );
    assert_eq!(context.severity_bands, vec![SeverityBand::Critical]);
    assert!(!context.unknown_severity);
    assert!(!issue.uncertain);

    let mut changed = data;
    changed.inventory.subjects[0].package_coordinate = "another-publisher/example".into();
    assert!(project(&input, &changed, &assessment).is_err());
    Ok(())
}

#[test]
fn every_valid_inventory_coordinate_remains_projectable() -> Result<()> {
    let mut data = common::fixture("1.2.0")?;
    data.inventory.subjects[0].package_coordinate = format!("publisher/{}", "a".repeat(1014));
    let input = data.freeze(vec![Profile::Vulnerabilities], common::evaluated_at()?)?;
    let assessment = evaluate(&input, &data)?;
    let attention = project(&input, &data, &assessment)?;
    assert_eq!(
        attention[0].issues[0]
            .selection_context
            .as_ref()
            .context("selection facts")?
            .package_coordinate
            .len(),
        1024
    );
    Ok(())
}
