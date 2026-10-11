//! Affected endpoint, comparator and complete configuration conformance tests.

use anyhow::Result;
use aos_assessment::advisory::{AffectedProduct, AffectedRange, RangeEvent, RangeKind};
use aos_assessment::nvd::{Configuration, Operator};
use aos_assessment::ranges::{Truth, affected_range, affected_version, compare_versions};
use aos_assessment::scan_inventory::ComponentInstance;
use aos_assessment::security::{AdvisoryVersionScheme, SecurityIdentity};
use aos_contract::Sha256Digest;
use serde_json::json;
use std::cmp::Ordering;

fn range(events: Vec<RangeEvent>) -> AffectedRange {
    AffectedRange {
        kind: RangeKind::Semver,
        repository: None,
        events,
    }
}

fn component() -> Result<ComponentInstance> {
    Ok(serde_json::from_value(json!({
        "componentRef":"main", "componentId":"main", "subjectRef":"subject",
        "scanDefinitionDigest":Sha256Digest::of_bytes("definition"),
        "current":{"upstreamId":"v1.2.0", "comparisonVersion":"1.2.0"},
        "security":{
            "identities":[{"kind":"cpe", "part":"a", "vendor":"example", "product":"product"}],
            "advisorySources":[{"provider":"nvd"}], "versionScheme":"semver",
            "dependencyCoverage":{"state":"unknown", "basis":"fixture"}
        }
    }))?)
}

fn term(product: &str, vulnerable: bool) -> Configuration {
    Configuration::Match {
        criteria: format!("cpe:2.3:a:example:{product}:*:*:*:*:*:*:*:*"),
        vulnerable,
        version_start_including: Some("1.0.0".into()),
        version_start_excluding: None,
        version_end_including: None,
        version_end_excluding: Some("1.3.0".into()),
    }
}

#[test]
fn osv_fixed_limit_and_last_affected_have_different_boundary_semantics() -> Result<()> {
    use RangeEvent::*;
    let scheme = AdvisoryVersionScheme::Semver;
    for endpoint in [Fixed("1.2.0".into()), Limit("1.2.0".into())] {
        let range = range(vec![Introduced("0".into()), endpoint]);
        assert_eq!(affected_range(&range, "1.1.9", scheme)?, Truth::True);
        assert_eq!(affected_range(&range, "1.2.0", scheme)?, Truth::False);
    }
    let range = range(vec![
        Introduced("1.0.0".into()),
        LastAffected("1.2.0".into()),
    ]);
    assert_eq!(affected_range(&range, "0.9.0", scheme)?, Truth::False);
    assert_eq!(affected_range(&range, "1.0.0", scheme)?, Truth::True);
    assert_eq!(affected_range(&range, "1.2.0", scheme)?, Truth::True);
    assert_eq!(affected_range(&range, "1.2.1", scheme)?, Truth::False);
    let point = AffectedRange {
        kind: RangeKind::Semver,
        repository: None,
        events: vec![Introduced("1.2.0".into()), LastAffected("1.2.0".into())],
    };
    assert_eq!(affected_range(&point, "1.2.0", scheme)?, Truth::True);
    Ok(())
}

#[test]
fn range_unions_preserve_reintroduction_and_unsupported_uncertainty() -> Result<()> {
    use RangeEvent::*;
    let first = range(vec![
        Introduced("0".into()),
        Fixed("1.0.0".into()),
        Introduced("2.0.0".into()),
    ]);
    assert_eq!(
        affected_range(&first, "1.2.0", AdvisoryVersionScheme::Semver)?,
        Truth::False
    );
    assert_eq!(
        affected_range(&first, "2.0.1", AdvisoryVersionScheme::Semver)?,
        Truth::True
    );
    assert_eq!(
        affected_range(&first, "opaque", AdvisoryVersionScheme::Semver)?,
        Truth::Unknown
    );
    assert_eq!(
        affected_range(&first, "1.2.0", AdvisoryVersionScheme::Unsupported)?,
        Truth::Unknown
    );
    let product = AffectedProduct {
        identity: SecurityIdentity::Ecosystem {
            ecosystem: "crates.io".into(),
            name: "example".into(),
        },
        versions: vec!["opaque".into()],
        ranges: vec![first],
        unsupported: vec!["source-specific-constraint".into()],
    };
    assert_eq!(
        affected_version(&product, "opaque", AdvisoryVersionScheme::Unsupported)?,
        Truth::True
    );
    assert_eq!(
        affected_version(&product, "1.2.0", AdvisoryVersionScheme::Semver)?,
        Truth::Unknown
    );
    Ok(())
}

#[test]
fn supported_comparators_never_use_lexical_fallback() -> Result<()> {
    assert_eq!(
        compare_versions(AdvisoryVersionScheme::DottedNumeric, "1.10", "1.9")?,
        Some(Ordering::Greater)
    );
    assert_eq!(
        compare_versions(AdvisoryVersionScheme::DottedNumeric, "1.0", "1.0.0")?,
        Some(Ordering::Equal)
    );
    assert_eq!(
        compare_versions(AdvisoryVersionScheme::Semver, "1.0.0+one", "1.0.0+two")?,
        Some(Ordering::Equal)
    );
    assert_eq!(
        compare_versions(AdvisoryVersionScheme::Semver, "1.0.0-rc.1", "1.0.0")?,
        Some(Ordering::Less)
    );
    assert!(compare_versions(AdvisoryVersionScheme::Semver, "1.0", "1.0.0").is_err());
    assert!(compare_versions(AdvisoryVersionScheme::DottedNumeric, "1a", "1").is_err());
    assert_eq!(
        compare_versions(AdvisoryVersionScheme::Git, "a", "b")?,
        None
    );
    Ok(())
}

#[test]
fn nvd_and_preserves_unknown_environment_and_false_dominance() -> Result<()> {
    let target = component()?;
    let expression = Configuration::Expression {
        operator: Operator::And,
        negate: false,
        children: vec![term("product", true), term("operating-system", false)],
    };
    assert_eq!(expression.evaluate(&target, &[])?.affected, Truth::Unknown);
    let no_match = Configuration::Expression {
        operator: Operator::And,
        negate: false,
        children: vec![
            term("different-product", true),
            Configuration::Unsupported {
                reason: "environment-unavailable".into(),
            },
        ],
    };
    assert_eq!(no_match.evaluate(&target, &[])?.affected, Truth::False);
    let environment_only = term("product", false);
    assert_eq!(
        environment_only
            .evaluate(&target, std::slice::from_ref(&target))?
            .affected,
        Truth::False
    );
    let or = Configuration::Expression {
        operator: Operator::Or,
        negate: false,
        children: vec![
            term("product", true),
            Configuration::Unsupported {
                reason: "environment-unavailable".into(),
            },
        ],
    };
    assert_eq!(or.evaluate(&target, &[])?.affected, Truth::True);
    Ok(())
}

#[test]
fn nvd_negation_and_unsupported_qualifiers_preserve_uncertainty() -> Result<()> {
    let target = component()?;
    let not = Configuration::Expression {
        operator: Operator::And,
        negate: true,
        children: vec![Configuration::Unsupported {
            reason: "unknown-fact".into(),
        }],
    };
    assert_eq!(not.evaluate(&target, &[])?.environment, Truth::Unknown);
    let mut qualifier = term("product", true);
    if let Configuration::Match { criteria, .. } = &mut qualifier {
        *criteria = "cpe:2.3:a:example:product:*:patched:*:*:*:*:*:*".into();
    }
    assert_eq!(qualifier.evaluate(&target, &[])?.affected, Truth::Unknown);
    Ok(())
}

#[test]
fn advisory_change_commitment_preserves_all_normalized_assertions_and_raw_custody() -> Result<()> {
    use aos_assessment::advisory::{ADVISORY_RECORD_V1, AdvisoryRecordV1};

    let original: AdvisoryRecordV1 = serde_json::from_value(json!({
        "schema": ADVISORY_RECORD_V1,
        "provider": "osv",
        "id": "GHSA-fixture-one",
        "modified": "2026-10-09T01:02:03.456Z",
        "aliases": ["CVE-2026-10001"],
        "related": ["GHSA-fixture-related"],
        "upstream": ["CVE-2026-10002"],
        "summary": "Fixture issue",
        "affected": [{
            "identity": {"kind": "ecosystem", "ecosystem": "crates.io", "name": "fixture"},
            "versions": ["1.2.0"],
            "ranges": [],
            "unsupported": []
        }],
        "severity": [{"source": "osv", "scheme": "CVSS_V3", "value": "reported", "baseScore": "9.8"}],
        "references": ["https://example.invalid/advisory"],
        "sourceDigest": Sha256Digest::of_bytes("original raw record")
    }))?;
    let original_bytes = serde_json::to_vec(&original)?;
    let identity = original.digest()?;
    let change = original.change_digest()?;
    assert_ne!(identity, change);

    let mut reencoded = original.clone();
    reencoded.source_digest = Sha256Digest::of_bytes("same meaning, different raw response");
    assert_ne!(reencoded.digest()?, identity);
    assert_eq!(reencoded.change_digest()?, change);
    assert_eq!(serde_json::to_vec(&original)?, original_bytes);

    let mut mutations = Vec::new();
    for field in ["provider", "id", "modified", "summary"] {
        let mut value = serde_json::to_value(&original)?;
        value[field] = json!(format!("{}-changed", value[field].as_str().unwrap()));
        mutations.push(serde_json::from_value::<AdvisoryRecordV1>(value)?);
    }
    for field in ["aliases", "related", "upstream", "references"] {
        let mut value = serde_json::to_value(&original)?;
        value[field] = json!([]);
        mutations.push(serde_json::from_value::<AdvisoryRecordV1>(value)?);
    }
    let mut withdrawn = original.clone();
    withdrawn.withdrawn = Some("2026-10-09T02:00:00Z".into());
    mutations.push(withdrawn);
    let mut affected = original.clone();
    affected.affected[0].versions = vec!["1.3.0".into()];
    mutations.push(affected);
    let mut severity = original.clone();
    severity.severity[0].base_score = Some("9.9".into());
    mutations.push(severity);
    let mut configured = original.clone();
    configured.configuration = Some(Configuration::Unsupported {
        reason: "new source constraint".into(),
    });
    mutations.push(configured);
    for mutation in mutations {
        assert_ne!(
            mutation.change_digest()?,
            change,
            "normalized assertion was omitted"
        );
    }

    let mut incompatible = original.clone();
    incompatible.schema = "aos.advisory-record/unsupported".into();
    assert!(incompatible.change_digest().is_err());
    let mut invalid = original;
    invalid.references = vec!["https://user:secret@example.invalid/".into()];
    assert!(invalid.change_digest().is_err());
    Ok(())
}
