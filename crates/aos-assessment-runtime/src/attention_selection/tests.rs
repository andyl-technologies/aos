//! Score boundaries, conflicting source facts and refusal of guessed severity.

use super::*;

fn severity(scheme: &str, score: Option<&str>) -> AdvisorySeverity {
    AdvisorySeverity {
        source: "fixture-cna".into(),
        scheme: scheme.into(),
        value: "source-provided-vector".into(),
        base_score: score.map(str::to_owned),
    }
}

#[test]
fn first_cvss_boundaries_are_exact_without_float_rounding() {
    for (score, expected) in [
        ("0.0", SeverityBand::None),
        ("0.1", SeverityBand::Low),
        ("3.9", SeverityBand::Low),
        ("4.0", SeverityBand::Medium),
        ("6.9", SeverityBand::Medium),
        ("7.0", SeverityBand::High),
        ("8.9", SeverityBand::High),
        ("9.0", SeverityBand::Critical),
        ("10.0", SeverityBand::Critical),
    ] {
        for scheme in ["CVSS_V3", "CVSS_V4"] {
            let context = AttentionSelectionContext::from_severities(
                "publisher/package".into(),
                &[severity(scheme, Some(score))],
            );
            context.validate().unwrap();
            assert_eq!(context.severity_bands, vec![expected]);
            assert!(!context.unknown_severity);
        }
    }
}

#[test]
fn unsupported_missing_and_malformed_scores_remain_unknown() {
    for score in [
        "", "9", "9.00", "09.0", "9e0", "-0.0", "+9.0", " 9.0", "9.0 ", "10.1", "11.0", "NaN", "∞",
    ] {
        assert_eq!(score_band(score), None, "{score}");
    }
    for entry in [
        severity("CVSS_V3", None),
        severity("CVSS_V2", Some("9.0")),
        severity("EPSS", Some("0.9")),
    ] {
        let context =
            AttentionSelectionContext::from_severities("publisher/package".into(), &[entry]);
        assert!(context.unknown_severity);
        assert!(context.severity_bands.is_empty());
    }
    assert!(
        AttentionSelectionContext::from_severities("publisher/package".into(), &[])
            .unknown_severity
    );
}

#[test]
fn conflicting_and_unknown_sources_are_preserved_without_lowest_score_winning() {
    let context = AttentionSelectionContext::from_severities(
        "publisher/package".into(),
        &[
            severity("CVSS_V3", Some("2.0")),
            severity("CVSS_V4", Some("9.0")),
            severity("CVSS_V3", Some("9.0")),
            severity("unsupported", None),
        ],
    );
    context.validate().unwrap();
    assert_eq!(
        context.severity_bands,
        vec![SeverityBand::Low, SeverityBand::Critical]
    );
    assert!(context.unknown_severity);
}
