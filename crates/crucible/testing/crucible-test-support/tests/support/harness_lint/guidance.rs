//! Floating-point guardrail for guidance and adaptive ordering sources.

use super::*;

pub(super) fn guidance_ordering_float_failures(
    path: &Path,
    content: &str,
    tokens: &[Token],
) -> Vec<String> {
    if !guidance_ordering_source(path, tokens) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for token in tokens {
        let Some(identifier @ ("f32" | "f64")) = token.kind.as_ident() else {
            continue;
        };
        push_finding(
            &mut findings,
            path,
            content,
            token.line,
            "floating-point guidance/adaptive ordering",
            identifier,
            "guidance-ordering-float",
        );
    }
    findings
}

fn guidance_ordering_source(path: &Path, tokens: &[Token]) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let source_path = [
        "crucible/src/model/exploration.rs",
        "crucible/src/model/adaptive_campaign.rs",
        "crucible/src/model/runtime.rs",
        "crucible/src/model/guidance_search.rs",
        "crucible/src/model/temporal_graph/guided_search.rs",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix));
    source_path
        && tokens.iter().any(|token| {
            matches!(
                token.kind.as_ident(),
                Some(
                    "GuidanceSignal"
                        | "GuidanceSearchConfig"
                        | "AdaptiveCampaignConfig"
                        | "AdaptiveStrategyConfig"
                        | "run_adaptive_strategy_selection"
                )
            )
        })
}

#[test]
fn rejects_float_types_but_ignores_comments_and_strings() {
    let path = Path::new("crucible/src/model/guidance_search.rs");
    let findings = super::custom_static_analysis_failures(
        path,
        r#"
            pub struct GuidanceSearchConfig;
            fn score() {
                let score: f64 = 1.0;
            }
        "#,
    );
    assert_contains(&findings, "floating-point guidance/adaptive ordering");
    assert_contains(&findings, "f64");

    let clean = super::custom_static_analysis_failures(
        path,
        r#"
            pub struct GuidanceSearchConfig;
            // f64 in a comment is inert.
            const EXAMPLE: &str = "f32 in a string is inert";
            fn score() {
                let score: u64 = 1;
            }
        "#,
    );
    assert!(
        clean
            .iter()
            .all(|finding| !finding.contains("floating-point guidance/adaptive ordering"))
    );
}
