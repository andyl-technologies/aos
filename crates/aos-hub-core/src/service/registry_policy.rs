//! Field-level review effects for operational registry policy changes.

use super::{pb, RegistryRecord};

/// Describes normalized policy updates, including each added or removed anchor.
pub(super) fn effects(
    current: &RegistryRecord,
    desired: &pb::PlanUpdateRegistryRequest,
) -> Vec<String> {
    let mut effects = Vec::new();
    for (label, before, after) in [
        (
            "Visibility",
            current.visibility.as_str(),
            desired.visibility.as_str(),
        ),
        (
            "Crawler policy",
            current.crawl_policy.as_str(),
            desired.crawl_policy.as_str(),
        ),
        (
            "llms.txt override",
            current.llms_txt_body.as_deref().unwrap_or_default(),
            desired.llms_txt_body.as_str(),
        ),
    ] {
        if before != after {
            effects.push(format!("{label}: {before:?} → {after:?}"));
        }
    }
    effects.extend(trust_key_effects(&current.trust_keys, &desired.trust_keys));
    if effects.is_empty() {
        effects.push("No registry policy values change.".to_string());
    }
    effects
}

fn trust_key_effects(before: &[String], after: &[String]) -> Vec<String> {
    let mut effects = Vec::new();
    for key in before.iter().filter(|key| !after.contains(key)) {
        effects.push(format!("Remove pinned trust anchor: {key}"));
    }
    for key in after.iter().filter(|key| !before.contains(key)) {
        effects.push(format!("Add pinned trust anchor: {key}"));
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::trust_key_effects;

    #[test]
    fn trust_anchor_review_identifies_rotations_and_clears() {
        let original = vec![
            "old:Ed25519:old-public-key".into(),
            "kept:Ed25519:kept-public-key".into(),
        ];
        let desired = vec![
            "kept:Ed25519:kept-public-key".into(),
            "new:Ed25519:new-public-key".into(),
        ];

        assert_eq!(
            trust_key_effects(&original, &desired),
            vec![
                "Remove pinned trust anchor: old:Ed25519:old-public-key",
                "Add pinned trust anchor: new:Ed25519:new-public-key",
            ]
        );
        assert_eq!(trust_key_effects(&original, &[]).len(), 2);
        assert!(trust_key_effects(&original, &original).is_empty());
    }
}
