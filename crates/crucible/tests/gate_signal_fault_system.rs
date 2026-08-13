//! Terminal closed-registry checks for the signal-driven fault system.
//!
//! Live production-backend proofs are composed by the hermetic Phase-7 Nix
//! gate. This addressable Cargo target owns the platform-independent portion:
//! closed vocabulary integrity, specification-only exclusions, and exact user
//! reference coverage.

#[path = "fault_reference.rs"]
mod fault_reference;

use std::collections::BTreeSet;

use crucible::model::{
    BindingSearchChoice, ContentHash, EffectKind, FaultAdapter, FaultTargetKind,
    PureSignalOperator, SearchChoiceId, SearchOverride, SignalSourceKind, StatefulSignalOperator,
};
use crucible::{Configuration, Decision, ScenarioDef};

#[test]
fn gate_signal_fault_system_has_closed_executable_registries() {
    let effects = EffectKind::all();
    assert_eq!(effects.len(), 71, "the reviewed effect ledger changed");
    assert_eq!(
        effects
            .iter()
            .map(|kind| kind.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        effects.len(),
        "effect keys must be unique"
    );
    for adapter in [
        FaultAdapter::Network,
        FaultAdapter::Storage,
        FaultAdapter::Node,
    ] {
        assert!(
            effects
                .iter()
                .any(|kind| kind.descriptor().adapter == adapter),
            "every production adapter must own at least one effect"
        );
    }

    for values in [
        SignalSourceKind::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        PureSignalOperator::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        StatefulSignalOperator::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        FaultTargetKind::all()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
    ] {
        assert_eq!(
            values.iter().copied().collect::<BTreeSet<_>>().len(),
            values.len(),
            "every accepted registry value must have one canonical spelling"
        );
        assert!(
            values
                .iter()
                .all(|value| !value.starts_with("sensor") && !value.starts_with("power.")),
            "specification-only device domains must not enter executable registries"
        );
    }
}

#[test]
fn gate_signal_fault_system_has_complete_per_effect_contract_metadata() {
    let mut capabilities = BTreeSet::new();

    for effect in EffectKind::all() {
        let descriptor = effect.descriptor();
        assert_eq!(descriptor.key, *effect);
        assert!(descriptor.semantic_version > 0);
        assert!(
            !descriptor.targets.is_empty(),
            "{effect} has no target kind"
        );
        assert!(
            !descriptor.phases.is_empty(),
            "{effect} has no application phase"
        );
        assert!(!descriptor.lifetimes.is_empty(), "{effect} has no lifetime");
        assert!(
            !descriptor.replay_evidence.is_empty(),
            "{effect} has no locked-replay evidence contract"
        );
        assert!(
            descriptor
                .targets
                .iter()
                .all(|target| target.adapter() == descriptor.adapter),
            "{effect} crosses adapter ownership"
        );
        assert!(
            capabilities.insert(descriptor.capability),
            "duplicate production capability {}",
            descriptor.capability
        );
        assert_eq!(EffectKind::from_key(effect.as_str()), Some(*effect));
    }
}

#[test]
fn signal_fault_search_decisions_round_trip_with_parent_identity() {
    let parent = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.signal-search-test.v1",
        "search-parent",
    ));
    let choice = BindingSearchChoice {
        id: SearchChoiceId::from_content_hash(ContentHash::from_bytes(b"choice")),
        candidates_digest: ContentHash::from_bytes(b"candidates"),
        candidate_count: 3,
        selected_index: None,
        overridden: false,
    };
    let decisions = choice.override_decisions(parent.id());
    assert_eq!(decisions.len(), 3);
    for (candidate_index, decision) in decisions.iter().enumerate() {
        let (decoded_id, decoded) = SearchOverride::from_override_decision(decision)
            .unwrap_or_else(|| panic!("candidate {candidate_index} must decode"));
        assert_eq!(decoded_id, choice.id);
        assert_eq!(decoded.candidate_index, candidate_index as u32);
        assert_eq!(decoded.candidates_digest, choice.candidates_digest);
        assert_eq!(decoded.parent_branch, Some(parent.id()));
    }
    let malformed = crucible::OverrideDecision {
        point: crucible::SchedulingPoint {
            key: String::from("signal-fault/not-a-hash/choice/candidates"),
        },
        choice: crucible::ChoiceTag {
            name: String::from("candidate/0"),
        },
    };
    assert!(SearchOverride::from_override_decision(&malformed).is_none());
    let mut noncanonical = decisions[0].clone();
    noncanonical.point.key.make_ascii_uppercase();
    assert!(SearchOverride::from_override_decision(&noncanonical).is_none());
    assert!(
        decisions
            .into_iter()
            .map(Decision::Override)
            .all(|decision| matches!(decision, Decision::Override(_)))
    );
}
