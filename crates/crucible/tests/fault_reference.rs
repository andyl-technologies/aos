//! User-reference completeness checks for the closed fault vocabulary.

use std::collections::BTreeMap;

use crucible::model::EffectKind;

const REFERENCE: &str = include_str!("../../../docs/users/crucible/reference.md");

#[test]
fn every_executable_effect_has_exactly_one_reference_row() {
    let section = REFERENCE
        .split_once("### Exhaustive effect registry")
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once("## Properties and predicates"))
        .map(|(section, _)| section)
        .unwrap_or_else(|| panic!("effect-reference section headings must remain present"));
    let mut documented = BTreeMap::<&str, usize>::new();
    for line in section.lines().filter(|line| line.starts_with("| `")) {
        let Some(key) = line.strip_prefix("| `").and_then(|line| line.split('`').next()) else {
            panic!("effect-reference row must begin with one code-formatted key: {line}");
        };
        *documented.entry(key).or_default() += 1;
    }

    assert_eq!(documented.len(), EffectKind::all().len());
    for effect in EffectKind::all() {
        assert_eq!(
            documented.get(effect.as_str()),
            Some(&1),
            "effect `{}` must have exactly one reference row",
            effect.as_str()
        );
    }
}
