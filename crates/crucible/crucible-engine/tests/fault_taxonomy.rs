//! Executable fault-taxonomy validation.
//!
//! `tests/data/fault-taxonomy.tsv` lists every executable taxonomy row together
//! with the effect program that realizes it. This test rejects malformed,
//! duplicated, or mis-sectioned rows and any effect program that names an
//! effect key absent from the [`EffectKind`] registry. The per-section
//! cardinality is pinned so that adding or removing a row is a reviewed change.

use std::collections::{BTreeMap, BTreeSet};

use crucible_engine::model::EffectKind;

const TAXONOMY: &str = include_str!("data/fault-taxonomy.tsv");

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExecutableSection {
    Wired,
    Radio,
    Satellite,
    Node,
    Storage,
}

impl ExecutableSection {
    const ALL: [Self; 5] = [
        Self::Wired,
        Self::Radio,
        Self::Satellite,
        Self::Node,
        Self::Storage,
    ];

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|section| section.name() == name)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Wired => "wired",
            Self::Radio => "radio",
            Self::Satellite => "satellite",
            Self::Node => "node",
            Self::Storage => "storage",
        }
    }
}

type TaxonomyKey = (ExecutableSection, String);

const MODEL_TIERS: [&str; 3] = ["Core", "Next", "Advanced"];

#[test]
fn fault_taxonomy_matches_every_executable_row() {
    let rows = parse_taxonomy(TAXONOMY)
        .unwrap_or_else(|error| panic!("fault taxonomy must be exact: {error}"));

    let section_counts = rows
        .keys()
        .fold(BTreeMap::new(), |mut counts, (section, _)| {
            *counts.entry(*section).or_insert(0_usize) += 1;
            counts
        });
    assert_eq!(
        section_counts,
        BTreeMap::from([
            (ExecutableSection::Wired, 76),
            (ExecutableSection::Radio, 52),
            (ExecutableSection::Satellite, 20),
            (ExecutableSection::Node, 41),
            (ExecutableSection::Storage, 37),
        ]),
        "the reviewed executable taxonomy cardinality changed"
    );
    assert_eq!(rows.len(), 226);
}

#[test]
fn fault_taxonomy_parser_rejects_hostile_row_mutations() {
    let taxonomy = minimal_taxonomy();
    parse_taxonomy(&taxonomy)
        .unwrap_or_else(|error| panic!("minimal valid taxonomy must pass: {error}"));

    let wired_row = "wired\tLink\twired fault\tstate\tCore\t`network.availability`";
    let mutations = [
        (
            taxonomy.replace(wired_row, &format!("{wired_row}\n{wired_row}")),
            "a duplicate taxonomy row must fail",
        ),
        (
            taxonomy.replace(wired_row, ""),
            "a missing executable section must fail",
        ),
        (
            taxonomy.replace("`node.lifecycle`", "`node.not_registered`"),
            "an unknown effect key must fail",
        ),
        (
            taxonomy.replace("`node.lifecycle`", "node lifecycle"),
            "a program without an effect expression must fail",
        ),
        (
            taxonomy.replace("`node.lifecycle`", "`node.lifecycle"),
            "an unbalanced code span must fail",
        ),
        (
            taxonomy.replace("wired\tLink", "orbital\tLink"),
            "an unknown section must fail",
        ),
        (
            taxonomy.replace(
                "\tCore\t`network.availability`",
                "\tSoon\t`network.availability`",
            ),
            "an unknown model tier must fail",
        ),
        (
            taxonomy.replace(
                "\tstate\tCore\t`network.availability`",
                "\tCore\t`network.availability`",
            ),
            "a row with a missing field must fail",
        ),
    ];

    for (mutated, message) in mutations {
        assert!(parse_taxonomy(&mutated).is_err(), "{message}");
    }
}

/// Parses the taxonomy into each row's registered effect keys.
fn parse_taxonomy(text: &str) -> Result<BTreeMap<TaxonomyKey, BTreeSet<String>>, String> {
    let mut rows = BTreeMap::new();

    for (index, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split('\t').collect::<Vec<_>>();
        let [section, area, fault, effect, tier, program] = fields.as_slice() else {
            return Err(format!(
                "line {}: expected six tab-separated fields",
                index + 1
            ));
        };
        let section = ExecutableSection::from_name(section)
            .ok_or_else(|| format!("line {}: unknown section {section:?}", index + 1))?;
        if area.is_empty() || fault.is_empty() || effect.is_empty() {
            return Err(format!(
                "line {}: area, fault, and effect must be set",
                index + 1
            ));
        }
        if !MODEL_TIERS.contains(tier) {
            return Err(format!("line {}: unknown model tier {tier:?}", index + 1));
        }

        let key = (section, (*fault).to_owned());
        let effects = registered_effects(program)?;
        if rows.insert(key.clone(), effects).is_some() {
            return Err(format!("duplicate taxonomy row {}", format_key(&key)));
        }
    }

    let sections = rows
        .keys()
        .map(|(section, _)| *section)
        .collect::<BTreeSet<_>>();
    if sections != BTreeSet::from(ExecutableSection::ALL) {
        return Err(format!(
            "executable sections differ; expected={:?}, actual={sections:?}",
            ExecutableSection::ALL
        ));
    }

    Ok(rows)
}

/// Extracts the effect keys named by backtick spans and checks each against
/// the engine registry.
fn registered_effects(program: &str) -> Result<BTreeSet<String>, String> {
    let spans = program.split('`').collect::<Vec<_>>();
    if spans.len() % 2 == 0 {
        return Err(format!(
            "unbalanced code span in effect program {program:?}"
        ));
    }

    let mut effects = BTreeSet::new();
    for expression in spans.iter().skip(1).step_by(2) {
        let key = expression
            .split_once('(')
            .map_or(*expression, |(key, _)| key)
            .trim();
        if EffectKind::from_key(key).is_none() {
            return Err(format!(
                "effect program {program:?} names unregistered effect {key:?}"
            ));
        }
        effects.insert(key.to_owned());
    }

    if effects.is_empty() {
        return Err(format!(
            "effect program {program:?} has no registered effect expression"
        ));
    }
    Ok(effects)
}

fn format_key((section, fault): &TaxonomyKey) -> String {
    format!("{}:{fault}", section.name())
}

fn minimal_taxonomy() -> String {
    [
        "# section\tarea\tfault\teffect\ttier\tprogram",
        "wired\tLink\twired fault\tstate\tCore\t`network.availability`",
        "radio\tRF\tradio fault\tstate\tCore\t`network.rf_channel`",
        "satellite\tContact\tsatellite fault\tstate\tCore\t`network.contact`",
        "node\tNode\tnode fault\tstate\tCore\t`node.lifecycle`",
        "storage\tDevice\tstorage fault\tstate\tCore\t`storage.availability`",
    ]
    .join("\n")
}
