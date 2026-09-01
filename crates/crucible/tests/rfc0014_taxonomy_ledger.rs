//! Exact RFC-0014 executable-taxonomy ledger validation.
//!
//! The executable taxonomy and its effect-program ledger are intentionally
//! maintained in separate normative chapters. This test parses both Markdown
//! surfaces and rejects missing, extra, duplicated, mis-sectioned, or
//! unregistered effect rows.

use std::collections::{BTreeMap, BTreeSet};

use crucible::model::EffectKind;

const TAXONOMY: &str =
    include_str!("../../../docs/rfcs/0014-signal-driven-fault-model/04-fault-taxonomy.md");
const EFFECT_CONTRACTS: &str = include_str!(
    "../../../docs/rfcs/0014-signal-driven-fault-model/08-executable-effect-contracts.md"
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExecutableSection {
    Wired,
    Radio,
    Satellite,
    Node,
    Storage,
}

impl ExecutableSection {
    const fn name(self) -> &'static str {
        match self {
            Self::Wired => "4.2-wired",
            Self::Radio => "4.3-radio",
            Self::Satellite => "4.4-satellite",
            Self::Node => "4.5-node",
            Self::Storage => "4.6-storage",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LedgerEntry {
    program: String,
    effects: BTreeSet<String>,
}

type TaxonomyKey = (ExecutableSection, String);

#[test]
fn rfc0014_taxonomy_ledger_matches_every_executable_row() {
    let rows = validate_documents(TAXONOMY, EFFECT_CONTRACTS)
        .unwrap_or_else(|error| panic!("RFC-0014 taxonomy ledger must be exact: {error}"));
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

    if let Ok(path) = std::env::var("CRUCIBLE_RFC0014_TAXONOMY_LEDGER_OUTPUT") {
        let mut output = String::new();
        for ((section, fault), entry) in rows {
            output.push_str(section.name());
            output.push('\t');
            output.push_str(&fault);
            output.push('\t');
            output.push_str(&entry.program);
            output.push('\t');
            output.push_str(&entry.effects.into_iter().collect::<Vec<_>>().join(","));
            output.push('\n');
        }
        std::fs::write(path, output)
            .unwrap_or_else(|error| panic!("taxonomy ledger artifact must be writable: {error}"));
    }
}

#[test]
fn rfc0014_taxonomy_ledger_parser_rejects_hostile_row_mutations() {
    let taxonomy = minimal_taxonomy();
    let ledger = minimal_ledger();
    validate_documents(&taxonomy, &ledger)
        .unwrap_or_else(|error| panic!("minimal valid ledger must pass: {error}"));

    let duplicated = taxonomy.replace(
        "| Link | wired fault | state | Core |",
        "| Link | wired fault | state | Core |\n| Link | wired fault | state | Core |",
    );
    assert!(
        validate_documents(&duplicated, &ledger).is_err(),
        "a duplicate taxonomy row must fail"
    );

    let missing = ledger.replace("| storage fault | `storage.availability` |", "");
    assert!(
        validate_documents(&taxonomy, &missing).is_err(),
        "a missing ledger row must fail"
    );

    let unknown = ledger.replace("`node.lifecycle`", "`node.not_registered`");
    assert!(
        validate_documents(&taxonomy, &unknown).is_err(),
        "an unknown effect key must fail"
    );

    let wrong_section = ledger
        .replace("| wired fault | `network.availability` |\n", "")
        .replace(
            "| radio fault | `network.rf_channel` |",
            "| radio fault | `network.rf_channel` |\n| wired fault | `network.availability` |",
        );
    assert!(
        validate_documents(&taxonomy, &wrong_section).is_err(),
        "a row assigned to the wrong section must fail"
    );

    let duplicate_ledger = ledger.replace(
        "| wired fault | `network.availability` |",
        "| wired fault | `network.availability` |\n| wired fault | `network.availability` |",
    );
    assert!(
        validate_documents(&taxonomy, &duplicate_ledger).is_err(),
        "a duplicate ledger row must fail"
    );
}

fn validate_documents(
    taxonomy: &str,
    effect_contracts: &str,
) -> Result<BTreeMap<TaxonomyKey, LedgerEntry>, String> {
    let taxonomy_rows = parse_taxonomy(taxonomy)?;
    let ledger_rows = parse_ledger(effect_contracts)?;
    let ledger_keys = ledger_rows.keys().cloned().collect::<BTreeSet<_>>();

    if taxonomy_rows != ledger_keys {
        let missing = taxonomy_rows
            .difference(&ledger_keys)
            .map(format_key)
            .collect::<Vec<_>>();
        let extra = ledger_keys
            .difference(&taxonomy_rows)
            .map(format_key)
            .collect::<Vec<_>>();
        return Err(format!(
            "taxonomy/ledger identity differs; missing={missing:?}, extra={extra:?}"
        ));
    }

    Ok(ledger_rows)
}

fn parse_taxonomy(markdown: &str) -> Result<BTreeSet<TaxonomyKey>, String> {
    let mut section = None;
    let mut rows = BTreeSet::new();

    for line in markdown.lines() {
        if line.starts_with("## ") {
            section = taxonomy_heading(line);
            continue;
        }
        let Some(section) = section else {
            continue;
        };
        let Some(cells) = table_cells(line) else {
            continue;
        };
        if cells.len() != 4 || cells[0] == "Area" || cells.iter().all(|cell| is_separator(cell)) {
            continue;
        }
        let key = (section, cells[1].to_owned());
        if !rows.insert(key.clone()) {
            return Err(format!("duplicate taxonomy row {}", format_key(&key)));
        }
    }

    require_all_sections(rows.iter().map(|(section, _)| *section), "taxonomy")?;
    Ok(rows)
}

fn parse_ledger(markdown: &str) -> Result<BTreeMap<TaxonomyKey, LedgerEntry>, String> {
    let mut section = None;
    let mut rows = BTreeMap::new();

    for line in markdown.lines() {
        if line.starts_with("## ") || line.starts_with("### ") {
            section = ledger_heading(line);
            continue;
        }
        let Some(section) = section else {
            continue;
        };
        let Some(cells) = table_cells(line) else {
            continue;
        };
        if cells.len() != 2
            || cells[0] == "Taxonomy fault/degradation"
            || cells.iter().all(|cell| is_separator(cell))
        {
            continue;
        }

        let key = (section, cells[0].to_owned());
        let entry = LedgerEntry {
            program: cells[1].to_owned(),
            effects: registered_effects(cells[1])?,
        };
        if rows.insert(key.clone(), entry).is_some() {
            return Err(format!("duplicate ledger row {}", format_key(&key)));
        }
    }

    require_all_sections(rows.keys().map(|(section, _)| *section), "ledger")?;
    Ok(rows)
}

fn taxonomy_heading(line: &str) -> Option<ExecutableSection> {
    match line {
        "## 4.2 Wired and logical networking" => Some(ExecutableSection::Wired),
        "## 4.3 Radios, wireless, mobile, and IoT networking" => Some(ExecutableSection::Radio),
        "## 4.4 Satellite, aerospace, and contact networking" => Some(ExecutableSection::Satellite),
        "## 4.5 Datacenter compute, CPU, memory, clock, and accelerators" => {
            Some(ExecutableSection::Node)
        }
        "## 4.6 Storage, flash, and filesystem-facing devices" => Some(ExecutableSection::Storage),
        _ => None,
    }
}

fn ledger_heading(line: &str) -> Option<ExecutableSection> {
    match line {
        "### Wired and logical network rows" => Some(ExecutableSection::Wired),
        "### Radio, mobile, and IoT-radio rows" => Some(ExecutableSection::Radio),
        "### Satellite, aerospace, and contact rows" => Some(ExecutableSection::Satellite),
        "### Node, CPU, interrupt, memory, clock, and accelerator rows" => {
            Some(ExecutableSection::Node)
        }
        "### Storage, flash, array, and filesystem-facing rows" => Some(ExecutableSection::Storage),
        _ => None,
    }
}

fn registered_effects(program: &str) -> Result<BTreeSet<String>, String> {
    let spans = program.split('`').collect::<Vec<_>>();
    if spans.len() % 2 == 0 {
        return Err(format!(
            "unbalanced code span in ledger program {program:?}"
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
                "ledger program {program:?} names unregistered effect {key:?}"
            ));
        }
        effects.insert(key.to_owned());
    }
    if effects.is_empty() {
        return Err(format!(
            "ledger program {program:?} has no registered effect expression"
        ));
    }
    Ok(effects)
}

fn table_cells(line: &str) -> Option<Vec<&str>> {
    let body = line.strip_prefix('|')?.strip_suffix('|')?;
    Some(body.split('|').map(str::trim).collect())
}

fn is_separator(cell: &str) -> bool {
    !cell.is_empty() && cell.chars().all(|character| matches!(character, '-' | ':'))
}

fn require_all_sections(
    sections: impl Iterator<Item = ExecutableSection>,
    source: &str,
) -> Result<(), String> {
    let actual = sections.collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        ExecutableSection::Wired,
        ExecutableSection::Radio,
        ExecutableSection::Satellite,
        ExecutableSection::Node,
        ExecutableSection::Storage,
    ]);
    if actual != expected {
        return Err(format!(
            "{source} executable sections differ; expected={expected:?}, actual={actual:?}"
        ));
    }
    Ok(())
}

fn format_key((section, fault): &TaxonomyKey) -> String {
    format!("{}:{fault}", section.name())
}

fn minimal_taxonomy() -> String {
    [
        "## 4.2 Wired and logical networking\n| Area | Fault/degradation | State | Tier |\n| --- | --- | --- | --- |\n| Link | wired fault | state | Core |",
        "## 4.3 Radios, wireless, mobile, and IoT networking\n| Area | Fault/degradation | State | Tier |\n| --- | --- | --- | --- |\n| RF | radio fault | state | Core |",
        "## 4.4 Satellite, aerospace, and contact networking\n| Area | Fault/degradation | State | Tier |\n| --- | --- | --- | --- |\n| Contact | satellite fault | state | Core |",
        "## 4.5 Datacenter compute, CPU, memory, clock, and accelerators\n| Area | Fault/degradation | State | Tier |\n| --- | --- | --- | --- |\n| Node | node fault | state | Core |",
        "## 4.6 Storage, flash, and filesystem-facing devices\n| Area | Fault/degradation | State | Tier |\n| --- | --- | --- | --- |\n| Device | storage fault | state | Core |",
    ]
    .join("\n\n")
}

fn minimal_ledger() -> String {
    [
        "### Wired and logical network rows\n| Taxonomy fault/degradation | Required effect program |\n| --- | --- |\n| wired fault | `network.availability` |",
        "### Radio, mobile, and IoT-radio rows\n| Taxonomy fault/degradation | Required effect program |\n| --- | --- |\n| radio fault | `network.rf_channel` |",
        "### Satellite, aerospace, and contact rows\n| Taxonomy fault/degradation | Required effect program |\n| --- | --- |\n| satellite fault | `network.contact` |",
        "### Node, CPU, interrupt, memory, clock, and accelerator rows\n| Taxonomy fault/degradation | Required effect program |\n| --- | --- |\n| node fault | `node.lifecycle` |",
        "### Storage, flash, array, and filesystem-facing rows\n| Taxonomy fault/degradation | Required effect program |\n| --- | --- |\n| storage fault | `storage.availability` |",
    ]
    .join("\n\n")
}
