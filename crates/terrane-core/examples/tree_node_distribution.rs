//! Measures the draft TREE-21..24 boundary rule on canonical fixture trees.
//!
//! This T0 spike constructs leaf and child-reference bytes directly from the
//! normative CDDL. It is deliberately separate from the future T1 tree API.
//! The default run exercises all three key families at 10^4, 10^5, 10^6, and
//! 10^7 entries and fails if the measured distribution contradicts TREE-22.
//! `--report-only` preserves evidence from a failed assumption. Both modes
//! replay each sorted stream with different ingestion batches and compare the
//! complete root identity and level statistics; this establishes deterministic
//! construction, rather than claiming coverage of future insertion algebra.

#[path = "tree_node_distribution/fixtures.rs"]
mod fixtures;

use std::error::Error;
use std::fmt;

use fixtures::{KeyFamily, build, verify_golden_node};
use terrane_core::boundary::MAX_NODE;

#[derive(Debug)]
struct DistributionFailure;

impl fmt::Display for DistributionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("the draft TREE-22 distribution or node-size limit failed; see measurements")
    }
}

impl Error for DistributionFailure {}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let report_only = arguments.iter().any(|argument| argument == "--report-only");
    if arguments.iter().any(|argument| argument != "--report-only") {
        return Err("usage: tree_node_distribution [--report-only]".into());
    }

    verify_golden_node()?;

    println!(
        "family\tentries\tlevel\tnodes\tmin\tmean\tp50\tp95\tmax\tforced\toversized\tcomplete_mean\troot"
    );
    let mut failed = false;

    for entries in [10_000, 100_000, 1_000_000, 10_000_000] {
        for family in KeyFamily::ALL {
            let fixture = family.fixture(entries)?;
            let tree = build(&fixture, 1)?;
            let replay = build(&fixture, 257)?;
            if tree != replay {
                return Err(
                    "TREE-24 failed: ingestion batches changed the root or node distribution"
                        .into(),
                );
            }

            for (level, report) in tree.levels.iter().enumerate() {
                let mean = report.bytes.iter().sum::<u64>() / report.bytes.len() as u64;
                let complete_mean = report.complete_mean();
                let oversized = report
                    .bytes
                    .iter()
                    .filter(|bytes| **bytes > MAX_NODE)
                    .count();
                let mut sorted = report.bytes.clone();
                sorted.sort_unstable();

                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    family.name(),
                    entries,
                    level,
                    sorted.len(),
                    sorted[0],
                    mean,
                    sorted[(sorted.len() - 1) / 2],
                    sorted[(sorted.len() - 1) * 95 / 100],
                    sorted[sorted.len() - 1],
                    report.forced,
                    oversized,
                    complete_mean.map_or_else(|| "-".to_owned(), |value| value.to_string()),
                    fixtures::hex(&tree.root),
                );

                // Roots and the final partial node are allowed below MIN_NODE.
                // Complete nodes still have to respect the stated target band.
                if oversized != 0
                    || complete_mean.is_some_and(|mean| !(8_192..=16_384).contains(&mean))
                {
                    failed = true;
                    eprintln!(
                        "TREE-22/TREE-27: {} entries={} level={} complete_mean={:?} oversized={}",
                        family.name(),
                        entries,
                        level,
                        complete_mean,
                        oversized,
                    );
                }
            }
        }
    }

    if failed && !report_only {
        return Err(Box::new(DistributionFailure));
    }

    Ok(())
}
