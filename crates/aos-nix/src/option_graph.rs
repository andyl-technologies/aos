//! First-class option read/write graph returned with native evaluation.
//!
//! The graph is a deterministic evaluator-side value. Integration layers feed
//! authenticated module access observations into [`OptionGraph::from_accesses`]
//! and receive the canonical graph beside strict JSON, avoiding reconstruction
//! from evaluator stderr.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Whether one module interface access reads or writes an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionAccessKind {
    /// A module consumes an option provided by another package.
    Read,
    /// A module defines or contributes an option.
    Write,
}

/// One attributed option access observed for an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionAccess {
    /// Package whose module performed the access.
    pub package: String,
    /// Fully qualified option path.
    pub option: String,
    /// Access direction.
    pub kind: OptionAccessKind,
    /// Package owning the option root, when the access crosses packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// Canonical option access graph for one native evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionGraph {
    /// Sorted, duplicate-free option accesses.
    pub accesses: Vec<OptionAccess>,
}

impl OptionGraph {
    /// Builds a canonical graph from attributed accesses.
    pub fn from_accesses(accesses: impl IntoIterator<Item = OptionAccess>) -> Self {
        Self {
            accesses: accesses
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

/// Strict JSON and its first-class option graph from one native evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEvalOutput {
    /// Deterministic strict JSON output.
    pub json: String,
    /// Canonical option accesses associated with the evaluation.
    pub option_graph: OptionGraph,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NixNative;

    #[test]
    fn graph_is_sorted_and_deduplicated() {
        let access = OptionAccess {
            package: "web".into(),
            option: "firewall.port".into(),
            kind: OptionAccessKind::Read,
            provider: Some("firewall".into()),
        };
        let graph = OptionGraph::from_accesses([access.clone(), access]);
        assert_eq!(graph.accesses.len(), 1);
    }

    #[test]
    fn graph_uses_executed_reads_and_evaluated_writes() {
        let root = tempfile::tempdir().unwrap();
        let module = root.path().join("module.nix");
        std::fs::write(
            &module,
            r#"let
              config = { firewall.port = 8080; };
            in {
              manifest = { port = config.firewall.port; };
              optionWrites = [ { package = "web"; option = "web.enable"; } ];
            }"#,
        )
        .unwrap();
        let evaluator = NixNative::new(0).unwrap();
        let output = evaluator
            .eval_expr_with_option_graph(
                &format!("import {}", module.display()),
                [(module, "web".to_string())],
                [("firewall".to_string(), "firewall".to_string())],
            )
            .unwrap();

        assert_eq!(output.json, r#"{"port":8080}"#);
        assert!(output.option_graph.accesses.contains(&OptionAccess {
            package: "web".into(),
            option: "firewall.port".into(),
            kind: OptionAccessKind::Read,
            provider: Some("firewall".into()),
        }));
        assert!(output.option_graph.accesses.contains(&OptionAccess {
            package: "web".into(),
            option: "web.enable".into(),
            kind: OptionAccessKind::Write,
            provider: None,
        }));
    }

    #[test]
    fn graph_observes_only_authenticated_module_sources() {
        let root = tempfile::tempdir().unwrap();
        let owned = root.path().join("owned");
        let unowned = root.path().join("unowned");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::create_dir_all(&unowned).unwrap();
        std::fs::write(owned.join("module.nix"), "{ config }: config.firewall.port").unwrap();
        std::fs::write(
            unowned.join("module.nix"),
            "{ config }: config.firewall.port",
        )
        .unwrap();
        let entry = root.path().join("entry.nix");
        std::fs::write(
            &entry,
            format!(
                r#"let
                  config = {{ firewall.port = 8080; }};
                in {{
                  manifest = {{
                    owned = import {} {{ inherit config; }};
                    unowned = import {} {{ inherit config; }};
                  }};
                  optionWrites = [];
                }}"#,
                owned.join("module.nix").display(),
                unowned.join("module.nix").display(),
            ),
        )
        .unwrap();

        let evaluator = NixNative::new(0).unwrap();
        let output = evaluator
            .eval_expr_with_option_graph(
                &format!("import {}", entry.display()),
                [(owned, "web".to_string())],
                [("firewall".to_string(), "firewall".to_string())],
            )
            .unwrap();

        assert_eq!(output.json, r#"{"owned":8080,"unowned":8080}"#);
        assert_eq!(
            output
                .option_graph
                .accesses
                .iter()
                .filter(|access| access.kind == OptionAccessKind::Read)
                .count(),
            1
        );
    }
}
