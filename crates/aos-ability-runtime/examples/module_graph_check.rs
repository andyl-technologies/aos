//! Exercises a Nix-generated graph through checked decoding and durable replay.
//!
//! This test driver uses an in-memory echo adapter, never a host command runner.
//! Run with `module_graph_check <graph.json> <journal-path>`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Effect};
use aos_ability_runtime::activation::{
    Action, Activation, ActivationAdapter, Invocation, Observation,
};
use aos_ability_runtime::adapter::CancellationToken;
use aos_ability_runtime::journal::JournalLimits;
use serde_json::Value;

struct Echo;

impl ActivationAdapter for Echo {
    fn retain(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }

    fn observe(&mut self, _: &Invocation, _: &CancellationToken) -> Result<Observation> {
        Ok(Observation::RetrySafe)
    }

    fn invoke(&mut self, invocation: &Invocation, _: &CancellationToken) -> Result<Value> {
        Ok(match invocation.action {
            Action::Apply => serde_json::json!({"value": invocation.input["value"]}),
            Action::Remove => serde_json::json!({}),
        })
    }

    fn release(&mut self, _: &Effect) -> Result<()> {
        Ok(())
    }
}

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let graph_path = PathBuf::from(arguments.next().context("graph path is required")?);
    let journal_path = PathBuf::from(arguments.next().context("journal path is required")?);
    let graph = CheckedModuleGraph::decode(&std::fs::read(graph_path)?)?;
    let cancellation = CancellationToken::default();
    let mut activation = Activation::open(&journal_path, JournalLimits::default())?;
    let results = activation.activate(&graph, &BTreeSet::new(), &mut Echo, &cancellation)?;
    ensure!(
        results.len() == graph.graph().nodes.len(),
        "not every effect completed"
    );
    ensure!(
        results
            .values()
            .all(|result| result["value"] == "module-generated"),
        "typed outputs were not propagated"
    );
    drop(activation);

    let recovered = Activation::open(&journal_path, JournalLimits::default())?;
    ensure!(
        recovered.retained() == results,
        "journal recovery changed the results"
    );
    println!(
        "validated, executed, and recovered {} module effects",
        results.len()
    );
    Ok(())
}
