//! Checks native package deployment artifacts without evaluating or activating them.
//!
//! Standard input contains a resolved package context, its transaction, and an
//! optional generated module reference:
//!
//! ```json
//! {"packages":{"system":"x86_64-linux","artifacts":[],"modules":[]},"transaction":{},"documentation":null}
//! ```
//! Successful validation exits silently. Artifact authentication and outer image
//! publication formats belong to the caller.

use std::io::Read as _;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_doc_model::runtime::RuntimeDocument;
use aos_package::deployment::model::{Deployment, ResolvedPackages};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    packages: ResolvedPackages,
    transaction: Value,
    #[serde(default)]
    documentation: Option<Value>,
}

fn check(bytes: &[u8]) -> Result<()> {
    let mut limits = GRAPH_LIMITS;
    limits.max_bytes *= 3;
    limits.max_items *= 3;
    limits.max_depth += 2;
    let input: Input = limits.decode(bytes, "native deployment check")?;
    let deployment = Deployment::decode(&serde_json::to_vec(&input.transaction)?, &input.packages)?;
    if let Some(documentation) = input.documentation {
        let reference = RuntimeDocument::from_json(&serde_json::to_vec(&documentation)?)?;
        let reference = reference
            .reference()
            .context("expected native module reference")?;
        ensure!(
            reference.scope == deployment.scope() && reference.system == input.packages.system,
            "documentation belongs to another deployment scope or target"
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments == ["--version"] {
        println!("aos-deployment-check {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    ensure!(
        arguments.is_empty(),
        "usage: aos-deployment-check < native-check-input.json"
    );
    let limit = GRAPH_LIMITS.max_bytes * 3;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "native deployment check exceeds its byte limit"
    );
    check(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!({
            "packages":{"system":"x86_64-linux","artifacts":[],"modules":[]},
            "transaction":{"schema":"aos.package.transaction","system":"x86_64-linux",
                "scope":["profile","main"],"inputs":[],"artifacts":[],"packages":[],"retire":[],
                "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}},
            "documentation":{"schema":"aos.module.documentation","system":"x86_64-linux",
                "scope":["profile","main"],"packages":[],"options":[],"abilities":{}}
        })
    }

    #[test]
    fn checks_native_context_and_reference_identity() {
        let mut input = fixture();
        check(&serde_json::to_vec(&input).unwrap()).unwrap();

        input["documentation"]["system"] = json!("aarch64-linux");
        assert!(check(&serde_json::to_vec(&input).unwrap()).is_err());
    }

    #[test]
    fn rejects_transaction_context_drift_and_unknown_input_fields() {
        let mut input = fixture();
        input["transaction"]["system"] = json!("aarch64-linux");
        assert!(check(&serde_json::to_vec(&input).unwrap()).is_err());

        let mut input = fixture();
        input["execute"] = json!(true);
        assert!(check(&serde_json::to_vec(&input).unwrap()).is_err());
    }
}
