//! Checked activation graphs derived from the Nix module fixed point.
//!
//! Module evaluation has already selected and expanded handlers. This boundary
//! validates that selection and its typed edges; it performs no discovery.
//! The serialized document is `{ "schema": "aos.activation.graph", "nodes":
//! { ... }, "order": [ ... ] }`. Node keys are hashes of logical identities.

mod resolution;
mod validation;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use aos_ability_model::OptionType;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bounds an activation document before decoding and validating it.
pub const GRAPH_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 32 * 1024 * 1024,
    max_depth: 64,
    max_items: 1_000_000,
    max_string_bytes: 1024 * 1024,
};

/// Owns the fully expanded, host-selected deferred operation graph.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleGraph {
    /// Identifies the graph contract.
    pub schema: String,
    /// Maps logical identity hashes to their bound operations.
    pub nodes: BTreeMap<String, Effect>,
    /// Lists every node exactly once, with dependencies preceding consumers.
    pub order: Vec<String>,
}

/// Defines one typed operation after handler selection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    /// Names the package owning this operation, or the deployment environment.
    pub owner: String,
    /// Names the environment, ability, operation, and invocation scope.
    pub identity: Vec<String>,
    /// Contains literal inputs and typed deferred references.
    pub input: Value,
    /// Retains declaration-derived argument documentation.
    pub inputs: BTreeMap<String, InputOption>,
    /// Describes the complete merged input value.
    pub input_type: OptionType,
    /// Declares additional success dependencies through output references.
    pub after: Vec<OutputReference>,
    /// Declares the complete named result contract.
    pub results: BTreeMap<String, OptionType>,
    /// Selects the already-bound handler interpretation.
    pub handler: Handler,
    /// Contains the exact deduplicated prerequisite node keys.
    pub dependencies: Vec<String>,
    /// Identifies the semantic desired value, independently of its logical key.
    pub revision: String,
    /// Governs reuse and removal of this operation's established state.
    pub lifetime: Lifetime,
    /// Bounds each handler invocation, including observation and removal.
    pub timeout_ms: u64,
}

/// Retains an input option's generated documentation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputOption {
    /// Describes the option as authored by its declaring module.
    pub description: String,
    /// Projects the native option type without a second schema declaration.
    #[serde(rename = "type")]
    pub value_type: OptionType,
}

/// Distinguishes executable implementations from pure handler composition.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Handler {
    /// Invokes an immutable artifact through the standard handler protocol.
    Process {
        /// Identifies the exact store output retaining the executable.
        artifact: String,
        /// Names the artifact's selected main program.
        executable: String,
    },
    /// Joins child effects and exports their typed results.
    Composition {
        /// Lists the immediate expanded child operations.
        children: Vec<String>,
        /// Connects the operation's results to their actual producers.
        exports: BTreeMap<String, OutputReference>,
    },
}

/// Determines when established state may be reused or automatically removed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifetime {
    /// Runs for each new transaction and is released when that transaction ends.
    Transaction,
    /// Remains established until its configured instance disappears.
    Instance,
    /// Remains retained when configuration disappears; deletion is explicit.
    Persistent,
}

/// Names a producer's result without executing that producer during evaluation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputReference {
    /// Carries the fixed deferred-value marker.
    #[serde(rename = "_type")]
    pub marker: String,
    /// Identifies the exact logical producer.
    pub identity: Vec<String>,
    /// Selects one result declared by that producer.
    pub output: String,
    /// Carries the producer's declared result type.
    pub schema: OptionType,
}

/// Contains a graph whose structure, references, schemas, and hashes are checked.
#[derive(Clone, Debug)]
pub struct CheckedModuleGraph {
    graph: ModuleGraph,
    document: Value,
}

impl CheckedModuleGraph {
    /// Decodes and checks a bounded module-generated activation document.
    ///
    /// # Errors
    /// Returns an error for malformed documents, inconsistent identities,
    /// unbound or cyclic edges, unsupported types, or invalid handler artifacts.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let raw: Value = GRAPH_LIMITS.decode(bytes, "module activation graph")?;
        validation::check_hashes(&raw)?;
        let graph: ModuleGraph = serde_json::from_value(raw.clone())?;
        validation::check_graph(&graph)?;
        Ok(Self {
            graph,
            document: raw,
        })
    }

    /// Returns the validated execution data.
    #[must_use]
    pub const fn graph(&self) -> &ModuleGraph {
        &self.graph
    }

    /// Serializes a checked graph for durable retention and replay.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::to_vec(&self.document)
    }
}

impl Effect {
    /// Validates concrete results returned by a terminal or composed handler.
    ///
    /// # Errors
    /// Returns an error for missing, extra, or incorrectly typed result values.
    pub fn check_results(&self, results: &Value) -> Result<()> {
        let object = results
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("results must be an object"))?;
        ensure!(
            object.len() == self.results.len(),
            "handler result set differs from its contract"
        );
        for (name, schema) in &self.results {
            let value = object
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("missing handler result {name}"))?;
            validation::check_concrete(value, schema)
                .with_context(|| format!("result {name} of effect {:?}", self.identity))?;
        }
        Ok(())
    }

    /// Resolves predecessor results and canonicalizes declared input sets.
    ///
    /// The graph must already have passed admission. Canonical sets are sorted
    /// and deduplicated after substitution because distinct references may
    /// return the same value or reverse their symbolic order. Ordered lists
    /// retain their order. Concrete input validation remains strict.
    ///
    /// # Errors
    /// Returns an error for missing or incompatible predecessor results,
    /// ambiguous union collection semantics, or invalid resolved input.
    pub fn resolve_input(&self, results: &BTreeMap<String, Value>) -> Result<Value> {
        let mut input = resolve(&self.input, results)?;
        resolution::normalize(&mut input, &self.input_type)?;
        self.check_input(&input)?;
        Ok(input)
    }

    /// Checks a fully resolved operation input against its module contract.
    ///
    /// # Errors
    /// Returns an error if the concrete value does not satisfy the input type.
    pub fn check_input(&self, input: &Value) -> Result<()> {
        validation::check_concrete(input, &self.input_type)
            .with_context(|| format!("input of effect {:?}", self.identity))?;
        Ok(())
    }
}

/// Computes the stable graph key for one logical module scope.
///
/// # Errors
/// Returns an error if the identity cannot be serialized.
pub fn identity_key(identity: &[String]) -> Result<String> {
    Ok(Sha256Digest::of_bytes(serde_json::to_vec(identity)?).hex())
}

/// Resolves deferred values using checked results from completed predecessors.
///
/// # Errors
/// Returns an error if a producer has not completed or its output is incompatible.
pub fn resolve(value: &Value, results: &BTreeMap<String, Value>) -> Result<Value> {
    if value.get("_type").and_then(Value::as_str) == Some("aos-effect-output") {
        let reference: OutputReference = serde_json::from_value(value.clone())?;
        let key = identity_key(&reference.identity)?;
        let result = results
            .get(&key)
            .and_then(|outputs| outputs.get(&reference.output))
            .ok_or_else(|| {
                anyhow::anyhow!("unavailable deferred output {key}.{}", reference.output)
            })?;
        validation::check_concrete(result, &reference.schema).with_context(|| {
            format!(
                "deferred result {} of effect {:?}",
                reference.output, reference.identity
            )
        })?;
        return Ok(result.clone());
    }
    match value {
        Value::Object(values) => Ok(Value::Object(
            values
                .iter()
                .map(|(name, value)| Ok((name.clone(), resolve(value, results)?)))
                .collect::<Result<_>>()?,
        )),
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .map(|value| resolve(value, results))
                .collect::<Result<_>>()?,
        )),
        value => Ok(value.clone()),
    }
}

/// Checks explicit retirement decisions against the configured desired graph.
///
/// The returned set preserves exact identities without inferring retirement from
/// effects omitted from the graph.
///
/// # Errors
/// Returns an error for duplicate, empty, or still-configured effect identities.
pub fn check_retirement(
    graph: &CheckedModuleGraph,
    identities: &[String],
) -> Result<BTreeSet<String>> {
    let retirement: BTreeSet<_> = identities.iter().cloned().collect();
    ensure!(
        retirement.len() == identities.len(),
        "duplicate retirement identity"
    );
    for identity in &retirement {
        ensure!(
            !identity.is_empty() && !graph.graph().nodes.contains_key(identity),
            "cannot retire an empty or configured effect"
        );
    }
    Ok(retirement)
}
