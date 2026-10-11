//! Native release references and reporter-authored transaction assertions.
//!
//! Exact reference bytes come from an authenticated release. A deployment report
//! is a bounded assertion by an enrolled reporter, not a live-state verification.
//!
//! A declaration aggregate carries one completed release pin and embeds each
//! retained reference's exact UTF-8 bytes:
//!
//! ```json
//! {"schema":"aos.module.release-graph","release":"1.0.0","registry_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"x86_64-linux","references":[]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_plan::module_graph::{CheckedModuleGraph, GRAPH_LIMITS};
use aos_contract::{Sha256Digest, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{RuntimeDocument, invalid};
use crate::Result;

// Embedded exact JSON is a transport string; its inner values retain the
// native reader's stricter per-string limits after decoding.
const RELEASE_GRAPH_LIMITS: aos_contract::limits::JsonLimits = aos_contract::limits::JsonLimits {
    max_string_bytes: GRAPH_LIMITS.max_bytes,
    ..GRAPH_LIMITS
};

/// Pins one native reference to its exact authenticated package coordinate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePackageIdentity {
    /// Identifies the authenticated registry commit.
    pub registry_commit: String,
    /// Names the package.
    pub package: String,
    /// Identifies its exact version.
    pub version: String,
    /// Names the target platform.
    pub platform: String,
    /// Identifies the exact native module reference bytes.
    pub document_sha256: Sha256Digest,
}

/// Preserves a reference's original UTF-8 bytes inside a release view.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasedReference {
    /// Pins the authenticated package and original reference digest.
    pub identity: NativePackageIdentity,
    /// Preserves exact native reference JSON without reserializing its contents.
    pub reference_json: String,
}

impl ReleasedReference {
    /// Checks its exact byte digest, package identity, and native declarations.
    ///
    /// # Errors
    /// Returns an error for mismatched identity, digest, or invalid declarations.
    pub fn check(&self) -> Result<RuntimeDocument> {
        if Sha256Digest::of_bytes(self.reference_json.as_bytes()) != self.identity.document_sha256 {
            return Err(invalid("native reference digest differs"));
        }
        if !matches!(self.identity.registry_commit.len(), 40 | 64)
            || !self
                .identity
                .registry_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("native reference commit identity is invalid"));
        }
        let document = RuntimeDocument::from_json(self.reference_json.as_bytes())?;
        document.verify_package_identity(
            &self.identity.package,
            &self.identity.version,
            &self.identity.platform,
        )?;
        Ok(document)
    }
}

/// Aggregates exact package declarations from one authenticated release.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleaseGraph {
    /// Identifies the native declaration graph format.
    pub schema: String,
    /// Names the exact completed release.
    pub release: String,
    /// Pins its authenticated commit.
    pub registry_commit: String,
    /// Names the shared target platform.
    pub platform: String,
    /// Lists exact references in package/version order.
    pub references: Vec<ReleasedReference>,
}

impl NativeReleaseGraph {
    /// Checks bounded canonical bytes and every retained reference identity.
    ///
    /// # Errors
    /// Returns an error for invalid references, duplicate coordinates, or format.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let graph: Self = RELEASE_GRAPH_LIMITS
            .decode(bytes, "native release graph")
            .map_err(invalid)?;
        if canonical::to_vec(&graph).map_err(invalid)? != bytes {
            return Err(invalid("native release graph is not canonical"));
        }
        graph.validate()?;
        Ok(graph)
    }

    /// Encodes a checked release graph without changing its reference bytes.
    ///
    /// # Errors
    /// Returns an error for invalid identity, references, or exceeded bounds.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical::to_vec(self).map_err(invalid)?;
        RELEASE_GRAPH_LIMITS
            .decode::<Value>(&bytes, "native release graph")
            .map_err(invalid)?;
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "aos.module.release-graph"
            || self.release.is_empty()
            || !matches!(self.registry_commit.len(), 40 | 64)
            || !self
                .registry_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.platform.is_empty()
        {
            return Err(invalid("invalid native release graph identity"));
        }
        let mut coordinates = BTreeSet::new();
        for reference in &self.references {
            if reference.identity.registry_commit != self.registry_commit
                || reference.identity.platform != self.platform
                || !coordinates.insert((&reference.identity.package, &reference.identity.version))
            {
                return Err(invalid(
                    "native release reference coordinate differs or repeats",
                ));
            }
            reference.check()?;
        }
        Ok(())
    }
}

/// Carries a reporter's checked desired graph and optional result assertions.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDeploymentReport {
    /// Identifies the native reporter format.
    pub schema: String,
    /// Names the independently enrolled reporter slot.
    pub deployment: String,
    /// Increases strictly for each accepted report in that slot.
    pub sequence: u64,
    /// Pins the exact authenticated native module reference.
    pub package: NativePackageIdentity,
    /// Preserves the native desired activation graph.
    pub graph: Value,
    /// Contains reporter assertions of named results, distinct from desired inputs.
    pub reported_outputs: BTreeMap<String, Value>,
    /// Records the reporter's wall-clock timestamp.
    pub reported_at_unix_seconds: u64,
    /// Bounds freshness from both reporter time and Hub receipt time.
    pub valid_for_seconds: u64,
}

impl NativeDeploymentReport {
    /// Decodes canonical bounded bytes and checks graph/result structure.
    ///
    /// # Errors
    /// Returns an error for unsupported schemas, invalid timing, or graph/results.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let report: Self = GRAPH_LIMITS
            .decode(bytes, "native deployment report")
            .map_err(invalid)?;
        if canonical::to_vec(&report).map_err(invalid)? != bytes {
            return Err(invalid("native deployment report is not canonical"));
        }
        report.checked_graph()?;
        Ok(report)
    }

    /// Checks desired graph structure and types every reported result assertion.
    ///
    /// # Errors
    /// Returns an error for invalid identities, bounds, or reported output types.
    pub fn checked_graph(&self) -> Result<CheckedModuleGraph> {
        if self.schema != "aos.module.deployment-report"
            || self.deployment.is_empty()
            || self.deployment.len() > 128
            || !self
                .deployment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || self.sequence == 0
            || !(1..=300).contains(&self.valid_for_seconds)
        {
            return Err(invalid(
                "invalid native deployment report identity or lifetime",
            ));
        }
        let graph = CheckedModuleGraph::decode(&canonical::to_vec(&self.graph).map_err(invalid)?)
            .map_err(invalid)?;
        for (id, outputs) in &self.reported_outputs {
            graph
                .graph()
                .nodes
                .get(id)
                .ok_or_else(|| invalid("reported result names an unknown effect"))?
                .check_results(outputs)
                .map_err(invalid)?;
        }
        Ok(graph)
    }

    /// Binds the assertion to an exact reference and its declared contracts.
    ///
    /// This does not authenticate handler contents or establish observed live state.
    /// The caller independently authenticates the reference and reporter identity.
    ///
    /// # Errors
    /// Returns an error for different package coordinates, unknown operations,
    /// or a graph contract differing from the authenticated reference.
    pub fn validate_reference(&self, reference: &ReleasedReference) -> Result<()> {
        if canonical::to_vec(&self.package).map_err(invalid)?
            != canonical::to_vec(&reference.identity).map_err(invalid)?
        {
            return Err(invalid(
                "report package differs from authenticated native reference",
            ));
        }
        let document = reference.check()?;
        let declarations = document
            .reference()
            .ok_or_else(|| invalid("missing native declarations"))?;
        for effect in self.checked_graph()?.graph().nodes.values() {
            let mut identity = effect.identity.iter().rev();
            let _instance = identity.next();
            let operation = identity
                .next()
                .ok_or_else(|| invalid("missing operation identity"))?;
            let ability = identity
                .next()
                .ok_or_else(|| invalid("missing ability identity"))?;
            let contract = declarations
                .abilities
                .get(ability)
                .and_then(|operations| operations.get(operation))
                .ok_or_else(|| {
                    invalid("reported operation has no authenticated native declaration")
                })?;
            if !contract
                .sources
                .input
                .iter()
                .chain(&contract.sources.result)
                .any(|source| source.owner == effect.owner)
            {
                return Err(invalid(
                    "reported effect owner has no authenticated operation declaration",
                ));
            }
            let result_fields = contract
                .result
                .iter()
                .map(|(name, field)| (name.clone(), field.option_type.clone()))
                .collect::<BTreeMap<_, _>>();
            if canonical::to_vec(&effect.input_type).map_err(invalid)?
                != canonical::to_vec(&contract.input_type).map_err(invalid)?
                || canonical::to_vec(&effect.results).map_err(invalid)?
                    != canonical::to_vec(&result_fields).map_err(invalid)?
            {
                return Err(invalid(
                    "reported operation contract differs from native reference",
                ));
            }
        }
        Ok(())
    }

    /// Encodes the exact checked reporter assertion.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded bounds.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.checked_graph()?;
        let bytes = canonical::to_vec(self).map_err(invalid)?;
        GRAPH_LIMITS
            .decode::<Value>(&bytes, "native deployment report")
            .map_err(invalid)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference() -> ReleasedReference {
        let reference_json = serde_json::to_string_pretty(&json!({
            "schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux",
            "packages":[{"name":"sample","version":"1"}],"options":[],
            "abilities":{"sample":{"run":{
                "input":{},"result":{"ok":{"description":"Result assertion.","type":{"kind":"bool"}}},
                "inputType":{"kind":"record","fields":{},"optional_fields":[]},
                "resultType":{"kind":"record","fields":{"ok":{"kind":"bool"}},"optional_fields":[]},
                "handlerAvailable":true,"configuredEffects":["one"],
                "sources":{"input":[{"file":"/module.nix","owner":"sample","priority":100,"provenance":"package"}],"result":[],"handler":[],"effects":[]}
            }}}
        })).unwrap();
        ReleasedReference {
            identity: NativePackageIdentity {
                registry_commit: "a".repeat(40),
                package: "sample".into(),
                version: "1".into(),
                platform: "x86_64-linux".into(),
                document_sha256: Sha256Digest::of_bytes(&reference_json),
            },
            reference_json,
        }
    }

    fn report() -> NativeDeploymentReport {
        let identity = vec![
            "package".into(),
            "sample".into(),
            "sample".into(),
            "run".into(),
            "one".into(),
        ];
        let key = aos_ability_plan::module_graph::identity_key(&identity).unwrap();
        let mut effect = json!({"owner":"sample","identity":identity,"input":{},
            "inputs":{},"input_type":{"kind":"record","fields":{},"optional_fields":[]},
            "after":[],"results":{"ok":{"kind":"bool"}},
            "handler":{"kind":"process","artifact":"/nix/store/00000000000000000000000000000000-handler","executable":"/nix/store/00000000000000000000000000000000-handler/bin/handler"},
            "dependencies":[],"lifetime":"instance","timeout_ms":1000});
        let mut semantic = effect.as_object().unwrap().clone();
        semantic.remove("dependencies");
        semantic.remove("inputs");
        effect["revision"] =
            json!(Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap()).hex());
        NativeDeploymentReport {
            schema: "aos.module.deployment-report".into(),
            deployment: "production".into(),
            sequence: 1,
            package: reference().identity,
            graph: json!({"schema":"aos.activation.graph","nodes":{key.clone():effect},"order":[key.clone()]}),
            reported_outputs: BTreeMap::from([(key, json!({"ok":true}))]),
            reported_at_unix_seconds: 1000,
            valid_for_seconds: 60,
        }
    }

    #[test]
    fn native_release_graph_preserves_exact_reference_bytes() {
        let graph = NativeReleaseGraph {
            schema: "aos.module.release-graph".into(),
            release: "1.0.0".into(),
            registry_commit: "a".repeat(40),
            platform: "x86_64-linux".into(),
            references: vec![reference()],
        };
        let decoded = NativeReleaseGraph::decode(&graph.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            decoded.references[0].reference_json,
            graph.references[0].reference_json
        );

        let mut changed = reference();
        changed.reference_json.push(' ');
        assert!(changed.check().is_err());
    }

    #[test]
    fn native_report_binds_declarations_and_types_reporter_assertions() {
        let mut report = report();
        report.validate_reference(&reference()).unwrap();
        let transaction=RuntimeDocument::from_json(&serde_json::to_vec(&json!({
            "schema":"aos.package.transaction","scope":["package","sample"],"system":"x86_64-linux","retire":[],"graph":report.graph
        })).unwrap()).unwrap();
        assert_eq!(
            transaction.transaction_graph().unwrap().graph().nodes.len(),
            1
        );
        assert!(reference().check().unwrap().transaction_graph().is_none());
        NativeDeploymentReport::decode(&report.canonical_bytes().unwrap()).unwrap();

        report.reported_outputs.values_mut().next().unwrap()["ok"] = json!("wrong type");
        assert!(report.checked_graph().is_err());
    }

    #[test]
    fn native_report_rejects_wrong_pins_and_excessive_lifetime() {
        let mut report = report();
        report.package.registry_commit = "b".repeat(40);
        assert!(report.validate_reference(&reference()).is_err());
        report.valid_for_seconds = 301;
        assert!(report.canonical_bytes().is_err());
    }
}
