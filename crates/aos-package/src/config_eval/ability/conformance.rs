//! Version-1 Nix/Rust ability-authoring conformance corpus.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use aos_ability_model::document::{
    InterfaceDocument, RequiredFeature, VersionedDocument, decode_canonical,
};
use aos_ability_model::plan::{DependencyEdge, DependencyKind, PlanNodeKey, compare_edges};
use aos_ability_model::value::{OperationResultReference, ResultProducerKey, ValueExpression};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, DiagnosticCode, EnvironmentId,
    ImplementationKind, InstanceId, InterfaceKey, InterfaceName, LocalKey, ProviderImplementation,
    RequestId, ScopePath, ScopedOperationKey, StringSyntax, ValueSchema,
};
use aos_ability_validate::{ValidationContext, ValidationErrors, validate_value};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    AbilityEntryPoint, AbilityEvaluationDiagnosticCode, AbilityEvaluationLimits,
    RestrictedAbilityEvaluator, ability_evaluation_diagnostic,
};

const CORPUS_SCHEMA: &str = "aos.ability.authoring-conformance/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    recipe_limits: RecipeLimits,
    public_helpers: BTreeMap<String, Vec<String>>,
    cases: Vec<CorpusCase>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeLimits {
    max_generated_depth: u64,
    max_generated_items: u64,
    max_generated_string_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    operation: String,
    arguments: Value,
    consumers: Vec<String>,
    rust: String,
    expected: ExpectedOutcome,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
enum ExpectedOutcome {
    Accept { value: Value },
    Reject { code: String },
}

struct ConformanceFixture {
    evaluator: RestrictedAbilityEvaluator,
    implementation: ProviderImplementation,
    corpus: Corpus,
    nix_instantiate: String,
    prlimit: String,
    cache: String,
    build_system: String,
}

#[test]
fn checked_in_corpus_agrees_across_nix_evaluation_and_rust_validation() {
    let Some(fixture) = conformance_fixture().unwrap() else {
        return;
    };

    validate_corpus_contract(&fixture.corpus).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let secret_path = temporary.path().join("authoring-secret");
    let secret = "authoring-conformance-secret-must-not-escape";
    std::fs::write(&secret_path, secret).unwrap();

    for case in &fixture.corpus.cases {
        if case
            .consumers
            .iter()
            .any(|consumer| consumer == "evaluator")
        {
            run_evaluator_case(&fixture, case, &secret_path, secret);
        }
        if case.consumers.iter().any(|consumer| consumer == "rust") {
            run_rust_case(&fixture.corpus, case);
        }
    }
}

fn conformance_fixture() -> Result<Option<ConformanceFixture>> {
    if std::env::var("AOS_TEST_ABILITY_EVALUATOR_DISABLED").as_deref() == Ok("1") {
        return Ok(None);
    }

    const REQUIRED_ENVIRONMENT: [&str; 7] = [
        "AOS_NIX_INSTANTIATE",
        "AOS_PRLIMIT",
        "AOS_TEST_ABILITY_BUILD_SYSTEM",
        "AOS_TEST_ABILITY_CACHE",
        "AOS_TEST_ABILITY_CONFORMANCE_FIXTURE",
        "AOS_TEST_ABILITY_CONFORMANCE_FIXTURE_NAR_HASH",
        "AOS_TEST_ABILITY_CONFORMANCE_CORPUS",
    ];
    if REQUIRED_ENVIRONMENT
        .iter()
        .all(|name| std::env::var_os(name).is_none())
    {
        return Ok(None);
    }

    let required = |name: &str| {
        std::env::var(name).with_context(|| format!("reading required test variable {name}"))
    };
    let nix_instantiate = required("AOS_NIX_INSTANTIATE")?;
    let prlimit = required("AOS_PRLIMIT")?;
    let cache = required("AOS_TEST_ABILITY_CACHE")?;
    let build_system = required("AOS_TEST_ABILITY_BUILD_SYSTEM")?;
    let fixture_path = required("AOS_TEST_ABILITY_CONFORMANCE_FIXTURE")?;
    let fixture_nar_hash =
        Sha256Digest::parse(&required("AOS_TEST_ABILITY_CONFORMANCE_FIXTURE_NAR_HASH")?)
            .context("parsing the authoring conformance fixture NAR hash")?;
    let corpus_path = required("AOS_TEST_ABILITY_CONFORMANCE_CORPUS")?;
    ensure!(
        Path::new(&corpus_path) == Path::new(&fixture_path).join("corpus.json"),
        "the conformance corpus must come from the exact evaluator fixture"
    );
    let corpus_bytes = std::fs::read(&corpus_path)
        .with_context(|| format!("reading ability conformance corpus {corpus_path}"))?;
    let corpus_value: Value = serde_json::from_slice(&corpus_bytes)
        .context("decoding the closed ability authoring conformance corpus")?;
    let canonical = aos_contract::canonical::to_vec(&corpus_value)?;
    let corpus: Corpus = serde_json::from_slice(&canonical)
        .context("decoding the normalized ability authoring conformance corpus")?;
    ensure!(
        serde_json::from_slice::<Value>(&canonical)? == corpus_value,
        "normalizing the ability authoring conformance corpus changed its value"
    );

    let evaluator = RestrictedAbilityEvaluator::new(
        &nix_instantiate,
        &prlimit,
        &cache,
        AbilityEvaluationLimits::default(),
    )?;
    let implementation = implementation_at(&fixture_path, fixture_nar_hash);

    Ok(Some(ConformanceFixture {
        evaluator,
        implementation,
        corpus,
        nix_instantiate,
        prlimit,
        cache,
        build_system,
    }))
}

fn validate_corpus_contract(corpus: &Corpus) -> Result<()> {
    ensure!(corpus.schema == CORPUS_SCHEMA, "unsupported corpus schema");
    ensure!(
        corpus.recipe_limits.max_generated_depth
            <= u64::from(ABILITY_LIMITS_V1.max_structural_depth),
        "corpus depth recipe exceeds the ability limit"
    );
    ensure!(
        corpus.recipe_limits.max_generated_items <= ABILITY_LIMITS_V1.max_collection_items,
        "corpus item recipe exceeds the ability limit"
    );
    ensure!(
        corpus.recipe_limits.max_generated_string_bytes
            <= ABILITY_LIMITS_V1.max_document_bytes + ABILITY_LIMITS_V1.max_string_bytes,
        "corpus string recipe exceeds its bounded test allowance"
    );
    ensure!(
        corpus
            .public_helpers
            .keys()
            .eq(["abilities", "effects", "schemas"]),
        "corpus public-helper inventory is incomplete"
    );

    let mut ids = BTreeSet::new();
    for case in &corpus.cases {
        ensure!(ids.insert(&case.id), "duplicate corpus case '{}'", case.id);
        ensure!(case.id.len() <= 128, "corpus case id is too long");
        ensure!(
            !case.consumers.is_empty(),
            "corpus case '{}' has no consumer",
            case.id
        );
        ensure!(
            case.consumers.iter().collect::<BTreeSet<_>>().len() == case.consumers.len(),
            "corpus case '{}' repeats a consumer",
            case.id
        );
        ensure!(
            case.consumers
                .iter()
                .all(|consumer| matches!(consumer.as_str(), "nix" | "evaluator" | "rust")),
            "corpus case '{}' names an unknown consumer",
            case.id
        );
        validate_case_recipe(case, corpus.recipe_limits)?;
    }
    Ok(())
}

fn validate_case_recipe(case: &CorpusCase, limits: RecipeLimits) -> Result<()> {
    let number = |name: &str| {
        case.arguments
            .get(name)
            .or_else(|| {
                case.arguments
                    .get("value")
                    .and_then(|value| value.get(name))
            })
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    ensure!(
        number("depth") <= limits.max_generated_depth,
        "corpus case '{}' exceeds its depth recipe bound",
        case.id
    );
    for name in ["items", "count", "chunks"] {
        ensure!(
            number(name) <= limits.max_generated_items,
            "corpus case '{}' exceeds its item recipe bound",
            case.id
        );
    }
    let generated_bytes = number("chunk_bytes").saturating_mul(number("count"));
    ensure!(
        generated_bytes <= limits.max_generated_string_bytes,
        "corpus case '{}' exceeds its generated byte bound",
        case.id
    );
    Ok(())
}

fn run_evaluator_case(
    fixture: &ConformanceFixture,
    case: &CorpusCase,
    secret_path: &Path,
    secret: &str,
) {
    let arguments = evaluator_arguments(case, fixture, secret_path);
    let limits = match case.id.as_str() {
        "restricted-stdout-limit" => AbilityEvaluationLimits {
            stdout_bytes: 128,
            ..AbilityEvaluationLimits::default()
        },
        "restricted-wall-time-limit" => AbilityEvaluationLimits {
            wall_time: Duration::from_millis(100),
            cpu_seconds: 5,
            ..AbilityEvaluationLimits::default()
        },
        _ => AbilityEvaluationLimits::default(),
    };
    let evaluator = if limits == AbilityEvaluationLimits::default() {
        &fixture.evaluator
    } else {
        // The cache owns only per-invocation private evaluator directories, so
        // a limit-specialized adapter may share its parent safely.
        &RestrictedAbilityEvaluator::new(
            &fixture.nix_instantiate,
            &fixture.prlimit,
            &fixture.cache,
            limits,
        )
        .unwrap()
    };
    let result = evaluator.evaluate::<Value>(
        &fixture.implementation,
        AbilityEntryPoint::Compose,
        &arguments,
    );

    match &case.expected {
        ExpectedOutcome::Accept { value } => {
            assert_eq!(result.unwrap(), *value, "evaluator case '{}'", case.id);
        }
        ExpectedOutcome::Reject { code } => {
            let error = result.expect_err("rejection case unexpectedly succeeded");
            assert!(
                !format!("{error:#}").contains(secret),
                "case '{}' leaked secret bytes in its diagnostic",
                case.id
            );
            let actual = ability_evaluation_diagnostic(&error).unwrap_or_else(|| {
                panic!(
                    "case '{}' returned an unclassified error: {error:#}",
                    case.id
                )
            });
            assert_eq!(
                actual.as_str(),
                code,
                "evaluator case '{}': {error:#}",
                case.id
            );
        }
    }
}

fn evaluator_arguments(
    case: &CorpusCase,
    fixture: &ConformanceFixture,
    secret_path: &Path,
) -> AbilityValue {
    let mut arguments = case.arguments.clone();
    replace_placeholder(
        &mut arguments,
        "@secret-path@",
        &secret_path.to_string_lossy(),
    );
    replace_placeholder(&mut arguments, "@builder@", &fixture.nix_instantiate);
    replace_placeholder(&mut arguments, "@system@", &fixture.build_system);

    AbilityValue::new(json!({
        "case": {
            "id": case.id,
            "operation": case.operation,
            "arguments": arguments,
        }
    }))
    .unwrap()
}

fn replace_placeholder(value: &mut Value, placeholder: &str, replacement: &str) {
    match value {
        Value::String(text) if text == placeholder => *text = replacement.to_string(),
        Value::Array(values) => {
            for value in values {
                replace_placeholder(value, placeholder, replacement);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_placeholder(value, placeholder, replacement);
            }
        }
        _ => {}
    }
}

fn run_rust_case(corpus: &Corpus, case: &CorpusCase) {
    let result = rust_validate(corpus, case);
    match &case.expected {
        ExpectedOutcome::Accept { value } => {
            let actual = result.unwrap_or_else(|diagnostics| {
                panic!("Rust case '{}' rejected with {diagnostics:?}", case.id)
            });
            let expected = aos_contract::canonical::to_vec(value).unwrap();
            let actual = aos_contract::canonical::to_vec(&actual).unwrap();
            assert_eq!(actual, expected, "Rust case '{}'", case.id);
        }
        ExpectedOutcome::Reject { code } => {
            let diagnostics = result.expect_err("Rust rejection case unexpectedly succeeded");
            assert_eq!(diagnostics, vec![code.as_str()], "Rust case '{}'", case.id);
        }
    }
}

fn rust_validate<'a>(corpus: &'a Corpus, case: &'a CorpusCase) -> Result<Value, Vec<&'a str>> {
    let accepted = match &case.expected {
        ExpectedOutcome::Accept { value } => Some(value),
        ExpectedOutcome::Reject { .. } => None,
    };
    let code = |diagnostic: DiagnosticCode| vec![diagnostic_code(diagnostic)];

    let validation = match case.rust.as_str() {
        "canonical-value"
        | "authoring-reference-bundle"
        | "composition-node"
        | "effect-plan"
        | "implementation-bundle" => AbilityValue::new(accepted.cloned().unwrap())
            .map(|_| ())
            .map_err(|error| code(error.diagnostic_code())),
        "identity-bundle" => {
            let value = accepted.unwrap();
            serde_json::from_value::<EnvironmentId>(value["environment"].clone())
                .and_then(|_| {
                    serde_json::from_value::<InstanceId>(strip_markers(&value["instance"]))
                })
                .and_then(|_| serde_json::from_value::<RequestId>(strip_markers(&value["request"])))
                .map(|_| ())
                .map_err(|_| code(DiagnosticCode::ValueTypeMismatch))
        }
        "value-schema" => {
            let schema = serde_json::from_value::<ValueSchema>(accepted.cloned().unwrap())
                .map_err(|_| code(DiagnosticCode::ValueTypeMismatch))?;
            validate_schema_with_default(&schema).map_err(|errors| validation_codes(&errors))
        }
        "schema-bundle" => accepted
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .try_for_each(|value| serde_json::from_value::<ValueSchema>(value.clone()).map(|_| ()))
            .map_err(|_| code(DiagnosticCode::ValueTypeMismatch)),
        "interface-document" => {
            let document = accepted.cloned().unwrap_or_else(|| {
                json!({
                    "schema": InterfaceDocument::SCHEMA,
                    "required_features": case.arguments["required_features"],
                    "interface": case.arguments["interface"],
                })
            });
            validate_interface_value(&document, &BTreeSet::new())
                .map_err(|diagnostic| code(diagnostic))
        }
        "schema-decode" => {
            let mut document = reference_interface(corpus);
            document["interface"]["request"] = case.arguments["value"].clone();
            validate_interface_value(&document, &BTreeSet::new())
                .map_err(|diagnostic| code(diagnostic))
        }
        "schema-depth" => {
            let depth = case.arguments["value"]["depth"].as_u64().unwrap();
            let mut schema = ValueSchema::Boolean;
            for _ in 0..depth {
                schema = ValueSchema::Optional {
                    value: Box::new(schema),
                };
            }
            validate_schema_with_default(&schema).map_err(|errors| validation_codes(&errors))
        }
        "schema-value" => {
            let schema =
                serde_json::from_value::<ValueSchema>(case.arguments["value"]["schema"].clone())
                    .unwrap();
            let value = AbilityValue::new(case.arguments["value"]["value"].clone()).unwrap();
            validate_value(&schema, &ValueExpression::Literal { value })
                .map_err(|errors| validation_codes(&errors))
        }
        "interface-decode" => {
            let document = json!({
                "schema": InterfaceDocument::SCHEMA,
                "required_features": case.arguments["required_features"],
                "interface": case.arguments["interface"],
            });
            validate_interface_value(&document, &BTreeSet::new())
                .map_err(|diagnostic| code(diagnostic))
        }
        "interface-schema" => {
            let mut document = reference_interface(corpus);
            document["schema"] = case.arguments["schema"].clone();
            validate_interface_value(&document, &BTreeSet::new())
                .map_err(|diagnostic| code(diagnostic))
        }
        "interface-unsupported-feature" => {
            let document = json!({
                "schema": InterfaceDocument::SCHEMA,
                "required_features": case.arguments["required_features"],
                "interface": case.arguments["interface"],
            });
            validate_interface_value(&document, &BTreeSet::new())
                .map_err(|diagnostic| code(diagnostic))
        }
        "semantic-phase" | "semantic-cycle" | "semantic-missing-reference" => {
            validate_semantic_fixture(&case.rust).map_err(|errors| validation_codes(&errors))
        }
        "generated-document-limit" => {
            let chunk_bytes = case.arguments["chunk_bytes"].as_u64().unwrap() as usize;
            let count = case.arguments["count"].as_u64().unwrap() as usize;
            let chunk = "x".repeat(chunk_bytes);
            AbilityValue::new(Value::Array(
                std::iter::repeat_n(Value::String(chunk), count).collect(),
            ))
            .map(|_| ())
            .map_err(|error| code(error.diagnostic_code()))
        }
        "none" => Ok(()),
        other => panic!("unknown Rust conformance route '{other}'"),
    };

    validation.map(|()| accepted.cloned().unwrap_or(Value::Null))
}

fn validate_interface_value(
    value: &Value,
    supported_features: &BTreeSet<RequiredFeature>,
) -> Result<(), DiagnosticCode> {
    let bytes =
        aos_contract::canonical::to_vec(value).map_err(|_| DiagnosticCode::ValueTypeMismatch)?;
    let document =
        decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, supported_features)
            .map_err(|error| error.diagnostic_code())?;
    ValidationContext::new(supported_features.clone(), [document])
        .map(|_| ())
        .map_err(|errors| errors.diagnostics()[0].code)
}

fn reference_interface(corpus: &Corpus) -> Value {
    corpus
        .cases
        .iter()
        .find_map(|case| {
            if case.id == "interface-request-output-and-method"
                && let ExpectedOutcome::Accept { value } = &case.expected
            {
                Some(value.clone())
            } else {
                None
            }
        })
        .expect("the corpus must contain its reference interface")
}

fn validate_schema_with_default(schema: &ValueSchema) -> Result<(), ValidationErrors> {
    let value = AbilityValue::new(default_value(schema)).expect("default schema value is bounded");
    validate_value(schema, &ValueExpression::Literal { value })
}

fn default_value(schema: &ValueSchema) -> Value {
    match schema {
        ValueSchema::Boolean => Value::Bool(false),
        ValueSchema::Integer { minimum, .. } => Value::from(*minimum),
        ValueSchema::String { syntax, .. } => Value::String(match syntax {
            None => String::new(),
            Some(StringSyntax::LocalKeyV1) => "key".to_string(),
            Some(StringSyntax::QualifiedNameV1) => "aos.test".to_string(),
        }),
        ValueSchema::StringEnum { values } => Value::String(values[0].clone()),
        ValueSchema::List { .. } => Value::Array(Vec::new()),
        ValueSchema::Map { .. } => Value::Object(serde_json::Map::new()),
        ValueSchema::Record {
            fields,
            optional_fields,
        } => Value::Object(
            fields
                .iter()
                .filter(|(name, _)| !optional_fields.contains(name))
                .map(|(name, schema)| (name.as_str().to_string(), default_value(schema)))
                .collect(),
        ),
        ValueSchema::TaggedUnion { tag, variants } => {
            let (variant_name, variant) = variants.first_key_value().unwrap();
            let mut value = default_value(variant).as_object().unwrap().clone();
            value.insert(
                tag.as_str().to_string(),
                Value::String(variant_name.as_str().to_string()),
            );
            Value::Object(value)
        }
        ValueSchema::Optional { .. } => Value::Null,
        ValueSchema::ArtifactReference
        | ValueSchema::ResourceReference
        | ValueSchema::ProviderAssignment
        | ValueSchema::OperationResultReference => {
            panic!("typed-reference schemas use the schema-bundle route")
        }
    }
}

fn validate_semantic_fixture(route: &str) -> Result<(), ValidationErrors> {
    let mut fixture = aos_ability_validate::test_support::plan_fixture();
    let existing = fixture.effect_plan.operations[0].clone();

    match route {
        "semantic-phase" => {
            let mut consumer = existing.clone();
            consumer.key = scoped("use");
            consumer.input_phase = aos_ability_model::ValuePhase::Planning;
            consumer.inputs = ValueExpression::OperationResult {
                reference: OperationResultReference {
                    producer: ResultProducerKey::Operation {
                        key: existing.key.clone(),
                    },
                    output: key("ready"),
                },
            };
            fixture.effect_plan.operations.push(consumer.clone());
            fixture.effect_plan.edges.push(DependencyEdge {
                from: operation_node(existing.key),
                to: operation_node(consumer.key),
                kind: DependencyKind::Data,
            });
        }
        "semantic-cycle" => {
            let mut second = existing.clone();
            second.key = scoped("second");
            fixture.effect_plan.operations.push(second.clone());
            fixture.effect_plan.edges.extend([
                DependencyEdge {
                    from: operation_node(existing.key.clone()),
                    to: operation_node(second.key.clone()),
                    kind: DependencyKind::RequiredSuccess,
                },
                DependencyEdge {
                    from: operation_node(second.key),
                    to: operation_node(existing.key),
                    kind: DependencyKind::RequiredSuccess,
                },
            ]);
        }
        "semantic-missing-reference" => {
            fixture.effect_plan.edges.push(DependencyEdge {
                from: operation_node(scoped("missing")),
                to: operation_node(existing.key),
                kind: DependencyKind::OrderingOnly,
            });
        }
        _ => unreachable!(),
    }
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| left.key.cmp(&right.key));
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.validate().map(|_| ())
}

fn operation_node(key: ScopedOperationKey) -> PlanNodeKey {
    PlanNodeKey::Operation { key }
}

fn scoped(value: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: ScopePath::root(),
        key: key(value),
    }
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static conformance key")
}

fn validation_codes(errors: &ValidationErrors) -> Vec<&'static str> {
    let mut codes = Vec::new();
    for diagnostic in errors.diagnostics() {
        let code = diagnostic_code(diagnostic.code);
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    codes
}

fn diagnostic_code(code: DiagnosticCode) -> &'static str {
    AbilityEvaluationDiagnosticCode::Contract(code).as_str()
}

fn strip_markers(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(strip_markers).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .filter(|(name, _)| name.as_str() != "_type")
                .map(|(name, value)| (name.clone(), strip_markers(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn implementation_at(store_path: &str, nar_hash: Sha256Digest) -> ProviderImplementation {
    ProviderImplementation {
        interface: InterfaceKey {
            name: InterfaceName::new("aos.test.authoring-conformance").unwrap(),
            abi: NonZeroU32::new(1).unwrap(),
            descriptor: digest('1'),
        },
        artifact: ArtifactReference {
            content: digest('2'),
            store_path: store_path.to_string(),
            nar_hash,
            closure: digest('3'),
        },
        requirements: Vec::new(),
        implementation: ImplementationKind::PureComposition {
            compose_entry: key("compose"),
            transition_entry: key("transition"),
        },
        owns_resource_kinds: Vec::new(),
    }
}

fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", digit.to_string().repeat(64))).unwrap()
}
