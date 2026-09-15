//! Portable-schema behavior conformance shared by Nix and Rust.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_model::value::ValueExpression;
use aos_ability_model::{
    AbilityValue, ArtifactReference, DiagnosticCode, InterfaceKey, InterfaceName, ModuleLocator,
    ProviderImplementation, RelativePath, ValueSchema,
};
use aos_ability_validate::validate_value;
use aos_contract::Sha256Digest;
use serde::Deserialize;
use serde_json::Value;

use super::{
    AbilityEntryPoint, AbilityEvaluationDiagnosticCode, RestrictedAbilityEvaluator,
    ability_evaluation_diagnostic,
};

const CORPUS_SCHEMA: &str = "aos.ability.authoring-conformance/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    cases: Vec<BehaviorCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BehaviorCase {
    id: String,
    schema: ValueSchema,
    value: Value,
    expected: ExpectedOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
enum ExpectedOutcome {
    Accept { value: Value },
    Reject { code: String },
}

struct ConformanceFixture {
    evaluator: RestrictedAbilityEvaluator,
    implementation: ProviderImplementation,
    module: ModuleLocator,
    corpus: Corpus,
}

#[test]
fn behavior_vectors_agree_across_nix_and_rust() {
    let Some(fixture) = conformance_fixture().unwrap() else {
        return;
    };

    validate_corpus_contract(&fixture.corpus).unwrap();
    for case in &fixture.corpus.cases {
        run_evaluator_case(&fixture, case);
        run_rust_case(case);
    }
}

fn conformance_fixture() -> Result<Option<ConformanceFixture>> {
    if std::env::var("AOS_TEST_ABILITY_EVALUATOR_DISABLED").as_deref() == Ok("1") {
        return Ok(None);
    }

    const REQUIRED_ENVIRONMENT: [&str; 6] = [
        "AOS_NIX_INSTANTIATE",
        "AOS_PRLIMIT",
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
    let fixture_path = required("AOS_TEST_ABILITY_CONFORMANCE_FIXTURE")?;
    let corpus_path = required("AOS_TEST_ABILITY_CONFORMANCE_CORPUS")?;
    ensure!(
        Path::new(&corpus_path) == Path::new(&fixture_path).join("corpus.json"),
        "the conformance corpus must come from the exact evaluator fixture"
    );

    let corpus_bytes = std::fs::read(&corpus_path)
        .with_context(|| format!("reading ability conformance corpus {corpus_path}"))?;
    let corpus_value: Value = serde_json::from_slice(&corpus_bytes)
        .context("decoding the generated ability conformance corpus")?;
    let canonical = aos_contract::canonical::to_vec(&corpus_value)?;
    let corpus: Corpus = serde_json::from_slice(&canonical)
        .context("decoding the normalized ability conformance corpus")?;
    ensure!(
        serde_json::from_slice::<Value>(&canonical)? == corpus_value,
        "normalizing the ability conformance corpus changed its value"
    );

    let fixture_nar_hash =
        Sha256Digest::parse(&required("AOS_TEST_ABILITY_CONFORMANCE_FIXTURE_NAR_HASH")?)
            .context("parsing the authoring conformance fixture NAR hash")?;
    let evaluator = RestrictedAbilityEvaluator::new(
        required("AOS_NIX_INSTANTIATE")?,
        required("AOS_PRLIMIT")?,
        required("AOS_TEST_ABILITY_CACHE")?,
        Default::default(),
    )?;

    let implementation = implementation_at(&fixture_path, fixture_nar_hash);
    let module = ModuleLocator {
        artifact: implementation.artifact.clone(),
        path: RelativePath::new("default.nix")?,
    };

    Ok(Some(ConformanceFixture {
        evaluator,
        implementation,
        module,
        corpus,
    }))
}

fn validate_corpus_contract(corpus: &Corpus) -> Result<()> {
    ensure!(corpus.schema == CORPUS_SCHEMA, "unsupported corpus schema");
    let mut ids = BTreeSet::new();
    for case in &corpus.cases {
        ensure!(
            ids.insert(&case.id),
            "duplicate behavior case '{}'",
            case.id
        );
        ensure!(case.id.len() <= 128, "behavior case id is too long");
    }
    ensure!(!corpus.cases.is_empty(), "behavior vector set is empty");

    Ok(())
}

fn run_evaluator_case(fixture: &ConformanceFixture, case: &BehaviorCase) {
    let arguments = AbilityValue::new(serde_json::json!({
        "case": {
            "schema": case.schema,
            "value": case.value,
        }
    }))
    .unwrap();
    let result = fixture.evaluator.evaluate::<Value>(
        &fixture.implementation,
        &fixture.module,
        AbilityEntryPoint::Compose,
        &arguments,
    );

    match &case.expected {
        ExpectedOutcome::Accept { value } => {
            assert_eq!(result.unwrap(), *value, "evaluator case '{}'", case.id);
        }
        ExpectedOutcome::Reject { code } => {
            let error = result.expect_err("rejection case unexpectedly succeeded");
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

fn run_rust_case(case: &BehaviorCase) {
    let value = AbilityValue::new(case.value.clone()).unwrap();
    let result = validate_value(&case.schema, &ValueExpression::Literal { value });

    match &case.expected {
        ExpectedOutcome::Accept { value } => {
            result.unwrap_or_else(|diagnostics| {
                panic!("Rust case '{}' rejected with {diagnostics:?}", case.id)
            });
            assert_eq!(&case.value, value, "Rust case '{}' expected value", case.id);
        }
        ExpectedOutcome::Reject { code } => {
            let diagnostics = result.expect_err("Rust rejection case unexpectedly succeeded");
            let actual: BTreeSet<_> = diagnostics
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic_code(diagnostic.code))
                .collect();
            assert_eq!(
                actual,
                BTreeSet::from([code.as_str()]),
                "Rust case '{}'",
                case.id
            );
        }
    }
}

fn diagnostic_code(code: DiagnosticCode) -> &'static str {
    AbilityEvaluationDiagnosticCode::Contract(code).as_str()
}

fn implementation_at(store_path: &str, nar_hash: Sha256Digest) -> ProviderImplementation {
    ProviderImplementation {
        name: aos_ability_model::LocalKey::new("provider").unwrap(),
        description: "Conformance test provider.".to_string(),
        interface: InterfaceKey {
            name: InterfaceName::new("aos.test.authoring-conformance").unwrap(),
            abi: NonZeroU32::new(1).unwrap(),
            descriptor: digest('1'),
        },
        guarantees: Vec::new(),
        artifact: ArtifactReference {
            content: digest('2'),
            store_path: store_path.to_string(),
            nar_hash,
            closure: digest('3'),
        },
        requirements: Vec::new(),
        desired_schema: None,
        provider_module: None,
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    }
}

fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", digit.to_string().repeat(64))).unwrap()
}
