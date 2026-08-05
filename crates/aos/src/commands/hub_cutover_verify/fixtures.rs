//! Sequential RFC 6901 fixture mutation and stage evaluation.
//!
//! Each mutation names its target so coherent positive cases can transform the
//! plan, report, and verification sidecar atomically before one semantic pass.

use std::{borrow::Cow, collections::BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::bundle::{
    authenticate_key_map_fixture, authenticate_manifest_fixture, validate_manifest_fixture_closure,
    verify_document_envelope,
};
use super::canonical::parse_json;
use super::schema::{SchemaFailure, SchemaFailureCode, validate_schema};
use super::semantics::{SemanticFailure, SemanticFailureCode, validate_semantics};
use super::{SignatureEnvelope, SignerKeyMap, VerifiedInputs};

const EXPECTED_FIXTURE_CASE_COUNT: usize = 77;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSet {
    schema_version: String,
    base: FixtureBase,
    cases: Vec<FixtureCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBase {
    plan_payload_node_id: String,
    report_payload_node_id: String,
    verification_payload_node_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FixtureFailureCode {
    AttemptContractInvalid,
    AuthContractInvalid,
    BlockerContractInvalid,
    BundleNotClosed,
    CanonicalOrderInvalid,
    DatabaseRestoreContractInvalid,
    DurableObjectAggregateInvalid,
    GcPartitionInvalid,
    MappingContractInvalid,
    ReferenceContractInvalid,
    SignatureInvalid,
    SignerRoleNotAuthorized,
    SmokeContractInvalid,
    TransitionContractInvalid,
    TypeMismatch,
    UnknownProperty,
    VerificationContractInvalid,
    VerifierIdentityMismatch,
}

impl FixtureFailureCode {
    fn from_error(error: &anyhow::Error) -> Option<Self> {
        error.chain().find_map(|cause| {
            if let Some(failure) = cause.downcast_ref::<FixtureEvaluationFailure>() {
                return Some(failure.code);
            }
            if let Some(failure) = cause.downcast_ref::<SchemaFailure>() {
                return Some(match failure.code {
                    SchemaFailureCode::TypeMismatch => Self::TypeMismatch,
                    SchemaFailureCode::UnknownProperty => Self::UnknownProperty,
                });
            }
            cause
                .downcast_ref::<SemanticFailure>()
                .map(|failure| match failure.code {
                    SemanticFailureCode::AttemptContractInvalid => Self::AttemptContractInvalid,
                    SemanticFailureCode::AuthContractInvalid => Self::AuthContractInvalid,
                    SemanticFailureCode::BlockerContractInvalid => Self::BlockerContractInvalid,
                    SemanticFailureCode::CanonicalOrderInvalid => Self::CanonicalOrderInvalid,
                    SemanticFailureCode::DatabaseRestoreContractInvalid => {
                        Self::DatabaseRestoreContractInvalid
                    }
                    SemanticFailureCode::DurableObjectAggregateInvalid => {
                        Self::DurableObjectAggregateInvalid
                    }
                    SemanticFailureCode::GcPartitionInvalid => Self::GcPartitionInvalid,
                    SemanticFailureCode::MappingContractInvalid => Self::MappingContractInvalid,
                    SemanticFailureCode::ReferenceContractInvalid => Self::ReferenceContractInvalid,
                    SemanticFailureCode::SmokeContractInvalid => Self::SmokeContractInvalid,
                    SemanticFailureCode::TransitionContractInvalid => {
                        Self::TransitionContractInvalid
                    }
                    SemanticFailureCode::VerificationContractInvalid => {
                        Self::VerificationContractInvalid
                    }
                    SemanticFailureCode::VerifierIdentityMismatch => Self::VerifierIdentityMismatch,
                })
        })
    }
}

#[derive(Debug)]
struct FixtureEvaluationFailure {
    code: FixtureFailureCode,
    source: anyhow::Error,
}

impl std::fmt::Display for FixtureEvaluationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "fixture evaluation failed: {:#}", self.source)
    }
}

impl std::error::Error for FixtureEvaluationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn fixture_failure(code: FixtureFailureCode, source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(FixtureEvaluationFailure { code, source })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    case_id: String,
    mutations: Vec<FixtureMutation>,
    evaluation_stage: String,
    expected_result: String,
    expected_code: Option<FixtureFailureCode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMutation {
    target: String,
    operation: String,
    pointer: String,
    #[serde(default, deserialize_with = "deserialize_mutation_value")]
    value: FixtureMutationValue,
    from_pointer: Option<String>,
}

#[derive(Default)]
enum FixtureMutationValue {
    #[default]
    Missing,
    Present(Value),
}

fn deserialize_mutation_value<'de, D>(
    deserializer: D,
) -> std::result::Result<FixtureMutationValue, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(FixtureMutationValue::Present)
}

impl FixtureMutationValue {
    fn cloned(&self) -> Option<Value> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value.clone()),
        }
    }

    fn as_value(&self) -> Option<&Value> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }

    fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }
}

struct FixtureState<'a> {
    plan: Value,
    report: Value,
    verification: Value,
    manifest_envelope: Value,
    key_map: Value,
    signature_envelopes: Value,
    verifier_bytes: Cow<'a, [u8]>,
}

/// Materializes and evaluates every closed fixture case.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_fixtures(
    fixtures: &Value,
    base_plan: &Value,
    base_report: &Value,
    base_verification: &Value,
    plan_schema: &Value,
    report_schema: &Value,
    verification_schema: &Value,
    inputs: &VerifiedInputs,
    key_map: &SignerKeyMap,
    root_key: &VerifyingKey,
) -> Result<usize> {
    let fixture_set: FixtureSet = serde_json::from_value(fixtures.clone())
        .context("invalid closed aos-cutover-fixtures/v1 manifest")?;
    if fixture_set.schema_version != "aos-cutover-fixtures/v1" {
        bail!("unsupported fixture schema_version");
    }
    let documents = &inputs.manifest_envelope.payload.documents;
    if fixture_set.base.plan_payload_node_id != documents.plan_payload_node_id
        || fixture_set.base.report_payload_node_id != documents.report_payload_node_id
        || fixture_set.base.verification_payload_node_id != documents.verification_payload_node_id
    {
        bail!("fixture base does not bind authenticated bundle documents");
    }
    let fixture_count = fixture_set.cases.len();
    if fixture_count != EXPECTED_FIXTURE_CASE_COUNT {
        bail!(
            "fixture case count must be exactly {EXPECTED_FIXTURE_CASE_COUNT}, got {fixture_count}"
        );
    }
    let mut case_ids = BTreeSet::new();
    if fixture_set
        .cases
        .windows(2)
        .any(|pair| pair[0].case_id >= pair[1].case_id)
    {
        bail!("noncanonical fixture case order");
    }
    for case in &fixture_set.cases {
        let empty_success = case.case_id == "success"
            && case.expected_result == "pass"
            && case.expected_code.is_none()
            && case.mutations.is_empty();
        if case.case_id.is_empty()
            || !case_ids.insert(case.case_id.as_str())
            || (case.mutations.is_empty() && !empty_success)
        {
            bail!("duplicate or vacuous fixture case");
        }
    }
    validate_semantics(
        base_plan,
        base_report,
        base_verification,
        &inputs.manifest_envelope.payload,
        fixture_count,
    )?;
    for case in &fixture_set.cases {
        let observed = evaluate_case(
            case,
            base_plan,
            base_report,
            base_verification,
            plan_schema,
            report_schema,
            verification_schema,
            inputs,
            key_map,
            root_key,
            fixture_count,
        );
        match (case.expected_result.as_str(), case.expected_code, observed) {
            ("pass", None, Ok(())) => {}
            ("fail", Some(code), Err(error))
                if FixtureFailureCode::from_error(&error) == Some(code) => {}
            (expected, code, result) => {
                bail!(
                    "fixture {} expected {expected}/{code:?}, observed {result:?}",
                    case.case_id
                );
            }
        }
    }
    Ok(fixture_set.cases.len())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_case(
    case: &FixtureCase,
    base_plan: &Value,
    base_report: &Value,
    base_verification: &Value,
    plan_schema: &Value,
    report_schema: &Value,
    verification_schema: &Value,
    inputs: &VerifiedInputs,
    key_map: &SignerKeyMap,
    root_key: &VerifyingKey,
    fixture_count: usize,
) -> Result<()> {
    validate_stage_targets(case)?;
    let manifest = &inputs.manifest_envelope.payload;
    let key_map_value = parse_json(
        inputs
            .bundle_files
            .get(&manifest.trust.key_map_payload_node_id)
            .ok_or_else(|| anyhow!("fixture key-map payload absent"))?,
        "fixture key map",
    )?;
    let signature_envelopes = serde_json::json!({
        "plan": parse_json(node(inputs, &manifest.documents.plan_signature_envelope_node_id)?, "plan envelope")?,
        "report": parse_json(node(inputs, &manifest.documents.report_signature_envelope_node_id)?, "report envelope")?,
        "verification": parse_json(
            node(inputs, &manifest.documents.verification_signature_envelope_node_id)?,
            "verification envelope"
        )?,
        "key_map": parse_json(node(inputs, &manifest.trust.key_map_signature_envelope_node_id)?, "key-map envelope")?
    });
    let mut state = FixtureState {
        plan: base_plan.clone(),
        report: base_report.clone(),
        verification: base_verification.clone(),
        manifest_envelope: inputs.manifest_value.clone(),
        key_map: key_map_value,
        signature_envelopes,
        verifier_bytes: Cow::Borrowed(node(inputs, &manifest.verifier_node_id)?),
    };
    for mutation in &case.mutations {
        if mutation.target == "verifier_bytes" {
            apply_verifier_mutation(&mut state.verifier_bytes, mutation)?;
            continue;
        }
        let target = match mutation.target.as_str() {
            "plan" => &mut state.plan,
            "report" => &mut state.report,
            "verification" => &mut state.verification,
            "bundle_manifest" => &mut state.manifest_envelope,
            "signer_key_map" => &mut state.key_map,
            "signature_envelope" => &mut state.signature_envelopes,
            unknown => bail!("unsupported fixture target: {unknown}"),
        };
        apply_mutation(target, mutation)?;
    }
    match case.evaluation_stage.as_str() {
        "schema" => {
            validate_schema(plan_schema, &state.plan, "fixture plan")?;
            validate_schema(report_schema, &state.report, "fixture report")?;
            validate_schema(
                verification_schema,
                &state.verification,
                "fixture verification",
            )?;
            let key_map_schema = parse_json(
                node(inputs, &manifest.schemas.signer_key_map_node_id)?,
                "fixture key-map schema",
            )?;
            validate_schema(&key_map_schema, &state.key_map, "fixture key map")?;
            Ok(())
        }
        "semantic" => validate_semantics(
            &state.plan,
            &state.report,
            &state.verification,
            manifest,
            fixture_count,
        ),
        "signature" => {
            let fixture_key_map: SignerKeyMap = serde_json::from_value(state.key_map.clone())?;
            if fixture_key_map.keys.iter().any(|key| {
                key.roles.is_empty()
                    || key
                        .roles
                        .iter()
                        .any(|role| !matches!(role.as_str(), "plan" | "report" | "verification"))
            }) {
                return Err(fixture_failure(
                    FixtureFailureCode::SignerRoleNotAuthorized,
                    anyhow!("fixture key map contains a role outside the closed role set"),
                ));
            }
            verify_fixture_signatures(inputs, key_map, root_key, &state)
                .map_err(|error| fixture_failure(FixtureFailureCode::SignatureInvalid, error))
        }
        "bundle" => {
            authenticate_manifest_fixture(&inputs.manifest_value, root_key)?;
            validate_manifest_fixture_closure(inputs, &state.manifest_envelope)
                .map_err(|error| fixture_failure(FixtureFailureCode::BundleNotClosed, error))?;
            if state.verifier_bytes.as_ref() != inputs.running_executable_bytes {
                return Err(fixture_failure(
                    FixtureFailureCode::VerifierIdentityMismatch,
                    anyhow!("fixture verifier bytes differ from the running verifier"),
                ));
            }
            Ok(())
        }
        unknown => bail!("unsupported fixture evaluation stage: {unknown}"),
    }
}

fn validate_stage_targets(case: &FixtureCase) -> Result<()> {
    let target_is_valid = |target: &str| match case.evaluation_stage.as_str() {
        "schema" => matches!(
            target,
            "plan" | "report" | "verification" | "signer_key_map"
        ),
        "semantic" => matches!(target, "plan" | "report" | "verification"),
        "signature" => matches!(
            target,
            "plan" | "report" | "verification" | "signer_key_map" | "signature_envelope"
        ),
        "bundle" => matches!(target, "bundle_manifest" | "verifier_bytes"),
        _ => false,
    };
    if case
        .mutations
        .iter()
        .any(|mutation| !target_is_valid(&mutation.target))
    {
        bail!("fixture target does not correspond to evaluation stage");
    }
    Ok(())
}

fn verify_fixture_signatures(
    inputs: &VerifiedInputs,
    key_map: &SignerKeyMap,
    root_key: &VerifyingKey,
    state: &FixtureState<'_>,
) -> Result<()> {
    let documents = &inputs.manifest_envelope.payload.documents;
    for (kind, payload_node, payload) in [
        ("plan", documents.plan_payload_node_id.as_str(), &state.plan),
        (
            "report",
            documents.report_payload_node_id.as_str(),
            &state.report,
        ),
        (
            "verification",
            documents.verification_payload_node_id.as_str(),
            &state.verification,
        ),
    ] {
        let envelope: SignatureEnvelope = serde_json::from_value(
            state
                .signature_envelopes
                .get(kind)
                .cloned()
                .ok_or_else(|| anyhow!("fixture signature envelope absent"))?,
        )?;
        verify_document_envelope(inputs, key_map, kind, payload_node, payload, &envelope)?;
    }
    let key_map_envelope: SignatureEnvelope = serde_json::from_value(
        state
            .signature_envelopes
            .get("key_map")
            .cloned()
            .ok_or_else(|| anyhow!("fixture key-map envelope absent"))?,
    )?;
    authenticate_key_map_fixture(inputs, root_key, &state.key_map, &key_map_envelope)
}

fn node<'a>(inputs: &'a VerifiedInputs, node_id: &str) -> Result<&'a [u8]> {
    inputs
        .bundle_files
        .get(node_id)
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("bundle node absent: {node_id}"))
}

fn apply_mutation(value: &mut Value, mutation: &FixtureMutation) -> Result<()> {
    let tokens = parse_pointer(&mutation.pointer)?;
    match mutation.operation.as_str() {
        "add" => {
            if mutation.from_pointer.is_some() {
                bail!("add forbids from_pointer");
            }
            add(
                value,
                &tokens,
                mutation
                    .value
                    .cloned()
                    .ok_or_else(|| anyhow!("add requires value"))?,
            )
        }
        "remove" => {
            if mutation.value.is_present() || mutation.from_pointer.is_some() {
                bail!("remove has forbidden fields");
            }
            remove(value, &tokens)
        }
        "replace" => {
            if mutation.from_pointer.is_some() {
                bail!("replace forbids from_pointer");
            }
            replace(
                value,
                &tokens,
                mutation
                    .value
                    .cloned()
                    .ok_or_else(|| anyhow!("replace requires value"))?,
            )
        }
        "copy" => {
            if mutation.value.is_present() {
                bail!("copy forbids value");
            }
            let source = parse_pointer(
                mutation
                    .from_pointer
                    .as_deref()
                    .ok_or_else(|| anyhow!("copy requires from_pointer"))?,
            )?;
            let copied = get(value, &source)?.clone();
            add(value, &tokens, copied)
        }
        unknown => bail!("unsupported fixture mutation operation: {unknown}"),
    }
}

fn apply_verifier_mutation(bytes: &mut Cow<'_, [u8]>, mutation: &FixtureMutation) -> Result<()> {
    if mutation.operation != "replace" || mutation.from_pointer.is_some() {
        bail!("verifier bytes support only replace mutations");
    }
    let tokens = parse_pointer(&mutation.pointer)?;
    let [index] = tokens.as_slice() else {
        bail!("verifier byte pointer must select exactly one byte");
    };
    let canonical_index = index;
    let index = canonical_index
        .parse::<usize>()
        .context("verifier byte pointer is not an array index")?;
    if index.to_string() != *canonical_index {
        bail!("verifier byte pointer is not canonical");
    }
    let replacement = mutation
        .value
        .as_value()
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| anyhow!("verifier byte replacement must be an integer byte"))?;
    let byte = bytes
        .to_mut()
        .get_mut(index)
        .ok_or_else(|| anyhow!("verifier byte pointer is out of bounds"))?;
    *byte = replacement;
    Ok(())
}

fn parse_pointer(pointer: &str) -> Result<Vec<String>> {
    if pointer.len() > 512 || !pointer.starts_with('/') {
        bail!("fixture pointer must be absolute and at most 512 bytes");
    }
    let mut tokens = Vec::new();
    for encoded in pointer[1..].split('/') {
        let mut decoded = String::new();
        let mut characters = encoded.chars();
        while let Some(character) = characters.next() {
            if character == '~' {
                match characters.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => bail!("noncanonical JSON pointer escape"),
                }
            } else {
                decoded.push(character);
            }
        }
        if decoded.replace('~', "~0").replace('/', "~1") != encoded {
            bail!("noncanonical JSON pointer token");
        }
        tokens.push(decoded);
    }
    Ok(tokens)
}

fn get<'a>(value: &'a Value, tokens: &[String]) -> Result<&'a Value> {
    let mut current = value;
    for token in tokens {
        current = match current {
            Value::Object(object) => object
                .get(token)
                .ok_or_else(|| anyhow!("fixture pointer member absent"))?,
            Value::Array(values) => values
                .get(array_index(token, values.len())?)
                .ok_or_else(|| anyhow!("fixture pointer index absent"))?,
            _ => bail!("fixture pointer traverses a scalar"),
        };
    }
    Ok(current)
}

fn parent_mut<'a, 'b>(
    value: &'a mut Value,
    tokens: &'b [String],
) -> Result<(&'a mut Value, &'b str)> {
    let (last, parents) = tokens
        .split_last()
        .ok_or_else(|| anyhow!("fixture mutation may not replace the document root"))?;
    let mut current = value;
    for token in parents {
        current = match current {
            Value::Object(object) => object
                .get_mut(token)
                .ok_or_else(|| anyhow!("fixture pointer member absent"))?,
            Value::Array(values) => {
                let index = array_index(token, values.len())?;
                values
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("fixture pointer index absent"))?
            }
            _ => bail!("fixture pointer traverses a scalar"),
        };
    }
    Ok((current, last))
}

fn array_index(token: &str, length: usize) -> Result<usize> {
    if token.is_empty()
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("noncanonical array index");
    }
    let index: usize = token.parse()?;
    if index >= length {
        bail!("array index out of range");
    }
    Ok(index)
}

fn add(value: &mut Value, tokens: &[String], new_value: Value) -> Result<()> {
    let (parent, last) = parent_mut(value, tokens)?;
    match parent {
        Value::Object(object) => {
            object.insert(last.to_owned(), new_value);
        }
        Value::Array(values) => {
            if last != "-" {
                bail!("fixture array add must use /-");
            }
            values.push(new_value);
        }
        _ => bail!("fixture add parent is a scalar"),
    }
    Ok(())
}

fn remove(value: &mut Value, tokens: &[String]) -> Result<()> {
    let (parent, last) = parent_mut(value, tokens)?;
    match parent {
        Value::Object(object) => {
            object
                .remove(last)
                .ok_or_else(|| anyhow!("remove member absent"))?;
        }
        Value::Array(values) => {
            let index = array_index(last, values.len())?;
            values.remove(index);
        }
        _ => bail!("fixture remove parent is a scalar"),
    }
    Ok(())
}

fn replace(value: &mut Value, tokens: &[String], new_value: Value) -> Result<()> {
    let (parent, last) = parent_mut(value, tokens)?;
    match parent {
        Value::Object(object) => {
            let slot = object
                .get_mut(last)
                .ok_or_else(|| anyhow!("replace member absent"))?;
            *slot = new_value;
        }
        Value::Array(values) => {
            let index = array_index(last, values.len())?;
            values[index] = new_value;
        }
        _ => bail!("fixture replace parent is a scalar"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_add_only_accepts_append_token() -> Result<()> {
        let mut value = serde_json::json!({"items":[1]});
        add(&mut value, &parse_pointer("/items/-")?, Value::from(2))?;
        assert_eq!(value, serde_json::json!({"items":[1,2]}));
        assert!(add(&mut value, &parse_pointer("/items/0")?, Value::from(3)).is_err());
        Ok(())
    }

    #[test]
    fn pointer_rejects_noncanonical_escapes() {
        assert_eq!(parse_pointer("/a~01b").unwrap(), ["a~1b"]);
        assert!(parse_pointer("/a~2b").is_err());
        assert!(parse_pointer("relative").is_err());
    }
}
