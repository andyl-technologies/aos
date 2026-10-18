//! Joins the exact uploaded prefix to the final Source and shared checkpoint.
//!
//! ```text
//! {schema,history:{schema,ancestry,node,source},
//!  coordinator_checkpoint:{reference,body}}
//! ```
//!
//! Prefix Capture housekeeping stays Preparing. Only the independently checked
//! final completed ledger can prove completion. Every other modeled Source,
//! ancestry and Node field is required to match the final semantic record.

use super::producer_fields::{field, object, read};
use super::source_fields::{ROOT_FIELDS, root_data};
use crate::node_contract::RuntimeError;
use crucible_node_contract::{ContentRef, canonical};
use serde_json::Value;

pub(super) struct Prefix17 {
    root: Value,
}

impl Prefix17 {
    pub(super) fn validate_data(
        bytes: &[u8],
        reference: &ContentRef,
        final_semantic: &Value,
        checkpoint_reference: &ContentRef,
        checkpoint_bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        if bytes.len() > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        reference
            .verify(bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let root = canonical::parse_json(bytes, maximum_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if canonical::canonical_json(&root).map_err(|_| RuntimeError::InvalidReceipt)? != bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        let envelope = object(&root, &["schema", "history", "coordinator_checkpoint"])?;
        if field(envelope, "schema")?.as_str()
            != Some("source-private.source-restored-settled-capture-prefix/17")
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let saved = object(
            field(envelope, "coordinator_checkpoint")?,
            &["reference", "body"],
        )?;
        let saved_reference: ContentRef = read(field(saved, "reference")?)?;
        let saved_bytes = canonical::canonical_json(field(saved, "body")?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        saved_reference
            .verify(&saved_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        checkpoint_reference
            .verify(checkpoint_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if saved_reference != *checkpoint_reference || saved_bytes != checkpoint_bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        let prefix_semantic = semantic_data(field(envelope, "history")?)?;
        let final_semantic = semantic_data(final_semantic)?;
        for key in ["schema", "ancestry", "node"] {
            if field(prefix_semantic, key)? != field(final_semantic, key)? {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        let prefix_source = root_data(field(prefix_semantic, "source")?)?;
        let final_source = root_data(field(final_semantic, "source")?)?;
        for key in ROOT_FIELDS {
            if key != "capture" && field(prefix_source, key)? != field(final_source, key)? {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        Ok(Self { root })
    }

    pub(super) fn capture_data(&self) -> Result<&Value, RuntimeError> {
        let envelope = object(&self.root, &["schema", "history", "coordinator_checkpoint"])?;
        let history = semantic_data(field(envelope, "history")?)?;
        let source = root_data(field(history, "source")?)?;
        field(source, "capture")
    }
}

pub(super) fn semantic_data(
    value: &Value,
) -> Result<&serde_json::Map<String, Value>, RuntimeError> {
    let semantic = object(value, &["schema", "ancestry", "node", "source"])?;
    if field(semantic, "schema")?.as_str()
        != Some("source-private.semantic-state-restored-settled/17")
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(semantic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn semantic() -> Value {
        let mut source = serde_json::Map::new();
        for field in ROOT_FIELDS {
            source.insert(field.into(), Value::Null);
        }
        source.insert(
            "schema".into(),
            json!("source-private.source-restored-settled-state/17"),
        );
        source.insert("capture".into(), json!({"phase":"complete"}));
        json!({"schema":"source-private.semantic-state-restored-settled/17",
            "ancestry":{"test":"immutable"},"node":{"test":"unchanged"},"source":source})
    }

    #[test]
    fn actual_prefix_comparison_allows_only_capture_housekeeping_delta() {
        // These values exercise pure prefix correspondence, not Source/native
        // validation or a live grant. The aggregate independently checks all
        // defining first/once/Producer/SDK/native/ledger types.
        let final_semantic = semantic();
        let mut prefix_semantic = final_semantic.clone();
        prefix_semantic["source"]["capture"] = json!({"phase":"preparing"});
        let checkpoint = json!({"test":"actual checkpoint bytes"});
        let checkpoint_bytes = canonical::canonical_json(&checkpoint).unwrap();
        let checkpoint_reference =
            canonical::content_ref(&checkpoint_bytes, "application/json").unwrap();
        let prefix = json!({"schema":"source-private.source-restored-settled-capture-prefix/17",
            "history":prefix_semantic,"coordinator_checkpoint":{"reference":checkpoint_reference,"body":checkpoint}});
        let bytes = canonical::canonical_json(&prefix).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();

        Prefix17::validate_data(
            &bytes,
            &reference,
            &final_semantic,
            &checkpoint_reference,
            &checkpoint_bytes,
            bytes.len(),
        )
        .unwrap();
        let mut changed = final_semantic.clone();
        changed["node"]["test"] = json!("different node");
        assert!(
            Prefix17::validate_data(
                &bytes,
                &reference,
                &changed,
                &checkpoint_reference,
                &checkpoint_bytes,
                bytes.len()
            )
            .is_err()
        );
        changed = final_semantic.clone();
        changed["source"]["limits"] = json!({"producer_used":0});
        assert!(
            Prefix17::validate_data(
                &bytes,
                &reference,
                &changed,
                &checkpoint_reference,
                &checkpoint_bytes,
                bytes.len()
            )
            .is_err()
        );
        changed = final_semantic;
        changed["ancestry"] = json!({"test":"different parent"});
        assert!(
            Prefix17::validate_data(
                &bytes,
                &reference,
                &changed,
                &checkpoint_reference,
                &checkpoint_bytes,
                bytes.len()
            )
            .is_err()
        );
    }
}
