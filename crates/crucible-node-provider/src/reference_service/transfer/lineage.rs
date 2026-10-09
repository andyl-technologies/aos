//! Transfers explicit selected consumption rows without reinterpreting payloads.

use crucible_node_contract::{ContentRef, Validate, canonical};
use serde_json::{Map, Value};

use crate::ProviderError;

use super::Resources;

pub(super) fn control_closure(
    resources: &Resources,
    result: &Map<String, Value>,
) -> Result<Vec<ContentRef>, ProviderError> {
    let mut walker = Walker {
        resources,
        visited: Vec::new(),
        output: Vec::new(),
        edges: 0,
    };
    walker
        .visited
        .try_reserve_exact(4096)
        .map_err(|_| ProviderError::ResourceExhausted("lineage transfer role slots"))?;
    walker
        .output
        .try_reserve_exact(4096)
        .map_err(|_| ProviderError::ResourceExhausted("lineage transfer output slots"))?;
    walker.value(&Value::Object(result.clone()), 0)?;
    Ok(walker.output)
}

struct Walker<'a> {
    resources: &'a Resources,
    visited: Vec<ContentRef>,
    output: Vec<ContentRef>,
    edges: usize,
}

impl Walker<'_> {
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), ProviderError> {
        if depth > 64 {
            return Err(ProviderError::ResourceExhausted("lineage evidence depth"));
        }
        match value {
            Value::Object(object)
                if object.contains_key("hash")
                    && object.contains_key("length")
                    && object.contains_key("media_type") =>
            {
                let reference = serde_json::from_value(value.clone())
                    .map_err(crucible_node_contract::ContractError::from)?;
                self.reference(&reference, depth)?;
            }
            Value::Object(object) => {
                for value in object.values() {
                    self.value(value, depth)?;
                }
            }
            Value::Array(array) => {
                for value in array {
                    self.value(value, depth)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn reference(&mut self, reference: &ContentRef, depth: usize) -> Result<(), ProviderError> {
        reference.validate()?;
        self.edges = self
            .edges
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted(
                "lineage evidence edge arithmetic",
            ))?;
        if self.edges > 65_536 || self.visited.len() >= 4096 || depth > 64 {
            return Err(ProviderError::ResourceExhausted(
                "lineage evidence closure credit",
            ));
        }
        if self.visited.contains(reference) {
            return Ok(());
        }
        self.visited.push(reference.clone());
        if self.resources.profile.content(reference).is_ok()
            || self
                .resources
                .bootstrap
                .installed_content
                .iter()
                .any(|content| content.reference == *reference)
            || self
                .resources
                .profile
                .implementation
                .artifacts
                .iter()
                .any(|artifact| artifact.content == *reference)
        {
            return Ok(());
        }
        let bytes = self.resources.content(reference)?;
        reference.verify(bytes)?;
        if let Some(object) = self
            .resources
            .child
            .as_ref()
            .and_then(|child| child.evidence(reference))
        {
            // These edges were created from the owning driver's actual Close
            // and the original accepted InputBatch codecs. Unknown parent
            // bodies refuse; no missing body is guessed to be a leaf.
            for dependency in object.dependencies() {
                self.reference(dependency, depth + 1)?;
            }
        } else if matches!(
            reference.media_type.as_str(),
            "application/vnd.crucible.reference-consumption-relation+json"
                | "application/vnd.crucible.reference-lineage-stage+json"
                | "application/vnd.crucible.reference-lineage-native-receipt+json"
        ) {
            return Err(ProviderError::Correlation(
                "foreign lineage nonleaf has no authenticated original dependency row",
            ));
        } else if reference.media_type == "application/json" {
            // Other roots are the existing retained CNP control records. The
            // selected byte lane stays application/octet-stream, so payload
            // contents cannot be mistaken for control dependency objects.
            self.value(&canonical::parse_json(bytes, 16 * 1024 * 1024)?, depth + 1)?;
        }
        self.output.push(reference.clone());
        Ok(())
    }
}
