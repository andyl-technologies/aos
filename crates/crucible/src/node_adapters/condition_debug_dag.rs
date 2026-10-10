//! Bounded original condition evidence with one body per content identity.
//!
//! This selected codec retains actual immutable bytes and explicit dependency
//! edges. Decoding verifies the entire reachable closure; it grants no native
//! custody or current-world authority. Existing host continuation editions do
//! not use this grammar.
//!
//! ```text
//! {"format":"crucible.host-condition-dag","version":1,
//!  "roots":[{"hash":...,"media_type":...,"size_bytes":...}],
//!  "objects":[{"reference":...,"bytes":"...","dependencies":[]}]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, ContentRef, canonical};
use serde::{Deserialize, Serialize};

use super::refuse;
use crate::node_contract::OperationFailure;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_adapters) struct Object {
    pub(in crate::node_adapters) reference: ContentRef,
    pub(in crate::node_adapters) bytes: Bytes,
    pub(in crate::node_adapters) dependencies: Vec<ContentRef>,
}

#[cfg(test)]
#[path = "condition_debug_dag_tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    version: u16,
    roots: Vec<ContentRef>,
    objects: Vec<Object>,
}

/// Retains deduplicated source bytes under absolute object and byte ceilings.
#[derive(Clone, Debug)]
pub(in crate::node_adapters) struct EvidenceDag {
    objects: BTreeMap<ContentRef, Object>,
    maximum_objects: usize,
    maximum_bytes: usize,
    body_bytes: usize,
}

impl EvidenceDag {
    pub(in crate::node_adapters) fn new(maximum_objects: usize, maximum_bytes: usize) -> Self {
        Self {
            objects: BTreeMap::new(),
            maximum_objects,
            maximum_bytes,
            body_bytes: 0,
        }
    }

    pub(in crate::node_adapters) fn insert(
        &mut self,
        reference: ContentRef,
        bytes: &[u8],
        mut dependencies: Vec<ContentRef>,
    ) -> Result<(), OperationFailure> {
        reference
            .verify(bytes)
            .map_err(|error| refuse(&error.to_string()))?;
        dependencies.sort();
        if dependencies.windows(2).any(|pair| pair[0] == pair[1])
            || dependencies.contains(&reference)
            || dependencies.len() > self.maximum_objects
        {
            return Err(refuse("condition DAG dependency inventory refused"));
        }
        if let Some(original) = self.objects.get(&reference) {
            return if original.bytes.as_slice() == bytes && original.dependencies == dependencies {
                Ok(())
            } else {
                Err(refuse("condition DAG original content association changed"))
            };
        }
        if self
            .objects
            .keys()
            .any(|known| known.hash == reference.hash)
        {
            return Err(refuse(
                "condition DAG content metadata aliases an original hash",
            ));
        }
        let size = self
            .body_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| refuse("condition DAG body size overflow"))?;
        if self.objects.len() >= self.maximum_objects || size > self.maximum_bytes {
            return Err(refuse("condition DAG original object credit exhausted"));
        }

        // Credit is checked before copying source-owned bytes. No reference
        // without its actual body can be installed through this method.
        self.objects.insert(
            reference.clone(),
            Object {
                reference,
                bytes: Bytes::new(bytes.to_vec()),
                dependencies,
            },
        );
        self.body_bytes = size;
        Ok(())
    }

    pub(in crate::node_adapters) fn add(
        &mut self,
        bytes: &[u8],
        media_type: &str,
        dependencies: Vec<ContentRef>,
    ) -> Result<ContentRef, OperationFailure> {
        let reference = canonical::content_ref(bytes, media_type)
            .map_err(|error| refuse(&error.to_string()))?;
        self.insert(reference.clone(), bytes, dependencies)?;
        Ok(reference)
    }

    pub(in crate::node_adapters) fn body(
        &self,
        reference: &ContentRef,
    ) -> Result<&[u8], OperationFailure> {
        self.objects
            .get(reference)
            .map(|object| object.bytes.as_slice())
            .ok_or_else(|| refuse("condition DAG original dependency body omitted"))
    }

    pub(in crate::node_adapters) fn objects(&self) -> impl Iterator<Item = &Object> {
        self.objects.values()
    }

    pub(in crate::node_adapters) fn closure(
        &self,
        root: &ContentRef,
    ) -> Result<Vec<&Object>, OperationFailure> {
        self.closure_with_limit(root, self.maximum_objects)
    }

    pub(in crate::node_adapters) fn closure_with_limit(
        &self,
        root: &ContentRef,
        maximum_entries: usize,
    ) -> Result<Vec<&Object>, OperationFailure> {
        let mut references = BTreeSet::new();
        let mut pending = BTreeSet::from([root]);
        if maximum_entries == 0 {
            return Err(refuse(
                "condition expanded dependency entry credit exhausted",
            ));
        }
        while let Some(reference) = pending.pop_first() {
            references.insert(reference);
            let object = self
                .objects
                .get(reference)
                .ok_or_else(|| refuse("condition DAG original source closure omitted"))?;
            for dependency in &object.dependencies {
                if !references.contains(dependency) {
                    pending.insert(dependency);
                    if pending
                        .len()
                        .checked_add(references.len())
                        .ok_or_else(|| refuse("condition expanded dependency count overflow"))?
                        > maximum_entries
                    {
                        return Err(refuse(
                            "condition expanded dependency entry credit exhausted",
                        ));
                    }
                }
            }
        }
        references
            .into_iter()
            .map(|reference| {
                self.objects
                    .get(reference)
                    .ok_or_else(|| refuse("condition DAG original source closure omitted"))
            })
            .collect()
    }

    pub(in crate::node_adapters) fn encode(
        &self,
        mut roots: Vec<ContentRef>,
    ) -> Result<Vec<u8>, OperationFailure> {
        roots.sort();
        self.validate(&roots)?;
        let wire = Wire {
            format: "crucible.host-condition-dag".into(),
            version: 1,
            roots,
            objects: self.objects.values().cloned().collect(),
        };
        let bytes = canonical::canonical_json(
            &serde_json::to_value(wire).map_err(|error| refuse(&error.to_string()))?,
        )
        .map_err(|error| refuse(&error.to_string()))?;
        if bytes.len() > self.maximum_bytes {
            return Err(refuse("condition DAG complete encoding credit exhausted"));
        }
        Ok(bytes)
    }

    pub(in crate::node_adapters) fn decode(
        bytes: &[u8],
        maximum_objects: usize,
        maximum_bytes: usize,
    ) -> Result<(Self, Vec<ContentRef>), OperationFailure> {
        if bytes.len() > maximum_bytes {
            return Err(refuse("condition DAG complete encoding credit exhausted"));
        }
        let wire: Wire =
            serde_json::from_slice(bytes).map_err(|error| refuse(&error.to_string()))?;
        if wire.format != "crucible.host-condition-dag"
            || wire.version != 1
            || wire.objects.len() > maximum_objects
            || wire
                .objects
                .windows(2)
                .any(|pair| pair[0].reference >= pair[1].reference)
            || wire.objects.iter().any(|object| {
                object
                    .dependencies
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            })
        {
            return Err(refuse("condition DAG selected grammar changed"));
        }
        let mut store = Self::new(maximum_objects, maximum_bytes);
        for object in wire.objects {
            store.insert(
                object.reference,
                object.bytes.as_slice(),
                object.dependencies,
            )?;
        }
        store.validate(&wire.roots)?;
        if store.encode(wire.roots.clone())? != bytes {
            return Err(refuse("condition DAG original canonical bytes changed"));
        }
        Ok((store, wire.roots))
    }

    fn validate(&self, roots: &[ContentRef]) -> Result<(), OperationFailure> {
        if roots.is_empty()
            || roots.len() > self.maximum_objects
            || roots.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(refuse("condition DAG original root inventory refused"));
        }
        let mut complete = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut stack: Vec<_> = roots.iter().map(|root| (root, false)).collect();
        while let Some((reference, leave)) = stack.pop() {
            if leave {
                active.remove(reference);
                complete.insert(reference);
                continue;
            }
            if complete.contains(reference) {
                continue;
            }
            if !active.insert(reference) {
                return Err(refuse(
                    "condition DAG original dependencies contain a cycle",
                ));
            }
            let object = self
                .objects
                .get(reference)
                .ok_or_else(|| refuse("condition DAG reachable original body omitted"))?;
            stack.push((reference, true));
            stack.extend(
                object
                    .dependencies
                    .iter()
                    .rev()
                    .map(|dependency| (dependency, false)),
            );
        }
        if complete.len() != self.objects.len() {
            return Err(refuse("condition DAG contains unbound original evidence"));
        }
        Ok(())
    }
}
