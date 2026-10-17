//! Bounds the selected staging codec before data copies and checks full direct rows.
//!
//! These decoded records are inert data. Only the caller's authenticated source
//! borrow establishes their origin; geometry or a valid hash grants no authority.

use crucible::{
    node_contract::{OriginalLineageRow, RuntimeError},
    node_scheduling::InputPayload,
};
use crucible_node_contract::ContentRef;
use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use super::{MAXIMUM_EDGES, MAXIMUM_INPUT_OBJECTS, MAXIMUM_SOURCE_BYTES};

// This is a closed inert codec record, not OriginalInputEvidence or a native
// source credential. Its original bytes came from the authenticated source
// getter, and the actual common ACK must still name this same root.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputEvidence {
    pub(super) root: ContentRef,
    pub(super) objects: Vec<InputPayload>,
    pub(super) rows: Vec<OriginalLineageRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceStaging {
    pub(super) schema: String,
    #[serde(rename = "input")]
    _input: IgnoredAny,
    #[serde(rename = "provenance")]
    _provenance: IgnoredAny,
    #[serde(rename = "publications")]
    _publications: IgnoredAny,
    #[serde(rename = "acknowledgement")]
    _acknowledgement: IgnoredAny,
    pub(super) native_evidence: InputEvidence,
    #[serde(rename = "coordinator_commit")]
    _coordinator_commit: IgnoredAny,
    pub(super) committed: bool,
}

pub(super) fn validate_rows(
    root: &ContentRef,
    objects: &[InputPayload],
    rows: &[OriginalLineageRow],
) -> Result<(), RuntimeError> {
    if objects.is_empty()
        || objects.len() > MAXIMUM_INPUT_OBJECTS
        || objects.len() != rows.len()
        || objects
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut bytes = 0usize;
    let mut edges = 0usize;
    for (object, row) in objects.iter().zip(rows) {
        bytes = bytes
            .checked_add(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        edges = edges
            .checked_add(row.dependencies.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > MAXIMUM_SOURCE_BYTES
            || edges > MAXIMUM_EDGES
            || object.reference != row.object
            || row.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || row.dependencies.iter().any(|dependency| {
                objects
                    .binary_search_by(|body| body.reference.cmp(dependency))
                    .is_err()
            })
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        object
            .reference
            .verify(&object.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    let root = objects
        .binary_search_by(|body| body.reference.cmp(root))
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let mut reached = vec![false; objects.len()];
    reached[root] = true;
    for _ in 0..objects.len() {
        let mut changed = false;
        for (index, row) in rows.iter().enumerate() {
            if !reached[index] {
                continue;
            }
            for dependency in &row.dependencies {
                let target = objects
                    .binary_search_by(|body| body.reference.cmp(dependency))
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                changed |= !reached[target];
                reached[target] = true;
            }
        }
        if !changed {
            break;
        }
    }
    if reached.iter().any(|reached| !reached) {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut finished = vec![false; objects.len()];
    for _ in 0..objects.len() {
        let mut changed = false;
        for (index, row) in rows.iter().enumerate() {
            if !finished[index]
                && row.dependencies.iter().all(|dependency| {
                    objects
                        .binary_search_by(|body| body.reference.cmp(dependency))
                        .is_ok_and(|target| finished[target])
                })
            {
                finished[index] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if finished.iter().any(|finished| !finished) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

// A nonretaining pass bounds source object/row/dependency arrays before the
// closed decoder can allocate typed bodies. It does not infer semantic roles.
#[derive(Clone, Copy)]
enum Scope {
    Document,
    Native,
    Objects,
    Object,
    Rows,
    Row,
    Edges,
    Bytes,
    Other,
}

struct Scan {
    tokens: usize,
    edges: usize,
}

struct Seed<'a> {
    scan: &'a mut Scan,
    scope: Scope,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.depth > 64 || self.scan.tokens == 0 {
            return Err(serde::de::Error::custom("source staging geometry exceeded"));
        }
        self.scan.tokens -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("bounded source staging JSON")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let (maximum, item) = match self.scope {
            Scope::Objects => (MAXIMUM_INPUT_OBJECTS, Scope::Object),
            Scope::Rows => (MAXIMUM_INPUT_OBJECTS, Scope::Row),
            Scope::Edges => (MAXIMUM_EDGES, Scope::Other),
            Scope::Bytes => (MAXIMUM_SOURCE_BYTES, Scope::Other),
            _ => (MAXIMUM_SOURCE_BYTES, Scope::Other),
        };
        let mut count = 0usize;
        while let Some(()) = sequence.next_element_seed(Seed {
            scan: self.scan,
            scope: item,
            depth: self.depth + 1,
        })? {
            count += 1;
            if count > maximum {
                return Err(serde::de::Error::custom("source staging array exceeded"));
            }
            if matches!(self.scope, Scope::Edges) {
                self.scan.edges += 1;
                if self.scan.edges > MAXIMUM_EDGES {
                    return Err(serde::de::Error::custom(
                        "source staging direct-edge ceiling",
                    ));
                }
            }
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 4096 {
                return Err(serde::de::Error::custom("source staging key exceeded"));
            }
            let scope = match (self.scope, key.as_str()) {
                (Scope::Document, "native_evidence") => Scope::Native,
                (Scope::Native, "objects") => Scope::Objects,
                (Scope::Native, "rows") => Scope::Rows,
                (Scope::Row, "dependencies") => Scope::Edges,
                (_, "bytes") => Scope::Bytes,
                _ => Scope::Other,
            };
            map.next_value_seed(Seed {
                scan: self.scan,
                scope,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

pub(super) fn parse_staging(bytes: &[u8]) -> Result<SourceStaging, RuntimeError> {
    if bytes.len() > MAXIMUM_SOURCE_BYTES {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut scan = Scan {
        tokens: bytes.len(),
        edges: 0,
    };
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    Seed {
        scan: &mut scan,
        scope: Scope::Document,
        depth: 0,
    }
    .deserialize(&mut parser)
    .map_err(|_| RuntimeError::ResourceLimit)?;
    parser.end().map_err(|_| RuntimeError::InvalidReceipt)?;
    serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidReceipt)
}

#[cfg(test)]
#[path = "geometry_tests.rs"]
mod tests;
