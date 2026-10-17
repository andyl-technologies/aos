//! Defines reference-only historical lineage records for a selected Runtime7 codec.
//!
//! These records contain no authority. Original bytes belong to the authenticated
//! typed world inventory; neither parsing nor reference geometry issues a live
//! input view. Existing capture paths remain unsupported for retained lineage.

use super::*;
use serde::{Deserialize, Serialize};

/// Retains the first runtime seal independently of fresh current input authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedOriginalInputScope {
    /// Preserves the original consumer world activation as historical data.
    pub source_activation: SavedRuntimeActivation,
    /// Names the original logical consumer.
    pub node: Id,
    /// Preserves the original native staging permission identity.
    pub stage_operation: Id,
    /// Preserves the original frozen batch identity.
    pub batch: Id,
    /// Preserves the original consumer incarnation roster without relabeling it.
    pub owners: Vec<OwnerIdentity>,
    /// Preserves the original exclusive input cut.
    pub cutoff: Position,
    /// Binds the original ordered delivery inventory.
    pub inventory: ContentRef,
}

impl SavedOriginalInputScope {
    pub(super) fn from_batch(batch: &RuntimeInputBatch) -> Self {
        Self {
            source_activation: batch.activation().record().into(),
            node: batch.node().clone(),
            stage_operation: batch.stage_operation().clone(),
            batch: batch.batch().clone(),
            owners: batch.owners().to_vec(),
            cutoff: batch.cutoff(),
            inventory: batch.inventory().clone(),
        }
    }
}

/// Preserves one ordered publication's original scope and exact typed body roles.
///
/// The Event bytes are the unchanged standalone `published` role. Large bodies
/// are stored separately, avoiding JSON byte arrays in the runtime envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedOriginalPublication {
    /// Retains the actual original producer/window scope.
    pub origin: OriginalPublicationOrigin,
    /// Names the exact original standalone Event body, including native FIFO.
    pub published: ContentRef,
    /// Lists complete original roles in strict full-reference order.
    pub objects: Vec<ContentRef>,
    /// Retains direct codec rows; missing rows never denote authenticated leaves.
    pub rows: Vec<OriginalLineageRow>,
}

impl SavedOriginalPublication {
    /// Checks historical geometry and bodies without authenticating their source.
    pub(crate) fn validate_recorded_bodies<'a>(
        &self,
        limits: OriginalInputLineageLimits,
        mut body: impl FnMut(&ContentRef) -> Option<&'a [u8]>,
    ) -> Result<usize, RuntimeError> {
        if self.objects.len() != self.rows.len()
            || self.objects.windows(2).any(|pair| pair[0] >= pair[1])
            || self.objects.len() > limits.maximum_objects
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let mut bytes = 0usize;
        for (reference, row) in self.objects.iter().zip(&self.rows) {
            let original = body(reference).ok_or(RuntimeError::InvalidReceipt)?;
            bytes = bytes
                .checked_add(original.len())
                .filter(|bytes| *bytes <= limits.maximum_bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            if reference != &row.object || reference.verify(original).is_err() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        geometry::validate_reference_rows(
            &self.rows,
            [
                &self.published,
                &self.origin.observation_batch,
                &self.origin.stop_receipt,
                &self.origin.measurement,
            ],
            limits,
        )
    }
}

/// Preserves ordered input ancestry as data without serializing the runtime seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedOriginalInputLineage {
    /// Selects the explicit reference-only lineage record edition.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Preserves the first original input scope through later fresh generations.
    pub source: SavedOriginalInputScope,
    /// Preserves one original publication per ordered delivery occurrence.
    pub publications: Vec<SavedOriginalPublication>,
}

impl OriginalInputLineage {
    /// Borrows immutable first-sealed scope independently of current authority.
    pub fn source_scope(&self) -> &SavedOriginalInputScope {
        &self.data.source_scope
    }

    /// Exports reference-only historical data after aggregate credit checks.
    ///
    /// The result cannot construct another runtime seal or authorize capture.
    /// A selected archive codec must retain and authenticate every original body
    /// and obtain genuine fresh producer/consumer native continuation evidence.
    ///
    /// # Errors
    /// Refuses aggregate role, byte or edge excess and allocation failure.
    pub fn saved_reference_view(
        &self,
        limits: OriginalInputLineageLimits,
    ) -> Result<SavedOriginalInputLineage, RuntimeError> {
        let mut available = limits;
        for claim in self.publications() {
            let derived = geometry::validate_claim_geometry(claim, available)?;
            available.maximum_objects = available
                .maximum_objects
                .checked_sub(claim.objects.len())
                .ok_or(RuntimeError::ResourceLimit)?;
            for object in &claim.objects {
                available.maximum_bytes = available
                    .maximum_bytes
                    .checked_sub(object.bytes.len())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            let direct = claim.rows.iter().try_fold(0usize, |total, row| {
                total
                    .checked_add(row.dependencies.len())
                    .ok_or(RuntimeError::ResourceLimit)
            })?;
            available.maximum_edges = available
                .maximum_edges
                .checked_sub(direct.max(derived))
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let mut publications = reserved(self.publications().len())?;
        for claim in self.publications() {
            let mut objects = reserved(claim.objects.len())?;
            objects.extend(claim.objects.iter().map(|object| object.reference.clone()));
            let mut rows = reserved(claim.rows.len())?;
            for row in &claim.rows {
                let mut dependencies = reserved(row.dependencies.len())?;
                dependencies.extend(row.dependencies.iter().cloned());
                rows.push(OriginalLineageRow {
                    object: row.object.clone(),
                    dependencies,
                });
            }
            publications.push(SavedOriginalPublication {
                origin: claim.origin.clone(),
                published: claim.published.clone(),
                objects,
                rows,
            });
        }
        Ok(SavedOriginalInputLineage {
            schema_version: 1,
            source: self.source_scope().clone(),
            publications,
        })
    }
}

fn reserved<T>(count: usize) -> Result<Vec<T>, RuntimeError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(result)
}
