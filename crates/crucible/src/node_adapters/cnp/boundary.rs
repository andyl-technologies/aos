//! Immutable original public proof bodies retained after native semantic validation.

use crucible_node_contract::ContentRef;

use super::{
    control::CnpControlledReference,
    readiness::{refused, unknown},
};
use crate::{
    node_contract::{InputProvenanceLimits, OperationFailure, WorldActivation},
    node_scheduling::InputPayload,
};

impl CnpControlledReference {
    pub(super) fn retain_boundary_record(
        &mut self,
        reference: &ContentRef,
        mut dependencies: Vec<ContentRef>,
    ) -> Result<(), OperationFailure> {
        dependencies.sort();
        dependencies.dedup();
        let bytes = self
            .controller()
            .map_err(unknown)?
            .content(reference)
            .map_err(unknown)?;
        let object = InputPayload {
            reference: reference.clone(),
            bytes: bytes.to_vec(),
        };
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| unknown(error.into()))?;
        if let Some(old) = self.boundary_evidence.get(reference) {
            if old != &object || self.boundary_dependencies.get(reference) != Some(&dependencies) {
                return Err(refused("original public boundary proof changed"));
            }
            return Ok(());
        }
        let total = self
            .boundary_evidence
            .values()
            .try_fold(object.bytes.len(), |size, object| {
                size.checked_add(object.bytes.len())
            });
        if self.boundary_evidence.len() >= 4096 || total.is_none_or(|size| size > 16 * 1024 * 1024)
        {
            return Err(refused(
                "retained public boundary evidence exceeds finite custody",
            ));
        }
        self.boundary_evidence.insert(reference.clone(), object);
        self.boundary_dependencies
            .insert(reference.clone(), dependencies);
        Ok(())
    }

    pub(super) fn retain_inherited_boundary_record(
        &mut self,
        reference: &ContentRef,
    ) -> Result<(), OperationFailure> {
        if let Some(original) = self.boundary_evidence.get(reference) {
            if self
                .controller()
                .map_err(unknown)?
                .content(reference)
                .map_err(unknown)?
                != original.bytes
            {
                return Err(refused("inherited original public proof bytes changed"));
            }
            return Ok(());
        }
        self.retain_boundary_record(reference, Vec::new())?;
        // Exact runtime-authenticated bytes are retained, but a consumer may
        // not infer that another producer's codec has no dependencies.
        self.boundary_dependencies.remove(reference);
        Ok(())
    }

    fn validate_evidence_world(
        &self,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        if self
            .prepared
            .as_ref()
            .is_none_or(|prepared| prepared.record != *activation.record())
            || self
                .active
                .as_ref()
                .is_some_and(|active| active != activation.record())
        {
            return Err(refused(
                "public boundary evidence belongs to another native world",
            ));
        }
        Ok(())
    }

    pub(super) fn read_public_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.validate_evidence_world(activation)?;
        let mut total = 0usize;
        let mut objects = Vec::new();
        for reference in references {
            let object = self.boundary_evidence.get(reference).ok_or_else(|| {
                refused("public boundary proof lacks original validated native custody")
            })?;
            total = total
                .checked_add(object.bytes.len())
                .filter(|size| *size <= maximum_bytes)
                .ok_or_else(|| refused("public boundary evidence byte ceiling"))?;
            objects.push(object.clone());
        }
        Ok(objects)
    }

    pub(super) fn validate_public_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        self.validate_evidence_world(activation)?;
        if references.len() != objects.len()
            || references
                .iter()
                .zip(objects)
                .any(|(reference, object)| self.boundary_evidence.get(reference) != Some(object))
        {
            return Err(refused(
                "public boundary proof bytes changed original custody",
            ));
        }
        Ok(())
    }

    pub(super) fn public_provenance_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.validate_evidence_world(activation)?;
        let mut visited = std::collections::BTreeSet::new();
        let mut pending = vec![root.clone()];
        let mut total = 0usize;
        while let Some(reference) = pending.pop() {
            if !visited.insert(reference.clone()) {
                continue;
            }
            let object = self
                .boundary_evidence
                .get(&reference)
                .ok_or_else(|| refused("public proof lacks original registered body"))?;
            total = total
                .checked_add(object.bytes.len())
                .filter(|size| *size <= limits.maximum_bytes)
                .ok_or_else(|| refused("public provenance byte ceiling"))?;
            if visited.len() > limits.maximum_objects {
                return Err(refused("public provenance object ceiling"));
            }
            let dependencies = self.boundary_dependencies.get(&reference).ok_or_else(|| {
                refused("inherited producer codec dependency inventory is unavailable")
            })?;
            pending.extend(dependencies.iter().cloned());
        }
        visited.remove(root);
        Ok(visited.into_iter().collect())
    }
}
