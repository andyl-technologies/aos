//! Authenticates full original input and publication dependency rows.
//!
//! Native records retain actual Stage and consumed Commit separately. These
//! source-owned direct rows also retain the same opaque producer lineage saved
//! before Stage. Host projection bytes never substitute native execution seals.

use super::super::packet_lineage::{self, Rows};
use super::*;

impl PacketConnectedSemanticSource {
    fn stage_rows(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
        rows: &mut Rows,
    ) -> Result<(), OperationFailure> {
        let record = self.stage_record(scope, root)?;
        let retained = self
            .input_lineage
            .try_borrow()
            .map_err(|_| refused("connected original producer lineage busy"))?;
        let lineage = retained
            .iter()
            .find(|row| row.original().stage_operation() == &record.cut.stage_operation_id)
            .ok_or_else(|| refused("connected original staged producer lineage absent"))?;
        let RequestBody::Input(request) =
            decode_request(record.original.method, &record.original.body).map_err(unknown)?
        else {
            return Err(refused("connected stage original Input absent"));
        };
        if self.original_cut(lineage.original(), &request)? != record.cut {
            return Err(refused(
                "connected stage changed retained opaque producer cut",
            ));
        }
        let mut inventory_dependencies = Vec::new();
        let mut dependencies = vec![record.cut.delivery_inventory.clone()];
        for claim in lineage.publications() {
            rows.claim(claim)?;
            if !self.world.is_complete() {
                inventory_dependencies.push(claim.origin.measurement.clone());
            }
            dependencies.push(claim.published.clone());
        }
        for (event, bytes) in record.batch.events.iter().zip(&record.payloads) {
            rows.add(&event.payload, bytes.as_slice(), Vec::new())?;
            if !self.world.is_complete() {
                inventory_dependencies.push(event.payload.clone());
            }
        }
        if self.world.is_complete() {
            self.add_complete_input_static_rows(rows)?;
            for delivery in lineage.original().deliveries() {
                inventory_dependencies.push(delivery.payload.clone());
                inventory_dependencies.push(delivery.provenance_ref.clone());
                inventory_dependencies.push(
                    delivery
                        .connection_policy_ref
                        .as_ref()
                        .ok_or_else(|| refused("complete original delivery policy absent"))?
                        .clone(),
                );
            }
        }
        rows.add(
            &record.cut.delivery_inventory,
            scope
                .controller
                .content(&record.cut.delivery_inventory)
                .map_err(unknown)?,
            inventory_dependencies,
        )?;
        rows.add(
            root,
            scope.controller.content(root).map_err(unknown)?,
            dependencies,
        )
    }

    fn commit_rows(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
        rows: &mut Rows,
    ) -> Result<(), OperationFailure> {
        let record = self.commit_record(scope, root)?;
        self.stage_rows(scope, &record.staged_record, rows)?;
        let receipt: ControlReceipt = self.object(scope, &record.staging_receipt)?;
        let custody: InputCustodyRecord = self.object(scope, &receipt.record_ref)?;
        // commit_record already authenticates the original Stage response;
        // these rows retain both full response bodies and its actual proof edge.
        if custody.evidence_refs.as_slice() != std::slice::from_ref(&record.staged_record) {
            return Err(refused(
                "connected original staging receipt dependency changed",
            ));
        }
        rows.add(
            &receipt.record_ref,
            scope
                .controller
                .content(&receipt.record_ref)
                .map_err(unknown)?,
            vec![record.staged_record.clone()],
        )?;
        rows.add(
            &record.staging_receipt,
            scope
                .controller
                .content(&record.staging_receipt)
                .map_err(unknown)?,
            vec![receipt.record_ref],
        )?;
        rows.add(
            root,
            scope.controller.content(root).map_err(unknown)?,
            vec![record.staged_record, record.staging_receipt],
        )
    }

    pub(super) fn publication_claim(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.guard(&scope)?;
        let answer = (|| {
            let root = self.operation_root(&scope, original)?;
            if self.mapped_outcome(&scope, original, &root)? != *outcome {
                return Err(refused(
                    "connected original publication complete outcome changed",
                ));
            }
            let record = self.native_record(&scope, &root)?;
            let mut rows = Rows::new(limits)?;
            let mut dependencies = Vec::new();
            for stage in &record.inventory.stages {
                self.stage_rows(&scope, stage, &mut rows)?;
                dependencies.push(stage.clone());
            }
            for commit in &record.inventory.commits {
                self.commit_rows(&scope, commit, &mut rows)?;
                dependencies.push(commit.clone());
            }
            for row in &record.inventory.retained_outputs {
                let output = &row.output;
                let payload =
                    canonical::content_ref(output.payload.as_slice(), "application/octet-stream")
                        .map_err(unknown)?;
                rows.add(&payload, output.payload.as_slice(), Vec::new())?;
                dependencies.push(payload);
            }
            if self.world.is_complete() {
                let wrapper:crucible_node_transport::reference_packet::control::PacketNative5Record=serde_json::from_value(
                    canonical::parse_json(scope.controller.content(&root).map_err(unknown)?,65_536).map_err(unknown)?).map_err(unknown)?;
                // The complete native_record check above authenticated the
                // exact wrapper/raw association under this original source.
                rows.add(
                    &wrapper.native_record,
                    scope
                        .controller
                        .content(&wrapper.native_record)
                        .map_err(unknown)?,
                    dependencies,
                )?;
                rows.add(
                    &root,
                    scope.controller.content(&root).map_err(unknown)?,
                    vec![wrapper.native_record],
                )?;
            } else {
                rows.add(
                    &root,
                    scope.controller.content(&root).map_err(unknown)?,
                    dependencies,
                )?;
            }
            packet_lineage::claim(
                &self.installation,
                original,
                outcome,
                publication,
                &root,
                if self.world.is_complete() { 5 } else { 4 },
                rows,
            )
        })();
        self.guard(&scope)?;
        answer
    }

    pub(super) fn input_evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalInputEvidence, OperationFailure> {
        self.guard(&scope)?;
        let answer = (|| {
            let batch = original
                .inputs()
                .ok_or_else(|| refused("connected original operation input absent"))?;
            if !super::lineage::same_batch(batch, staged.batch()) || !staged.committed() {
                return Err(refused(
                    "connected original Stage/Commit runtime association changed",
                ));
            }
            let completed_lineage = staged
                .lineage()
                .ok_or_else(|| refused("connected completion original lineage absent"))?;
            let retained = self
                .input_lineage
                .try_borrow()
                .map_err(|_| refused("connected original lineage busy"))?;
            let issued = retained
                .iter()
                .find(|row| row.original().stage_operation() == batch.stage_operation())
                .ok_or_else(|| refused("connected original Stage lineage absent"))?;
            if !super::lineage::same_batch(issued.original(), completed_lineage.original())
                || issued.publications() != completed_lineage.publications()
            {
                return Err(refused("connected completed opaque Stage lineage changed"));
            }
            drop(retained);
            let commit = staged
                .coordinator_commit()
                .ok_or_else(|| refused("connected original coordinator commit absent"))?;
            self.commitment(batch, commit)?;
            let operation_root = self.operation_root(&scope, original)?;
            let native = self.native_record(&scope, &operation_root)?;
            let (_, consumed) =
                self.original_commit(&scope, batch, Some(native.original.sequence))?;
            let root = &staged.acknowledgement().proof_ref;
            let record = self.stage_record(&scope, root)?;
            if consumed.staged_record != *root || consumed.cut != record.cut {
                return Err(refused("connected original consumed native Stage differs"));
            }
            let RequestBody::Input(request) =
                decode_request(record.original.method, &record.original.body).map_err(unknown)?
            else {
                return Err(refused("connected original stage request absent"));
            };
            if record.cut != self.original_cut(batch, &request)? {
                return Err(refused("connected original full Stage input cut changed"));
            }
            // The Stage root does not depend on its later Commit. Actual
            // consumed Commit was authenticated above, through this operation's
            // original sequence, without inventing a future edge in the DAG.
            let mut rows = Rows::new(limits)?;
            self.stage_rows(&scope, root, &mut rows)?;
            let (objects, rows) = rows.finish();
            Ok(OriginalInputEvidence {
                root: root.clone(),
                objects,
                rows,
            })
        })();
        self.guard(&scope)?;
        answer
    }
}

// Byte custody is independent of emission: a complete authenticated native
// inventory also retains pending inputs and publications. Cache presence cannot
// turn their raw payloads into native JSON records or supply source authority.
pub(super) fn original_evidence_bytes<'a>(
    inventory: &'a PacketConnectedInventory,
    reference: &ContentRef,
    stored: Option<&'a [u8]>,
    authenticate_native_record: impl FnOnce() -> Result<(), OperationFailure>,
) -> Result<&'a [u8], OperationFailure> {
    let payloads = inventory
        .reactions
        .iter()
        .map(|row| row.payload.as_slice())
        .chain(
            inventory
                .delivered_inputs
                .iter()
                .map(|row| row.reaction.payload.as_slice()),
        )
        .chain(
            inventory
                .publications
                .iter()
                .map(|row| row.reaction.payload.as_slice()),
        )
        .chain(
            inventory
                .retained_outputs
                .iter()
                .map(|row| row.output.payload.as_slice()),
        );
    for bytes in payloads {
        let original =
            canonical::content_ref(bytes, "application/octet-stream").map_err(unknown)?;
        if &original == reference {
            if stored.is_some_and(|stored| stored != bytes) {
                return Err(refused("connected original payload cache bytes changed"));
            }
            return Ok(bytes);
        }
    }
    let bytes =
        stored.ok_or_else(|| refused("packet requested evidence has no native original body"))?;
    authenticate_native_record()?;
    Ok(bytes)
}

#[cfg(test)]
#[path = "evidence/byte_custody_tests.rs"]
mod byte_custody_tests;
