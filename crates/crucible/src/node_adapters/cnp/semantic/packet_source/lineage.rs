//! Validates inert publication projections against the original source-two grant.

use super::super::packet_lineage::{self, Rows};
use super::*;

impl PacketSemanticSource {
    pub(super) fn publication_claim(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.authenticate_provider(scope.native)?;
        let answer = (|| {
            if !std::ptr::eq(scope.installation, &self.installation)
                || scope
                    .native
                    .controller()
                    .is_none_or(|controller| !std::ptr::eq(controller, scope.controller))
                || !publication.causal_parents.is_empty()
            {
                return Err(refused(
                    "packet source-two foreign original publication scope",
                ));
            }
            let root = self.operation_root(&scope, original)?;
            if self.mapped_outcome(&scope, original, &root)? != *outcome {
                return Err(refused(
                    "packet original publication complete outcome changed",
                ));
            }
            let record = self.native_record(&scope, &root)?;
            let mut rows = Rows::new(limits)?;
            let mut dependencies = Vec::new();
            for output in &record.inventory.retained_outputs {
                let reference =
                    canonical::content_ref(output.payload.as_slice(), "application/octet-stream")
                        .map_err(unknown)?;
                rows.add(&reference, output.payload.as_slice(), Vec::new())?;
                dependencies.push(reference);
            }
            // The full source record and original grant remain present after
            // output ACK; no regenerated observation can replace this root.
            rows.add(
                &root,
                scope.controller.content(&root).map_err(unknown)?,
                dependencies,
            )?;
            packet_lineage::claim(
                &self.installation,
                original,
                outcome,
                publication,
                &root,
                2,
                rows,
            )
        })();
        self.authenticate_provider(scope.native)?;
        answer
    }
}
