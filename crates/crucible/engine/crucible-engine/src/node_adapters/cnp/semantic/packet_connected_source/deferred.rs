//! Authenticates publication of a reaction completed by an earlier original grant.
//!
//! The two records remain bound to the same child and controller journal. The
//! earlier reaction must retain this exact pending publication, and its native
//! retirement must precede the emitting grant. This does not widen either grant.

use super::*;
use crucible_node_transport::reference_packet::connected::PacketConnectedGrant;

impl PacketConnectedSemanticSource {
    pub(super) fn deferred_publication(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        prior: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        self.guard(&scope)?;
        let answer = (|| {
            if !original.activation().same_authority(prior.activation())
                || original.token().route() != prior.token().route()
                || original.token().operation() == prior.token().operation()
            {
                return Err(refused("connected deferred original authority changed"));
            }
            let root = self.operation_root(&scope, original)?;
            let prior_root = self.operation_root(&scope, prior)?;
            if self.mapped_outcome(&scope, original, &root)? != *outcome
                || self.mapped_outcome(&scope, prior, &prior_root)? != *prior_outcome
            {
                return Err(refused("connected deferred original outcome changed"));
            }
            let current = self.native_record(&scope, &root)?;
            let previous = self.native_record(&scope, &prior_root)?;
            if previous.original.sequence >= current.original.sequence
                || previous.native_pid != current.native_pid
            {
                return Err(refused("connected deferred native source order changed"));
            }
            let grant = current
                .grant
                .as_ref()
                .ok_or_else(|| refused("connected emitting native grant absent"))?;
            let earlier = previous
                .grant
                .as_ref()
                .ok_or_else(|| refused("connected earlier native grant absent"))?;
            let output = self
                .definition
                .output
                .as_ref()
                .ok_or_else(|| refused("connected sink cannot defer a publication"))?;
            validate_pending_publication(grant, earlier, output, publication)?;

            let begin_id = previous
                .original
                .request_id
                .0
                .as_ref()
                .ok_or_else(|| refused("connected prior original request absent"))?;
            let expected =
                self.consumption(scope, prior, prior_outcome, &prior_outcome.retained_outputs)?;
            let mut retirement = None;
            for row in controller_originals(scope.controller) {
                if row.request.method != Method::Retire
                    || row.request.sequence <= previous.original.sequence
                    || row.request.sequence >= current.original.sequence
                {
                    continue;
                }
                let RequestBody::Retire(request) =
                    decode_request(row.request.method, &row.request.body).map_err(unknown)?
                else {
                    continue;
                };
                if request.operation_ids.as_slice()
                    != std::slice::from_ref(prior.token().operation())
                {
                    continue;
                }
                if retirement.is_some() {
                    return Err(refused("connected original retirement repeated"));
                }
                let response = row
                    .response
                    .as_ref()
                    .ok_or_else(|| refused("connected earlier retirement unsettled"))?;
                let decoded =
                    decode_response(&RequestBody::Retire(request.clone()), &response.body)
                        .map_err(unknown)?;
                let Some(MethodResult::Retire(result)) = decoded.result else {
                    return Err(refused("connected earlier retirement refused"));
                };
                if result.retired_operation_ids != request.operation_ids
                    || result.retired_request_ids != request.request_ids
                    || request.request_ids.as_slice() != std::slice::from_ref(begin_id)
                    || request.disposition != RetirementDisposition::Consumed
                    || !request.extensions.is_empty()
                    || request.custody_receipt.0.as_ref() != Some(&expected.reference)
                    || scope
                        .controller
                        .content(&expected.reference)
                        .map_err(unknown)?
                        != expected.bytes
                {
                    return Err(refused("connected deferred original consumption changed"));
                }
                retirement = Some(());
            }
            retirement.ok_or_else(|| refused("connected earlier original retirement absent"))
        })();
        self.guard(&scope)?;
        answer
    }
}

// Native records and their complete outcomes are authenticated by the caller.
// This conjunction joins the unchanged typed pending/output tuples and windows.
fn validate_pending_publication(
    current: &PacketConnectedGrant,
    prior: &PacketConnectedGrant,
    output: &Endpoint,
    publication: &NativePublication,
) -> Result<(), OperationFailure> {
    let row = current
        .newborn
        .iter()
        .find(|row| row.output.event == publication.publication_id)
        .ok_or_else(|| refused("connected deferred newborn publication absent"))?;
    let pending = &row.pending;
    let evaluation = pending.reaction.evaluation;
    let payload = canonical::content_ref(row.output.payload.as_slice(), "application/octet-stream")
        .map_err(unknown)?;
    if !current.complete
        || !prior.complete
        || current.operation == prior.operation
        || current.inventory.reached != current.limit
        || prior.inventory.reached != prior.limit
        || prior.limit > current.start
        || evaluation < prior.start
        || evaluation >= prior.limit
        || evaluation >= current.start
        || evaluation.phase != Phase::Reaction
        || pending.reaction_operation != prior.operation
        || !prior.inventory.publications.contains(pending)
        || prior.newborn.iter().any(|row| row.pending == *pending)
        || pending.publication
            != evaluation
                .reaction_publication(U64::new(16))
                .map_err(unknown)?
        || pending.publication < current.start
        || pending.publication >= current.limit
        || row.output.event != pending.event
        || row.output.payload != pending.reaction.payload
        || row.output.evaluation != evaluation
        || row.output.publication != pending.publication
        || publication.endpoint != *output
        || publication.native_sequence != row.output.sequence
        || publication.evaluation != Some(evaluation)
        || publication.publication != pending.publication
        || publication.causal_parents.as_slice() != std::slice::from_ref(&pending.reaction.parent)
        || publication.payload != payload
        || publication.payload_bytes != row.output.payload.as_slice()
    {
        return Err(refused("connected deferred pending publication changed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "deferred/tests.rs"]
mod tests;
