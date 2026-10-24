//! One-shot source consumption of the coordinator's original staged input cut.
//!
//! A retained staging ACK only authenticates custody. This module holds the
//! distinct opaque later commitment and its single original native request.
//! Pending dispatch is never replaced, and source validation precedes a grant.

use std::rc::Rc;

use crucible_node_transport::{bodies::MethodResult, envelope::Method};

use crate::{node_contract::OperationFailure, node_scheduling::InputCustodyCommit};

use super::super::{
    CnpSemanticNode, after_effect,
    preparation::request_id,
    refused,
    state::{OriginalInput, OriginalInputCommit},
    unknown,
};

impl CnpSemanticNode {
    fn original_input_commit(
        &self,
        commit: &InputCustodyCommit,
    ) -> Result<&OriginalInput, OperationFailure> {
        let staged = self
            .state()?
            .inputs
            .get(commit.stage_operation())
            .ok_or_else(|| refused("generic consumed commitment has no original stage"))?;
        let batch = &staged.original;
        if !batch.activation().same_authority(commit.activation())
            || batch.activation().record() != commit.activation().record()
            || batch.node() != commit.node()
            || batch.node() != &self.route.node
            || batch.owners() != self.route.owners
            || batch.stage_operation() != commit.stage_operation()
            || batch.batch() != commit.batch()
            || batch.inventory() != commit.inventory()
            || batch.cutoff() != commit.cutoff()
            || staged.acknowledgement.is_none()
            || staged.response.is_none()
        {
            return Err(refused(
                "generic commitment changed original opaque stage authority",
            ));
        }
        if let Some(attempt) = &staged.commitment {
            let original = &attempt.original;
            if !original.activation().same_authority(commit.activation())
                || original.activation().record() != commit.activation().record()
                || original.node() != commit.node()
                || original.stage_operation() != commit.stage_operation()
                || original.batch() != commit.batch()
                || original.inventory() != commit.inventory()
                || original.cutoff() != commit.cutoff()
            {
                return Err(refused(
                    "generic repeated commitment changed original authority",
                ));
            }
        }
        Ok(staged)
    }

    pub(in super::super) fn commit_original_input(
        &mut self,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let staged = self.original_input_commit(commit)?;
        if staged.commitment.is_some() {
            return self.validate_original_input_commit(commit);
        }
        let source = self.source()?;
        let maximum = source.installation().maximum_semantic_bytes;
        let staging = staged
            .response
            .as_ref()
            .ok_or_else(|| refused("generic original staging response absent"))?;
        let (extensions, context) = source.input_commit_context(
            self.scope()?,
            &staged.original,
            commit,
            &staged.request,
            staging,
        )?;
        // A source cannot opt into a bare second staging request. Consumption
        // requires an explicitly negotiated, closed later envelope context.
        if extensions.is_empty() {
            return Err(refused(
                "generic consumption has no negotiated source context",
            ));
        }
        let result_credit = source.installation().maximum_result_bytes;
        // Retain one copy in the semantic attempt and one in its original
        // controller envelope; both extents precede either owned copy.
        self.state_mut()?.credit.reserve(&extensions, maximum)?;
        self.state_mut()?.credit.reserve(&extensions, maximum)?;
        self.state_mut()?.credit.reserve(&context, maximum)?;
        for payload in &context {
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
        }
        self.state_mut()?
            .credit
            .reserve_bytes(result_credit, maximum)?;
        let request_bytes = super::super::budget::serialized_size(
            &self.original_input_commit(commit)?.request,
            maximum,
        )?;
        self.state_mut()?
            .credit
            .reserve_bytes(request_bytes, maximum)?;
        self.state_mut()?.credit.reserve(
            &(
                commit.node(),
                commit.stage_operation(),
                commit.batch(),
                commit.inventory(),
                commit.cutoff(),
            ),
            maximum,
        )?;
        let request = self.original_input_commit(commit)?.request.clone();
        let id = request_id("input-consumed", commit.stage_operation())?;
        self.state_mut()?.credit.reserve(&id, maximum)?;
        let context = Rc::new(context);
        // The complete coordinator authority and Pending row precede uploads,
        // transport and source effects. Every failure keeps this same attempt.
        self.state_mut()?
            .inputs
            .get_mut(commit.stage_operation())
            .ok_or_else(|| unknown("generic original stage disappeared"))?
            .commitment = Some(OriginalInputCommit {
            original: commit.retained_copy(),
            request_id: id.clone(),
            extensions: extensions.clone(),
            context: Rc::clone(&context),
            response: None,
        });
        for payload in context.iter() {
            self.upload(&payload.reference, &payload.bytes)
                .map_err(after_effect)?;
        }
        let response = self
            .call_with_extensions(id, None, Method::Input, true, request, extensions)
            .map_err(after_effect)?;
        let Some(MethodResult::Input(response)) = response.result else {
            return Err(unknown(
                "generic original consumed input remains unresolved",
            ));
        };
        self.state_mut()?
            .inputs
            .get_mut(commit.stage_operation())
            .and_then(|staged| staged.commitment.as_mut())
            .ok_or_else(|| unknown("generic consumed attempt disappeared"))?
            .response = Some(response);
        self.validate_original_input_commit(commit)
            .map_err(after_effect)
    }

    pub(in super::super) fn validate_original_input_commit(
        &self,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let staged = self.original_input_commit(commit)?;
        let staging = staged
            .response
            .as_ref()
            .ok_or_else(|| refused("generic original staging response absent"))?;
        let response = staged
            .commitment
            .as_ref()
            .and_then(|attempt| attempt.response.as_ref())
            .ok_or_else(|| unknown("generic original consumed input remains pending"))?;
        let attempt = staged
            .commitment
            .as_ref()
            .ok_or_else(|| unknown("generic consumed commitment disappeared"))?;
        let original = self
            .scope()?
            .controller
            .original(&attempt.request_id)
            .ok_or_else(|| unknown("generic consumed request has no original transport journal"))?;
        let crucible_node_transport::bodies::RequestBody::Input(request) =
            crucible_node_transport::bodies::decode_request(Method::Input, &original.request.body)
                .map_err(unknown)?
        else {
            return Err(unknown("generic original consumed method changed"));
        };
        if original.request.method != Method::Input
            || original.request.extensions != attempt.extensions
            || request != staged.request
            || original.response.is_none()
        {
            return Err(unknown(
                "generic original consumed request association changed",
            ));
        }
        for payload in attempt.context.iter() {
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
            if self
                .scope()?
                .controller
                .content(&payload.reference)
                .map_err(unknown)?
                != payload.bytes
            {
                return Err(unknown("generic consumed context bytes changed"));
            }
        }
        self.source()?.validate_input_commit(
            self.scope()?,
            &staged.original,
            commit,
            &staged.request,
            staging,
            response,
        )?;
        self.current()
    }
}
