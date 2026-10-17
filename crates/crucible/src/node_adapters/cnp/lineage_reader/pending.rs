//! Exact installed native input/output roster beneath complete pending receipts.

use crucible_node_contract::*;
use crucible_node_provider::ProviderError;

use super::control::ReaderState;

pub(super) struct ExpectedPending<'a> {
    pub(super) operation: Option<&'a Id>,
    pub(super) grant: Option<&'a Id>,
    pub(super) revision: U64,
    pub(super) input: &'a ContentRef,
    pub(super) output: Option<&'a ContentRef>,
    pub(super) watermark: U64,
}

impl ReaderState {
    pub(super) fn verify_pending(
        &self,
        reference: &ContentRef,
        expected: ExpectedPending<'_>,
    ) -> Result<(), ProviderError> {
        let ExpectedPending {
            operation,
            grant,
            revision,
            input,
            output,
            watermark,
        } = expected;
        let controller = self.controller()?;
        let bootstrap = &controller.bootstrap;
        let pending: PendingInventory = controller.record(reference)?;
        let mut expected = vec![PendingEntry {
            id: Id::new("accepted-input")?,
            kind: PendingKind::Input,
            owner_id: bootstrap.owner_id.clone(),
            deadline: Bound {
                kind: BoundKind::Unknown,
                position: None,
                evidence: None,
            },
            state_ref: input.clone(),
            extensions: Extensions::new(),
        }];
        if let Some(output) = output {
            expected.push(PendingEntry {
                id: Id::new("staged-output")?,
                kind: PendingKind::Output,
                owner_id: bootstrap.owner_id.clone(),
                deadline: Bound {
                    kind: BoundKind::Unknown,
                    position: None,
                    evidence: None,
                },
                state_ref: output.clone(),
                extensions: Extensions::new(),
            });
        }
        if pending.execution_owner_id != bootstrap.owner_id
            || pending.owner_binding_hash != self.owner_binding.identity()?
            || pending.world_binding_hash != bootstrap.world_binding_hash
            || pending.activation_id.as_ref() != Some(&bootstrap.activation_id)
            || pending.world_generation != bootstrap.world_generation
            || pending.operation_id.as_ref() != operation
            || pending.grant_id.as_ref() != grant
            || pending.owner_generation != bootstrap.authority.owner_generation
            || pending.revision != revision
            || !pending.complete
            || pending.input_watermark != watermark
            || pending.input_epoch != bootstrap.authority.input_epoch
            || pending.entries != expected
            || !pending.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "complete public pending roster changed original input/output custody",
            ));
        }
        Ok(())
    }
}
