//! Lends mutable current correlation inside complete original decoded custody.
//!
//! Publication has its own Received/Writing/Confirmed predicates. The older
//! completed request/proof loans keep requiring their actual received record.

use super::*;

impl Attempt {
    /// Lends the actual guard for one separately admitted publication occurrence.
    ///
    /// The enclosing owner spends its publication occurrence before entry and
    /// authenticates its explicit SDK state before and after every mutation.
    /// Inspection allocations and returned Copy DATA need original credit.
    ///
    /// # Errors
    /// Refuses incomplete/failed correlation, stale Source/Host/SDK custody,
    /// callback or terminal guards. Refusal fences without dropping SDK records.
    pub(in super::super) fn with_publication_context_data<R: Copy>(
        &mut self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(
            super::view::Header<'_>,
            &mut CorrelationGuard,
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
            &BootstrapAckOperands<'_>,
            super::bootstrap_normalizations::Digests,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.complete || self.failed || self.step != Some(Step::Receive) {
            return Err(refused());
        }
        let outcome = inputs.codec.with_request_and_operands_data(
            inputs.original,
            inputs.normalizations,
            inputs.literal,
            inputs.parsed,
            |envelope, request, proof, operands, digests| {
                self.authenticate(inputs, operands)?;
                // The guard is the retained same original SDK correlation;
                // no replacement, clone, or fresh sequence owner is created.
                let header = super::view::Header {
                    complete: &self.complete,
                    failed: &self.failed,
                    cut: &self.cut,
                    launch: &self.launch,
                    step: &self.step,
                };
                let outcome = inspect(
                    header,
                    self.guard.as_mut().ok_or_else(refused)?,
                    envelope,
                    request,
                    proof,
                    operands,
                    digests,
                );
                let terminal = self.authenticate(inputs, operands);
                let result = outcome?;
                terminal?;
                Ok(result)
            },
        );
        if outcome.is_err() {
            self.refuse_data();
        }
        outcome
    }
}

/// Counts the actual mutably borrowed SDK beside its unchanged attempt header.
///
/// # Errors
/// Refuses unsupported actual metadata or checked accumulation overflow.
pub(in super::super) fn retained_borrowed_data(
    guard: &CorrelationGuard,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    guard.observe_owned_metadata(&mut observer)?;
    size_of::<Attempt>()
        .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
        .ok_or_else(exhausted)
}
