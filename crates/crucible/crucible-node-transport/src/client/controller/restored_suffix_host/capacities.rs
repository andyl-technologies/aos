//! Observes actual suffix partials without invoking assignment or completion.
//!
//! Original controller addresses remain non-owning labels. Raw envelopes, the
//! separately boxed typed response and full content-root Vec retain independent
//! backing, even when the original has no correlated terminal.

use super::*;
use crate::retained_metadata::MetadataObserver;

impl OriginalRestoredSuffixHostAttempt {
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "retained suffix creator differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.check_capacity_creator_data()?;
        let Self {
            request_id,
            operation_id,
            method,
            controller,
            process,
            thread,
            cut,
            completed_frontier,
            original,
            response,
            decoded,
            roots,
            stage,
        } = self;
        inline(method);
        inline(controller);
        inline(process);
        inline(thread);
        inline(cut);
        inline(completed_frontier);
        inline(stage);

        observer.observe(request_id)?;
        observer.observe(operation_id)?;
        observer.observe(original)?;
        observer.observe(response)?;
        observer.observe(roots)?;
        if let Some(decoded) = decoded {
            observer.boxed_value(decoded.as_ref())?;
            crate::retained_metadata::restored_suffix::response(decoded, observer)?;
        }
        self.check_capacity_creator_data()
    }

    pub(crate) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Id,
                &Option<Id>,
                &Method,
                &*const CnpController,
                &u32,
                &std::thread::ThreadId,
                &Option<OperationalDeadline>,
                &Option<U64>,
                &Option<Envelope>,
                &Option<Envelope>,
                &Option<Box<ResponseBody>>,
                &Vec<ContentRef>,
                &Stage,
            )>()
            + size_of::<&Box<ResponseBody>>()
            + size_of::<&ResponseBody>()
            + size_of::<&mut MetadataObserver<'_>>()
            + size_of::<Result<(), ProviderError>>()
            + crate::retained_metadata::restored_suffix::counter_scratch_data()
    }
}

const fn inline<T: Copy>(_value: &T) {}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
