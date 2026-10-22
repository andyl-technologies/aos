//! Lends disjoint actual correlation fields during a guarded SDK transition.
//!
//! A view contains references to the original attempt and actual SDK records.
//! It owns no replacement guard and cannot fence, renew or reconstruct records.

use super::*;

/// Borrows the original immutable association while its SDK field is mutable.
#[derive(Clone, Copy)]
pub(in super::super) struct Header<'a> {
    pub(super) complete: &'a bool,
    pub(super) failed: &'a bool,
    pub(super) cut: &'a Option<OperationalDeadline>,
    pub(super) launch: &'a Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    pub(super) step: &'a Option<Step>,
}

/// Borrows the same header and actual SDK for pure received-request work.
#[derive(Clone, Copy)]
pub(in super::super) struct View<'a> {
    header: Header<'a>,
    guard: Option<&'a CorrelationGuard>,
}

impl Attempt {
    /// Borrows original fields without cloning or inspecting any SDK record.
    pub(in super::super) fn view_data(&self) -> View<'_> {
        View {
            header: self.header_data(),
            guard: self.guard.as_ref(),
        }
    }

    fn header_data(&self) -> Header<'_> {
        Header {
            complete: &self.complete,
            failed: &self.failed,
            cut: &self.cut,
            launch: &self.launch,
            step: &self.step,
        }
    }
}

impl Header<'_> {
    /// Borrows this actual header beside its actual current SDK field.
    pub(in super::super) fn with_guard_data<'a>(self, guard: &'a CorrelationGuard) -> View<'a>
    where
        Self: 'a,
    {
        View {
            header: self,
            guard: Some(guard),
        }
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = self.launch {
            if !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            ) {
                return Err(refused());
            }
        }
        Ok(())
    }

    fn authenticate(
        &self,
        inputs: Inputs<'_>,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_alias(inputs.original)?;
        if *self.cut != Some(inputs.original.cut) || inputs.original.cut.is_expired() {
            return Err(refused());
        }
        inputs.original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }
}

impl View<'_> {
    /// Counts actual original SDK backing through this borrowed disjoint view.
    ///
    /// # Errors
    /// Refuses foreign association, unsupported metadata or checked overflow.
    pub(in super::super) fn retained_requested_bytes_data(
        self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.header.authenticate_alias(original)?;
        let mut observer = MetadataObserver::new();
        if let Some(guard) = self.guard {
            guard.observe_owned_metadata(&mut observer)?;
        }
        size_of::<Attempt>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(exhausted)
    }

    fn authenticate_received(&self, envelope: &Envelope) -> Result<(), ProviderError> {
        let guard = self.guard.ok_or_else(refused)?;
        let mut incoming = guard.incoming_requests();
        if incoming.next() != Some(envelope)
            || incoming.next().is_some()
            || guard.pending_requests().next().is_some()
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Lends the actual reserved request inside complete original custody.
    ///
    /// # Errors
    /// Preserves incomplete/fenced state, callback and original terminal refusal.
    pub(in super::super) fn with_received_context_data<R: Copy>(
        self,
        inputs: Inputs<'_>,
        inspect: impl FnOnce(
            &CorrelationGuard,
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
            &BootstrapAckOperands<'_>,
            super::super::bootstrap_normalizations::Digests,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !*self.header.complete || *self.header.failed || *self.header.step != Some(Step::Receive)
        {
            return Err(refused());
        }
        inputs.codec.with_request_and_operands_data(
            inputs.original,
            inputs.normalizations,
            inputs.literal,
            inputs.parsed,
            |envelope, request, proof, operands, digests| {
                self.header.authenticate(inputs, operands)?;
                self.authenticate_received(envelope)?;
                let guard = self.guard.ok_or_else(refused)?;
                let received = guard.incoming_requests().next().ok_or_else(refused)?;
                let outcome = inspect(guard, received, request, proof, operands, digests);
                let terminal = self
                    .header
                    .authenticate(inputs, operands)
                    .and_then(|()| self.authenticate_received(envelope));
                let result = outcome?;
                terminal?;
                Ok(result)
            },
        )
    }
}

/// Names borrowed adapters beside the independently priced complete SDK loan.
pub(in super::super) fn counter_scratch_data() -> usize {
    size_of::<Header<'static>>() * 3
        + size_of::<View<'static>>() * 6
        + size_of::<Option<&CorrelationGuard>>() * 2
        + size_of::<&Option<OperationalDeadline>>()
        + size_of::<&Option<Weak<PacketNativeImport18SelectedLaunchWireData>>>()
        + size_of::<&Option<Step>>()
        + size_of::<&bool>() * 2
        + size_of::<Result<(), ProviderError>>() * 3
}
