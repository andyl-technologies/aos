//! Same-actor loans and explicit saved-budget JSON admission for the transport.
//!
//! The enclosing decoder keeper remains borrowed through every descriptor,
//! buffer and diagnostic. An uncertain monitor import retains these loans for
//! actual actor containment; facade destruction never refunds that uncertainty.

use std::sync::Arc;

use crucible::owned_decode::{DecodeDescriptorLoan, DecodeScratch, deserialize_with_budget};
use crucible_linux_resource::host_supervision::HostOperationGuard;

use super::*;

type BackingVisitor<'visitor> = &'visitor mut dyn for<'event> FnMut(
    super::super::readonly_backing_stream::BackingEvent<'event>,
) -> io::Result<()>;

type ActorBackingParser<'owner, 'visitor> =
    super::super::readonly_backing_stream::QmpReadOnlyBackingParser<
        'owner,
        BackingVisitor<'visitor>,
    >;

/// Borrows the authenticated actor keeper and its exact preparation identity.
pub(crate) struct ActorBackingTransportPurpose<'owner> {
    owner: &'owner crate::OriginalActorDecodeOwner,
    original: &'owner Arc<HostOperationGuard>,
    descriptors: Option<DecodeDescriptorLoan>,
    storage: Option<DecodeScratch>,
    diagnostics: Option<DecodeScratch>,
    uncertain: bool,
}

impl<'owner> ActorBackingTransportPurpose<'owner> {
    // The decoder owner's fixed entry checks private Arc identity first. This
    // crate-private value cannot be constructed by a host protocol consumer.
    pub(crate) fn verified(
        owner: &'owner crate::OriginalActorDecodeOwner,
        original: &'owner Arc<HostOperationGuard>,
    ) -> Self {
        Self {
            owner,
            original,
            descriptors: None,
            storage: None,
            diagnostics: None,
            uncertain: false,
        }
    }

    // Fixed operation uses only the keeper verified at construction. It never
    // returns a bank/guard or accepts another caller's decoder authority.
    pub(crate) fn prepare_parser<'visitor>(
        &self,
        binding: &super::super::readonly_backing_stream::QmpReadOnlyBackingBinding,
        visitor: BackingVisitor<'visitor>,
    ) -> Result<ActorBackingParser<'owner, 'visitor>, BackingTransportCause> {
        self.check_original()
            .map_err(BackingTransportCause::Original)?;
        let owner = self.owner;
        let budget = owner.budget().map_err(BackingTransportCause::Original)?;
        super::super::readonly_backing_stream::QmpReadOnlyBackingParser::prepare(
            budget, binding, visitor,
        )
        .map_err(BackingTransportCause::Stream)
    }
}

impl BackingTransportPurpose for ActorBackingTransportPurpose<'_> {
    fn prepare(
        &mut self,
        geometry: BackingTransportGeometry,
        _contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<(), OriginalActorAccountError> {
        self.check_original()?;
        if self.storage.is_some() || self.descriptors.is_some() || self.diagnostics.is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let budget = self.owner.budget()?;
        let control =
            std::alloc::Layout::from_size_align(geometry.control_bytes, geometry.control_alignment)
                .map_err(|_| OriginalActorAccountError::Unavailable)?
                .pad_to_align()
                .size();
        let bytes = control
            .checked_add(geometry.io_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        self.storage = Some(
            budget
                .reserve_scratch_bytes(bytes)
                .map_err(OriginalActorAccountError::Decode)?,
        );
        self.descriptors = Some(
            budget
                .reserve_descriptors(geometry.descriptors)
                .map_err(OriginalActorAccountError::Decode)?,
        );
        // This is a source-derived diagnostic allocation purpose, not an
        // increased wire limit. It remains external to any owning parser error
        // and to the typed remote-error strings admitted by the saved decoder.
        let diagnostics = diagnostic_extent(geometry.decoded_message_wire_bytes)?;
        self.diagnostics = Some(
            budget
                .reserve_scratch_bytes(diagnostics)
                .map_err(OriginalActorAccountError::Decode)?,
        );
        self.check_original()
    }

    fn remaining(&self) -> Result<Duration, OriginalActorAccountError> {
        self.owner
            .budget()?
            .verify_live()
            .map_err(OriginalActorAccountError::Decode)?;
        self.original
            .wait_slice()
            .map_err(OriginalActorAccountError::Supervision)
    }

    fn check_original(&self) -> Result<(), OriginalActorAccountError> {
        self.remaining().map(|_| ())
    }

    fn check_original_post(&self) -> Result<(), OriginalActorAccountError> {
        // Sticky budget refusal is the primary cause, not permission to omit
        // the actual original clock/cancellation cut after an operation fails.
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(OriginalActorAccountError::Supervision)
    }

    fn quarantine(&mut self) {
        self.uncertain = true;
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        &self,
        bytes: &[u8],
    ) -> Result<Frame<T>, BackingTransportCause> {
        self.check_original()
            .map_err(BackingTransportCause::Original)?;
        let budget = self
            .owner
            .budget()
            .map_err(BackingTransportCause::Original)?;
        // This exact SliceRead bound is the shared codec's pinned allocation
        // argument: consumed source plus four-byte escape/minimum growth,
        // including simultaneous old/new RawVec storage. It pays parser scratch
        // separately from typed visitor outputs and retained diagnostics.
        let scratch = bytes
            .len()
            .checked_add(16)
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(BackingTransportCause::Invalid(
                "JSON scratch extent overflow",
            ))?;
        let _scratch = budget.reserve_scratch_bytes(scratch).map_err(|source| {
            BackingTransportCause::Original(OriginalActorAccountError::Decode(source))
        })?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let result = deserialize_with_budget(&mut decoder, budget);
        match result {
            Ok(frame) => {
                decoder.end().map_err(BackingTransportCause::Json)?;
                self.check_original()
                    .map_err(BackingTransportCause::Original)?;
                Ok(frame)
            }
            Err(error) => Err(BackingTransportCause::Json(error)),
        }
    }
}

impl Drop for ActorBackingTransportPurpose<'_> {
    fn drop(&mut self) {
        if self.uncertain {
            // The same budget aliases prevent a decoder close from releasing
            // its account while monitor imports or retained diagnostics remain
            // uncertain. The enclosing actor must physically contain them.
            if let Some(loan) = self.descriptors.take() {
                std::mem::forget(loan);
            }
            if let Some(loan) = self.storage.take() {
                std::mem::forget(loan);
            }
            if let Some(loan) = self.diagnostics.take() {
                std::mem::forget(loan);
            }
        }
    }
}

fn diagnostic_extent(wire: usize) -> Result<u64, OriginalActorAccountError> {
    // Fixed accepted DTOs have at most seven short field names. serde errors
    // format one unexpected input and a static expected list; Rust debug text
    // may expand each input byte to six bytes. The 512 bytes cover those fixed
    // strings, numeric tokens and minimum String capacity. Three extents cover
    // old/new growth or conversion to Box<str>. ErrorImpl is bounded by its
    // variant payloads, discriminant and two source-position words.
    let message = wire.checked_mul(6).and_then(|bytes| bytes.checked_add(512));
    let control = std::alloc::Layout::new::<(std::io::Error, Box<str>, usize, usize, usize)>()
        .pad_to_align()
        .size();
    message
        .and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| bytes.checked_add(control))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(OriginalActorAccountError::Unavailable)
}
