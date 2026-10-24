//! Counts every initialized bank, including failed construction and SDK prefixes.
//!
//! Inline optional payloads belong to the actual owner-vector allocation. Only
//! independent backing is added below. SDK and bootstrap fields are measured by
//! their defining public visitors; Provider observer internals stay private.

use super::super::storage_error::StorageError;
use super::*;
use crucible_node_transport::{
    ProviderError,
    client::CnpController,
    reference_packet::service::complete_restore::import18::bootstrap_ack::{
        PacketNativeImport18BootstrapRetainedData,
        native_import18_bootstrap_retention_counter_scratch_data,
    },
    retained_metadata::RetainedProtocolMetadataFacts,
};
use std::alloc::Layout;

impl PacketCompleteSemanticSource {
    /// Quotes the actual retained SDK metadata work before the owning census.
    ///
    /// The caller first funds the static bank counter, then admits this result
    /// before walking actual SDK partial Values. Empty journals add no invented
    /// expanded profile. This lookup neither traverses Values nor allocates.
    ///
    /// # Errors
    /// Refuses foreign Source or SDK origin, a busy bank or checked overflow.
    pub fn native_import18_phase_bank_metadata_counter_data(&self) -> Result<usize, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .native_import18_phase_bank
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut bytes = retained_counter_scratch_data();
        if let Some(bank) = slot.as_ref() {
            for owner in &bank.owners {
                if let Some(sdk) = &owner.bootstrap.sdk_owner {
                    bytes = add(
                        bytes,
                        sdk.retained_metadata_counter_scratch_data()
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                        usize::MAX,
                    )?;
                }
                if let Some(sdk) = &owner.prepare_capsule {
                    bytes = add(
                        bytes,
                        sdk.retained_metadata_counter_scratch_data()
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                        usize::MAX,
                    )?;
                }
            }
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(bytes)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn native_import18_phase_bank_storage_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let slot = self
            .native_import18_phase_bank
            .try_borrow()
            .map_err(|_| E::refused("Source18 phase bank already borrowed"))?;
        let bytes = match slot.as_ref() {
            Some(bank) => bank.retained_backing_data(maximum).map_err(E::runtime)?,
            None => 0,
        };
        self.storage_origin_with_error::<E>()?;
        Ok(bytes)
    }
}

impl NativeImport18SourcePhaseBank {
    /// Includes the actual Box payload and full spare vector capacity.
    pub(super) fn retained_backing_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let slots = Layout::array::<NativeImport18SourcePhaseOwner>(self.owners.capacity())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let mut bytes = add(size_of::<Self>(), slots.size(), maximum)?;
        for owner in &self.owners {
            bytes = add(bytes, owner.retained_backing_data(maximum)?, maximum)?;
        }
        Ok(bytes)
    }
}

impl NativeImport18SourcePhaseOwner {
    fn retained_backing_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut bytes = self.bootstrap.retained_backing_data(maximum)?;
        bytes = add(bytes, self.prepare.retained_backing_data(maximum)?, maximum)?;
        bytes = add(bytes, self.commit.retained_backing_data(maximum)?, maximum)?;
        bytes = add(
            bytes,
            foreign_backing(
                &OriginalNativeImport18Assignment::source_input_retained_metadata_data(
                    None,
                    None,
                    self.prepare_request.as_ref(),
                    self.commit_request.as_ref(),
                    self.binding.as_ref(),
                )
                .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum,
            )?,
            maximum,
        )?;
        for row in self.sdk_rows.iter().flatten() {
            bytes = add(
                bytes,
                foreign_backing(
                    &row.retained_metadata_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?,
                maximum,
            )?;
        }
        if let Some(sdk) = &self.prepare_capsule {
            bytes = add(
                bytes,
                foreign_backing(
                    &sdk.retained_metadata_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?,
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

impl BootstrapPartials {
    fn retained_backing_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut sdk_bytes = 0;
        if let Some(row) = &self.sdk_row {
            sdk_bytes = add(
                sdk_bytes,
                foreign_backing(
                    &row.retained_metadata_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?,
                maximum,
            )?;
        }
        if let Some(owner) = &self.sdk_owner {
            sdk_bytes = add(
                sdk_bytes,
                foreign_backing(
                    &owner
                        .retained_metadata_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?,
                maximum,
            )?;
        }
        let mut bytes = add(sdk_bytes, self.encoded.capacity(), maximum)?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        bytes = add(
            bytes,
            literal_backing(
                self.literal_attempt.as_ref(),
                self.literal.as_ref(),
                maximum,
            )?,
            maximum,
        )?;
        bytes = add(
            bytes,
            foreign_backing(
                &OriginalNativeImport18Assignment::source_input_retained_metadata_data(
                    self.request_id.as_ref(),
                    None,
                    None,
                    None,
                    None,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?,
                maximum,
            )?,
            maximum,
        )?;
        let fields = [
            self.request
                .as_ref()
                .map(PacketNativeImport18BootstrapRetainedData::Request),
            self.result
                .as_ref()
                .map(PacketNativeImport18BootstrapRetainedData::Result),
            self.context
                .as_ref()
                .map(PacketNativeImport18BootstrapRetainedData::Context),
            self.proof
                .as_ref()
                .map(PacketNativeImport18BootstrapRetainedData::Proof),
            self.receipt
                .as_ref()
                .map(PacketNativeImport18BootstrapRetainedData::Receipt),
        ];
        for field in fields.into_iter().flatten() {
            bytes = add(
                bytes,
                foreign_backing(
                    &field
                        .retained_metadata_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                    maximum,
                )?,
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

impl PhasePartials {
    fn retained_backing_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut bytes = foreign_backing(
            &OriginalNativeImport18Assignment::source_input_retained_metadata_data(
                self.request_id.as_ref(),
                self.baseline.as_ref(),
                None,
                None,
                None,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?,
            maximum,
        )?;
        for literal in &self.normalized {
            bytes = add(bytes, literal.encoded.capacity(), maximum)?;
            bytes = add(
                bytes,
                literal_backing(literal.attempt.as_ref(), literal.literal.as_ref(), maximum)?,
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

fn literal_backing(
    attempt: Option<&LiteralValue18TokenAttempt>,
    literal: Option<&LiteralValue18Data>,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut bytes = 0;
    if let Some(attempt) = attempt {
        let actual = attempt.retained_requested_storage_data(maximum)?;
        let backing = actual
            .checked_sub(size_of::<LiteralValue18TokenAttempt>())
            .ok_or(RuntimeError::ResourceLimit)?;
        bytes = add(bytes, backing, maximum)?;
    }
    if let Some(literal) = literal {
        let actual = literal.retained_requested_storage_data(maximum)?;
        let backing = actual
            .checked_sub(size_of::<LiteralValue18Data>())
            .ok_or(RuntimeError::ResourceLimit)?;
        bytes = add(bytes, backing, maximum)?;
    }
    Ok(bytes)
}

fn foreign_backing(
    facts: &RetainedProtocolMetadataFacts,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(facts, maximum)
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

/// Names only the actual fixed census and metadata-prewalk controls.
pub(super) fn retained_counter_scratch_data() -> usize {
    PacketCompleteSemanticSource::retained_metadata_conversion_counter_scratch_data()
        + OriginalNativeImport18Assignment::source_input_metadata_counter_scratch_data()
        + CnpController::original_native_import18_assignment_counter_scratch_data()
        + native_import18_bootstrap_retention_counter_scratch_data()
        + CnpController::original_native_import18_bootstrap_counter_scratch_data()
        + size_of::<&OriginalNativeImport18Bootstrap>()
        + size_of::<&OriginalNativeImport18BootstrapConstructionData>()
        + LiteralValue18Data::retained_counter_scratch_data()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>>()
        + size_of::<Result<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>, BorrowError>>()
        + size_of::<Result<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>, RuntimeError>>(
        )
        + size_of::<&NativeImport18SourcePhaseBank>()
        + size_of::<Option<&Box<NativeImport18SourcePhaseBank>>>()
        + size_of::<&NativeImport18SourcePhaseOwner>()
        + size_of::<std::slice::Iter<'static, NativeImport18SourcePhaseOwner>>()
        + size_of::<&BootstrapPartials>()
        + size_of::<&PhasePartials>()
        + size_of::<&LiteralPartial>()
        + size_of::<std::slice::Iter<'static, LiteralPartial>>()
        + size_of::<&LiteralValue18TokenAttempt>()
        + size_of::<&LiteralValue18Data>()
        + size_of::<Option<&LiteralValue18TokenAttempt>>()
        + size_of::<Option<&LiteralValue18Data>>()
        + size_of::<&OriginalNativeImport18Assignment>()
        + size_of::<Option<&OriginalNativeImport18Assignment>>()
        + size_of::<&OriginalNativeImport18AssignmentStorageData>()
        + size_of::<std::slice::Iter<'static, Option<OriginalNativeImport18AssignmentStorageData>>>(
        )
        + size_of::<
            std::iter::Flatten<
                std::slice::Iter<'static, Option<OriginalNativeImport18AssignmentStorageData>>,
            >,
        >()
        + size_of::<[Option<PacketNativeImport18BootstrapRetainedData<'static>>; 5]>()
        + size_of::<
            std::array::IntoIter<Option<PacketNativeImport18BootstrapRetainedData<'static>>, 5>,
        >()
        + size_of::<
            std::iter::Flatten<
                std::array::IntoIter<Option<PacketNativeImport18BootstrapRetainedData<'static>>, 5>,
            >,
        >()
        + size_of::<PacketNativeImport18BootstrapRetainedData<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<&RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<Layout>()
        + size_of::<Result<Layout, std::alloc::LayoutError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<std::thread::Thread>()
        + size_of::<ThreadId>()
        + size_of::<&ThreadId>() * 2
        + size_of::<&u32>() * 2
        + size_of::<u32>()
        + size_of::<Result<(), RuntimeError>>()
        // Eight explicit bounds, seven running census totals, the literal's
        // actual/backing pair, add's two operands and the SDK prewalk result.
        + size_of::<usize>() * 20
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
