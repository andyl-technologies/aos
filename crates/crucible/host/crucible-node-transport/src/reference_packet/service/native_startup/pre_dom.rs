//! Enforces selected original-frame layout credit before allocating a Value.
//!
//! These borrowed limits carry no authority. The actual private bootstrap or
//! original boot owner authenticates its existing row before creating a view.
//! Literal reads finish before this check; strict parsing and all semantic,
//! canonical, digest and MAC checks remain with their original constructors.

use super::*;

mod raw_shape;

/// Borrows a restrictive DATA view of an already-authenticated original row.
///
/// This view grants no parser, stream, Source, or construction authority.
pub(crate) struct OriginalNativeFramePreflight<'a> {
    row: &'a PacketNativeStartupAllocationRow,
    kind: FrameKind<'a>,
}

enum FrameKind<'a> {
    Private {
        typed_launch_backing: usize,
    },
    Hello {
        launch: &'a super::super::PacketNative5SourceLaunch,
        registration: &'a [u8],
    },
}

impl<'a> OriginalNativeFramePreflight<'a> {
    /// Borrows the original private row and its independently live typed owner.
    pub(in crate::reference_packet::service) fn private(
        row: &'a PacketNativeStartupAllocationRow,
        typed_launch_backing: usize,
    ) -> Self {
        Self {
            row,
            kind: FrameKind::Private {
                typed_launch_backing,
            },
        }
    }

    /// Borrows the original native row and actual retained Hello inputs.
    pub(in crate::reference_packet::service) fn hello(
        row: &'a PacketNativeStartupAllocationRow,
        launch: &'a super::super::PacketNative5SourceLaunch,
        registration: &'a [u8],
    ) -> Self {
        Self {
            row,
            kind: FrameKind::Hello {
                launch,
                registration,
            },
        }
    }

    /// Checks the literal body allocation before its bounded read begins.
    ///
    /// # Errors
    /// Refuses incomplete rows or a body/scratch window above that same row.
    pub(crate) fn admit_raw_bank(&self, length: usize) -> Result<(), ProviderError> {
        self.row.requested_peak_data()?;
        let carry = match self.kind {
            FrameKind::Private {
                typed_launch_backing,
            } => typed_launch_backing,
            FrameKind::Hello { .. } => 0,
        };
        let body_and_carry = length.checked_add(carry).ok_or_else(exhausted)?;
        if body_and_carry as u64 > self.row.maximum_simultaneous_transient_bytes.get()
            || counter_scratch_data() as u64 > self.row.declared_counter_scratch_bytes.get()
        {
            return Err(exhausted());
        }
        Ok(())
    }

    /// Checks actual raw occurrences before constructing the first Value.
    ///
    /// # Errors
    /// Refuses incomplete rows, overflow, or complete requested work above the
    /// independently admitted transient/scratch window. Strict parsing follows.
    pub(crate) fn admit(&self, raw: &[u8]) -> Result<(), ProviderError> {
        self.row.requested_peak_data()?;
        let maximum = usize::try_from(self.row.maximum_simultaneous_transient_bytes.get())
            .map_err(|_| exhausted())?;
        if counter_scratch_data() as u64 > self.row.declared_counter_scratch_bytes.get() {
            return Err(exhausted());
        }
        let extent = raw_shape::extent(raw)?;
        let requested = match self.kind {
            FrameKind::Private {
                typed_launch_backing,
            } => super::storage::private_frame_work_data(extent, typed_launch_backing)?,
            FrameKind::Hello {
                launch,
                registration,
            } => super::storage::hello_frame_work_data(launch, registration, extent, maximum)?,
        };
        // FrameReader retains its independent raw body Vec through this gate
        // and the strict Value parse. The literal journal is a distinct owner;
        // neither it nor a separate length<=T check pays this simultaneous bank.
        let requested = raw.len().checked_add(requested).ok_or_else(exhausted)?;
        if requested > maximum {
            return Err(exhausted());
        }
        Ok(())
    }
}

pub(super) fn raw_extent_data(
    raw: &[u8],
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    ProviderError,
> {
    raw_shape::extent(raw)
}

pub(super) fn counter_scratch_data() -> usize {
    raw_shape::counter_scratch_data()
        + std::mem::size_of::<OriginalNativeFramePreflight<'static>>()
        + std::mem::size_of::<FrameKind<'static>>()
        + std::mem::size_of::<Result<(), ProviderError>>()
        + std::mem::size_of::<[usize; 4]>()
        + std::mem::size_of::<[usize; 2]>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
        + std::mem::size_of::<Option<OriginalNativeFramePreflight<'static>>>()
        + std::mem::size_of::<Result<Option<OriginalNativeFramePreflight<'static>>, ProviderError>>(
        )
        + std::mem::size_of::<
            Option<
                std::cell::Ref<
                    'static,
                    crate::reference_packet::service::ack_emitter::NativeAckBoot,
                >,
            >,
        >()
        + std::mem::size_of::<
            Result<
                Option<
                    std::cell::Ref<
                        'static,
                        crate::reference_packet::service::ack_emitter::NativeAckBoot,
                    >,
                >,
                ProviderError,
            >,
        >()
        + std::mem::size_of::<crate::transport::RetainedFrame>()
        + std::mem::size_of::<Result<Option<crate::transport::RetainedFrame>, ProviderError>>()
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or_else(exhausted)
    })
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native original frame layout window")
}

#[cfg(test)]
mod tests;
