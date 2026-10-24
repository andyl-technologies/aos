//! Projects actual launch-custody layout DATA through the established recipe.
//!
//! The image pair and complete Controller profile are independently held by
//! the original. This width alone supplies no channel, launch or admission.

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

/// Describes the actual upper launch owner's single inline destination.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerLaunchReceivingShapeV1 {
    /// Actual upper original layout, including its fixed native result fields.
    pub original_bytes: usize,
}

impl ControllerLaunchReceivingShapeV1 {
    pub(super) fn fixed_demand_v1(self) -> Result<ResourceVector, AccountingError> {
        let (receive_bytes, receive_files) =
            SeqpacketSocket::pid1_controller_range_receive_obligations_v2();
        // Both strict receives retain preview and consumed native carriers.
        // Include separate descriptor target/inspection paths conservatively;
        // the lower requested-byte sum alone is not a whole allocator proof.
        let inspections = receive_files.checked_mul(2 * 4096 + 64 * 1024)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        // The same closed Bank producer owns this finite record recipe.
        let records = super::bank_launch::mutation::enrollment_record_bytes_v1()
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let bytes = self.original_bytes
            .checked_add(2 * receive_bytes)
            .and_then(|value| value.checked_add(inspections))
            .and_then(|value| value.checked_add(records))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let bytes = u64::try_from(bytes)
            .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let files = u64::try_from(2 * receive_files + 8)
            .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files))
    }
}
