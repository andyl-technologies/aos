//! Reached encoded-buffer obligations for the shared State record codecs.
//!
//! The allocation-free counting writer uses the same JSON serializer as the
//! encoder. A continuously borrowed genuine State stage prepays dominant byte
//! peaks before wire-model or encoded-buffer construction. Pure scratch uses
//! normal local destruction; actual mutation/native owners remain external.

use std::io::{self, Write};

use serde::Serialize;

use crate::StorageStateError;

pub(crate) type StateEncodingLoanV1<'cut, 'original> =
    aos_sandbox_controller_domain::StorageStateRecoveryEncodingLoanV1<'cut, 'original>;

/// Preserves the actual arithmetic/payment failure on the mutation owner.
#[derive(Default)]
pub(super) struct StateCodecOriginalV1 {
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    arithmetic: Option<aos_sandbox_model::AccountingError>,
}

impl StateCodecOriginalV1 {
    pub(super) fn is_complete_v1(&self) -> bool {
        self.arithmetic.is_none() && !matches!(self.payment, Some(Err(_)))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.arithmetic.as_ref().map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}

/// Borrows the same genuine payer and the actual mutation failure destination.
///
/// This context creates no resource original or model/effect authority.
pub(crate) struct StateEncodingContextV1<'stage, 'cut, 'original> {
    receiving: &'stage mut StateEncodingLoanV1<'cut, 'original>,
    payment: &'stage mut Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    arithmetic: &'stage mut Option<aos_sandbox_model::AccountingError>,
}

impl<'stage, 'cut, 'original> StateEncodingContextV1<'stage, 'cut, 'original> {
    pub(super) fn new(
        receiving: &'stage mut StateEncodingLoanV1<'cut, 'original>,
        original: &'stage mut StateCodecOriginalV1,
    ) -> Self {
        let StateCodecOriginalV1 { payment, arithmetic } = original;
        Self { receiving, payment, arithmetic }
    }

    /// Pays an actually reached non-JSON buffer in this same mutation.
    pub(crate) fn reserve_owned_capacity_v1(
        &mut self,
        capacity: Result<usize, aos_sandbox_model::AccountingError>,
        cells: usize,
    ) -> Result<(), StorageStateError> {
        if self.arithmetic.is_some() || matches!(self.payment, Some(Err(_))) {
            return Err(StorageStateError::Receiving);
        }
        let capacity = capacity.map_err(|cause| {
            *self.arithmetic = Some(cause);
            StorageStateError::Receiving
        })?;
        *self.payment = Some(self.receiving.reserve_encoded_capacity_v1(capacity, cells));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(StorageStateError::Receiving);
        }
        Ok(())
    }

    pub(crate) fn reserve_owned_shape_v1(
        &mut self,
        shape: Result<(usize, usize), aos_sandbox_model::AccountingError>,
    ) -> Result<(), StorageStateError> {
        if self.arithmetic.is_some() || matches!(self.payment, Some(Err(_))) {
            return Err(StorageStateError::Receiving);
        }
        let (bytes, cells) = shape.map_err(|cause| {
            *self.arithmetic = Some(cause);
            StorageStateError::Receiving
        })?;
        self.reserve_owned_capacity_v1(Ok(bytes), cells)
    }

    pub(crate) fn reserve_catalog_wire_v1(
        &mut self,
        geometry: Result<
            crate::catalog_transition::CatalogWireGeometryV1,
            aos_sandbox_model::AccountingError,
        >,
    ) -> Result<(), StorageStateError> {
        if self.arithmetic.is_some() || matches!(self.payment, Some(Err(_))) {
            return Err(StorageStateError::Receiving);
        }
        let geometry = geometry.map_err(|cause| {
            *self.arithmetic = Some(cause);
            StorageStateError::Receiving
        })?;
        let memory = geometry.memory.checked_add(std::mem::size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StateCodecOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(
                2 * std::mem::size_of::<crate::catalog_transition::CatalogWireGeometryV1>(),
            ));
        let memory = memory.ok_or_else(|| {
            *self.arithmetic = Some(aos_sandbox_model::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
            });
            StorageStateError::Receiving
        })?;
        self.reserve_owned_capacity_v1(Ok(memory), geometry.metadata)
    }
}

#[derive(Default)]
struct EncodedByteCount {
    bytes: usize,
}

impl Write for EncodedByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn encode_json_v1<T: Serialize + ?Sized>(
    value: &T,
    receiving: Option<&mut StateEncodingContextV1<'_, '_, '_>>,
) -> Result<Vec<u8>, StorageStateError> {
    let Some(receiving) = receiving else {
        return serde_json::to_vec(value).map_err(|_| StorageStateError::InvalidValue);
    };
    let mut count = EncodedByteCount::default();
    serde_json::to_writer(&mut count, value).map_err(|_| StorageStateError::InvalidValue)?;
    // This is the actual reached JSON width, not a synthetic model or maximum
    // transaction forecast. Native retains its conservative three-backing byte
    // multiplier. Earlier live payloads remain charged by their own reserves.
    let capacity = count.bytes.max(128)
        .checked_add(2 * std::mem::size_of::<Vec<u8>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<EncodedByteCount>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StateCodecOriginalV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StateEncodingContextV1<'_, '_, '_>>()))
        .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
            dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
        });
    receiving.reserve_owned_capacity_v1(capacity, 0)?;
    serde_json::to_vec(value).map_err(|_| StorageStateError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_count_follows_real_json_escape_and_decimal_expansion() {
        #[derive(Serialize)]
        struct Wire<'value> {
            text: &'value str,
            bytes: [u8; 4],
            generation: u64,
        }
        let wire = Wire {
            text: "line\n\"\\\t",
            bytes: [0, 9, 99, 255],
            generation: u64::MAX,
        };
        let mut count = EncodedByteCount::default();

        serde_json::to_writer(&mut count, &wire).unwrap();
        let ordinary = serde_json::to_vec(&wire).unwrap();

        assert_eq!(count.bytes, ordinary.len());
        assert_eq!(&*encode_json_v1(&wire, None).unwrap(), ordinary.as_slice());
    }

    #[test]
    fn failed_counter_growth_keeps_the_prior_reached_extent() {
        let mut count = EncodedByteCount {
            bytes: usize::MAX - 1,
        };

        let failure = count.write(b"two").unwrap_err();

        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
        assert_eq!(count.bytes, usize::MAX - 1);
    }
}
