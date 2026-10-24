//! Compares the fixed scope of a complete native Host absence observation.
//!
//! This companion is signed-inventory DATA. Its decoder establishes neither
//! discovery provenance nor resource permission. The actual Host emits it only
//! after its complete manager, cgroup, retained-custody and independent posts.
//!
//! ```text
//! AOSHIC05 | request16 | boot16 | recipient16 | beforeBoot8 | afterBoot8
//! ```

use crate::ProtocolValidationError;

/// Gives the sole width of the native Host absence companion.
pub const HOST_INVENTORY_ABSENCE_BYTES_V5: usize = 72;
const MAGIC: &[u8; 8] = b"AOSHIC05";

/// Describes the scope and clock sandwich of one native empty census.
///
/// Structural construction is intentionally public DATA. Only the completed
/// authenticated same-request outcome from the actual Host supplies provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostInventoryAbsenceDataV5 {
    request: [u8; 16],
    boot: [u8; 16],
    recipient: [u8; 16],
    before: u64,
    after: u64,
}

impl HostInventoryAbsenceDataV5 {
    /// Bounds the actual Inventory request decoder before its native clock.
    ///
    /// The byte count is the already retained authenticated body. The supplier
    /// prices generated Header/model/error/canonical backing as Memory only;
    /// it establishes no validated Header, peer identity or request horizon.
    #[must_use]
    pub fn request_decoding_memory_bytes_v5(actual_body_bytes: usize) -> Option<usize> {
        use aos_sandbox_api::aos::sandbox::local::v1::{InventoryRuntimeRequest, RequestHeader};
        use std::mem::size_of;
        let body = u64::try_from(actual_body_bytes).ok()?;
        let model =
            aos_sandbox_broker_session_protocol::receiving_geometry::schema_protobuf_carriers_v1(
                body, 1,
            )
            .ok()?;
        let fixed = u64::try_from(
            3 * (size_of::<InventoryRuntimeRequest>()
                + size_of::<RequestHeader>()
                + size_of::<crate::ValidatedHeader>()),
        )
        .ok()?;
        usize::try_from(
            fixed
                .checked_add(model.checked_mul(3)?)?
                .checked_add(body.checked_mul(3)?)?,
        )
        .ok()
    }

    /// Checks the fixed nonauthorizing observation coordinates.
    ///
    /// # Errors
    /// Refuses zero identities, a missing sample or a backward clock sandwich.
    pub fn from_data_v5(
        request: [u8; 16],
        boot: [u8; 16],
        recipient: [u8; 16],
        before: u64,
        after: u64,
    ) -> Result<Self, ProtocolValidationError> {
        if request == [0; 16]
            || boot == [0; 16]
            || recipient == [0; 16]
            || before == 0
            || after < before
        {
            return Err(invalid());
        }
        Ok(Self {
            request,
            boot,
            recipient,
            before,
            after,
        })
    }

    /// Encodes the complete fixed DATA without allocation.
    #[must_use]
    pub fn encode_v5(self) -> [u8; HOST_INVENTORY_ABSENCE_BYTES_V5] {
        let mut bytes = [0; HOST_INVENTORY_ABSENCE_BYTES_V5];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.request);
        bytes[24..40].copy_from_slice(&self.boot);
        bytes[40..56].copy_from_slice(&self.recipient);
        bytes[56..64].copy_from_slice(&self.before.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.after.to_le_bytes());
        bytes
    }

    /// Decodes the sole fixed inventory grammar without allocation.
    ///
    /// # Errors
    /// Refuses another version, width, trailing bytes or invalid coordinates.
    pub fn decode_v5(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_INVENTORY_ABSENCE_BYTES_V5 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        Self::from_data_v5(
            field(bytes, 8)?,
            field(bytes, 24)?,
            field(bytes, 40)?,
            u64::from_le_bytes(field(bytes, 56)?),
            u64::from_le_bytes(field(bytes, 64)?),
        )
    }

    /// Projects the canonical companion from a decoded Inventory response.
    ///
    /// Authentication and same-request validation remain the enclosing Session's
    /// responsibility. An old empty response returns `None`, never absence.
    ///
    /// # Errors
    /// Refuses malformed fixed DATA or any coexisting runtime/namespace row.
    pub fn from_inventory_v5(
        inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
    ) -> Result<Option<Self>, ProtocolValidationError> {
        if !inventory.cleanup_lineages_v1.is_empty() { return Err(invalid()); }
        if inventory.native_absence_v5.is_empty() {
            return Ok(None);
        }
        if !inventory.runtimes.is_empty() || !inventory.stopped_namespaces_v4.is_empty()
            || !inventory.recovered_namespaces_v7.is_empty()
            || !inventory.present_stop_cleanup_candidates_v1.is_empty() {
            return Err(invalid());
        }
        Self::decode_v5(&inventory.native_absence_v5).map(Some)
    }

    /// Borrows the actual signed Inventory request identity.
    #[must_use]
    pub const fn request_id_v5(&self) -> &[u8; 16] {
        &self.request
    }

    /// Borrows the actual Host kernel boot identity.
    #[must_use]
    pub const fn boot_v5(&self) -> &[u8; 16] {
        &self.boot
    }

    /// Borrows the actual image-enrolled Host service invocation.
    #[must_use]
    pub const fn recipient_invocation_v5(&self) -> &[u8; 16] {
        &self.recipient
    }

    /// Returns the original native observation's closed BOOTTIME sandwich.
    #[must_use]
    pub const fn boottime_interval_v5(&self) -> (u64, u64) {
        (self.before, self.after)
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host native inventory absence")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_fresh_same_scope_grammar_roundtrips() {
        let value =
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 4, 5).unwrap();
        let bytes = value.encode_v5();
        assert_eq!(
            HostInventoryAbsenceDataV5::decode_v5(&bytes).unwrap(),
            value
        );
        assert!(HostInventoryAbsenceDataV5::decode_v5(&bytes[..71]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(HostInventoryAbsenceDataV5::decode_v5(&trailing).is_err());
        assert!(HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 5, 4).is_err());
        assert!(HostInventoryAbsenceDataV5::from_data_v5([0; 16], [2; 16], [3; 16], 4, 5).is_err());
    }

    #[test]
    fn an_old_empty_response_is_not_absence_and_a_native_companion_cannot_hide_a_row() {
        use aos_sandbox_api::aos::sandbox::local::v1::{InventoryRuntimeResponse, RuntimeObservation};
        let mut inventory = InventoryRuntimeResponse::default();
        assert_eq!(
            HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).unwrap(),
            None
        );
        let value =
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 4, 5).unwrap();
        inventory.native_absence_v5 = value.encode_v5().to_vec();
        assert_eq!(
            HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).unwrap(),
            Some(value)
        );
        inventory.runtimes.push(RuntimeObservation::default());
        assert!(HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).is_err());
        inventory.runtimes.clear();
        inventory.stopped_namespaces_v4.push(vec![1]);
        assert!(HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).is_err());
    }
}
