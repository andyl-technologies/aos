//! Encodes the finite Mount16 and Network19 native absence companions.
//!
//! ```text
//! AOSMIC02|AOSNIC02 | request16 | boot16 | recipientInvocation16 |
//! beforeBoot8 | afterBoot8 | rootDevice8 | rootInode8 | rootMount8
//! ```
//!
//! These comparison bytes grant no service, finance or native authority. Their
//! genuine producer must retain complete native, protected-state and Session
//! observations. Each decoder accepts only its own closed service purpose.

use crate::ProtocolValidationError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Mount,
    Network,
}

impl Kind {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Mount => b"AOSMIC02",
            Self::Network => b"AOSNIC02",
        }
    }
}

/// Contains one purpose-bound, complete fixed-service native census companion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedServiceInventoryAbsenceDataV2 {
    kind: Kind,
    request: [u8; 16],
    boot: [u8; 16],
    invocation: [u8; 16],
    before: u64,
    after: u64,
    root: (u64, u64, u64),
}

impl FixedServiceInventoryAbsenceDataV2 {
    /// Returns the exact canonical wire width for either closed purpose.
    pub const BYTES_V2: usize = 96;

    /// Checks comparison fields for a Mount16 native census.
    ///
    /// # Errors
    /// Refuses reserved identities, invalid intervals or absent root identity.
    pub fn from_mount_native_data_v2(
        request: [u8; 16], boot: [u8; 16], invocation: [u8; 16],
        before: u64, after: u64, root: (u64, u64, u64),
    ) -> Result<Self, ProtocolValidationError> {
        Self::from_native(Kind::Mount, request, boot, invocation, before, after, root)
    }

    /// Checks comparison fields for a Network19 native census.
    ///
    /// # Errors
    /// Refuses reserved identities, invalid intervals or absent root identity.
    pub fn from_network_native_data_v2(
        request: [u8; 16], boot: [u8; 16], invocation: [u8; 16],
        before: u64, after: u64, root: (u64, u64, u64),
    ) -> Result<Self, ProtocolValidationError> {
        Self::from_native(Kind::Network, request, boot, invocation, before, after, root)
    }

    fn from_native(kind: Kind, request: [u8; 16], boot: [u8; 16], invocation: [u8; 16],
        before: u64, after: u64, root: (u64, u64, u64)) -> Result<Self, ProtocolValidationError> {
        if request == [0; 16] || boot == [0; 16] || invocation == [0; 16]
            || before == 0 || after < before || root.1 == 0 || root.2 == 0 {
            return Err(invalid());
        }
        Ok(Self { kind, request, boot, invocation, before, after, root })
    }

    /// Decodes only the canonical Mount16 companion.
    ///
    /// # Errors
    /// Refuses another purpose, version, width or invalid comparison fields.
    pub fn decode_mount_v2(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        Self::decode(Kind::Mount, bytes)
    }

    /// Decodes only the canonical Network19 companion.
    ///
    /// # Errors
    /// Refuses another purpose, version, width or invalid comparison fields.
    pub fn decode_network_v2(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        Self::decode(Kind::Network, bytes)
    }

    fn decode(kind: Kind, bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != Self::BYTES_V2 || &bytes[..8] != kind.magic() {
            return Err(invalid());
        }
        let array = |range: std::ops::Range<usize>| bytes.get(range).ok_or_else(invalid);
        let word = |start| -> Result<u64, ProtocolValidationError> {
            Ok(u64::from_be_bytes(array(start..start + 8)?.try_into().map_err(|_| invalid())?))
        };
        Self::from_native(kind,
            array(8..24)?.try_into().map_err(|_| invalid())?,
            array(24..40)?.try_into().map_err(|_| invalid())?,
            array(40..56)?.try_into().map_err(|_| invalid())?,
            word(56)?, word(64)?, (word(72)?, word(80)?, word(88)?))
    }

    /// Encodes the same checked purpose and comparison fields without allocation.
    pub fn encode_v2(self) -> [u8; Self::BYTES_V2] {
        let mut bytes = [0; Self::BYTES_V2];
        bytes[..8].copy_from_slice(self.kind.magic());
        bytes[8..24].copy_from_slice(&self.request);
        bytes[24..40].copy_from_slice(&self.boot);
        bytes[40..56].copy_from_slice(&self.invocation);
        for (start, word) in [(56, self.before), (64, self.after),
            (72, self.root.0), (80, self.root.1), (88, self.root.2)] {
            bytes[start..start + 8].copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    /// Returns the same signed request identifier as comparison DATA.
    pub const fn request_id_v2(&self) -> &[u8; 16] { &self.request }

    /// Returns the actual observed kernel boot as comparison DATA.
    pub const fn boot_v2(&self) -> &[u8; 16] { &self.boot }

    /// Returns the enrolled recipient invocation, distinct from Session IDs.
    pub const fn recipient_invocation_v2(&self) -> &[u8; 16] { &self.invocation }

    /// Returns both actual observation times without renewing a cutoff.
    pub const fn boottime_interval_v2(&self) -> (u64, u64) { (self.before, self.after) }

    /// Returns the protected root's device, inode and unique mount ID.
    pub const fn root_identity_v2(&self) -> (u64, u64, u64) { self.root }
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("fixed-service native absence")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_codec_preserves_mount_bytes_and_refuses_cross_service_replay() {
        let mount = FixedServiceInventoryAbsenceDataV2::from_mount_native_data_v2(
            [1; 16], [2; 16], [3; 16], 41, 43, (5, 7, 11)).unwrap();
        let network = FixedServiceInventoryAbsenceDataV2::from_network_native_data_v2(
            [1; 16], [2; 16], [3; 16], 41, 43, (5, 7, 11)).unwrap();
        let mount_bytes = mount.encode_v2();
        let network_bytes = network.encode_v2();

        assert_eq!(&mount_bytes[..8], b"AOSMIC02");
        assert_eq!(&network_bytes[..8], b"AOSNIC02");
        assert_eq!(mount_bytes[8..], network_bytes[8..]);
        assert_eq!(FixedServiceInventoryAbsenceDataV2::decode_mount_v2(&mount_bytes).unwrap(), mount);
        assert_eq!(FixedServiceInventoryAbsenceDataV2::decode_network_v2(&network_bytes).unwrap(), network);
        assert!(FixedServiceInventoryAbsenceDataV2::decode_mount_v2(&network_bytes).is_err());
        assert!(FixedServiceInventoryAbsenceDataV2::decode_network_v2(&mount_bytes).is_err());
    }

    #[test]
    fn malformed_width_version_and_time_are_refused() {
        let data = FixedServiceInventoryAbsenceDataV2::from_mount_native_data_v2(
            [1; 16], [2; 16], [3; 16], 41, 43, (5, 7, 11)).unwrap();
        let mut bytes = data.encode_v2();
        bytes[7] = b'1';

        assert!(FixedServiceInventoryAbsenceDataV2::decode_mount_v2(&bytes).is_err());
        assert!(FixedServiceInventoryAbsenceDataV2::decode_mount_v2(&data.encode_v2()[..95]).is_err());
        assert!(FixedServiceInventoryAbsenceDataV2::from_network_native_data_v2(
            [1; 16], [2; 16], [3; 16], 43, 41, (5, 7, 11)).is_err());
    }
}
