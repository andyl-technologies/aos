//! Compares the fixed scope of a Host's positively disposed runtime namespace.
//!
//! These bytes are passive signed-inventory DATA. Decoding does not prove a
//! Stop, close a descriptor, authorize Mount Reap or reconstruct a native owner.
//! The actual Host producer emits them only from its retained disposal original.
//!
//! ```text
//! AOSHNS04 | boot16 | sandbox16 | incarnation16 | epoch8 | generation8 |
//! assignment32 | anchor32 | runtime32 | Launch(id16,session32,signed32) |
//! Stop(id16,session32,signed32)
//! ```
//!
//! The separately versioned LaunchReady-only format uses `AOSHLR10` and the
//! identical prefix through Launch. It contains no Stop tuple or phase.

use crate::{ProtocolValidationError, ValidatedAssignmentFence};

mod completed_inventory;
pub use completed_inventory::HostStoppedInventoryDataV1;

/// Gives the exact fixed width of one scoped namespace-disposal inventory row.
pub const HOST_STOPPED_NAMESPACE_BYTES_V4: usize = 328;
const MAGIC: &[u8; 8] = b"AOSHNS04";

/// Names one exact authenticated request as passive comparison DATA.
pub type HostStoppedRequestIdentityDataV4 = ([u8; 16], [u8; 32], [u8; 32]);

/// Gives the exact canonical LaunchReady scope width without a Stop identity.
pub const HOST_LAUNCH_NAMESPACE_BYTES_V1: usize = 248;
const LAUNCH_MAGIC: &[u8; 8] = b"AOSHLR10";

/// Names immutable protected LaunchReady history as passive comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLaunchNamespaceDataV1 {
    boot: [u8; 16],
    fence: ValidatedAssignmentFence,
    anchor: [u8; 32],
    runtime: [u8; 32],
    launch: HostStoppedRequestIdentityDataV4,
}

impl HostLaunchNamespaceDataV1 {
    /// Checks Launch coordinates without constructing a Stop identity or owner.
    ///
    /// # Errors
    /// Refuses unspecified boot, anchor or authenticated Launch coordinates.
    pub fn from_data_v1(
        boot: [u8; 16],
        fence: ValidatedAssignmentFence,
        anchor: [u8; 32],
        launch: HostStoppedRequestIdentityDataV4,
    ) -> Result<Self, ProtocolValidationError> {
        if boot == [0; 16]
            || anchor == [0; 32]
            || launch.0 == [0; 16]
            || launch.1 == [0; 32]
            || launch.2 == [0; 32]
        {
            return Err(invalid());
        }
        let runtime = crate::semantics::host::runtime_handle_v1(
            fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.assignment_digest(),
        );
        Ok(Self {
            boot,
            fence,
            anchor,
            runtime,
            launch,
        })
    }

    /// Encodes the sole Launch-only grammar without a synthetic Stop tuple.
    #[must_use]
    pub fn encode_v1(self) -> [u8; HOST_LAUNCH_NAMESPACE_BYTES_V1] {
        let mut bytes = [0; HOST_LAUNCH_NAMESPACE_BYTES_V1];
        self.encode_prefix_v1(LAUNCH_MAGIC, &mut bytes);
        bytes
    }

    pub(crate) fn encode_prefix_v1(&self, magic: &[u8; 8], bytes: &mut [u8]) {
        let epoch = self.fence.assignment_epoch().to_le_bytes();
        let generation = self.fence.desired_generation().to_le_bytes();
        let parts: [&[u8]; 12] = [
            magic,
            &self.boot,
            self.fence.sandbox_id(),
            self.fence.incarnation_id(),
            &epoch,
            &generation,
            self.fence.assignment_digest(),
            &self.anchor,
            &self.runtime,
            &self.launch.0,
            &self.launch.1,
            &self.launch.2,
        ];
        let mut offset = 0;
        for part in parts {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
    }

    /// Decodes the canonical Launch-only scope through the shared scope codec.
    ///
    /// # Errors
    /// Refuses another version, invalid fields, changed runtime or trailing data.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_LAUNCH_NAMESPACE_BYTES_V1 || &bytes[..8] != LAUNCH_MAGIC {
            return Err(invalid());
        }
        Self::decode_prefix_v1(bytes)
    }

    pub(crate) fn decode_prefix_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let fence = ValidatedAssignmentFence {
            sandbox_id: field(bytes, 24)?,
            incarnation_id: field(bytes, 40)?,
            assignment_epoch: u64::from_le_bytes(field(bytes, 56)?),
            desired_generation: u64::from_le_bytes(field(bytes, 64)?),
            assignment_digest: field(bytes, 72)?,
        };
        if fence.sandbox_id == [0; 16]
            || fence.incarnation_id == [0; 16]
            || fence.assignment_epoch == 0
            || fence.desired_generation == 0
            || fence.assignment_digest == [0; 32]
        {
            return Err(invalid());
        }
        let value = Self::from_data_v1(
            field(bytes, 8)?,
            fence,
            field(bytes, 104)?,
            (field(bytes, 168)?, field(bytes, 184)?, field(bytes, 216)?),
        )?;
        if value.runtime != field::<32>(bytes, 136)? {
            return Err(invalid());
        }
        Ok(value)
    }

    /// Borrows the immutable original Launch boot.
    #[must_use]
    pub const fn boot_v1(&self) -> &[u8; 16] {
        &self.boot
    }

    /// Borrows the full immutable original Launch resource fence.
    #[must_use]
    pub const fn fence_v1(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Borrows the original typed Launch anchor.
    #[must_use]
    pub const fn anchor_v1(&self) -> &[u8; 32] {
        &self.anchor
    }

    /// Borrows the canonical runtime comparison handle.
    #[must_use]
    pub const fn runtime_v1(&self) -> &[u8; 32] {
        &self.runtime
    }

    /// Returns the original authenticated Launch request coordinates.
    #[must_use]
    pub const fn launch_v1(&self) -> HostStoppedRequestIdentityDataV4 {
        self.launch
    }
}

/// Retains the complete fixed scope claimed by one fresh signed Host inventory.
///
/// This value is deliberately constructible DATA. Only the actual authenticated
/// outcome and genuine independently checked Source/Controller/Host native
/// owners can make its contents usable at a closed destruction boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostStoppedNamespaceDataV4 {
    boot: [u8; 16],
    fence: ValidatedAssignmentFence,
    anchor: [u8; 32],
    runtime: [u8; 32],
    launch: HostStoppedRequestIdentityDataV4,
    stop: HostStoppedRequestIdentityDataV4,
}

impl HostStoppedNamespaceDataV4 {
    /// Checks the complete fixed nonauthorizing namespace scope.
    ///
    /// # Errors
    /// Refuses unspecified identities or reuse of the Launch request as Stop.
    pub fn from_data_v4(
        boot: [u8; 16],
        fence: ValidatedAssignmentFence,
        anchor: [u8; 32],
        launch: HostStoppedRequestIdentityDataV4,
        stop: HostStoppedRequestIdentityDataV4,
    ) -> Result<Self, ProtocolValidationError> {
        let scope = HostLaunchNamespaceDataV1::from_data_v1(boot, fence, anchor, launch)?;
        Self::from_launch_scope_v1(scope, stop)
    }

    fn from_launch_scope_v1(
        scope: HostLaunchNamespaceDataV1,
        stop: HostStoppedRequestIdentityDataV4,
    ) -> Result<Self, ProtocolValidationError> {
        if stop.0 == [0; 16]
            || stop.1 == [0; 32]
            || stop.2 == [0; 32]
            || scope.launch.0 == stop.0
            || scope.launch.2 == stop.2
        {
            return Err(invalid());
        }
        Ok(Self {
            boot: scope.boot,
            fence: scope.fence,
            anchor: scope.anchor,
            runtime: scope.runtime,
            launch: scope.launch,
            stop,
        })
    }

    /// Encodes this checked DATA without allocating.
    #[must_use]
    pub fn encode_v4(self) -> [u8; HOST_STOPPED_NAMESPACE_BYTES_V4] {
        let mut bytes = [0; HOST_STOPPED_NAMESPACE_BYTES_V4];
        self.launch_scope_v1()
            .encode_prefix_v1(MAGIC, &mut bytes[..248]);
        bytes[248..264].copy_from_slice(&self.stop.0);
        bytes[264..296].copy_from_slice(&self.stop.1);
        bytes[296..328].copy_from_slice(&self.stop.2);
        bytes
    }

    /// Decodes the sole exact fixed inventory grammar without allocating.
    ///
    /// # Errors
    /// Refuses an old version, a trailing byte, invalid scope or changed handle.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_STOPPED_NAMESPACE_BYTES_V4 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let scope = HostLaunchNamespaceDataV1::decode_prefix_v1(&bytes[..248])?;
        Self::from_launch_scope_v1(
            scope,
            (field(bytes, 248)?, field(bytes, 264)?, field(bytes, 296)?),
        )
    }

    /// Projects the shared Launch-only comparison without creating a Stop row.
    #[must_use]
    pub const fn launch_scope_v1(&self) -> HostLaunchNamespaceDataV1 {
        HostLaunchNamespaceDataV1 {
            boot: self.boot,
            fence: self.fence,
            anchor: self.anchor,
            runtime: self.runtime,
            launch: self.launch,
        }
    }

    /// Returns the original Host kernel boot identity.
    #[must_use]
    pub const fn boot_v4(&self) -> &[u8; 16] { &self.boot }

    /// Borrows the exact original assignment fence.
    #[must_use]
    pub const fn fence_v4(&self) -> &ValidatedAssignmentFence { &self.fence }

    /// Borrows the exact anchor admitted by the original typed Launch plan.
    #[must_use]
    pub const fn anchor_v4(&self) -> &[u8; 32] { &self.anchor }

    /// Borrows the sole canonical runtime handle for this assignment.
    #[must_use]
    pub const fn runtime_v4(&self) -> &[u8; 32] { &self.runtime }

    /// Returns the exact original signed Launch request identity.
    #[must_use]
    pub const fn launch_v4(&self) -> HostStoppedRequestIdentityDataV4 { self.launch }

    /// Returns the distinct exact signed Stop request identity.
    #[must_use]
    pub const fn stop_v4(&self) -> HostStoppedRequestIdentityDataV4 { self.stop }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes.get(offset..offset + N).ok_or_else(invalid)?.try_into().map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host stopped namespace scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_scope_roundtrip_rejects_another_runtime_and_old_or_trailing_grammar() {
        let fence = ValidatedAssignmentFence { sandbox_id: [1; 16], incarnation_id: [2; 16],
            assignment_epoch: 3, desired_generation: 4, assignment_digest: [5; 32] };
        let value = HostStoppedNamespaceDataV4::from_data_v4([6; 16], fence, [7; 32],
            ([8; 16], [9; 32], [10; 32]), ([11; 16], [12; 32], [13; 32])).unwrap();
        let bytes = value.encode_v4();
        assert_eq!(HostStoppedNamespaceDataV4::decode_v4(&bytes).unwrap(), value);

        let mut other_runtime = bytes;
        other_runtime[136] ^= 1;
        assert!(HostStoppedNamespaceDataV4::decode_v4(&other_runtime).is_err());
        let mut old = bytes;
        old[..8].copy_from_slice(b"AOSHNS03");
        assert!(HostStoppedNamespaceDataV4::decode_v4(&old).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(HostStoppedNamespaceDataV4::decode_v4(&trailing).is_err());
        assert!(HostStoppedNamespaceDataV4::from_data_v4([6; 16], fence, [7; 32],
            value.launch_v4(), value.launch_v4()).is_err());
        let launch = value.launch_scope_v1();
        let launch_bytes = launch.encode_v1();
        assert_eq!(launch_bytes.len(), 248);
        assert_eq!(&launch_bytes[8..], &bytes[8..248]);
        assert_eq!(HostLaunchNamespaceDataV1::decode_v1(&launch_bytes).unwrap(), launch);
        assert!(HostStoppedNamespaceDataV4::decode_v4(&launch_bytes).is_err());
        assert!(HostLaunchNamespaceDataV1::decode_v1(&bytes).is_err());
    }
}
