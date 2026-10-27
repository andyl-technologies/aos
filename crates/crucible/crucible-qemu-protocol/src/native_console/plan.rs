//! Canonical closed native UART stream plans and observed capabilities.

use sha2::{Digest, Sha256};

use super::*;

/// Maximum sorted stream bindings in one plan.
pub const NATIVE_CONSOLE_MAX_STREAMS: usize = 16;
/// Exact plan header bytes.
pub const NATIVE_CONSOLE_PLAN_HEADER_BYTES: usize = 64;
/// Exact bytes in a plan stream row.
pub const NATIVE_CONSOLE_PLAN_ROW_BYTES: usize = 64;
/// Exact bytes in the observed native capability table.
pub const NATIVE_CONSOLE_CAPABILITY_BYTES: usize = 128;
/// Exact V1 capability bits: origin, operation seal, owner, stop and allowance.
pub const NATIVE_CONSOLE_CAPABILITY_BITS: u32 = 0b1_1111;

/// Supported native UART binding kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NativeConsoleDevice {
    /// The original 16550 frontend transmit operation.
    Serial16550 = 1,
    /// The original PL011 frontend transmit operation.
    Pl011 = 2,
}

impl NativeConsoleDevice {
    /// Derives the closed logical identity for the fixed console backend.
    ///
    /// The native adapter must first resolve the actual supported UART and
    /// backend, then compare this identity with the declared row. This digest
    /// contains no native address or physical process identity.
    #[must_use]
    pub fn fixed_console_identity(self) -> [u8; 32] {
        let label = b"crucible-console";
        let mut digest = Sha256::new();
        digest.update(b"crucible-native-console-device-v1\0");
        digest.update((self as u16).to_le_bytes());
        digest.update((label.len() as u32).to_le_bytes());
        digest.update(label);
        digest.finalize().into()
    }
}

impl TryFrom<u16> for NativeConsoleDevice {
    type Error = NativeConsoleError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Serial16550),
            2 => Ok(Self::Pl011),
            _ => Err(NativeConsoleError::Plan),
        }
    }
}

/// One stable logical stream binding, without native addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeConsoleStream {
    /// Distinct nonzero stream ID, sorted within the plan.
    pub stream: u32,
    /// Closed supported frontend kind.
    pub device: NativeConsoleDevice,
    /// Stable digest of the admitted device identity.
    pub device_identity: [u8; 32],
    /// Nonempty mask of admitted owning vCPUs, limited to 64.
    pub owner_mask: u64,
    /// Retained cumulative stream sequence at the start of this lifecycle.
    pub sequence_base: u64,
}

/// Hashes sorted logical rows constructed after actual device resolution.
///
/// Host callers compute the expected projection. Native callers must construct
/// each row from their unique realized UART/backend and actual vCPU-mask checks;
/// neither hashing declared rows nor a matching digest establishes resolution.
/// Each row is 48 little-endian bytes: stream, kind, outbound direction1,
/// fixed identity and owner mask. Sequence bases and physical owners are absent.
///
/// # Errors
///
/// Refuses an empty/oversized projection, invalid fixed identity or owner mask,
/// or duplicate, zero or unsorted stream IDs.
pub fn resolved_streams_digest(
    streams: &[NativeConsoleStream],
) -> Result<[u8; 32], NativeConsoleError> {
    if streams.is_empty()
        || streams.len() > NATIVE_CONSOLE_MAX_STREAMS
        || streams.iter().any(|row| {
            row.stream == 0
                || row.owner_mask == 0
                || row.device_identity != row.device.fixed_console_identity()
        })
        || streams
            .windows(2)
            .any(|rows| rows[0].stream >= rows[1].stream)
    {
        return Err(NativeConsoleError::Plan);
    }
    let mut digest = Sha256::new();
    digest.update(b"crucible-native-console-resolved-streams-v1\0");
    digest.update((streams.len() as u32).to_le_bytes());
    for row in streams {
        digest.update(row.stream.to_le_bytes());
        digest.update((row.device as u16).to_le_bytes());
        digest.update(1_u16.to_le_bytes());
        digest.update(row.device_identity);
        digest.update(row.owner_mask.to_le_bytes());
    }
    Ok(digest.finalize().into())
}

/// One canonical setup plan; its validity does not resolve native devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeConsolePlan {
    /// Physical slot where the plan will be authenticated.
    pub slot: u32,
    /// Checkpointed canonical console generation, separate from restore ACKs.
    pub logical_generation: u64,
    /// Retained cumulative node byte sequence.
    pub node_sequence_base: u64,
    /// Sorted closed stream rows; an empty plan admits no canonical console.
    pub streams: Vec<NativeConsoleStream>,
}

impl NativeConsolePlan {
    /// Validates stream owners against the proposed console profile's VM shape.
    ///
    /// This must be called before guest start by the later launch adapter.
    /// Ordinary profiles are unaffected. The V1 mask cannot represent a VM
    /// with more than 64 vCPUs; unsupported console shapes refuse explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for a zero or greater-than-64 vCPU count,
    /// invalid rows, or owner bits outside the supplied VM shape.
    pub fn validate_vm_shape(&self, vcpus: u32) -> Result<(), NativeConsoleError> {
        if vcpus == 0 || vcpus > 64 {
            return Err(NativeConsoleError::Plan);
        }
        self.encode()?;
        let mask = if vcpus == 64 {
            u64::MAX
        } else {
            (1_u64 << vcpus) - 1
        };
        if self.streams.iter().any(|row| row.owner_mask & !mask != 0) {
            return Err(NativeConsoleError::Plan);
        }
        Ok(())
    }

    /// Encodes the exact bounded plan with sorted, distinct stream IDs.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for too many rows, absent identity or
    /// owner bits, zero IDs, or duplicate/unsorted IDs.
    pub fn encode(&self) -> Result<Vec<u8>, NativeConsoleError> {
        if self.streams.len() > NATIVE_CONSOLE_MAX_STREAMS
            || self
                .streams
                .iter()
                .any(|row| row.stream == 0 || row.owner_mask == 0 || row.device_identity == [0; 32])
            || self
                .streams
                .windows(2)
                .any(|rows| rows[0].stream >= rows[1].stream)
        {
            return Err(NativeConsoleError::Plan);
        }
        let length =
            NATIVE_CONSOLE_PLAN_HEADER_BYTES + self.streams.len() * NATIVE_CONSOLE_PLAN_ROW_BYTES;
        let mut out = vec![0; length];
        out[..8].copy_from_slice(b"NCPLAN01");
        put16(&mut out, 8, 1);
        put16(&mut out, 10, NATIVE_CONSOLE_PLAN_HEADER_BYTES as u16);
        put32(&mut out, 12, length as u32);
        put32(&mut out, 16, self.slot);
        put32(&mut out, 20, self.streams.len() as u32);
        put32(&mut out, 24, NATIVE_CONSOLE_CAPACITY);
        put32(&mut out, 28, 1);
        put64(&mut out, 32, self.logical_generation);
        put64(&mut out, 40, self.node_sequence_base);
        for (index, row) in self.streams.iter().enumerate() {
            let at = NATIVE_CONSOLE_PLAN_HEADER_BYTES + index * NATIVE_CONSOLE_PLAN_ROW_BYTES;
            put32(&mut out, at, row.stream);
            put16(&mut out, at + 4, row.device as u16);
            out[at + 6] = 1;
            out[at + 8..at + 40].copy_from_slice(&row.device_identity);
            put64(&mut out, at + 40, row.owner_mask);
            put64(&mut out, at + 48, row.sequence_base);
        }
        Ok(out)
    }

    /// Decodes an exact canonical plan, including zero reserved bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for malformed framing, sizes, kinds,
    /// owners, identities, duplicate rows or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        if bytes.len() < NATIVE_CONSOLE_PLAN_HEADER_BYTES {
            return Err(NativeConsoleError::Length);
        }
        let count = get32(bytes, 20) as usize;
        if count > NATIVE_CONSOLE_MAX_STREAMS {
            return Err(NativeConsoleError::Plan);
        }
        exact(
            bytes,
            NATIVE_CONSOLE_PLAN_HEADER_BYTES + count * NATIVE_CONSOLE_PLAN_ROW_BYTES,
        )?;
        if &bytes[..8] != b"NCPLAN01"
            || get16(bytes, 8) != 1
            || usize::from(get16(bytes, 10)) != NATIVE_CONSOLE_PLAN_HEADER_BYTES
            || get32(bytes, 12) as usize != bytes.len()
            || get32(bytes, 24) != NATIVE_CONSOLE_CAPACITY
            || get32(bytes, 28) != 1
            || bytes[48..64].iter().any(|value| *value != 0)
        {
            return Err(NativeConsoleError::Framing);
        }
        let mut streams = Vec::with_capacity(count);
        for index in 0..count {
            let at = NATIVE_CONSOLE_PLAN_HEADER_BYTES + index * NATIVE_CONSOLE_PLAN_ROW_BYTES;
            if bytes[at + 6] != 1
                || bytes[at + 7] != 0
                || bytes[at + 56..at + 64].iter().any(|value| *value != 0)
            {
                return Err(NativeConsoleError::Framing);
            }
            let mut identity = [0; 32];
            identity.copy_from_slice(&bytes[at + 8..at + 40]);
            streams.push(NativeConsoleStream {
                stream: get32(bytes, at),
                device: get16(bytes, at + 4).try_into()?,
                device_identity: identity,
                owner_mask: get64(bytes, at + 40),
                sequence_base: get64(bytes, at + 48),
            });
        }
        let plan = Self {
            slot: get32(bytes, 16),
            logical_generation: get64(bytes, 32),
            node_sequence_base: get64(bytes, 40),
            streams,
        };
        plan.encode()?;
        Ok(plan)
    }

    /// Hashes the closed logical device projection after native resolution.
    ///
    /// Sorted 48-byte rows retain stream ID, supported kind, outbound direction,
    /// fixed device identity and vCPU owner mask. Physical owners, sequence bases
    /// and native addresses are excluded. Computing this expected projection
    /// does not establish that a native device was resolved.
    ///
    /// # Errors
    ///
    /// Refuses malformed rows or an identity that differs from the supported
    /// kind's fixed console identity.
    pub fn resolved_streams_digest(&self) -> Result<[u8; 32], NativeConsoleError> {
        self.encode()?;
        resolved_streams_digest(&self.streams)
    }

    /// Returns the domain-separated SHA-256 of the complete canonical plan.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] when the plan cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], NativeConsoleError> {
        let mut digest = Sha256::new();
        digest.update(b"crucible-native-console-plan-v1\0");
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }
}

/// Native observed setup capability; an adapter must prove native resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleCapability {
    /// Physical VM slot.
    pub slot: u32,
    /// Physical region incarnation.
    pub region: [u8; 16],
    /// Nonzero physical process incarnation.
    pub process: u64,
    /// Exact complete transport plan hash, including its physical slot.
    pub plan_hash: [u8; 32],
    /// Digest of the actual native-resolved device/owner projection.
    pub resolved_streams: [u8; 32],
}

impl NativeConsoleCapability {
    /// Encodes the exact V1 capability shape and fixed supported bitset.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an absent physical owner or digest.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_CAPABILITY_BYTES], NativeConsoleError> {
        if self.region == [0; 16]
            || self.process == 0
            || self.plan_hash == [0; 32]
            || self.resolved_streams == [0; 32]
        {
            return Err(NativeConsoleError::Field);
        }
        let mut out = [0; NATIVE_CONSOLE_CAPABILITY_BYTES];
        out[..4].copy_from_slice(b"NCCP");
        put16(&mut out, 4, 1);
        put16(&mut out, 6, NATIVE_CONSOLE_CAPABILITY_BYTES as u16);
        put32(&mut out, 8, NATIVE_CONSOLE_CAPABILITY_BITS);
        put32(&mut out, 12, self.slot);
        out[16..32].copy_from_slice(&self.region);
        put64(&mut out, 32, self.process);
        out[40..72].copy_from_slice(&self.plan_hash);
        out[72..104].copy_from_slice(&self.resolved_streams);
        put32(&mut out, 104, NATIVE_CONSOLE_CAPACITY);
        put32(&mut out, 108, NATIVE_CONSOLE_RECORD_BYTES as u32);
        Ok(out)
    }

    /// Decodes only the exact V1 bitset, geometry and zero reserved bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for malformed framing or absent fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_CAPABILITY_BYTES)?;
        if &bytes[..4] != b"NCCP"
            || get16(bytes, 4) != 1
            || usize::from(get16(bytes, 6)) != NATIVE_CONSOLE_CAPABILITY_BYTES
            || get32(bytes, 8) != NATIVE_CONSOLE_CAPABILITY_BITS
            || get32(bytes, 104) != NATIVE_CONSOLE_CAPACITY
            || get32(bytes, 108) as usize != NATIVE_CONSOLE_RECORD_BYTES
            || bytes[112..].iter().any(|value| *value != 0)
        {
            return Err(NativeConsoleError::Framing);
        }
        let mut region = [0; 16];
        region.copy_from_slice(&bytes[16..32]);
        let mut plan_hash = [0; 32];
        plan_hash.copy_from_slice(&bytes[40..72]);
        let mut resolved_streams = [0; 32];
        resolved_streams.copy_from_slice(&bytes[72..104]);
        let value = Self {
            slot: get32(bytes, 12),
            region,
            process: get64(bytes, 32),
            plan_hash,
            resolved_streams,
        };
        value.encode()?;
        Ok(value)
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    fn stream(device: NativeConsoleDevice, mask: u64) -> NativeConsoleStream {
        NativeConsoleStream {
            stream: 1,
            device,
            device_identity: device.fixed_console_identity(),
            owner_mask: mask,
            sequence_base: 0,
        }
    }

    #[test]
    fn fixed_device_and_resolved_rows_match_portable_golden_bytes() -> Result<(), NativeConsoleError>
    {
        let serial16550 = stream(NativeConsoleDevice::Serial16550, 1);
        assert_eq!(
            serial16550.device_identity,
            [
                0x6f, 0x71, 0x2c, 0xfe, 0x15, 0x19, 0x8c, 0xa2, 0x75, 0x90, 0x17, 0xd6, 0x9c, 0x1e,
                0xaa, 0x6f, 0x60, 0xd6, 0xad, 0xe7, 0xa2, 0x01, 0x11, 0x28, 0xc3, 0x46, 0x49, 0xbc,
                0x93, 0x4f, 0x68, 0x51
            ]
        );
        assert_eq!(
            resolved_streams_digest(&[serial16550])?,
            [
                0x52, 0x34, 0xc2, 0xb6, 0xa0, 0xcb, 0x90, 0x81, 0xff, 0x1b, 0xc2, 0xbc, 0x71, 0x4c,
                0x9c, 0x62, 0x6d, 0xc3, 0x52, 0x64, 0x6f, 0x0a, 0x42, 0x18, 0xa3, 0xb4, 0xaf, 0x6f,
                0xe6, 0x89, 0x8c, 0x15
            ]
        );
        let pl011 = stream(NativeConsoleDevice::Pl011, 15);
        assert_eq!(
            pl011.device_identity,
            [
                0xe9, 0x27, 0x62, 0xc9, 0xd7, 0x4c, 0x61, 0xed, 0x3a, 0x08, 0x39, 0x6f, 0xe7, 0x96,
                0x2d, 0x6b, 0x6f, 0x69, 0xdf, 0x8f, 0xda, 0x44, 0xa6, 0xb2, 0x46, 0x18, 0x55, 0x46,
                0x05, 0x1b, 0xce, 0xb1
            ]
        );
        assert_eq!(
            resolved_streams_digest(&[pl011])?,
            [
                0x74, 0xa8, 0xe8, 0x4c, 0x92, 0x80, 0x6d, 0x42, 0x89, 0x94, 0x28, 0xc6, 0x09, 0xf4,
                0x4b, 0xd8, 0xb8, 0x62, 0xcc, 0x65, 0xbb, 0x47, 0xde, 0x6a, 0x43, 0xac, 0xda, 0xe3,
                0x18, 0xed, 0xe7, 0xb1
            ]
        );
        Ok(())
    }

    #[test]
    fn resolved_projection_excludes_physical_and_sequence_incarnations()
    -> Result<(), NativeConsoleError> {
        let mut plan = NativeConsolePlan {
            slot: 0,
            logical_generation: 0,
            node_sequence_base: 0,
            streams: vec![stream(NativeConsoleDevice::Serial16550, 3)],
        };
        let logical = plan.resolved_streams_digest()?;
        let transport = plan.digest()?;
        plan.slot = 7;
        plan.logical_generation = 19;
        plan.node_sequence_base = 33;
        plan.streams[0].sequence_base = 28;
        assert_eq!(logical, plan.resolved_streams_digest()?);
        assert_ne!(transport, plan.digest()?);
        plan.streams[0].owner_mask = 1;
        assert_ne!(logical, plan.resolved_streams_digest()?);
        Ok(())
    }

    #[test]
    fn resolved_projection_refuses_foreign_identity_and_unordered_rows()
    -> Result<(), NativeConsoleError> {
        let good = stream(NativeConsoleDevice::Serial16550, 1);
        for mutation in 0..4 {
            let mut changed = good.clone();
            match mutation {
                0 => changed.device_identity[0] ^= 1,
                1 => changed.owner_mask = 0,
                2 => changed.stream = 0,
                _ => changed.device = NativeConsoleDevice::Pl011,
            }
            assert_eq!(
                resolved_streams_digest(&[changed]),
                Err(NativeConsoleError::Plan)
            );
        }
        assert_eq!(resolved_streams_digest(&[]), Err(NativeConsoleError::Plan));
        assert_eq!(
            resolved_streams_digest(&[good.clone(), good.clone()]),
            Err(NativeConsoleError::Plan)
        );
        let mut second = good.clone();
        second.stream = 2;
        assert_eq!(
            resolved_streams_digest(&[second, good]),
            Err(NativeConsoleError::Plan)
        );
        Ok(())
    }
}
