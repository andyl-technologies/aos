//! Bounded original Linux launch provenance for the source constructor.
//!
//! The source authenticates actual original descriptors and constructor objects
//! before effects. These explicit bytes supply correlation, never source-issued
//! RAM ownership, native readiness or permission to substitute mutable files.
//!
//! ```text
//! Launch128: CWHLLCH\0, version1/extent:u32, ISA/vcpus4/clockSIM1/properties:u32,
//!            RAMbase/length:u64, slope50/unitsPS1:u32, machine/CPUlen:u16,
//!            cmdline_len/assets3/reserved0:u32, cmdline_SHA256[32],
//!            RAMbacking_kind/fd:u32, RAMoffset/reserved0:u64
//! variable: machine[M], CPU[C], full_command_line[K], asset64[3]
//! asset64: role/presence:u16, inherited_fd:u32, length:u64, SHA256[32], reserved[16]
//! Integers are big endian. Absent assets use fdUINT32_MAX, length0 and zero hash.
//! ```

use crate::whole_control::{WholeControlError, put_u32, put_u64, read_u32, read_u64};
use sha2::{Digest, Sha256};

/// Bounds every original launch byte before native constructor publication.
pub const LAUNCH_SELECTION_MAX_BYTES: usize = 4096;
/// Bounds the complete original kernel command line within full-body overhead.
pub const LAUNCH_COMMAND_LINE_MAX_BYTES: usize = 3072;

/// Selects one explicitly supported initial four-vCPU Linux architecture profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LaunchArchitecture {
    /// Selects microvm/qemu64, no ACPI or cmdline rewriting, qboot and bounded RAM.
    X86_64 = 1,
    /// Selects virt/cortex-a72, GICv2, no secure/virtualization/highmem, direct boot.
    Arm64 = 2,
}

/// Correlates one original fully sealed source image descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchAsset {
    /// Selects kernel one, initrd two or firmware three in the public profile.
    pub role: u16,
    /// Distinguishes an actual original descriptor from explicitly absent input.
    pub present: bool,
    /// Correlates the inherited descriptor number, or UINT32_MAX when absent.
    pub inherited_fd: u32,
    /// Retains the entire actual original source image byte extent.
    pub byte_length: u64,
    /// Commits every actual original image byte with SHA-256.
    pub sha256: [u8; 32],
}

/// Borrows a complete original launch body validated before native effects.
pub struct LaunchSelection<'a> {
    body: &'a [u8],
    /// Selects the explicit versioned architecture profile.
    pub architecture: LaunchArchitecture,
    /// Retains the actual requested original machine name.
    pub machine: &'a str,
    /// Retains the actual requested original CPU model name.
    pub cpu_model: &'a str,
    /// Retains all original kernel command-line bytes, without truncation.
    pub kernel_command_line: &'a str,
    /// Retains the native guest RAM physical base.
    pub ram_base: u64,
    /// Retains the native guest RAM byte extent.
    pub ram_byte_length: u64,
    /// Selects inherited original FD one or source-owned native constructor two.
    pub ram_backing_kind: u32,
    /// Correlates the inherited RAM descriptor, or UINT32_MAX for source ownership.
    pub ram_inherited_fd: u32,
    /// Retains the actual backing offset for the original native RAM block.
    pub ram_backing_offset: u64,
    /// Retains complete original kernel, initrd and firmware descriptor correlations.
    pub assets: [LaunchAsset; 3],
}

impl<'a> LaunchSelection<'a> {
    /// Validates complete original launch fields without native constructor authority.
    ///
    /// # Errors
    /// Rejects malformed extents, unsupported profiles, properties, RAM geometry,
    /// image correlations, command-line digest, reserved fields or duplicate FDs.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if !(128 + 3 * 64..=LAUNCH_SELECTION_MAX_BYTES).contains(&body.len())
            || body[..8] != *b"CWHLLCH\0"
            || read_u32(body, 8) != 1
            || read_u32(body, 12) as usize != body.len()
            || read_u32(body, 20) != 4
            || read_u32(body, 24) != 1
            || read_u32(body, 48) != 50
            || read_u32(body, 52) != 1
            || read_u32(body, 64) != 3
            || read_u32(body, 68) != 0
            || read_u64(body, 120) != 0
        {
            return Err(WholeControlError::Body);
        }
        let architecture = match read_u32(body, 16) {
            1 if read_u32(body, 28) == 33 && read_u64(body, 32) == 0 => LaunchArchitecture::X86_64,
            2 if read_u32(body, 28) == 30 && read_u64(body, 32) == 0x4000_0000 => {
                LaunchArchitecture::Arm64
            }
            _ => return Err(WholeControlError::Body),
        };
        let ram_length = read_u64(body, 40);
        let backing_kind = read_u32(body, 104);
        let ram_fd = read_u32(body, 108);
        let ram_offset = read_u64(body, 112);
        if ram_length == 0
            || ram_length > 3 * 1024 * 1024 * 1024
            || !ram_length.is_multiple_of(4096)
            || !ram_offset.is_multiple_of(4096)
            || ram_offset.checked_add(ram_length).is_none()
            || !matches!(
                (backing_kind, ram_fd, ram_offset),
                (1, 3..=1024, _) | (2, u32::MAX, 0)
            )
        {
            return Err(WholeControlError::Body);
        }
        let machine_len = u16::from_be_bytes([body[56], body[57]]) as usize;
        let cpu_len = u16::from_be_bytes([body[58], body[59]]) as usize;
        let command_len = read_u32(body, 60) as usize;
        let extent = machine_len
            .checked_add(cpu_len)
            .and_then(|sum| sum.checked_add(command_len))
            .and_then(|sum| sum.checked_add(128 + 3 * 64));
        if !(1..=128).contains(&machine_len)
            || !(1..=128).contains(&cpu_len)
            || command_len > LAUNCH_COMMAND_LINE_MAX_BYTES
            || extent != Some(body.len())
        {
            return Err(WholeControlError::Body);
        }
        let machine_end = 128 + machine_len;
        let cpu_end = machine_end + cpu_len;
        let command_end = cpu_end + command_len;
        let machine = ascii(&body[128..machine_end])?;
        let cpu_model = ascii(&body[machine_end..cpu_end])?;
        let command = ascii(&body[cpu_end..command_end])?;
        let expected = match architecture {
            LaunchArchitecture::X86_64 => ("microvm", "qemu64"),
            LaunchArchitecture::Arm64 => ("virt", "cortex-a72"),
        };
        if (machine, cpu_model) != expected
            || Sha256::digest(command.as_bytes()).as_slice() != &body[72..104]
        {
            return Err(WholeControlError::Correlation);
        }
        let assets = [0, 1, 2].map(|index| {
            decode_asset(
                &body[command_end + index * 64..command_end + (index + 1) * 64],
                index as u16 + 1,
            )
        });
        let [kernel, initrd, firmware] = assets;
        let assets = [kernel?, initrd?, firmware?];
        if !assets[0].present
            || (architecture == LaunchArchitecture::X86_64 && !assets[2].present)
            || (architecture == LaunchArchitecture::Arm64 && assets[2].present)
        {
            return Err(WholeControlError::Body);
        }
        for (index, asset) in assets.iter().enumerate() {
            if asset.present
                && ((backing_kind == 1 && asset.inherited_fd == ram_fd)
                    || assets[..index]
                        .iter()
                        .any(|prior| prior.present && prior.inherited_fd == asset.inherited_fd))
            {
                return Err(WholeControlError::Body);
            }
        }
        Ok(Self {
            body,
            architecture,
            machine,
            cpu_model,
            kernel_command_line: command,
            ram_base: read_u64(body, 32),
            ram_byte_length: ram_length,
            ram_backing_kind: backing_kind,
            ram_inherited_fd: ram_fd,
            ram_backing_offset: ram_offset,
            assets,
        })
    }

    /// Borrows every complete original launch byte, including all image commitments.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// Supplies complete original requested launch provenance to the bounded encoder.
pub struct LaunchSelectionParts<'a> {
    /// Selects the explicit source constructor architecture profile.
    pub architecture: LaunchArchitecture,
    /// Supplies every original kernel command-line byte.
    pub kernel_command_line: &'a str,
    /// Supplies the original guest RAM byte extent.
    pub ram_byte_length: u64,
    /// Selects inherited original RAM descriptor one or source constructor two.
    pub ram_backing_kind: u32,
    /// Correlates inherited RAM, or UINT32_MAX for native source ownership.
    pub ram_inherited_fd: u32,
    /// Retains the actual original RAM backing offset.
    pub ram_backing_offset: u64,
    /// Supplies complete kernel, initrd and firmware correlations in that order.
    pub assets: [LaunchAsset; 3],
}

impl LaunchSelectionParts<'_> {
    /// Encodes full launch provenance into exact caller-owned bounded backing.
    ///
    /// # Errors
    /// Rejects malformed geometry, unsupported inputs or backing extent. This
    /// operation creates no original descriptors, RAM ownership or native Ready.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        let (machine, cpu, properties, base) = match self.architecture {
            LaunchArchitecture::X86_64 => ("microvm", "qemu64", 33, 0),
            LaunchArchitecture::Arm64 => ("virt", "cortex-a72", 30, 0x4000_0000),
        };
        if self.kernel_command_line.len() > LAUNCH_COMMAND_LINE_MAX_BYTES
            || 128 + machine.len() + cpu.len() + self.kernel_command_line.len() + 3 * 64
                != body.len()
            || body.len() > LAUNCH_SELECTION_MAX_BYTES
        {
            return Err(WholeControlError::Body);
        }
        body.fill(0);
        body[..8].copy_from_slice(b"CWHLLCH\0");
        for (offset, value) in [
            (8, 1),
            (12, body.len() as u32),
            (16, self.architecture as u32),
            (20, 4),
            (24, 1),
            (28, properties),
            (48, 50),
            (52, 1),
            (60, self.kernel_command_line.len() as u32),
            (64, 3),
            (104, self.ram_backing_kind),
            (108, self.ram_inherited_fd),
        ] {
            put_u32(body, offset, value);
        }
        put_u64(body, 32, base);
        put_u64(body, 40, self.ram_byte_length);
        put_u64(body, 112, self.ram_backing_offset);
        body[56..58].copy_from_slice(&(machine.len() as u16).to_be_bytes());
        body[58..60].copy_from_slice(&(cpu.len() as u16).to_be_bytes());
        body[72..104].copy_from_slice(&Sha256::digest(self.kernel_command_line.as_bytes()));
        let mut offset = 128;
        for part in [machine, cpu, self.kernel_command_line] {
            body[offset..offset + part.len()].copy_from_slice(part.as_bytes());
            offset += part.len();
        }
        for asset in self.assets {
            body[offset..offset + 2].copy_from_slice(&asset.role.to_be_bytes());
            body[offset + 2..offset + 4].copy_from_slice(&u16::from(asset.present).to_be_bytes());
            put_u32(body, offset + 4, asset.inherited_fd);
            put_u64(body, offset + 8, asset.byte_length);
            body[offset + 16..offset + 48].copy_from_slice(&asset.sha256);
            offset += 64;
        }
        LaunchSelection::decode(body)?;
        Ok(())
    }
}

fn decode_asset(body: &[u8], role: u16) -> Result<LaunchAsset, WholeControlError> {
    let present = u16::from_be_bytes([body[2], body[3]]);
    let fd = read_u32(body, 4);
    let length = read_u64(body, 8);
    let mut sha256 = [0; 32];
    sha256.copy_from_slice(&body[16..48]);
    if u16::from_be_bytes([body[0], body[1]]) != role
        || body[48..64] != [0; 16]
        || !matches!(present, 0 | 1)
        || (present == 0 && (fd != u32::MAX || length != 0 || sha256 != [0; 32]))
        || (present == 1 && (!(3..=1024).contains(&fd) || length == 0 || sha256 == [0; 32]))
    {
        return Err(WholeControlError::Body);
    }
    Ok(LaunchAsset {
        role,
        present: present == 1,
        inherited_fd: fd,
        byte_length: length,
        sha256,
    })
}

fn ascii(body: &[u8]) -> Result<&str, WholeControlError> {
    if !body.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err(WholeControlError::Body);
    }
    std::str::from_utf8(body).map_err(|_| WholeControlError::Body)
}
