//! Explicit version-two canonical launch provenance for the original constructor.
//!
//! ```text
//! Launch256: CWHLLCH\0, version2/extent, original Launch1 fields through127,
//! run_seed/RRquantum, canonical disabled endpoints/icount/SIM/RTC/RNG fields,
//! reserved204..255; exact declared strings; four original Asset64 records
//! ```
//!
//! These bytes request a profile and correlate its original resources. Actual
//! source constructors independently enroll the four CPUs, RAM, clock, images,
//! RNG and remaining device/backend cohorts before source readiness is possible.

use sha2::{Digest, Sha256};

use super::launch::{LAUNCH_SELECTION_MAX_BYTES, LaunchArchitecture, LaunchAsset};
use crate::whole_control::{WholeControlError, put_u32, put_u64, read_u32, read_u64};

/// Counts the complete fixed explicit version-two launch prefix.
pub const LAUNCH2_HEADER_BYTES: usize = 256;

/// Retains complete original requested version-two launch provenance.
pub struct LaunchSelection2<'a> {
    body: &'a [u8],
    /// Identifies the explicitly requested source architecture profile.
    pub architecture: LaunchArchitecture,
    /// Borrows the complete original kernel command line.
    pub kernel_command_line: &'a str,
    /// Retains the original guest RAM byte extent.
    pub ram_byte_length: u64,
    /// Selects original inherited RAM one or actual source constructor two.
    pub ram_backing_kind: u32,
    /// Retains original inherited RAM FD or UINT32_MAX for native construction.
    pub ram_inherited_fd: u32,
    /// Retains the original inherited backing offset, or zero for native RAM.
    pub ram_backing_offset: u64,
    /// Retains the actual requested seed of the original source RNG.
    pub run_seed: u64,
    /// Retains the original SIM scheduler's instruction switch quantum.
    pub rr_switch_quantum: u64,
    /// Retains kernel, initrd, effective firmware and entropy in that order.
    pub assets: [LaunchAsset; 4],
}

impl<'a> LaunchSelection2<'a> {
    /// Validates every complete version-two launch byte before exposing fields.
    ///
    /// # Errors
    /// Rejects malformed geometry, reserved fields, unsupported canonical
    /// arguments, duplicate resource descriptors or changed full commitments.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if body.len() < LAUNCH2_HEADER_BYTES + 4 * 64
            || body.len() > LAUNCH_SELECTION_MAX_BYTES
            || body[..8] != *b"CWHLLCH\0"
            || read_u32(body, 8) != 2
            || read_u32(body, 12) as usize != body.len()
            || read_u32(body, 20) != 4
            || read_u32(body, 24) != 1
            || read_u32(body, 48) != 50
            || read_u32(body, 52) != 1
            || read_u32(body, 64) != 4
            || read_u32(body, 68) != 0
            || body[120..128] != [0; 8]
            || body[204..256] != [0; 52]
            || read_u32(body, 144) != 63
            || read_u32(body, 148) != 0
            || read_u32(body, 152) != 0
            || read_u32(body, 156) != 0
            || read_u32(body, 160) != 1
            || read_u32(body, 164) != 1
            || read_u32(body, 168) != 1
            || read_u32(body, 184) != 1
            || read_u64(body, 192) != 1_767_225_600
            || read_u32(body, 200) != 32
            || !(1..=i32::MAX as u64).contains(&read_u64(body, 136))
        {
            return Err(WholeControlError::Body);
        }

        let (architecture, machine, cpu, properties, base, features) = match read_u32(body, 16) {
            1 => (
                LaunchArchitecture::X86_64,
                "pc-q35-9.2",
                "qemu64,-rdrand,-rdseed",
                0,
                0,
                3,
            ),
            2 => (
                LaunchArchitecture::Arm64,
                "virt",
                "cortex-a72,pmu=off",
                30,
                0x4000_0000,
                4,
            ),
            _ => return Err(WholeControlError::Body),
        };
        let ram_length = read_u64(body, 40);
        let backing_kind = read_u32(body, 104);
        let ram_fd = read_u32(body, 108);
        let ram_offset = read_u64(body, 112);
        if read_u32(body, 28) != properties
            || read_u64(body, 32) != base
            || read_u32(body, 188) != features
            || ram_length == 0
            || !ram_length.is_multiple_of(4096)
            || ram_length > 3 * 1024 * 1024 * 1024
            || !matches!(backing_kind, 1 | 2)
            || (backing_kind == 1
                && (!(3..=1024).contains(&ram_fd)
                    || !ram_offset.is_multiple_of(4096)
                    || ram_offset.checked_add(ram_length).is_none()))
            || (backing_kind == 2 && (ram_fd != u32::MAX || ram_offset != 0))
        {
            return Err(WholeControlError::Body);
        }

        let command_length = read_u32(body, 60) as usize;
        if command_length > 3072 {
            return Err(WholeControlError::Body);
        }
        let lengths = [
            read_u16(body, 56),
            read_u16(body, 58),
            command_length,
            read_u16(body, 172),
            read_u16(body, 174),
            read_u16(body, 176),
            read_u16(body, 178),
            read_u16(body, 180),
            read_u16(body, 182),
        ];
        let strings_extent = lengths
            .iter()
            .try_fold(0usize, |sum, length| sum.checked_add(*length))
            .ok_or(WholeControlError::Body)?;
        if LAUNCH2_HEADER_BYTES + strings_extent + 4 * 64 != body.len() {
            return Err(WholeControlError::Body);
        }
        let mut cursor = LAUNCH2_HEADER_BYTES;
        let mut strings = [""; 9];
        for (index, length) in lengths.into_iter().enumerate() {
            let bytes = &body[cursor..cursor + length];
            if !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                return Err(WholeControlError::Body);
            }
            strings[index] = std::str::from_utf8(bytes).map_err(|_| WholeControlError::Body)?;
            cursor += length;
        }
        if strings[0] != machine
            || strings[1] != cpu
            || strings[3] != "2026-01-01T00:00:00"
            || strings[4] != "rng-builtin"
            || strings[5] != "crucible-rng0"
            || strings[6] != "virtio-rng-pci"
            || strings[7] != "pcie.0"
            || strings[8] != "opt/crucible/seed"
            || body[72..104] != Sha256::digest(strings[2].as_bytes())[..]
        {
            return Err(WholeControlError::Correlation);
        }
        let mut assets = [LaunchAsset {
            role: 0,
            present: false,
            inherited_fd: u32::MAX,
            byte_length: 0,
            sha256: [0; 32],
        }; 4];
        for (index, asset) in assets.iter_mut().enumerate() {
            let row = &body[cursor..cursor + 64];
            let presence = read_u16(row, 2);
            let fd = read_u32(row, 4);
            let length = read_u64(row, 8);
            let mut digest = [0; 32];
            digest.copy_from_slice(&row[16..48]);
            if read_u16(row, 0) != index + 1
                || !matches!(presence, 0 | 1)
                || row[48..] != [0; 16]
                || (presence == 0 && (fd != u32::MAX || length != 0 || digest != [0; 32]))
                || (presence == 1 && (fd != 10 + index as u32 || length == 0 || digest == [0; 32]))
                || (backing_kind == 1 && presence == 1 && fd == ram_fd)
            {
                return Err(WholeControlError::Body);
            }
            *asset = LaunchAsset {
                role: (index + 1) as u16,
                present: presence == 1,
                inherited_fd: fd,
                byte_length: length,
                sha256: digest,
            };
            cursor += 64;
        }
        if !assets[0].present
            || !assets[3].present
            || assets[3].byte_length != 32
            || (architecture == LaunchArchitecture::X86_64 && !assets[2].present)
            || (architecture == LaunchArchitecture::Arm64 && assets[2].present)
        {
            return Err(WholeControlError::Body);
        }
        Ok(Self {
            body,
            architecture,
            kernel_command_line: strings[2],
            ram_byte_length: ram_length,
            ram_backing_kind: backing_kind,
            ram_inherited_fd: ram_fd,
            ram_backing_offset: ram_offset,
            run_seed: read_u64(body, 128),
            rr_switch_quantum: read_u64(body, 136),
            assets,
        })
    }

    /// Borrows every complete original version-two launch byte.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// Supplies original requested provenance to the bounded version-two encoder.
pub struct LaunchSelection2Parts<'a> {
    /// Selects the explicit source architecture profile.
    pub architecture: LaunchArchitecture,
    /// Supplies every original kernel command-line byte.
    pub kernel_command_line: &'a str,
    /// Supplies the original RAM byte extent.
    pub ram_byte_length: u64,
    /// Selects original inherited RAM one or actual native constructor two.
    pub ram_backing_kind: u32,
    /// Supplies original RAM descriptor or UINT32_MAX for native construction.
    pub ram_inherited_fd: u32,
    /// Supplies original RAM backing offset or zero for native construction.
    pub ram_backing_offset: u64,
    /// Supplies the original scenario/run seed consumed by the native RNG.
    pub run_seed: u64,
    /// Supplies the original SIM scheduler switch quantum in instructions.
    pub rr_switch_quantum: u64,
    /// Supplies complete kernel, initrd, firmware and entropy commitments.
    pub assets: [LaunchAsset; 4],
}

impl LaunchSelection2Parts<'_> {
    /// Counts the complete version-two body before allocating original backing.
    ///
    /// # Errors
    /// Rejects oversized or overflowing complete command-line provenance.
    pub fn encoded_len(&self) -> Result<usize, WholeControlError> {
        if self.kernel_command_line.len() > 3072 {
            return Err(WholeControlError::Body);
        }
        let strings = self.strings();
        strings
            .iter()
            .try_fold(LAUNCH2_HEADER_BYTES + 4 * 64, |sum, value| {
                sum.checked_add(value.len())
            })
            .filter(|extent| *extent <= LAUNCH_SELECTION_MAX_BYTES)
            .ok_or(WholeControlError::Body)
    }

    /// Encodes the complete original profile into exact preowned byte backing.
    ///
    /// # Errors
    /// Rejects malformed arguments, FD correlations, resource geometry or extent.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        if body.len() != self.encoded_len()? {
            return Err(WholeControlError::Body);
        }
        body.fill(0);
        body[..8].copy_from_slice(b"CWHLLCH\0");
        let (properties, base, features) = match self.architecture {
            LaunchArchitecture::X86_64 => (0, 0, 3),
            LaunchArchitecture::Arm64 => (30, 0x4000_0000, 4),
        };
        for (offset, value) in [
            (8, 2),
            (12, body.len() as u32),
            (16, self.architecture as u32),
            (20, 4),
            (24, 1),
            (28, properties),
            (48, 50),
            (52, 1),
            (60, self.kernel_command_line.len() as u32),
            (64, 4),
            (104, self.ram_backing_kind),
            (108, self.ram_inherited_fd),
            (144, 63),
            (160, 1),
            (164, 1),
            (168, 1),
            (184, 1),
            (188, features),
            (200, 32),
        ] {
            put_u32(body, offset, value);
        }
        for (offset, value) in [
            (32, base),
            (40, self.ram_byte_length),
            (112, self.ram_backing_offset),
            (128, self.run_seed),
            (136, self.rr_switch_quantum),
            (192, 1_767_225_600),
        ] {
            put_u64(body, offset, value);
        }
        body[72..104].copy_from_slice(&Sha256::digest(self.kernel_command_line.as_bytes()));
        let mut cursor = LAUNCH2_HEADER_BYTES;
        for (index, (offset, value)) in [56, 58, 60, 172, 174, 176, 178, 180, 182]
            .into_iter()
            .zip(self.strings())
            .enumerate()
        {
            if index != 2 {
                body[offset..offset + 2].copy_from_slice(&(value.len() as u16).to_be_bytes());
            }
            body[cursor..cursor + value.len()].copy_from_slice(value.as_bytes());
            cursor += value.len();
        }
        for asset in self.assets {
            body[cursor..cursor + 2].copy_from_slice(&asset.role.to_be_bytes());
            body[cursor + 2..cursor + 4].copy_from_slice(&u16::from(asset.present).to_be_bytes());
            put_u32(body, cursor + 4, asset.inherited_fd);
            put_u64(body, cursor + 8, asset.byte_length);
            body[cursor + 16..cursor + 48].copy_from_slice(&asset.sha256);
            cursor += 64;
        }
        LaunchSelection2::decode(body)?;
        Ok(())
    }

    fn strings(&self) -> [&str; 9] {
        let (machine, cpu) = match self.architecture {
            LaunchArchitecture::X86_64 => ("pc-q35-9.2", "qemu64,-rdrand,-rdseed"),
            LaunchArchitecture::Arm64 => ("virt", "cortex-a72,pmu=off"),
        };
        [
            machine,
            cpu,
            self.kernel_command_line,
            "2026-01-01T00:00:00",
            "rng-builtin",
            "crucible-rng0",
            "virtio-rng-pci",
            "pcie.0",
            "opt/crucible/seed",
        ]
    }
}

fn read_u16(body: &[u8], offset: usize) -> usize {
    usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]))
}
