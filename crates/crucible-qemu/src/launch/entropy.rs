//! Guest entropy materialization for deterministic QEMU launches.

use std::fs;
use std::path::{Path, PathBuf};

pub(super) const GUEST_ENTROPY_FW_CFG_NAME: &str = "opt/crucible/seed";
pub(super) const GUEST_ENTROPY_SEED_FILE_NAME: &str = "crucible-guest-entropy-seed.bin";
pub(super) const GUEST_ENTROPY_RNG_ID: &str = "crucible-rng0";
const GUEST_ENTROPY_SEED_BYTES: usize = 32;

/// A deterministic seed delivered to the guest through QEMU firmware config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestEntropySeed {
    bytes: [u8; GUEST_ENTROPY_SEED_BYTES],
}

impl GuestEntropySeed {
    /// Derives guest entropy from a scenario seed.
    #[must_use]
    pub fn from_scenario_seed(scenario_seed: u64) -> Self {
        let mut bytes = [0; GUEST_ENTROPY_SEED_BYTES];
        let mut state = scenario_seed ^ 0x4352_5543_4942_4c45;

        for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            state = state
                .wrapping_add(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(index as u64);
            chunk.copy_from_slice(&splitmix64(state).to_le_bytes());
        }

        Self { bytes }
    }

    /// Returns the seed bytes as delivered to the guest entropy boundary.
    #[must_use]
    pub fn bytes(&self) -> &[u8; GUEST_ENTROPY_SEED_BYTES] {
        &self.bytes
    }

    /// Returns the seed bytes as lowercase hexadecimal text.
    #[must_use]
    pub fn to_lower_hex(&self) -> String {
        let mut hex = String::with_capacity(GUEST_ENTROPY_SEED_BYTES * 2);
        for byte in self.bytes {
            hex.push(nibble_to_hex(byte >> 4));
            hex.push(nibble_to_hex(byte & 0x0f));
        }
        hex
    }
}

/// A deterministic fw_cfg seed file required by a launch profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestEntropySeedFile {
    pub(super) file_name: &'static str,
    pub(super) bytes: [u8; GUEST_ENTROPY_SEED_BYTES],
}

impl GuestEntropySeedFile {
    /// Returns the file name referenced by the canonical QEMU `-fw_cfg` argument.
    #[must_use]
    pub fn file_name(&self) -> &'static str {
        self.file_name
    }

    /// Returns the exact bytes that must be written to the fw_cfg seed file.
    #[must_use]
    pub fn bytes(&self) -> &[u8; GUEST_ENTROPY_SEED_BYTES] {
        &self.bytes
    }

    /// Writes the deterministic seed file into a QEMU working directory.
    ///
    /// # Errors
    ///
    /// Returns any filesystem error reported while writing the seed file.
    pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        let path = dir.as_ref().join(self.file_name);
        fs::write(&path, self.bytes.as_slice())?;
        Ok(path)
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked to four bits"),
    }
}
