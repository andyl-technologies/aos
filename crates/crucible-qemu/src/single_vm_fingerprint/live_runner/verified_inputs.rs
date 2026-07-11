//! Verified content identities for one production live fingerprint run.
//!
//! This module converts explicit SHA-256 component identities and exact guest-visible
//! text into [`SingleVmFingerprintRunInputs`]. It owns the canonical guest-image
//! manifest, hashes seed bytes under a dedicated domain, admits only the explicitly
//! empty injected-input sequence, and extends a base launch definition with the
//! verified run inputs using unambiguous length framing.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{SingleVmFingerprintGateError, SingleVmFingerprintRunInputs};

const GUEST_MANIFEST_DOMAIN: &str = "crucible.qemu.live-run.guest-manifest.v1";
const SEED_BYTES_DOMAIN: &str = "crucible.qemu.live-run.seed-bytes.v1";
const EMPTY_INPUT_SEQUENCE_DOMAIN: &str = "crucible.qemu.live-run.injected-input-sequence.empty.v1";
const VERIFIED_LAUNCH_DEFINITION_DOMAIN: &str =
    "crucible.qemu.live-run.verified-launch-definition.v1";
const VERIFIED_RUN_INPUTS_MATERIAL_DOMAIN: &str =
    "crucible.qemu.live-run.verified-inputs-material.v1";

/// SHA-256 identities of the immutable diskless guest image components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGuestImageDigests {
    firmware: [u8; 32],
    kernel: [u8; 32],
    initrd: [u8; 32],
}

impl VerifiedGuestImageDigests {
    pub(super) fn diskless(firmware: [u8; 32], kernel: [u8; 32], initrd: [u8; 32]) -> Self {
        Self {
            firmware,
            kernel,
            initrd,
        }
    }

    fn validate(self) -> Result<Self, VerifiedLiveRunInputsError> {
        for (field, digest) in [
            ("firmware", self.firmware),
            ("kernel", self.kernel),
            ("initrd", self.initrd),
        ] {
            validate_nonzero_digest(field, digest)?;
        }
        Ok(self)
    }

    /// Returns the firmware image SHA-256 digest.
    #[must_use]
    pub const fn firmware(self) -> [u8; 32] {
        self.firmware
    }

    /// Returns the kernel image SHA-256 digest.
    #[must_use]
    pub const fn kernel(self) -> [u8; 32] {
        self.kernel
    }

    /// Returns the initial RAM filesystem SHA-256 digest.
    #[must_use]
    pub const fn initrd(self) -> [u8; 32] {
        self.initrd
    }
}

/// Verified immutable and guest-visible identities for one live run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLiveRunInputs {
    guest_components: VerifiedGuestImageDigests,
    canonical_guest_manifest: String,
    guest_manifest_digest: [u8; 32],
    kernel_cmdline: String,
    seed_digest: [u8; 32],
    empty_input_sequence_digest: [u8; 32],
    base_launch_digest: [u8; 32],
    launch_definition_digest: [u8; 32],
}

impl VerifiedLiveRunInputs {
    /// Verifies and derives the complete live run-input identity.
    ///
    /// `seed_bytes` are hashed directly; callers do not supply a claimed seed
    /// digest. The injected-input sequence is always the domain-separated empty
    /// sequence and cannot be replaced with an unverified event list.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedLiveRunInputsError`] when a component or base digest is
    /// all zero, the kernel command line is empty or contains a NUL/newline, or
    /// the seed byte sequence is empty.
    pub(super) fn new(
        guest_components: VerifiedGuestImageDigests,
        kernel_cmdline: impl Into<String>,
        seed_bytes: &[u8],
        base_launch_digest: [u8; 32],
    ) -> Result<Self, VerifiedLiveRunInputsError> {
        let guest_components = guest_components.validate()?;
        validate_nonzero_digest("base_launch_digest", base_launch_digest)?;
        let kernel_cmdline = kernel_cmdline.into();
        if kernel_cmdline.is_empty()
            || kernel_cmdline
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        {
            return Err(VerifiedLiveRunInputsError::InvalidKernelCmdline);
        }
        if seed_bytes.is_empty() {
            return Err(VerifiedLiveRunInputsError::EmptySeed);
        }

        let canonical_guest_manifest = canonical_guest_manifest(guest_components);
        let guest_manifest_digest = hash_segments(
            GUEST_MANIFEST_DOMAIN,
            &[("canonical-manifest", canonical_guest_manifest.as_bytes())],
        );
        let seed_digest = hash_segments(SEED_BYTES_DOMAIN, &[("seed-bytes", seed_bytes)]);
        let empty_input_sequence_digest = empty_input_sequence_digest();
        let launch_definition_digest = hash_segments(
            VERIFIED_LAUNCH_DEFINITION_DOMAIN,
            &[
                ("base-launch", &base_launch_digest),
                ("guest-manifest", &guest_manifest_digest),
                ("kernel-cmdline", kernel_cmdline.as_bytes()),
                ("seed", &seed_digest),
                ("injected-input-sequence", &empty_input_sequence_digest),
            ],
        );

        Ok(Self {
            guest_components,
            canonical_guest_manifest,
            guest_manifest_digest,
            kernel_cmdline,
            seed_digest,
            empty_input_sequence_digest,
            base_launch_digest,
            launch_definition_digest,
        })
    }

    /// Returns the explicit immutable guest component identities.
    #[must_use]
    pub const fn guest_components(&self) -> VerifiedGuestImageDigests {
        self.guest_components
    }

    /// Returns the canonical guest-image manifest.
    #[must_use]
    pub fn canonical_guest_manifest(&self) -> &str {
        &self.canonical_guest_manifest
    }

    /// Returns the SHA-256 digest of the canonical guest-image manifest.
    #[must_use]
    pub const fn guest_manifest_digest(&self) -> [u8; 32] {
        self.guest_manifest_digest
    }

    /// Returns the exact kernel command line.
    #[must_use]
    pub fn kernel_cmdline(&self) -> &str {
        &self.kernel_cmdline
    }

    /// Returns the domain-separated SHA-256 digest of the seed bytes.
    #[must_use]
    pub const fn seed_digest(&self) -> [u8; 32] {
        self.seed_digest
    }

    /// Returns the domain-separated digest of the explicitly empty input sequence.
    #[must_use]
    pub const fn injected_input_sequence_digest(&self) -> [u8; 32] {
        self.empty_input_sequence_digest
    }

    /// Returns zero, proving that no injected input event was admitted.
    #[must_use]
    pub const fn injected_input_count(&self) -> u64 {
        0
    }

    /// Returns the config-derived stable base-launch digest.
    #[must_use]
    pub const fn base_launch_digest(&self) -> [u8; 32] {
        self.base_launch_digest
    }

    /// Returns the launch digest extended with all verified run inputs.
    #[must_use]
    pub const fn launch_definition_digest(&self) -> [u8; 32] {
        self.launch_definition_digest
    }

    /// Returns canonical human-readable material for audit and provenance records.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        [
            VERIFIED_RUN_INPUTS_MATERIAL_DOMAIN.to_owned(),
            self.canonical_guest_manifest.clone(),
            format!(
                "guest_manifest_sha256={}",
                lower_hex(&self.guest_manifest_digest)
            ),
            format!("kernel_cmdline={}", self.kernel_cmdline),
            format!("seed_sha256={}", lower_hex(&self.seed_digest)),
            "injected_input_count=0".to_owned(),
            format!(
                "injected_input_sequence_sha256={}",
                lower_hex(&self.empty_input_sequence_digest)
            ),
            format!("base_launch_sha256={}", lower_hex(&self.base_launch_digest)),
            format!(
                "launch_definition_sha256={}",
                lower_hex(&self.launch_definition_digest)
            ),
        ]
        .join("\n")
    }

    /// Derives the existing single-VM run-input contract.
    ///
    /// # Errors
    ///
    /// Returns [`VerifiedLiveRunInputsError`] if the downstream run-input type
    /// rejects a derived digest. This would indicate an internal contract-width
    /// mismatch because every derived SHA-256 value is exactly 32 bytes.
    pub fn to_run_inputs(
        &self,
    ) -> Result<SingleVmFingerprintRunInputs, VerifiedLiveRunInputsError> {
        SingleVmFingerprintRunInputs::new(
            self.guest_manifest_digest,
            self.kernel_cmdline.clone(),
            self.seed_digest,
            self.empty_input_sequence_digest,
            self.launch_definition_digest,
        )
        .map_err(|source| VerifiedLiveRunInputsError::RunInputs { source })
    }

    /// Computes the stable digest for the only admitted injected-input sequence.
    #[must_use]
    pub fn empty_injected_input_sequence_digest() -> [u8; 32] {
        empty_input_sequence_digest()
    }
}

/// Invalid verified live run-input material.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifiedLiveRunInputsError {
    /// A SHA-256 identity used the all-zero sentinel.
    #[error("{field} must not use the all-zero SHA-256 sentinel")]
    ZeroDigest {
        /// Rejected digest field.
        field: &'static str,
    },
    /// Kernel command line was absent or not one exact line.
    #[error("kernel command line must be non-empty and contain no NUL or newline")]
    InvalidKernelCmdline,
    /// Seed bytes were absent.
    #[error("seed byte sequence must be non-empty")]
    EmptySeed,
    /// Existing run-input validation rejected derived material.
    #[error("derived single-VM run inputs were rejected: {source}")]
    RunInputs {
        /// Downstream validation failure.
        source: SingleVmFingerprintGateError,
    },
}

fn validate_nonzero_digest(
    field: &'static str,
    digest: [u8; 32],
) -> Result<(), VerifiedLiveRunInputsError> {
    if digest == [0; 32] {
        Err(VerifiedLiveRunInputsError::ZeroDigest { field })
    } else {
        Ok(())
    }
}

fn canonical_guest_manifest(components: VerifiedGuestImageDigests) -> String {
    [
        "crucible.qemu.live-run.guest-image-manifest.v1".to_owned(),
        "storage=diskless".to_owned(),
        "block_devices=0".to_owned(),
        format!("firmware_sha256={}", lower_hex(&components.firmware)),
        format!("kernel_sha256={}", lower_hex(&components.kernel)),
        format!("initrd_sha256={}", lower_hex(&components.initrd)),
        "disk_sha256=none".to_owned(),
    ]
    .join("\n")
}

fn empty_input_sequence_digest() -> [u8; 32] {
    hash_segments(
        EMPTY_INPUT_SEQUENCE_DOMAIN,
        &[("event-count", &0_u64.to_be_bytes())],
    )
}

fn hash_segments(domain: &str, segments: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_framed(&mut hasher, domain.as_bytes());
    hash_u64(&mut hasher, segments.len() as u64);
    for (label, bytes) in segments {
        hash_framed(&mut hasher, label.as_bytes());
        hash_framed(&mut hasher, bytes);
    }
    hasher.finalize().into()
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn components() -> VerifiedGuestImageDigests {
        VerifiedGuestImageDigests::diskless([1; 32], [2; 32], [3; 32])
    }

    fn verified(
        cmdline: &str,
        seed: &[u8],
    ) -> Result<VerifiedLiveRunInputs, VerifiedLiveRunInputsError> {
        VerifiedLiveRunInputs::new(components(), cmdline, seed, [9; 32])
    }

    #[test]
    fn derives_existing_run_inputs_from_verified_material() -> Result<(), Box<dyn Error>> {
        let verified = verified("console=ttyS0 panic=1", b"fixed-seed")?;
        let inputs = verified.to_run_inputs()?;
        assert_eq!(
            inputs.guest_image_digest(),
            verified.guest_manifest_digest()
        );
        assert_eq!(inputs.kernel_cmdline(), verified.kernel_cmdline());
        assert_eq!(inputs.seed_digest(), verified.seed_digest());
        assert_eq!(
            inputs.injected_input_sequence_digest(),
            verified.injected_input_sequence_digest()
        );
        assert_eq!(
            inputs.launch_definition_digest(),
            verified.launch_definition_digest()
        );
        assert_eq!(verified.injected_input_count(), 0);
        Ok(())
    }

    #[test]
    fn guest_component_change_updates_manifest_and_launch_identity() -> Result<(), Box<dyn Error>> {
        let diskless = verified("console=ttyS0", b"seed")?;
        let changed_components = VerifiedLiveRunInputs::new(
            VerifiedGuestImageDigests::diskless([1; 32], [8; 32], [3; 32]),
            "console=ttyS0",
            b"seed",
            [9; 32],
        )?;
        assert_ne!(
            diskless.guest_manifest_digest(),
            changed_components.guest_manifest_digest()
        );
        assert_ne!(
            diskless.launch_definition_digest(),
            changed_components.launch_definition_digest()
        );
        assert!(
            diskless
                .canonical_guest_manifest()
                .contains("disk_sha256=none")
        );
        Ok(())
    }

    #[test]
    fn cmdline_and_seed_are_bound_independently() -> Result<(), Box<dyn Error>> {
        let baseline = verified("console=ttyS0", b"seed-a")?;
        let cmdline = verified("console=ttyS1", b"seed-a")?;
        let seed = verified("console=ttyS0", b"seed-b")?;
        assert_eq!(
            baseline.guest_manifest_digest(),
            cmdline.guest_manifest_digest()
        );
        assert_eq!(baseline.seed_digest(), cmdline.seed_digest());
        assert_ne!(
            baseline.launch_definition_digest(),
            cmdline.launch_definition_digest()
        );
        assert_ne!(baseline.seed_digest(), seed.seed_digest());
        assert_ne!(
            baseline.launch_definition_digest(),
            seed.launch_definition_digest()
        );
        Ok(())
    }

    #[test]
    fn empty_input_digest_is_domain_separated_and_stable() {
        let first = VerifiedLiveRunInputs::empty_injected_input_sequence_digest();
        let second = VerifiedLiveRunInputs::empty_injected_input_sequence_digest();
        let raw_empty: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(first, second);
        assert_ne!(first, raw_empty);
        assert_ne!(first, [0; 32]);
    }

    #[test]
    fn invalid_placeholders_are_rejected() {
        assert_eq!(
            VerifiedLiveRunInputs::new(components(), "", b"seed", [9; 32]),
            Err(VerifiedLiveRunInputsError::InvalidKernelCmdline)
        );
        assert_eq!(
            VerifiedLiveRunInputs::new(components(), "console=ttyS0", b"", [9; 32]),
            Err(VerifiedLiveRunInputsError::EmptySeed)
        );
        assert_eq!(
            VerifiedLiveRunInputs::new(components(), "console=ttyS0", b"seed", [0; 32]),
            Err(VerifiedLiveRunInputsError::ZeroDigest {
                field: "base_launch_digest"
            })
        );
    }
}
