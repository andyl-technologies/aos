//! Content-addressed definition for the Rust-plugin single-VM fingerprint.
//!
//! The Rust control plugin, not the C trace plugin, is the fingerprint
//! authority for this definition. Its content-addressed identity therefore
//! binds the Rust plugin build (`rust_plugin_build_digest`) exactly where the
//! imported C-trace definition binds `trace_plugin_build_digest`, so a stream
//! produced against a different plugin build can never be compared as equal.
//!
//! The canonical material is a newline-joined, order-fixed key/value block:
//!
//! ```text
//! crucible.qemu.rust-plugin-fingerprint.v1
//! status=canonical
//! cadence_icount=4000000
//! target=4000000
//! target=8000000
//! target=12000000
//! component=aggregate-icount
//! component=all-vcpu-register-files-sha256-v1
//! component=full-guest-ram-sha256-v1
//! component=qemu-non-ram-vmstate-sha256-v1
//! complete_current_device_state=true
//! event_boundary_sampling=true
//! process_argv_attestation=raw-unix-argv-v2-required
//! rr_switch_quantum=4096
//! vcpu_count=2
//! qemu_build_digest=<64 hex>
//! rust_plugin_build_digest=<64 hex>
//! ```

use crucible::ContentHash;

use crate::single_vm_fingerprint::SingleVmFingerprintGateError;

/// Content-addressing domain for the single-vCPU Rust-plugin fingerprint.
///
/// Distinct from the imported C-trace domain
/// `crucible.qemu.trace-fingerprint-definition.v3`, so the two authorities mint
/// disjoint definition digests even for identical cadence and topology. Used for
/// the single-vCPU topology only; multi-vCPU topologies use
/// [`RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN`].
pub const RUST_PLUGIN_FINGERPRINT_DOMAIN: &str = "crucible.qemu.rust-plugin-fingerprint.v1";

/// Content-addressing domain for the multi-vCPU Rust-plugin fingerprint.
///
/// The `.v2` domain the single-vCPU `.v1` definition reserved for the multi-vCPU
/// widening (M3). It is a distinct content-addressing domain, so a multi-vCPU
/// definition digest can never collide with a `.v1` single-vCPU one even at the
/// same cadence, and the frozen `.v1` constants are untouched. The topology
/// (`vcpu_count`) still enters the canonical material, so distinct `-smp N` mint
/// distinct digests within this domain too.
pub const RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN: &str = "crucible.qemu.rust-plugin-fingerprint.v2";

/// Fixed periodic aggregate-icount cadence for the Rust-plugin fingerprint.
pub const CADENCE_ICOUNT: u64 = 4_000_000;

/// The ascending aggregate-icount boundaries sampled for one run.
///
/// Every target is below the diskless firmware guest's idle onset (~15.8M
/// icount), so each is reached by a busy quantum that stops exactly at the
/// host-published ceiling, giving an instruction-exact, deterministic guest
/// state at every boundary. The last target is the run horizon.
pub const TARGET_ICOUNTS: [u64; 3] = [4_000_000, 8_000_000, 12_000_000];

/// The width of a 64-character lowercase-hex build digest string.
const BUILD_DIGEST_HEX_LEN: usize = 64;

/// The Rust-plugin fingerprint definition minted for one fixed launch.
///
/// Combining the fixed cadence and topology with the observed QEMU and Rust
/// plugin build digests yields the content-addressed `definition_digest`
/// threaded through the scenario, the run inputs, and every published sample.
///
/// The topology (`vcpu_count`, `rr_switch_quantum`) selects the content-
/// addressing domain: a single vCPU mints under [`RUST_PLUGIN_FINGERPRINT_DOMAIN`]
/// (`.v1`), and `vcpu_count > 1` mints under [`RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN`]
/// (`.v2`), the multi-vCPU widening landed in M3 (T-TIME-9 / T-QEMU-16 /
/// T-PLUG-26). The frozen `.v1` single-vCPU constants and digest are unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustPluginFingerprintDefinition {
    rr_switch_quantum: u64,
    vcpu_count: u32,
    qemu_build_digest: String,
    rust_plugin_build_digest: String,
}

impl RustPluginFingerprintDefinition {
    /// Builds a definition from the launch topology and observed build digests.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError::InvalidScenario`] when the vCPU
    /// count or RR switch quantum is zero, or either build digest is not a
    /// 64-character lowercase-hex string.
    pub fn new(
        rr_switch_quantum: u64,
        vcpu_count: u32,
        qemu_build_digest: impl Into<String>,
        rust_plugin_build_digest: impl Into<String>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if vcpu_count == 0 {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "rust-plugin fingerprint vcpu count must be non-zero",
            });
        }
        if rr_switch_quantum == 0 {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "rust-plugin fingerprint rr switch quantum must be non-zero",
            });
        }
        let qemu_build_digest = qemu_build_digest.into();
        let rust_plugin_build_digest = rust_plugin_build_digest.into();
        if !is_lower_hex_64(&qemu_build_digest) {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "qemu build digest must be 64 lowercase hex characters",
            });
        }
        if !is_lower_hex_64(&rust_plugin_build_digest) {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "rust plugin build digest must be 64 lowercase hex characters",
            });
        }
        Ok(Self {
            rr_switch_quantum,
            vcpu_count,
            qemu_build_digest,
            rust_plugin_build_digest,
        })
    }

    /// Returns the content-addressing domain this definition mints under.
    ///
    /// A single-vCPU definition uses [`RUST_PLUGIN_FINGERPRINT_DOMAIN`] (`.v1`);
    /// a multi-vCPU definition uses [`RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN`]
    /// (`.v2`).
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        if self.vcpu_count == 1 {
            RUST_PLUGIN_FINGERPRINT_DOMAIN
        } else {
            RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN
        }
    }

    /// Returns the run horizon icount (the last sampled target).
    #[must_use]
    pub const fn run_horizon_icount(&self) -> u64 {
        TARGET_ICOUNTS[TARGET_ICOUNTS.len() - 1]
    }

    /// Returns the ascending aggregate-icount sample targets.
    #[must_use]
    pub const fn targets(&self) -> [u64; 3] {
        TARGET_ICOUNTS
    }

    /// Returns the 32-byte content-addressed fingerprint definition digest.
    #[must_use]
    pub fn definition_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(self.domain(), &self.canonical_material()).bytes
    }

    fn canonical_material(&self) -> String {
        let mut lines = vec![
            self.domain().to_owned(),
            "status=canonical".to_owned(),
            format!("cadence_icount={CADENCE_ICOUNT}"),
        ];
        for target in TARGET_ICOUNTS {
            lines.push(format!("target={target}"));
        }
        lines.extend(
            [
                "component=aggregate-icount",
                "component=all-vcpu-register-files-sha256-v1",
                "component=full-guest-ram-sha256-v1",
                "component=qemu-non-ram-vmstate-sha256-v1",
                "complete_current_device_state=true",
                "event_boundary_sampling=true",
                "process_argv_attestation=raw-unix-argv-v2-required",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        lines.push(format!("rr_switch_quantum={}", self.rr_switch_quantum));
        lines.push(format!("vcpu_count={}", self.vcpu_count));
        lines.push(format!("qemu_build_digest={}", self.qemu_build_digest));
        lines.push(format!(
            "rust_plugin_build_digest={}",
            self.rust_plugin_build_digest
        ));
        lines.join("\n")
    }
}

/// Returns whether `value` is exactly 64 lowercase-hex characters.
fn is_lower_hex_64(value: &str) -> bool {
    value.len() == BUILD_DIGEST_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> String {
        core::iter::repeat_n(format!("{seed:02x}"), 32).collect()
    }

    #[test]
    fn targets_are_ascending_and_below_idle_onset() {
        let mut previous = 0;
        for target in TARGET_ICOUNTS {
            assert!(target > previous, "targets must be strictly ascending");
            assert!(
                target < 15_825_232,
                "targets must stay in the busy boot phase"
            );
            previous = target;
        }
    }

    #[test]
    fn distinct_plugin_builds_mint_distinct_digests() {
        let base = RustPluginFingerprintDefinition::new(4096, 2, digest(0x11), digest(0x22))
            .expect("base definition");
        let other_plugin =
            RustPluginFingerprintDefinition::new(4096, 2, digest(0x11), digest(0x33))
                .expect("other-plugin definition");
        assert_ne!(base.definition_digest(), other_plugin.definition_digest());
    }

    #[test]
    fn same_inputs_are_content_stable() {
        let first = RustPluginFingerprintDefinition::new(4096, 2, digest(0x11), digest(0x22))
            .expect("first definition");
        let second = RustPluginFingerprintDefinition::new(4096, 2, digest(0x11), digest(0x22))
            .expect("second definition");
        assert_eq!(first.definition_digest(), second.definition_digest());
        assert_eq!(first.run_horizon_icount(), 12_000_000);
    }

    #[test]
    fn vcpu_count_selects_the_content_addressing_domain() {
        let single = RustPluginFingerprintDefinition::new(4096, 1, digest(0x11), digest(0x22))
            .expect("single-vCPU definition");
        let multi = RustPluginFingerprintDefinition::new(4096, 4, digest(0x11), digest(0x22))
            .expect("multi-vCPU definition");
        assert_eq!(single.domain(), RUST_PLUGIN_FINGERPRINT_DOMAIN);
        assert_eq!(multi.domain(), RUST_PLUGIN_FINGERPRINT_NVCPU_DOMAIN);
        // The domain plus the vcpu_count both differ, so the digests are disjoint.
        assert_ne!(single.definition_digest(), multi.definition_digest());
    }

    #[test]
    fn single_vcpu_digest_is_frozen_under_v1() {
        // The single-vCPU definition must keep minting the exact frozen v1 digest
        // that the M1 gate pins, unchanged by the multi-vCPU domain split.
        let single = RustPluginFingerprintDefinition::new(4096, 1, digest(0x11), digest(0x22))
            .expect("single-vCPU definition");
        let expected = ContentHash::from_canonical_material(
            RUST_PLUGIN_FINGERPRINT_DOMAIN,
            &single.canonical_material(),
        )
        .bytes;
        assert_eq!(single.definition_digest(), expected);
        assert!(
            single
                .canonical_material()
                .starts_with(RUST_PLUGIN_FINGERPRINT_DOMAIN)
        );
    }

    #[test]
    fn rejects_non_hex_build_digest() {
        assert!(RustPluginFingerprintDefinition::new(4096, 2, "not-hex", digest(0x22)).is_err());
        assert!(RustPluginFingerprintDefinition::new(4096, 0, digest(0x11), digest(0x22)).is_err());
    }
}
