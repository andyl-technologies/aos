//! Model-aware private launch and native serial receipts for the successor driver.
//!
//! These closed records describe inert data. An installed source-owned profile
//! verifier must authenticate the selected model, dialect, complete asset and
//! tool closure before bootstrap, capture qualification, or modeled effects.
//! A serial birth never becomes a guest stdout write by adding a synthetic PID.
//!
//! ```text
//! {"facet":"serial","terminal":"system.terminal","output_id":"1",
//!  "tick":"1166530000","event_ordinal":"116654","tick_ordinal":"1",
//!  "causal_parent":"17","payload":[91]}
//! ```

use crucible_node_contract::{ContentRef, Id, U64, Validate};
use serde::{Deserialize, Serialize};

use super::Gem5Boundary;
use super::refusal::Gem5DiagnosticCreditPolicy;
use crate::ProviderError;

/// Selects a source-installed native protocol without implicit fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gem5ModelDialect {
    /// Preserves the existing fixed-ELF native/2 implementation unchanged.
    #[serde(rename = "crucible.gem5.native/2")]
    LegacySe,
    /// Selects the diagnostic-reservation SE successor.
    #[serde(rename = "crucible.gem5.native/3")]
    ReservedSe,
    /// Selects source-owned ARM full-system serial and diagnostic reservation.
    #[serde(rename = "crucible.gem5.arm-linux-native/1")]
    ArmLinux,
}

/// Retains an exact immutable role and its already measured portable bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ModelAsset {
    /// Names a fixed role-relative basename, never an operator source path.
    pub file: String,
    /// Commits to every original artifact byte and its finite extent.
    pub content: ContentRef,
    /// Binds the same bytes to the native model's independent SHA-256 check.
    pub sha256: String,
}

/// Commits to every ordered configuration path and source byte of a fixed model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ConfigurationTree {
    /// Bounds the complete ordered source-file roster.
    pub files: U64,
    /// Bounds the complete aggregate source byte extent.
    pub bytes: U64,
    /// Commits to the original canonical path, extent and content rows.
    pub sha256: String,
}

/// Describes exactly one source-owned realization family and its immutable roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Gem5ModelSelection {
    /// Selects the existing fixed no-ingress O3/cache/DDR3 checksum workload.
    #[serde(rename = "freestanding_o3")]
    FreestandingO3 {
        /// Selects exactly one supported guest instruction-set architecture.
        guest_isa: String,
        /// Retains the complete source-owned fixed executable.
        executable: Gem5ModelAsset,
    },
    /// Selects the fixed functional VExpress ARM Linux model and finite assets.
    #[serde(rename = "arm_linux")]
    ArmLinux {
        /// Retains the complete installed Linux ELF artifact.
        kernel: Box<Gem5ModelAsset>,
        /// Retains the complete fixed PID1 initramfs artifact.
        initramfs: Box<Gem5ModelAsset>,
        /// Retains the complete fixed ARM bootloader artifact.
        firmware: Box<Gem5ModelAsset>,
        /// Retains the complete source-owned board configuration tree.
        configuration: Gem5ConfigurationTree,
    },
    /// Selects the distinct closed VExpress ARM root-computation model and finite assets.
    #[serde(rename = "arm_linux_root")]
    ArmLinuxRoot {
        /// Retains the complete installed Linux ELF artifact.
        kernel: Box<Gem5ModelAsset>,
        /// Retains the complete fixed PID1 initramfs artifact.
        initramfs: Box<Gem5ModelAsset>,
        /// Retains the complete fixed ARM bootloader artifact.
        firmware: Box<Gem5ModelAsset>,
        /// Retains the complete source-owned board configuration tree.
        configuration: Gem5ConfigurationTree,
    },
}

impl Gem5ModelSelection {
    /// Validates role shape under an explicitly selected native dialect.
    ///
    /// This does not authenticate installed source or authorize model execution.
    /// Exact CPU, board and timing parameters remain fixed by the source-owned
    /// installed model artifact; no caller knobs are admitted here.
    ///
    /// # Errors
    /// Refuses incompatible dialects, unknown architectures, changed role names,
    /// invalid content commitments or configuration extents beyond finite credit.
    pub fn validate_for(&self, dialect: Gem5ModelDialect) -> Result<(), ProviderError> {
        match self {
            Self::FreestandingO3 {
                guest_isa,
                executable,
            } => {
                if dialect == Gem5ModelDialect::ArmLinux
                    || !matches!(guest_isa.as_str(), "x86_64" | "aarch64")
                {
                    return Err(ProviderError::Correlation(
                        "gem5 model and native dialect differ",
                    ));
                }
                validate_asset(executable, "guest.elf")
            }
            Self::ArmLinux {
                kernel,
                initramfs,
                firmware,
                configuration,
            }
            | Self::ArmLinuxRoot {
                kernel,
                initramfs,
                firmware,
                configuration,
            } => {
                if dialect != Gem5ModelDialect::ArmLinux {
                    return Err(ProviderError::Correlation(
                        "ARM model lacks its serial native dialect",
                    ));
                }
                validate_asset(kernel, "kernel.elf")?;
                validate_asset(initramfs, "initrd.img")?;
                validate_asset(firmware, "boot_v2.arm64")?;
                if configuration.files.get() > 4096
                    || configuration.bytes.get() > 64 * 1024 * 1024
                    || configuration.sha256.len() != 64
                    || !configuration
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ProviderError::Frame(
                        "ARM configuration tree exceeds its closed source schema",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn validate_asset(asset: &Gem5ModelAsset, expected: &str) -> Result<(), ProviderError> {
    asset.content.validate()?;
    if asset.file != expected
        || asset.content.length.get() == 0
        || asset.content.length.get() > 1024 * 1024 * 1024
        || asset.sha256.len() != 64
        || !asset
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderError::Frame(
            "gem5 immutable model asset role or extent differs",
        ));
    }
    Ok(())
}

/// Retains the native model's inert digest and extent for one immutable role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5NativeAssetBinding {
    /// Retains the exact finite observed immutable byte extent.
    pub bytes: U64,
    /// Retains the native independently measured role SHA-256.
    pub sha256: String,
}

/// Retains all three mandatory source-owned ARM guest roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ArmNativeAssets {
    /// Retains the original installed Linux ELF binding.
    pub kernel: Gem5NativeAssetBinding,
    /// Retains the original fixed initramfs binding.
    pub initramfs: Gem5NativeAssetBinding,
    /// Retains the original fixed ARM bootloader binding.
    pub firmware: Gem5NativeAssetBinding,
}

/// Describes native ARM realization data without granting execution admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ArmNativeScope {
    /// Must select the closed model-scope record edition.
    pub schema: String,
    /// Must identify the fixed source-owned functional ARM board model.
    pub model_id: String,
    /// Reports that this is a full-system realization, not guest stdout emulation.
    pub full_system: bool,
    /// Remains false; only an installed host certificate can qualify capture.
    pub complete_process_closure_qualified: bool,
    /// Remains false for the fixed functional Atomic timing model.
    pub cpu_timing_qualified: bool,
    /// Remains false; an early UART byte does not prove application readiness.
    pub guest_readiness_qualified: bool,
    /// Retains every mandatory original native guest asset role.
    pub guest_assets: Gem5ArmNativeAssets,
    /// Retains the complete original native board configuration commitment.
    pub configuration_tree: Gem5ConfigurationTree,
}

/// Retains ARM readiness under explicitly selected model and dialect custody.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5ArmNativeReady {
    /// Must select the private readiness response kind.
    pub kind: String,
    /// Retains the explicitly installed ARM protocol schema without fallback.
    pub schema: Gem5ModelDialect,
    /// Names the original indivisible owner whose kernel peer is authenticated.
    pub owner: Id,
    /// Names the source or freshly rebound native incarnation.
    pub incarnation: Id,
    /// Fences older incarnations without wrapping.
    pub generation: U64,
    /// Classifies original, reconnected, captured or restored operational routing.
    pub continuation: String,
    /// Retains the mandatory finite diagnostic reservation/refusal policy.
    pub diagnostic_credit_policy: Gem5DiagnosticCreditPolicy,
    /// Retains the native callback cut independently of modeled coverage.
    pub boundary: Gem5Boundary,
    /// Retains inert native source/model commitments, never a public capability.
    pub model_scope: Gem5ArmNativeScope,
}

impl Gem5ArmNativeReady {
    /// Checks readiness data against exact retained model and owner selection.
    ///
    /// Installed source/tool verification and authentic kernel peer supervision
    /// remain prerequisites. This structural check cannot mint a live certificate.
    ///
    /// # Errors
    /// Refuses foreign scope, old dialects, absent finite credit policy, changed
    /// assets/configuration, unsupported routing, or native admission overclaims.
    pub fn validate_selection(
        &self,
        selection: &Gem5ModelSelection,
        owner: &Id,
        incarnation: &Id,
        generation: U64,
    ) -> Result<(), ProviderError> {
        selection.validate_for(self.schema)?;
        let (Gem5ModelSelection::ArmLinux {
            kernel,
            initramfs,
            firmware,
            configuration,
        }
        | Gem5ModelSelection::ArmLinuxRoot {
            kernel,
            initramfs,
            firmware,
            configuration,
        }) = selection
        else {
            return Err(ProviderError::Correlation(
                "ARM readiness selected a different realization",
            ));
        };
        let scope = &self.model_scope;
        let policy = &self.diagnostic_credit_policy;
        if self.kind != "ready"
            || self.schema != Gem5ModelDialect::ArmLinux
            || &self.owner != owner
            || &self.incarnation != incarnation
            || self.generation != generation
            || !matches!(
                self.continuation.as_str(),
                "original" | "reconnected" | "captured" | "restored"
            )
            || policy.schema != "crucible.gem5.diagnostic-credit-policy.v1"
            || policy.refusal_schema != "crucible.gem5.run-refused.v1"
            || policy.maximum_object_bytes.get() != 64 * 1024 * 1024
            || policy.maximum_total_bytes.get() != 256 * 1024 * 1024
            || policy.maximum_files.get() != 1024
            || scope.schema != "crucible.gem5.model-scope.v1"
            || scope.model_id
                != match selection {
                    Gem5ModelSelection::ArmLinuxRoot { .. } => {
                        "arm-linux-vexpress-atomic-root-functional-v1"
                    }
                    Gem5ModelSelection::ArmLinux { .. } => {
                        "arm-linux-vexpress-atomic-functional-v1"
                    }
                    Gem5ModelSelection::FreestandingO3 { .. } => "unsupported",
                }
            || !scope.full_system
            || scope.complete_process_closure_qualified
            || scope.cpu_timing_qualified
            || scope.guest_readiness_qualified
            || scope.configuration_tree != *configuration
        {
            return Err(ProviderError::Correlation(
                "ARM readiness differs from installed model custody",
            ));
        }
        for (observed, original) in [
            (&scope.guest_assets.kernel, kernel),
            (&scope.guest_assets.initramfs, initramfs),
            (&scope.guest_assets.firmware, firmware),
        ] {
            if observed.bytes != original.content.length || observed.sha256 != original.sha256 {
                return Err(ProviderError::Correlation(
                    "ARM native guest role differs from selected artifact",
                ));
            }
        }
        Ok(())
    }
}

/// Retains an actual original native Terminal byte and callback birth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gem5SerialPublication {
    /// Names the native FIFO's non-reused original publication identity.
    pub output_id: U64,
    /// Retains the actual native callback tick in picoseconds.
    pub tick: U64,
    /// Retains the global serviced-callback ordinal at byte birth.
    pub event_ordinal: U64,
    /// Retains the native same-time callback ordinal without normalization.
    pub tick_ordinal: U64,
    /// Retains the explicitly bound original sealed input parent.
    pub causal_parent: U64,
    /// Must select the serial facet under this source-owned native model.
    pub facet: String,
    /// Names the source-owned native Terminal, not a modeled guest descriptor.
    pub terminal: String,
    /// Retains the original single byte until its exact FIFO acknowledgment.
    pub payload: Vec<u8>,
}

impl Gem5SerialPublication {
    /// Checks an original byte against the actual native callback boundary.
    ///
    /// No live source authority, publication permission, or acknowledgment is
    /// created by structural validation. The owner separately authenticates its
    /// original prefix request, full range, peer, model and installed policy.
    ///
    /// # Errors
    /// Refuses foreign facets, synthetic console fields, changed original FIFO
    /// identity or parent, invalid extents, and absent or altered callback birth.
    pub fn validate_birth(
        &self,
        before: &Gem5Boundary,
        after: &Gem5Boundary,
        original_id: U64,
        original_parent: U64,
    ) -> Result<(), ProviderError> {
        if self.facet != "serial"
            || self.terminal != "system.terminal"
            || self.payload.len() != 1
            || self.output_id.get() == 0
            || self.output_id != original_id
            || self.causal_parent != original_parent
            || self.tick != after.tick
            || self.event_ordinal != after.ordinal
            || self.tick_ordinal != after.tick_ordinal
            || self.tick_ordinal.get() == 0
            || self.event_ordinal <= before.ordinal
        {
            return Err(ProviderError::Correlation(
                "native serial birth differs from original prefix",
            ));
        }
        Ok(())
    }
}
