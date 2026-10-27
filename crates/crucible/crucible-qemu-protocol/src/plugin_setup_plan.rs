//! Immutable composite plugin setup plans.
//!
//! Control-protocol v4 uses this process-neutral body in the third sealed
//! `Setup` descriptor. It length-frames the independently versioned app-random
//! branch plan, guest-selectable catalog, and bounded console admission plan without exposing host or QEMU
//! implementation types across the process boundary.
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "CRUCSUP3"
//! 8       4     schema version = 3, big-endian
//! 12      4     header length = 32, big-endian
//! 16      4     total byte length, big-endian
//! 20      4     app-random plan byte length, big-endian
//! 24      4     selectable catalog plan byte length, big-endian
//! 28      4     console admission byte length, big-endian (zero when absent)
//! 32      A     canonical AppRandomBranchPlanV1 body
//! 32+A    S     canonical SelectableCatalogPlanV4 body
//! 32+A+S  C     canonical NativeConsoleSetupPlanV1 body
//! ```

use thiserror::Error;

use crate::{
    app_random_branch_plan::{
        AppRandomBranchPlan, AppRandomBranchPlanError, MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
    },
    native_console::{NATIVE_CONSOLE_SETUP_MAX_BYTES, NativeConsoleError, NativeConsoleSetupPlan},
    selectable_catalog_plan::{
        SELECTABLE_CATALOG_PLAN_MAX_BYTES, SelectableCatalogPlan, SelectableCatalogPlanError,
    },
};

/// Frozen magic at the start of every composite plugin setup plan.
pub const PLUGIN_SETUP_PLAN_MAGIC: [u8; 8] = *b"CRUCSUP3";
/// Canonical composite setup-plan schema version.
pub const PLUGIN_SETUP_PLAN_VERSION: u32 = 3;
/// Fixed composite setup-plan header bytes.
pub const PLUGIN_SETUP_PLAN_HEADER_BYTES: usize = 32;
/// Maximum canonical bytes in one composite plugin setup plan.
pub const PLUGIN_SETUP_PLAN_MAX_BYTES: usize = PLUGIN_SETUP_PLAN_HEADER_BYTES
    + MAX_APP_RANDOM_BRANCH_PLAN_BYTES
    + SELECTABLE_CATALOG_PLAN_MAX_BYTES
    + NATIVE_CONSOLE_SETUP_MAX_BYTES;

/// One complete immutable process-neutral plugin setup plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSetupPlan {
    app_random_branch_plan: AppRandomBranchPlan,
    selectable_catalog_plan: SelectableCatalogPlan,
    native_console_plan: Option<NativeConsoleSetupPlan>,
}

impl PluginSetupPlan {
    /// Builds a composite plan from two independently validated nested plans.
    #[must_use]
    pub const fn new(
        app_random_branch_plan: AppRandomBranchPlan,
        selectable_catalog_plan: SelectableCatalogPlan,
    ) -> Self {
        Self {
            app_random_branch_plan,
            selectable_catalog_plan,
            native_console_plan: None,
        }
    }

    /// Retains one validated immutable console admission in the same descriptor.
    #[must_use]
    pub fn with_native_console(mut self, plan: NativeConsoleSetupPlan) -> Self {
        self.native_console_plan = Some(plan);
        self
    }

    /// Returns the admitted console policy and closed stream plan, if present.
    #[must_use]
    pub const fn native_console_plan(&self) -> Option<&NativeConsoleSetupPlan> {
        self.native_console_plan.as_ref()
    }

    /// Returns the immutable app-random branch plan.
    #[must_use]
    pub const fn app_random_branch_plan(&self) -> &AppRandomBranchPlan {
        &self.app_random_branch_plan
    }

    /// Returns the immutable guest-selectable catalog and continuation plan.
    #[must_use]
    pub const fn selectable_catalog_plan(&self) -> &SelectableCatalogPlan {
        &self.selectable_catalog_plan
    }

    /// Consumes the composite and returns all independently validated plans.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AppRandomBranchPlan,
        SelectableCatalogPlan,
        Option<NativeConsoleSetupPlan>,
    ) {
        (
            self.app_random_branch_plan,
            self.selectable_catalog_plan,
            self.native_console_plan,
        )
    }

    /// Encodes this plan in the canonical composite descriptor-body format.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupPlanError`] if the selectable plan cannot be
    /// encoded or the aggregate canonical length cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, PluginSetupPlanError> {
        let app_random_bytes = self.app_random_branch_plan.encode();
        let selectable_bytes = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let console_bytes = self
            .native_console_plan
            .as_ref()
            .map(NativeConsoleSetupPlan::encode)
            .transpose()
            .map_err(|source| PluginSetupPlanError::NativeConsole { source })?
            .unwrap_or_default();
        let total_len = checked_total_len(
            app_random_bytes.len(),
            selectable_bytes.len(),
            console_bytes.len(),
        )?;
        let total_len_u32 =
            u32::try_from(total_len).map_err(|_error| PluginSetupPlanError::PlanTooLarge {
                bytes: total_len,
                maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
            })?;
        let app_random_len = u32::try_from(app_random_bytes.len()).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_bytes.len(),
                selectable_bytes: selectable_bytes.len(),
                console_bytes: console_bytes.len(),
            }
        })?;
        let selectable_len = u32::try_from(selectable_bytes.len()).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_bytes.len(),
                selectable_bytes: selectable_bytes.len(),
                console_bytes: console_bytes.len(),
            }
        })?;

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&PLUGIN_SETUP_PLAN_MAGIC);
        bytes.extend_from_slice(&PLUGIN_SETUP_PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(PLUGIN_SETUP_PLAN_HEADER_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&total_len_u32.to_be_bytes());
        bytes.extend_from_slice(&app_random_len.to_be_bytes());
        bytes.extend_from_slice(&selectable_len.to_be_bytes());
        bytes.extend_from_slice(&(console_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&app_random_bytes);
        bytes.extend_from_slice(&selectable_bytes);
        bytes.extend_from_slice(&console_bytes);
        Ok(bytes)
    }

    /// Decodes one complete canonical composite descriptor body.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupPlanError`] when the body is oversized, truncated,
    /// uses another magic, version, or header length, declares inconsistent
    /// lengths, contains a noncanonical nested plan, or has trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginSetupPlanError> {
        if bytes.len() > PLUGIN_SETUP_PLAN_MAX_BYTES {
            return Err(PluginSetupPlanError::PlanTooLarge {
                bytes: bytes.len(),
                maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
            });
        }
        if bytes.len() < PLUGIN_SETUP_PLAN_HEADER_BYTES {
            return Err(PluginSetupPlanError::Truncated);
        }
        let version = read_u32(bytes, 8)?;
        if bytes[..8] != PLUGIN_SETUP_PLAN_MAGIC {
            return Err(PluginSetupPlanError::InvalidMagic);
        }
        if version != PLUGIN_SETUP_PLAN_VERSION {
            return Err(PluginSetupPlanError::UnsupportedVersion { version });
        }
        let header_len = usize::try_from(read_u32(bytes, 12)?)
            .map_err(|_error| PluginSetupPlanError::InvalidHeaderLength { bytes: usize::MAX })?;
        if header_len != PLUGIN_SETUP_PLAN_HEADER_BYTES {
            return Err(PluginSetupPlanError::InvalidHeaderLength { bytes: header_len });
        }
        let declared_total = usize::try_from(read_u32(bytes, 16)?).map_err(|_error| {
            PluginSetupPlanError::DeclaredLengthMismatch {
                declared: usize::MAX,
                actual: bytes.len(),
            }
        })?;
        if declared_total != bytes.len() {
            return Err(PluginSetupPlanError::DeclaredLengthMismatch {
                declared: declared_total,
                actual: bytes.len(),
            });
        }
        let console_len = read_u32(bytes, 28)? as usize;
        let app_random_len = usize::try_from(read_u32(bytes, 20)?).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: usize::MAX,
                selectable_bytes: 0,
                console_bytes: console_len,
            }
        })?;
        let selectable_len = usize::try_from(read_u32(bytes, 24)?).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_len,
                selectable_bytes: usize::MAX,
                console_bytes: console_len,
            }
        })?;
        if app_random_len > MAX_APP_RANDOM_BRANCH_PLAN_BYTES
            || selectable_len > SELECTABLE_CATALOG_PLAN_MAX_BYTES
            || console_len > NATIVE_CONSOLE_SETUP_MAX_BYTES
            || checked_total_len(app_random_len, selectable_len, console_len)? != bytes.len()
        {
            return Err(PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_len,
                selectable_bytes: selectable_len,
                console_bytes: console_len,
            });
        }

        let app_random_end = PLUGIN_SETUP_PLAN_HEADER_BYTES + app_random_len;
        let app_random_branch_plan =
            AppRandomBranchPlan::decode(&bytes[PLUGIN_SETUP_PLAN_HEADER_BYTES..app_random_end])
                .map_err(|source| PluginSetupPlanError::AppRandom { source })?;
        let selectable_end = app_random_end + selectable_len;
        let selectable_catalog_plan =
            SelectableCatalogPlan::decode(&bytes[app_random_end..selectable_end])
                .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let native_console_plan = if console_len == 0 {
            None
        } else {
            Some(
                NativeConsoleSetupPlan::decode(&bytes[selectable_end..])
                    .map_err(|source| PluginSetupPlanError::NativeConsole { source })?,
            )
        };
        Ok(Self {
            app_random_branch_plan,
            selectable_catalog_plan,
            native_console_plan,
        })
    }
}

fn checked_total_len(
    app_random_len: usize,
    selectable_len: usize,
    console_len: usize,
) -> Result<usize, PluginSetupPlanError> {
    let total = PLUGIN_SETUP_PLAN_HEADER_BYTES
        .checked_add(app_random_len)
        .and_then(|bytes| bytes.checked_add(selectable_len))
        .and_then(|bytes| bytes.checked_add(console_len))
        .ok_or(PluginSetupPlanError::PlanTooLarge {
            bytes: usize::MAX,
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        })?;
    if total > PLUGIN_SETUP_PLAN_MAX_BYTES {
        return Err(PluginSetupPlanError::PlanTooLarge {
            bytes: total,
            maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
        });
    }
    Ok(total)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PluginSetupPlanError> {
    let field = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(PluginSetupPlanError::Truncated)?;
    let mut value = [0_u8; 4];
    value.copy_from_slice(field);
    Ok(u32::from_be_bytes(value))
}

/// Invalid canonical composite plugin setup plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupPlanError {
    /// The body is shorter than the fixed header or one declared field.
    #[error("plugin setup plan is truncated")]
    Truncated,
    /// The fixed plan magic differs.
    #[error("plugin setup plan magic is invalid")]
    InvalidMagic,
    /// The schema version is not supported.
    #[error("plugin setup plan version {version} is unsupported")]
    UnsupportedVersion {
        /// Unsupported version.
        version: u32,
    },
    /// The fixed header length differs from the canonical profile.
    #[error("plugin setup plan header has {bytes} bytes, expected 32")]
    InvalidHeaderLength {
        /// Declared header byte length.
        bytes: usize,
    },
    /// The declared total length differs from the supplied body.
    #[error("plugin setup plan declares {declared} bytes, actual {actual}")]
    DeclaredLengthMismatch {
        /// Declared total byte length.
        declared: usize,
        /// Supplied total byte length.
        actual: usize,
    },
    /// Nested lengths do not exactly partition the complete body.
    #[error(
        "plugin setup plan nested lengths are invalid: app-random {app_random_bytes}, selectable {selectable_bytes}, console {console_bytes}"
    )]
    InvalidNestedLengths {
        /// Declared app-random plan byte length.
        app_random_bytes: usize,
        /// Declared selectable catalog plan byte length.
        selectable_bytes: usize,
        /// Declared native console admission byte length.
        console_bytes: usize,
    },
    /// The aggregate body exceeds the fixed byte profile.
    #[error("plugin setup plan has {bytes} bytes, maximum {maximum}")]
    PlanTooLarge {
        /// Actual or overflow-saturated byte count.
        bytes: usize,
        /// Maximum admitted byte count.
        maximum: usize,
    },
    /// The nested app-random plan is invalid.
    #[error("plugin setup app-random plan is invalid: {source}")]
    AppRandom {
        /// Nested validation failure.
        source: AppRandomBranchPlanError,
    },
    /// The nested selectable catalog plan is invalid.
    #[error("plugin setup selectable catalog plan is invalid: {source}")]
    Selectable {
        /// Nested validation failure.
        source: SelectableCatalogPlanError,
    },
    /// The nested native console admission is invalid.
    #[error("plugin setup native console admission is invalid: {source}")]
    NativeConsole {
        /// Nested validation failure.
        source: NativeConsoleError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_console::{NativeConsoleDevice, NativeConsolePlan, NativeConsoleStream};
    use crate::selectable_catalog_plan::{SelectablePlanContinuation, SelectablePlanLimits};

    fn empty_plan() -> PluginSetupPlan {
        PluginSetupPlan::new(
            AppRandomBranchPlan::default(),
            SelectableCatalogPlan::new(
                SelectablePlanLimits::new(1, 1, 1)
                    .unwrap_or_else(|error| panic!("limits must validate: {error}")),
                Vec::new(),
                SelectablePlanContinuation::cold(),
            )
            .unwrap_or_else(|error| panic!("catalog plan must validate: {error}")),
        )
    }

    #[test]
    fn composite_plan_round_trips_and_freezes_big_endian_layout() {
        let plan = empty_plan();
        let bytes = plan
            .encode()
            .unwrap_or_else(|error| panic!("setup plan must encode: {error}"));
        assert_eq!(&bytes[..8], b"CRUCSUP3");
        assert_eq!(&bytes[8..12], &[0, 0, 0, 3]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 32]);
        assert_eq!(&bytes[16..20], &[0, 0, 0, 160]);
        assert_eq!(&bytes[20..24], &[0, 0, 0, 16]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 112]);
        assert_eq!(&bytes[28..32], &[0, 0, 0, 0]);
        assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));
    }

    #[test]
    fn composite_plan_rejects_nested_substitution_and_length_drift() {
        let mut bytes = empty_plan()
            .encode()
            .unwrap_or_else(|error| panic!("setup plan must encode: {error}"));
        bytes[32] = 0;
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::AppRandom {
                source: AppRandomBranchPlanError::InvalidMagic
            })
        ));

        let mut bytes = empty_plan()
            .encode()
            .unwrap_or_else(|error| panic!("setup plan must encode: {error}"));
        bytes[24..28].copy_from_slice(&95_u32.to_be_bytes());
        assert_eq!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: 16,
                selectable_bytes: 95,
                console_bytes: 0,
            })
        );
    }

    #[test]
    fn coordinated_console_cutover_refuses_prior_composite_grammar()
    -> Result<(), PluginSetupPlanError> {
        assert_eq!(
            crate::CONTROL_PROTOCOL_VERSION,
            crate::native_console::NATIVE_CONSOLE_REQUIRED_CONTROL_VERSION
        );
        assert_eq!(
            PLUGIN_SETUP_PLAN_VERSION,
            crate::native_console::NATIVE_CONSOLE_REQUIRED_SETUP_SCHEMA
        );
        let current = empty_plan().encode()?;

        // Reconstruct the prior complete body, including its shorter header.
        // A coordinated cutover never selects that grammar as a fallback.
        let mut prior = current.clone();
        prior.drain(28..32);
        prior[..8].copy_from_slice(b"CRUCSUP2");
        prior[8..12].copy_from_slice(&2_u32.to_be_bytes());
        prior[12..16].copy_from_slice(&28_u32.to_be_bytes());
        let length = u32::try_from(prior.len())
            .unwrap_or_else(|_| panic!("fixed fixture length must fit u32"));
        prior[16..20].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            PluginSetupPlan::decode(&prior),
            Err(PluginSetupPlanError::InvalidMagic)
        );

        let mut unsupported = current;
        unsupported[8..12].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            PluginSetupPlan::decode(&unsupported),
            Err(PluginSetupPlanError::UnsupportedVersion { version: 2 })
        );
        Ok(())
    }

    #[test]
    fn composite_plan_retains_console_policy_and_refuses_nested_substitution()
    -> Result<(), PluginSetupPlanError> {
        let console = NativeConsoleSetupPlan::new(
            NativeConsolePlan {
                slot: 0,
                logical_generation: 3,
                node_sequence_base: 0,
                streams: vec![NativeConsoleStream {
                    stream: 1,
                    device: NativeConsoleDevice::Serial16550,
                    device_identity: [9; 32],
                    owner_mask: 1,
                    sequence_base: 0,
                }],
            },
            7,
            13,
        )
        .map_err(|source| PluginSetupPlanError::NativeConsole { source })?;
        let plan = empty_plan().with_native_console(console.clone());
        let mut bytes = plan.encode()?;

        assert_eq!(PluginSetupPlan::decode(&bytes)?, plan);
        assert_eq!(plan.native_console_plan(), Some(&console));
        assert_eq!(console.issued_authorization_capacity(), 7);
        assert_eq!(console.authorization_allowance(), 13);
        let console_offset = PLUGIN_SETUP_PLAN_HEADER_BYTES
            + read_u32(&bytes, 20)? as usize
            + read_u32(&bytes, 24)? as usize;
        bytes[console_offset] = 0;
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::NativeConsole { .. })
        ));
        Ok(())
    }
}
