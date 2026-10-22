//! Immutable composite plugin setup plans.
//!
//! The current Crucible carrier uses this process-neutral body in the third sealed
//! `Setup` descriptor. It length-frames the independently versioned app-random
//! branch plan and guest-selectable catalog plan without exposing host or QEMU
//! implementation types across the process boundary.
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "CRUCSUP8"
//! 8       4     schema version = 8, big-endian
//! 12      4     header length = 40, big-endian
//! 16      4     total byte length, big-endian
//! 20      4     app-random plan byte length, big-endian
//! 24      4     selectable catalog plan byte length, big-endian
//! 28      4     device-digest purpose length (0 or 128), big-endian
//! 32      4     original startup length (0 or 128), big-endian
//! 36      4     process purpose length (0 for assembly, 2520 when issued)
//! 40      A     canonical AppRandomBranchPlanV1 body
//! 40+A    S     canonical SelectableCatalogPlanV4 body
//! 40+A+S  W     fixed workspace record, when issued
//! 40+A+S+W T    fixed StartupOperation body, when issued
//! 40+A+S+W+T P  issued process purpose, when present
//! ```

use thiserror::Error;

mod preexec;
mod publisher;
mod quantum;
mod quantum_stack;
pub use quantum_stack::QuantumStackPlanParts;
mod startup_operation;

/// Fixed byte length of the current issued workspace record.
pub const DEVICE_DIGEST_PURPOSE_BYTES: usize = 128;

/// Fixed byte length of the complete issued process purpose.
///
/// Its optional RAM endpoint tail names the existing paid socket incarnation;
/// its fixed family tail names two reservations occupied by the same issuer.
/// The record supplies no descriptor ownership or native service credit.
pub const PROCESS_PURPOSE_BYTES: usize = 2520;

pub use startup_operation::{
    STARTUP_OPERATION_BYTES, StartupOperation, StartupOperationError, StartupOperationFields,
};

use crate::{
    app_random_branch_plan::{
        AppRandomBranchPlan, AppRandomBranchPlanError, MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
    },
    selectable_catalog_plan::{
        SELECTABLE_CATALOG_PLAN_MAX_BYTES, SelectableCatalogPlan, SelectableCatalogPlanError,
    },
};

/// Frozen magic at the start of every composite plugin setup plan.
pub const PLUGIN_SETUP_PLAN_MAGIC: [u8; 8] = *b"CRUCSUP8";
/// Canonical composite setup-plan schema version.
pub const PLUGIN_SETUP_PLAN_VERSION: u32 = 8;
/// Fixed composite setup-plan header bytes.
pub const PLUGIN_SETUP_PLAN_HEADER_BYTES: usize = 40;
/// Maximum canonical bytes in one composite plugin setup plan.
// The new header and purpose consume existing aggregate headroom.
// Changing the edition never enlarges the admitted descriptor-body cap.
pub const PLUGIN_SETUP_PLAN_MAX_BYTES: usize =
    28 + MAX_APP_RANDOM_BRANCH_PLAN_BYTES + SELECTABLE_CATALOG_PLAN_MAX_BYTES;

/// One complete immutable process-neutral plugin setup plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSetupPlan {
    app_random_branch_plan: AppRandomBranchPlan,
    selectable_catalog_plan: SelectableCatalogPlan,
    startup_operation: Option<StartupOperation>,
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
            startup_operation: None,
        }
    }

    /// Includes evidence for the same prebirth original startup operation.
    ///
    /// Data assembly does not create a token or authenticate its issuer. Native
    /// acceptance requires the genuine retained guard and cancellation role.
    #[must_use]
    pub const fn with_startup_operation(mut self, startup: StartupOperation) -> Self {
        self.startup_operation = Some(startup);
        self
    }

    /// Borrows the optional original startup evidence without granting authority.
    #[must_use]
    pub const fn startup_operation(&self) -> Option<&StartupOperation> {
        self.startup_operation.as_ref()
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

    /// Consumes the composite and returns both independently validated plans.
    #[must_use]
    pub fn into_parts(self) -> (AppRandomBranchPlan, SelectableCatalogPlan) {
        (self.app_random_branch_plan, self.selectable_catalog_plan)
    }

    /// Reports the assembly payload length without encoding or allocating.
    ///
    /// This counts the optional startup section and both immutable nested plans.
    /// It does not reserve memory or establish an issuer or startup permission.
    ///
    /// # Errors
    /// Refuses nested length overflow or the unchanged aggregate byte limit.
    pub fn encoded_len(&self) -> Result<usize, PluginSetupPlanError> {
        self.encoded_body_len(
            0,
            self.startup_operation
                .as_ref()
                .map_or(0, |_| STARTUP_OPERATION_BYTES),
            0,
        )
    }

    /// Reports the selected pre-exec payload length without issuing material.
    ///
    /// The workspace flag selects only the fixed section length. The actual
    /// encoder still checks structural correspondence of the supplied records.
    /// This counts requested payload bytes, not allocator bookkeeping.
    ///
    /// This query includes the mandatory fixed startup and process sections even
    /// before their records exist. The actual encoder still refuses missing or
    /// mismatched records; a length is never evidence of their issuance.
    ///
    /// # Errors
    /// Refuses nested length overflow or the unchanged aggregate byte limit.
    pub fn preexec_encoded_len(&self, has_workspace: bool) -> Result<usize, PluginSetupPlanError> {
        self.encoded_body_len(
            if has_workspace {
                DEVICE_DIGEST_PURPOSE_BYTES
            } else {
                0
            },
            STARTUP_OPERATION_BYTES,
            PROCESS_PURPOSE_BYTES,
        )
    }

    /// Encodes this plan in the canonical composite descriptor-body format.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupPlanError`] if the selectable plan cannot be
    /// encoded or the aggregate canonical length cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, PluginSetupPlanError> {
        self.encode_body(
            None,
            self.startup_operation.map(|startup| startup.encode()),
            None,
            None,
        )
    }

    /// Encodes the current sealed carrier using already-issued process material.
    ///
    /// This method validates structural correspondence and assembles bytes. It
    /// issues no authority: the genuine pre-exec owner must pay, seal, publish
    /// and retain the carrier, and native authenticates its same issuer.
    ///
    /// # Errors
    /// Refuses missing startup, mismatched issued material,
    /// invalid nested plans, or an aggregate length exceeding the existing cap.
    pub fn encode_preexec(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self
            .startup_operation
            .as_ref()
            .ok_or(PluginSetupPlanError::InvalidPreexecSection { section: "startup" })?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        self.encode_body(
            workspace.copied(),
            Some(startup.encode()),
            Some(purpose),
            None,
        )
    }

    fn encode_body(
        &self,
        workspace_bytes: Option<[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        startup_bytes: Option<[u8; STARTUP_OPERATION_BYTES]>,
        purpose: Option<&[u8; PROCESS_PURPOSE_BYTES]>,
        publisher: Option<&[u8; crate::publisher_subscription::PUBLISHER_PURPOSE_BYTES]>,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let workspace_len = workspace_bytes.as_ref().map_or(0, |bytes| bytes.len());
        let startup_len = startup_bytes.as_ref().map_or(0, |bytes| bytes.len());
        let purpose_len = purpose.map_or(0, |bytes| bytes.len());
        let total_len = publisher::with_publisher_extent(
            self.encoded_body_len(workspace_len, startup_len, purpose_len)?,
            publisher.is_some(),
        )?;

        let app_random_bytes = self.app_random_branch_plan.encode();
        let selectable_bytes = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let total_len_u32 =
            u32::try_from(total_len).map_err(|_| PluginSetupPlanError::PlanTooLarge {
                bytes: total_len,
                maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
            })?;
        let app_random_len = u32::try_from(app_random_bytes.len()).map_err(|_| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_bytes.len(),
                selectable_bytes: selectable_bytes.len(),
            }
        })?;
        let selectable_len = u32::try_from(selectable_bytes.len()).map_err(|_| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_bytes.len(),
                selectable_bytes: selectable_bytes.len(),
            }
        })?;
        let mut bytes = Vec::with_capacity(total_len);
        let (magic, version, header) = if publisher.is_some() {
            (b"CRUCSUP9", 9_u32, 48_u32)
        } else {
            (
                &PLUGIN_SETUP_PLAN_MAGIC,
                PLUGIN_SETUP_PLAN_VERSION,
                PLUGIN_SETUP_PLAN_HEADER_BYTES as u32,
            )
        };
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&header.to_be_bytes());
        bytes.extend_from_slice(&total_len_u32.to_be_bytes());
        bytes.extend_from_slice(&app_random_len.to_be_bytes());
        bytes.extend_from_slice(&selectable_len.to_be_bytes());
        bytes.extend_from_slice(&(workspace_len as u32).to_be_bytes());
        bytes.extend_from_slice(&(startup_len as u32).to_be_bytes());
        bytes.extend_from_slice(&(purpose_len as u32).to_be_bytes());
        if let Some(publisher) = publisher {
            bytes.extend_from_slice(&(publisher.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
        }
        bytes.extend_from_slice(&app_random_bytes);
        bytes.extend_from_slice(&selectable_bytes);
        if let Some(workspace) = workspace_bytes {
            bytes.extend_from_slice(&workspace);
        }
        if let Some(startup) = startup_bytes {
            bytes.extend_from_slice(&startup);
        }
        if let Some(purpose) = purpose {
            bytes.extend_from_slice(purpose);
        }
        if let Some(publisher) = publisher {
            bytes.extend_from_slice(publisher);
        }
        Ok(bytes)
    }

    fn encoded_body_len(
        &self,
        workspace_len: usize,
        startup_len: usize,
        purpose_len: usize,
    ) -> Result<usize, PluginSetupPlanError> {
        let app_random_len = self
            .app_random_branch_plan
            .encoded_len()
            .map_err(|source| PluginSetupPlanError::AppRandom { source })?;
        let selectable_len = self
            .selectable_catalog_plan
            .encoded_len()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let total = checked_total_len(app_random_len, selectable_len, workspace_len, startup_len)?
            .checked_add(purpose_len)
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

    /// Decodes the nested plans from the selected edition-3 pre-exec carrier.
    ///
    /// The fixed outer-5 framing and original/purpose relation are checked
    /// before decoding the two nested plans. This returns only plan data; native
    /// acceptance and the actual retained issuer independently own all credit,
    /// artifact, original, module, descriptor and process authentication.
    /// A refused selected carrier cannot fall back to an assembly-only body.
    ///
    /// # Errors
    /// Refuses another edition, oversized or inconsistent sections, invalid
    /// original/purpose binding, or noncanonical nested plans.
    pub fn decode_preexec_parts(
        bytes: &[u8],
    ) -> Result<(AppRandomBranchPlan, SelectableCatalogPlan), PluginSetupPlanError> {
        preexec::decode_parts(bytes)
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
        if read_u32(bytes, 36)? != 0 {
            return Err(PluginSetupPlanError::InvalidPreexecSection {
                section: "unissued assembly purpose",
            });
        }
        let app_random_len = usize::try_from(read_u32(bytes, 20)?).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: usize::MAX,
                selectable_bytes: 0,
            }
        })?;
        let selectable_len = usize::try_from(read_u32(bytes, 24)?).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_len,
                selectable_bytes: usize::MAX,
            }
        })?;
        let workspace_len = read_u32(bytes, 28)? as usize;
        if workspace_len != 0 {
            return Err(PluginSetupPlanError::InvalidPreexecSection {
                section: "unissued workspace",
            });
        }
        let startup_len =
            usize::try_from(read_u32(bytes, 32)?).map_err(|_| PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidFraming,
            })?;
        if startup_len != 0 && startup_len != STARTUP_OPERATION_BYTES {
            return Err(PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidFraming,
            });
        }
        if app_random_len > MAX_APP_RANDOM_BRANCH_PLAN_BYTES
            || selectable_len > SELECTABLE_CATALOG_PLAN_MAX_BYTES
            || checked_total_len(app_random_len, selectable_len, workspace_len, startup_len)?
                != bytes.len()
        {
            return Err(PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_len,
                selectable_bytes: selectable_len,
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
        let mut plan = Self::new(app_random_branch_plan, selectable_catalog_plan);
        if startup_len != 0 {
            let startup = StartupOperation::decode(&bytes[selectable_end + workspace_len..])
                .map_err(|source| PluginSetupPlanError::Startup { source })?;
            plan = plan.with_startup_operation(startup);
        }
        Ok(plan)
    }
}

fn checked_total_len(
    app_random_len: usize,
    selectable_len: usize,
    workspace_len: usize,
    startup_len: usize,
) -> Result<usize, PluginSetupPlanError> {
    let total = PLUGIN_SETUP_PLAN_HEADER_BYTES
        .checked_add(app_random_len)
        .and_then(|bytes| bytes.checked_add(selectable_len))
        .and_then(|bytes| bytes.checked_add(workspace_len))
        .and_then(|bytes| bytes.checked_add(startup_len))
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
    #[error("plugin setup plan header has {bytes} bytes, expected 40")]
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
        "plugin setup plan nested lengths are invalid: app-random {app_random_bytes}, selectable {selectable_bytes}"
    )]
    InvalidNestedLengths {
        /// Declared app-random plan byte length.
        app_random_bytes: usize,
        /// Declared selectable catalog plan byte length.
        selectable_bytes: usize,
    },
    /// The fixed original startup-operation record is invalid.
    #[error("plugin setup original startup operation is invalid: {source}")]
    Startup {
        /// Invalid original startup evidence.
        source: StartupOperationError,
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
    /// A selected pre-exec section has invalid framing or original binding.
    #[error("selected plugin setup section {section} is invalid")]
    InvalidPreexecSection {
        /// Fixed section name, without caller-formatted data.
        section: &'static str,
    },
    /// The nested selectable catalog plan is invalid.
    #[error("plugin setup selectable catalog plan is invalid: {source}")]
    Selectable {
        /// Nested validation failure.
        source: SelectableCatalogPlanError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(&bytes[..8], b"CRUCSUP8");
        assert_eq!(&bytes[8..12], &[0, 0, 0, 8]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 40]);
        assert_eq!(&bytes[16..20], &[0, 0, 0, 192]);
        assert_eq!(&bytes[20..24], &[0, 0, 0, 16]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 136]);
        assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));
    }

    #[test]
    fn payload_geometry_counts_only_the_selected_fixed_sections() {
        let plain = empty_plan();
        assert_eq!(plain.encoded_len(), Ok(192));
        assert_eq!(plain.preexec_encoded_len(false), Ok(2840));
        assert_eq!(
            plain.encode_preexec(&[0; PROCESS_PURPOSE_BYTES], None),
            Err(PluginSetupPlanError::InvalidPreexecSection { section: "startup" })
        );

        let plan = plain.with_startup_operation(fixed_startup());
        let before = plan.clone();
        assert_eq!(plan.encoded_len(), Ok(320));
        assert_eq!(plan.preexec_encoded_len(false), Ok(2840));
        assert_eq!(plan.preexec_encoded_len(true), Ok(2968));
        assert_eq!(plan, before);
        let bytes = plan.encode().unwrap();
        assert_eq!(bytes.len(), 320);
        assert_eq!(&bytes[16..20], &[0, 0, 1, 64]);
        assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));
    }

    #[test]
    fn payload_geometry_preserves_overflow_and_aggregate_refusals() {
        assert_eq!(
            checked_total_len(usize::MAX, 136, 0, 0),
            Err(PluginSetupPlanError::PlanTooLarge {
                bytes: usize::MAX,
                maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
            })
        );
        assert!(
            checked_total_len(
                MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
                SELECTABLE_CATALOG_PLAN_MAX_BYTES,
                0,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn composite_plan_rejects_nested_substitution_and_length_drift() {
        let mut bytes = empty_plan()
            .encode()
            .unwrap_or_else(|error| panic!("setup plan must encode: {error}"));
        bytes[40] = 0;
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
            })
        );
    }

    #[test]
    fn current_carrier_refuses_the_superseded_outer3() {
        let mut bytes = empty_plan().encode().unwrap();
        bytes[..8].copy_from_slice(b"CRUCSUP3");
        bytes[8..12].copy_from_slice(&3_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&36_u32.to_be_bytes());
        assert!(PluginSetupPlan::decode(&bytes).is_err());
        assert!(PluginSetupPlan::decode_preexec_parts(&bytes).is_err());
    }

    #[test]
    fn new_header_and_purpose_consume_the_existing_aggregate_cap() {
        assert_eq!(
            PLUGIN_SETUP_PLAN_MAX_BYTES,
            28 + MAX_APP_RANDOM_BRANCH_PLAN_BYTES + SELECTABLE_CATALOG_PLAN_MAX_BYTES
        );
        assert!(matches!(
            checked_total_len(
                MAX_APP_RANDOM_BRANCH_PLAN_BYTES,
                SELECTABLE_CATALOG_PLAN_MAX_BYTES,
                DEVICE_DIGEST_PURPOSE_BYTES,
                STARTUP_OPERATION_BYTES,
            ),
            Err(PluginSetupPlanError::PlanTooLarge {
                maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
                ..
            })
        ));
        let mut bytes = empty_plan()
            .encode()
            .unwrap_or_else(|error| panic!("carrier: {error}"));
        bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::UnsupportedVersion { version: 2 })
        );
        bytes[8..12].copy_from_slice(&8_u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&127_u32.to_be_bytes());
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::InvalidPreexecSection {
                section: "unissued workspace"
            })
        ));
    }

    fn fixed_startup() -> StartupOperation {
        StartupOperation::new(StartupOperationFields {
            cap_id: [9; 32],
            operation_id: 4,
            original_start_ns: 100,
            absolute_end_ns: 200,
            poll_ns: 10,
            process_generation: 11,
            cancellation_device: 17,
            cancellation_inode: 18,
            cancellation_event_id: 19,
            cancellation_descriptor: 20,
            original_total_metadata_bytes: 1 << 20,
        })
        .unwrap_or_else(|error| panic!("startup fixture: {error}"))
    }

    #[test]
    fn current_startup_assembly_has_no_issued_workspace_or_process_purpose() {
        let plan = empty_plan().with_startup_operation(fixed_startup());
        let encoded = plan.encode().unwrap();
        assert_eq!(&encoded[28..32], &[0; 4]);
        assert_eq!(&encoded[36..40], &[0; 4]);
        assert_eq!(PluginSetupPlan::decode(&encoded), Ok(plan));
        assert!(PluginSetupPlan::decode_preexec_parts(&encoded).is_err());
    }

    #[test]
    fn original_startup_rejects_refreshed_framing_and_absent_event_identity() {
        let startup = fixed_startup();
        let mut bytes = startup.encode();
        bytes[112..120].fill(0);
        assert_eq!(
            StartupOperation::decode(&bytes),
            Err(StartupOperationError::InvalidTerms)
        );
        bytes = startup.encode();
        bytes[120..128].fill(0);
        assert_eq!(
            StartupOperation::decode(&bytes),
            Err(StartupOperationError::InvalidTerms)
        );
        bytes = startup.encode();
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            StartupOperation::decode(&bytes),
            Err(StartupOperationError::InvalidFraming)
        );
        bytes = startup.encode();
        bytes[64..72].copy_from_slice(&100_u64.to_be_bytes());
        assert_eq!(
            StartupOperation::decode(&bytes),
            Err(StartupOperationError::InvalidTerms)
        );
        let plan = empty_plan().with_startup_operation(startup);
        let mut bytes = plan
            .encode()
            .unwrap_or_else(|error| panic!("carrier: {error}"));
        bytes[32..36].copy_from_slice(&127_u32.to_be_bytes());
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidFraming
            })
        ));
    }
}
