//! Immutable composite plugin setup plans.
//!
//! Control-protocol v5 uses this process-neutral body in the third sealed
//! `Setup` descriptor. It length-frames the independently versioned app-random
//! branch plan and guest-selectable catalog plan without exposing host or QEMU
//! implementation types across the process boundary.
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "CRUCSUP3"
//! 8       4     schema version = 3, big-endian
//! 12      4     header length = 36, big-endian
//! 16      4     total byte length, big-endian
//! 20      4     app-random plan byte length, big-endian
//! 24      4     selectable catalog plan byte length, big-endian
//! 28      4     device-digest purpose length (0 or 128), big-endian
//! 32      4     original startup length (0 or 128), big-endian
//! 36      A     canonical AppRandomBranchPlanV1 body
//! 36+A    S     canonical SelectableCatalogPlanV4 body
//! 36+A+S  W     fixed DeviceDigestPurpose body, when issued
//! 36+A+S+W T    fixed StartupOperation body, when issued
//! ```

use thiserror::Error;

mod device_digest_purpose;
mod startup_operation;

pub use device_digest_purpose::{
    DEVICE_DIGEST_PURPOSE_BYTES, DeviceDigestPurpose, DeviceDigestPurposeError,
    DeviceDigestPurposeFields, DeviceDigestPurposeScope,
};

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
pub const PLUGIN_SETUP_PLAN_MAGIC: [u8; 8] = *b"CRUCSUP3";
/// Canonical composite setup-plan schema version.
pub const PLUGIN_SETUP_PLAN_VERSION: u32 = 3;
/// Fixed composite setup-plan header bytes.
pub const PLUGIN_SETUP_PLAN_HEADER_BYTES: usize = 36;
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
    device_digest_purpose: Option<DeviceDigestPurpose>,
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
            device_digest_purpose: None,
            startup_operation: None,
        }
    }

    /// Includes fixed evidence issued by the genuine setup-plan producer.
    ///
    /// This method only assembles process-neutral data. It cannot issue credit
    /// or authenticate the record; native acceptance requires the sealed carrier
    /// and its matched compiled source proof.
    #[must_use]
    pub const fn with_device_digest_purpose(mut self, purpose: DeviceDigestPurpose) -> Self {
        self.device_digest_purpose = Some(purpose);
        self
    }

    /// Borrows the optional fixed purpose evidence without granting authority.
    #[must_use]
    pub const fn device_digest_purpose(&self) -> Option<&DeviceDigestPurpose> {
        self.device_digest_purpose.as_ref()
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
        let workspace_bytes = self.device_digest_purpose.map(|purpose| purpose.encode());
        let workspace_len = workspace_bytes.as_ref().map_or(0, |bytes| bytes.len());
        let startup_bytes = self.startup_operation.map(|startup| startup.encode());
        let startup_len = startup_bytes.as_ref().map_or(0, |bytes| bytes.len());
        validate_process_binding(
            self.device_digest_purpose.as_ref(),
            self.startup_operation.as_ref(),
        )?;
        let total_len = checked_total_len(
            app_random_bytes.len(),
            selectable_bytes.len(),
            workspace_len,
            startup_len,
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
            }
        })?;
        let selectable_len = u32::try_from(selectable_bytes.len()).map_err(|_error| {
            PluginSetupPlanError::InvalidNestedLengths {
                app_random_bytes: app_random_bytes.len(),
                selectable_bytes: selectable_bytes.len(),
            }
        })?;

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&PLUGIN_SETUP_PLAN_MAGIC);
        bytes.extend_from_slice(&PLUGIN_SETUP_PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(PLUGIN_SETUP_PLAN_HEADER_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&total_len_u32.to_be_bytes());
        bytes.extend_from_slice(&app_random_len.to_be_bytes());
        bytes.extend_from_slice(&selectable_len.to_be_bytes());
        bytes.extend_from_slice(&(workspace_len as u32).to_be_bytes());
        bytes.extend_from_slice(&(startup_len as u32).to_be_bytes());
        bytes.extend_from_slice(&app_random_bytes);
        bytes.extend_from_slice(&selectable_bytes);
        if let Some(workspace_bytes) = workspace_bytes {
            bytes.extend_from_slice(&workspace_bytes);
        }
        if let Some(startup_bytes) = startup_bytes {
            bytes.extend_from_slice(&startup_bytes);
        }
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
        let workspace_len =
            usize::try_from(read_u32(bytes, 28)?).map_err(|_| PluginSetupPlanError::Workspace {
                source: DeviceDigestPurposeError::InvalidFraming,
            })?;
        if workspace_len != 0 && workspace_len != DEVICE_DIGEST_PURPOSE_BYTES {
            return Err(PluginSetupPlanError::Workspace {
                source: DeviceDigestPurposeError::InvalidFraming,
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
        if workspace_len != 0 {
            let purpose =
                DeviceDigestPurpose::decode(&bytes[selectable_end..selectable_end + workspace_len])
                    .map_err(|source| PluginSetupPlanError::Workspace { source })?;
            plan = plan.with_device_digest_purpose(purpose);
        }
        if startup_len != 0 {
            let startup = StartupOperation::decode(&bytes[selectable_end + workspace_len..])
                .map_err(|source| PluginSetupPlanError::Startup { source })?;
            plan = plan.with_startup_operation(startup);
        }
        validate_process_binding(
            plan.device_digest_purpose.as_ref(),
            plan.startup_operation.as_ref(),
        )?;
        Ok(plan)
    }
}

fn validate_process_binding(
    workspace: Option<&DeviceDigestPurpose>,
    startup: Option<&StartupOperation>,
) -> Result<(), PluginSetupPlanError> {
    if let (Some(workspace), Some(startup)) = (workspace, startup)
        && (workspace.fields().process_generation != startup.fields().process_generation
            || workspace.fields().original_total_metadata_bytes
                != startup.fields().original_total_metadata_bytes)
    {
        return Err(PluginSetupPlanError::Startup {
            source: StartupOperationError::InvalidTerms,
        });
    }
    Ok(())
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
    #[error("plugin setup plan header has {bytes} bytes, expected 36")]
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
    /// The fixed device-digest purpose record is invalid.
    #[error("plugin setup plan device digest purpose is invalid: {source}")]
    Workspace {
        /// Invalid fixed purpose evidence.
        source: DeviceDigestPurposeError,
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
        assert_eq!(&bytes[..8], b"CRUCSUP3");
        assert_eq!(&bytes[8..12], &[0, 0, 0, 3]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 36]);
        assert_eq!(&bytes[16..20], &[0, 0, 0, 188]);
        assert_eq!(&bytes[20..24], &[0, 0, 0, 16]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 136]);
        assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));
    }

    #[test]
    fn composite_plan_rejects_nested_substitution_and_length_drift() {
        let mut bytes = empty_plan()
            .encode()
            .unwrap_or_else(|error| panic!("setup plan must encode: {error}"));
        bytes[36] = 0;
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

    fn fixed_purpose(scope: DeviceDigestPurposeScope) -> DeviceDigestPurpose {
        DeviceDigestPurpose::new(DeviceDigestPurposeFields {
            scope,
            source_proof_digest: [7; 32],
            original_total_metadata_bytes: 1 << 20,
            metadata_purpose_bytes: 1 << 17,
            resident_purpose_bytes: 1 << 18,
            process_generation: 11,
            account_generation: 12,
            workspace_generation: 13,
            device: 14,
            inode: 15,
            native_descriptor_peak: 2,
            native_mapping_peak: 1,
        })
        .unwrap_or_else(|error| panic!("wire fixture must validate: {error}"))
    }

    #[test]
    fn sealed_purpose_carrier_preserves_total_and_distinct_lifecycle_scope() {
        for scope in [
            DeviceDigestPurposeScope::Initial,
            DeviceDigestPurposeScope::Child,
        ] {
            let purpose = fixed_purpose(scope);
            let record = purpose.encode();
            assert_eq!(&record[..8], b"CRUCWSP1");
            assert_eq!(&record[48..56], &(1_u64 << 20).to_be_bytes());
            assert_eq!(&record[120..128], &65_536_u64.to_be_bytes());
            assert_eq!(DeviceDigestPurpose::decode(&record), Ok(purpose));

            let plan = empty_plan().with_device_digest_purpose(purpose);
            let bytes = plan
                .encode()
                .unwrap_or_else(|error| panic!("carrier: {error}"));
            assert_eq!(&bytes[28..32], &128_u32.to_be_bytes());
            assert_eq!(&bytes[bytes.len() - 128..], &record);
            assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));
        }
    }

    #[test]
    fn purpose_rejects_unknown_scope_size_and_inconsistent_resident_subset() {
        let purpose = fixed_purpose(DeviceDigestPurposeScope::Initial);
        for (offset, value) in [(12, 3_u32), (8, 2_u32)] {
            let mut bytes = purpose.encode();
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                DeviceDigestPurpose::decode(&bytes),
                Err(DeviceDigestPurposeError::InvalidFraming)
            );
        }
        let mut bytes = purpose.encode();
        bytes[120..128].copy_from_slice(&65_535_u64.to_be_bytes());
        assert_eq!(
            DeviceDigestPurpose::decode(&bytes),
            Err(DeviceDigestPurposeError::InvalidFraming)
        );
        bytes = purpose.encode();
        bytes[64..72].copy_from_slice(&65_536_u64.to_be_bytes());
        assert_eq!(
            DeviceDigestPurpose::decode(&bytes),
            Err(DeviceDigestPurposeError::InvalidTerms)
        );
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
        bytes[8..12].copy_from_slice(&3_u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&127_u32.to_be_bytes());
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::Workspace {
                source: DeviceDigestPurposeError::InvalidFraming
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
    fn common_startup_and_workspace_records_have_separate_exact_frames() {
        let startup = fixed_startup();
        let workspace = fixed_purpose(DeviceDigestPurposeScope::Initial);
        let plan = empty_plan()
            .with_startup_operation(startup)
            .with_device_digest_purpose(workspace);
        let bytes = plan
            .encode()
            .unwrap_or_else(|error| panic!("carrier: {error}"));
        assert_eq!(&bytes[28..36], &[0, 0, 0, 128, 0, 0, 0, 128]);
        assert_eq!(
            &bytes[bytes.len() - 256..bytes.len() - 128],
            &workspace.encode()
        );
        assert_eq!(&bytes[bytes.len() - 128..], &startup.encode());
        assert_eq!(PluginSetupPlan::decode(&bytes), Ok(plan));

        let mut fields = *startup.fields();
        fields.process_generation += 1;
        let mismatched =
            StartupOperation::new(fields).unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(matches!(
            empty_plan()
                .with_startup_operation(mismatched)
                .with_device_digest_purpose(workspace)
                .encode(),
            Err(PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidTerms
            })
        ));
    }

    #[test]
    fn startup_and_workspace_cannot_describe_different_original_total_partitions() {
        let startup = fixed_startup();
        let workspace = fixed_purpose(DeviceDigestPurposeScope::Initial);
        let mut fields = *startup.fields();
        fields.original_total_metadata_bytes += 1;
        let mismatched =
            StartupOperation::new(fields).unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(matches!(
            empty_plan()
                .with_startup_operation(mismatched)
                .with_device_digest_purpose(workspace)
                .encode(),
            Err(PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidTerms
            })
        ));

        let mut bytes = empty_plan()
            .with_startup_operation(startup)
            .with_device_digest_purpose(workspace)
            .encode()
            .unwrap_or_else(|error| panic!("fixture: {error}"));
        let total_offset = bytes.len() - 8;
        bytes[total_offset..].copy_from_slice(&fields.original_total_metadata_bytes.to_be_bytes());
        assert!(matches!(
            PluginSetupPlan::decode(&bytes),
            Err(PluginSetupPlanError::Startup {
                source: StartupOperationError::InvalidTerms
            })
        ));
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
