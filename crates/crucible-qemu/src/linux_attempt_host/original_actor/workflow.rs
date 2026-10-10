//! Authenticates the fixed workflow before deriving its original service policy.
//!
//! Only the actor's retained parent evidence supplies the expected digest and
//! width. The projection below reads required service declarations under the
//! same closed decoder owner; it creates no account or physical Source grant.
//! Scenario, schedule and native artifact authentication remain the genuine
//! packaged service's responsibility before execution.

use crucible::owned_decode::json_profiles::workflow::{
    Aggregate, InstalledInput, ResourceVector, ServiceMode, ServiceServer, WorkflowProjection,
};

use std::sync::Arc;

use crucible::owned_decode::from_json_slice_closed;
#[cfg(test)]
use crucible::owned_decode::json_profiles::workflow::{
    GuestAssets, ServiceOperator, ServiceProfile,
};
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};
use crucible_linux_resource::measurement_origin::{
    CertifiedMeasurementMode, MeasurementOriginError,
};
#[cfg(test)]
use serde::de::IgnoredAny;

use super::{OriginalActorAccountCustody, OriginalActorAccountError, OriginalActorDecodeOwner};

mod guest_assets;
use guest_assets::GuestAssetsValidation;

/// Retains required SQLite service declarations authenticated by the parent.
///
/// There is no constructor accepting numeric limits. This value is produced
/// only after matching the workflow bytes and the same actor's decoder guard.
/// Its declarations do not prove native initialization's pre-limit peak or
/// filesystem capacity. Those physical purposes remain separately qualified.
pub struct OriginalActorServicePolicy {
    pub(super) catalog: Option<OriginalActorCatalogPurpose>,
    pub(super) launch: Option<OriginalActorServiceLaunchPurpose>,
    pub(super) original: Arc<HostOperationGuard>,
    pub(super) bootstrap_bytes: u64,
    pub(super) heap_bytes: u64,
    pub(super) connections: usize,
    pub(super) main_stack_bytes: u64,
    pub(super) bootstrap_digest: [u8; 32],
    pub(super) campaign_digest: [u8; 32],
    pub(super) campaign_projection_digest: [u8; 32],
}

/// Retains the authenticated listener declaration and component-file identity.
///
/// This move-only declaration grants no listener, worker or native admission.
/// The daemon must reserve actual construction and serving purposes separately.
pub struct OriginalActorServiceLaunchPurpose {
    original: Arc<HostOperationGuard>,
    server: ServiceServer,
    mode: ServiceMode,
    components_digest: [u8; 32],
    workflow_digest: [u8; 32],
}

impl OriginalActorServiceLaunchPurpose {
    /// Returns the six authenticated server declarations in wire-field order.
    #[must_use]
    pub fn server_declarations(&self) -> (usize, usize, usize, u64, u64, u64) {
        let server = &self.server;
        (
            server.connection_workers,
            server.pending_connections,
            server.maximum_requests_per_connection,
            server.accept_poll_millis,
            server.read_timeout_millis,
            server.write_timeout_millis,
        )
    }

    /// Returns whether the authenticated service denies mutations.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        matches!(self.mode, ServiceMode::ReadOnly)
    }

    /// Borrows the exact installed component-authority file digest.
    #[must_use]
    pub fn component_authorities_digest(&self) -> &[u8; 32] {
        &self.components_digest
    }

    /// Authenticates the same workflow bytes without exposing their authority.
    ///
    /// # Errors
    /// Refuses altered workflow bytes, cancellation or original expiry.
    pub fn verify_workflow_bytes(&self, bytes: &[u8]) -> Result<(), OriginalActorAccountError> {
        self.original.wait_slice()?;
        if blake3::hash(bytes).as_bytes() != &self.workflow_digest {
            return Err(OriginalActorAccountError::WorkflowBoundary {
                source: MeasurementOriginError::Authentication("original asset workflow bytes"),
                original: self.original.wait_slice().err(),
            });
        }
        self.original.wait_slice().map(|_| ()).map_err(Into::into)
    }

    /// Verifies the exact decoder owner without exposing a guard or account.
    ///
    /// # Errors
    /// Refuses an unrelated original allocation, cancellation or expiry.
    pub fn verify_decoder(
        &self,
        decoder: &OriginalActorDecodeOwner,
    ) -> Result<(), OriginalActorAccountError> {
        decoder.verify_original(&self.original)
    }

    /// Checks the original preparation retained by this declaration.
    ///
    /// # Errors
    /// Refuses the same original's terminal state or absolute expiry.
    pub fn verify_original(&self) -> Result<(), HostSupervisionError> {
        self.original.wait_slice().map(|_| ())
    }
}

/// Carries the one catalog entitlement authenticated by the same workflow.
///
/// This move-only value contains no account, quota readback or launch permit.
/// The catalog owner must still admit its actual audit and bind the installed
/// kernel project under this exact original preparation.
pub struct OriginalActorCatalogPurpose {
    pub(super) original: Arc<HostOperationGuard>,
    pub(super) project_id: u32,
}

impl OriginalActorServicePolicy {
    /// Moves the one authenticated prepared-service declaration.
    ///
    /// # Errors
    /// Refuses repeated transfer, cancellation or expiry of this original.
    pub fn take_launch_purpose(
        &mut self,
    ) -> Result<OriginalActorServiceLaunchPurpose, OriginalActorAccountError> {
        self.original.wait_slice()?;
        self.launch
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    /// Moves the one authenticated catalog purpose into its physical owner.
    ///
    /// # Errors
    /// Refuses repeated transfer or this original's expiry or cancellation.
    pub fn take_catalog_purpose(
        &mut self,
    ) -> Result<OriginalActorCatalogPurpose, OriginalActorAccountError> {
        self.original.wait_slice()?;
        self.catalog
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    /// Borrows the exact service policy identity bound by this same workflow.
    #[must_use]
    pub fn campaign_policy_digest(&self) -> &[u8; 32] {
        &self.campaign_digest
    }

    /// Borrows the source-built policy projection identity bound by this workflow.
    #[must_use]
    pub fn campaign_policy_projection_digest(&self) -> &[u8; 32] {
        &self.campaign_projection_digest
    }
}

trait InstalledInputValidation {
    fn digest(&self, expected_path: &str) -> Result<[u8; 32], MeasurementOriginError>;
}

impl InstalledInputValidation for InstalledInput<'_> {
    fn digest(&self, expected_path: &str) -> Result<[u8; 32], MeasurementOriginError> {
        if self.path != expected_path
            || self.blake3.len() != 64
            || !self
                .blake3
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MeasurementOriginError::Authentication(
                "original installed service input",
            ));
        }
        blake3::Hash::from_hex(self.blake3)
            .map(|hash| *hash.as_bytes())
            .map_err(|_| {
                MeasurementOriginError::Authentication("original installed service digest")
            })
    }
}

const CATALOG: ResourceVector = ResourceVector {
    resident_peak_bytes: 512 << 20,
    backing_peak_bytes: 8 << 30,
    metadata_bytes: 256 << 20,
    staging_bytes: 32 << 20,
    paging_io_slots: 1,
    cpu_slots: 1,
    task_slots: 1,
    file_descriptors: 128,
};

const NATIVE: ResourceVector = ResourceVector {
    resident_peak_bytes: 1536 << 20,
    backing_peak_bytes: 4 << 30,
    metadata_bytes: 512 << 20,
    staging_bytes: 32 << 20,
    paging_io_slots: 1,
    cpu_slots: 1,
    task_slots: 69,
    file_descriptors: 1056,
};

const AGGREGATE: Aggregate = Aggregate {
    native_slots: 4,
    cpu_slots: 10,
    resident_bytes: 16 << 30,
    backing_bytes: 64 << 30,
    metadata_bytes: 8 << 30,
    staging_bytes: 1 << 30,
    task_slots: 4096,
    file_descriptors: 65_536,
    paging_io_slots: 16,
    dirty_units: 150_000,
};

trait WorkflowProjectionValidation {
    fn validate(&self, native_count: u64) -> Result<(), MeasurementOriginError>;
}

impl WorkflowProjectionValidation for WorkflowProjection<'_> {
    fn validate(&self, native_count: u64) -> Result<(), MeasurementOriginError> {
        let profile = &self.service_profile;
        let operator = &profile.operator;
        let registry = operator.registry;
        // Metadata and staging occupy subsets of full residency. The four
        // authored host worker purposes, registry and catalog still fit CPU10;
        // a larger registry declaration never increases that enclosing cap.
        let subsets = registry.metadata_bytes.checked_add(registry.staging_bytes);
        let cpus = native_count
            .checked_add(4)
            .and_then(|cpus| cpus.checked_add(CATALOG.cpu_slots))
            .and_then(|cpus| cpus.checked_add(registry.cpu_slots));
        if self.schema != "crucible.measurement-resident-workflow.v2"
            || self.family != "residentThroughput"
            || self.native_count != native_count
            || ![1, 2, 4].contains(&native_count)
            || self.hot_fork.is_some()
            || self.world_memory_mib != 512
            || self.execution_quanta != 32
            || profile.catalog != CATALOG
            || profile.catalog_maximum_inodes != 1_048_576
            || profile.native != NATIVE
            || profile.aggregate != AGGREGATE
            || profile.preparation_seconds != 3600
            || profile.invocation_seconds != 3900
            || operator.sqlite_bootstrap_bytes == 0
            || operator.sqlite_heap_bytes == 0
            || operator.sqlite_heap_bytes > i64::MAX as u64
            || operator.sqlite_connections == 0
            || operator.actor_main_stack_bytes < 16_384
            || !operator.actor_main_stack_bytes.is_multiple_of(4096)
            || operator.actor_main_stack_bytes > AGGREGATE.resident_bytes
            || operator.registry_project_id == 0
            || operator.catalog_project_id == 0
            || operator.catalog_project_id == operator.registry_project_id
            || operator.registry_maximum_inodes == 0
            || [
                registry.resident_peak_bytes,
                registry.backing_peak_bytes,
                registry.metadata_bytes,
                registry.staging_bytes,
                registry.paging_io_slots,
                registry.cpu_slots,
                registry.task_slots,
                registry.file_descriptors,
            ]
            .contains(&0)
            || subsets.is_none_or(|bytes| bytes > registry.resident_peak_bytes)
            || registry.resident_peak_bytes > AGGREGATE.resident_bytes
            || registry.backing_peak_bytes > AGGREGATE.backing_bytes
            || registry.metadata_bytes > AGGREGATE.metadata_bytes
            || registry.staging_bytes > AGGREGATE.staging_bytes
            || registry.paging_io_slots > AGGREGATE.paging_io_slots
            || registry.task_slots > AGGREGATE.task_slots
            || registry.file_descriptors > AGGREGATE.file_descriptors
            || cpus.is_none_or(|cpus| cpus > AGGREGATE.cpu_slots)
        {
            return Err(MeasurementOriginError::Authentication(
                "original resident service profile",
            ));
        }
        operator
            .sqlite_bootstrap_proof
            .digest("/etc/crucible/sqlite-bootstrap-target.json")?;
        operator
            .campaign_policy
            .digest("/etc/crucible/measurement-service-policy.toml")?;
        operator
            .campaign_policy_projection
            .digest("/etc/crucible/measurement-service-policy.json")?;
        self.guest_assets.validate()?;
        // These fields remain in the authenticated input for the genuine
        // packaged decoder. Ignoring their shape here supplies no artifact,
        // scenario, schedule or completed-row authentication.
        let _packaged_inputs = (&self.qemu, &self.plugin, &self.rows);
        Ok(())
    }
}

impl OriginalActorAccountCustody {
    /// Authenticates the fixed workflow and derives its required service policy.
    ///
    /// The caller pays and retains the input bytes through the same decode
    /// owner before dispatch. This method verifies that owner's exact original
    /// allocation identity before parsing, then checks the retained parent's
    /// workflow digest, mode and width. It exposes no bank or arbitrary issuer.
    ///
    /// # Errors
    /// Refuses unavailable or different original custody, original expiry,
    /// altered workflow bytes, unsupported family, absent operator purposes,
    /// a changed corpus vector, or original decoder admission and syntax errors.
    /// The parser's first error precedes its separate original postcheck.
    pub fn admit_workflow_service(
        &self,
        owner: &OriginalActorDecodeOwner,
        bytes: &[u8],
    ) -> Result<OriginalActorServicePolicy, OriginalActorAccountError> {
        let held = self
            .held
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        held.preparation.wait_slice()?;
        owner.verify_original(&held.preparation)?;
        if blake3::hash(bytes).as_bytes() != held.evidence.workflow_digest()
            || held.evidence.mode() != &CertifiedMeasurementMode::NativeOnly
        {
            return Err(OriginalActorAccountError::WorkflowBoundary {
                source: MeasurementOriginError::Authentication("original workflow bytes or mode"),
                original: held.preparation.wait_slice().err(),
            });
        }

        let budget = owner.budget()?;
        let _scope = budget.enter();
        let decoded: WorkflowProjection<'_> = match from_json_slice_closed(bytes, budget) {
            Ok(decoded) => decoded,
            Err(source) => {
                return Err(OriginalActorAccountError::WorkflowDecode {
                    source,
                    original: held.preparation.wait_slice().err(),
                });
            }
        };
        if let Err(source) = decoded.validate(held.evidence.native_count()) {
            return Err(OriginalActorAccountError::WorkflowBoundary {
                source,
                original: held.preparation.wait_slice().err(),
            });
        }
        budget.check().map_err(OriginalActorAccountError::Decode)?;
        held.preparation.wait_slice()?;
        let components_digest = decoded
            .service_profile
            .operator
            .component_authorities
            .digest("/etc/crucible/measurement-components.v1")?;
        Ok(OriginalActorServicePolicy {
            launch: Some(OriginalActorServiceLaunchPurpose {
                original: Arc::clone(&held.preparation),
                server: decoded.service_profile.operator.campaign_server,
                mode: decoded.service_profile.operator.campaign_mode,
                components_digest,
                workflow_digest: *held.evidence.workflow_digest(),
            }),
            catalog: Some(OriginalActorCatalogPurpose {
                original: Arc::clone(&held.preparation),
                project_id: decoded.service_profile.operator.catalog_project_id,
            }),
            original: Arc::clone(&held.preparation),
            bootstrap_bytes: decoded.service_profile.operator.sqlite_bootstrap_bytes,
            heap_bytes: decoded.service_profile.operator.sqlite_heap_bytes,
            connections: decoded.service_profile.operator.sqlite_connections,
            main_stack_bytes: decoded.service_profile.operator.actor_main_stack_bytes,
            bootstrap_digest: decoded
                .service_profile
                .operator
                .sqlite_bootstrap_proof
                .digest("/etc/crucible/sqlite-bootstrap-target.json")?,
            campaign_digest: decoded
                .service_profile
                .operator
                .campaign_policy
                .digest("/etc/crucible/measurement-service-policy.toml")?,
            campaign_projection_digest: decoded
                .service_profile
                .operator
                .campaign_policy_projection
                .digest("/etc/crucible/measurement-service-policy.json")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection(width: u64) -> WorkflowProjection<'static> {
        WorkflowProjection {
            schema: "crucible.measurement-resident-workflow.v2",
            family: "residentThroughput",
            native_count: width,
            hot_fork: None,
            world_memory_mib: 512,
            execution_quanta: 32,
            service_profile: ServiceProfile {
                operator: ServiceOperator {
                    campaign_server: ServiceServer {
                        connection_workers: 1,
                        pending_connections: 1,
                        maximum_requests_per_connection: 1,
                        accept_poll_millis: 1,
                        read_timeout_millis: 100,
                        write_timeout_millis: 100,
                    },
                    campaign_mode: ServiceMode::ReadWrite,
                    component_authorities: InstalledInput {
                        path: "/etc/crucible/measurement-components.v1",
                        blake3: "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    sqlite_bootstrap_bytes: 4096,
                    sqlite_heap_bytes: 8192,
                    sqlite_connections: 1,
                    actor_main_stack_bytes: 8 << 20,
                    sqlite_bootstrap_proof: InstalledInput {
                        path: "/etc/crucible/sqlite-bootstrap-target.json",
                        blake3: "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    campaign_policy: InstalledInput {
                        path: "/etc/crucible/measurement-service-policy.toml",
                        blake3: "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    campaign_policy_projection: InstalledInput {
                        path: "/etc/crucible/measurement-service-policy.json",
                        blake3: "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                    registry: ResourceVector {
                        resident_peak_bytes: 256 << 20,
                        backing_peak_bytes: 1 << 30,
                        metadata_bytes: 32 << 20,
                        staging_bytes: 32 << 20,
                        paging_io_slots: 1,
                        cpu_slots: 1,
                        task_slots: 1,
                        file_descriptors: 64,
                    },
                    registry_project_id: 42,
                    catalog_project_id: 43,
                    registry_maximum_inodes: 1024,
                },
                catalog: CATALOG,
                catalog_maximum_inodes: 1_048_576,
                native: NATIVE,
                aggregate: AGGREGATE,
                preparation_seconds: 3600,
                invocation_seconds: 3900,
            },
            guest_assets: GuestAssets::fixture(),
            qemu: IgnoredAny,
            plugin: IgnoredAny,
            rows: IgnoredAny,
        }
    }

    #[test]
    fn fixed_vectors_and_required_sqlite_purposes_preserve_each_authored_width() {
        for width in [1, 2, 4] {
            let mut input = projection(width);
            assert!(input.validate(width).is_ok());

            input.service_profile.operator.sqlite_bootstrap_bytes = 0;
            assert!(input.validate(width).is_err());
            input.service_profile.operator.sqlite_bootstrap_bytes = 4096;
            input.service_profile.native.metadata_bytes += 1;
            assert!(input.validate(width).is_err());
        }
    }

    #[test]
    fn metadata_subsets_and_all_simultaneous_cpu_purposes_cannot_raise_actor_caps() {
        let mut input = projection(4);
        input.service_profile.operator.registry.cpu_slots = 2;
        assert!(input.validate(4).is_err());

        input.service_profile.operator.registry.cpu_slots = 1;
        input.service_profile.operator.registry.resident_peak_bytes = 1 << 20;
        assert!(input.validate(4).is_err());
    }

    #[test]
    fn catalog_project_identity_is_required_and_distinct_from_registry() {
        let mut input = projection(1);
        input.service_profile.operator.catalog_project_id = 0;
        assert!(input.validate(1).is_err());
        input.service_profile.operator.catalog_project_id = 42;
        assert!(input.validate(1).is_err());
        input.service_profile.operator.catalog_project_id = 43;
        assert!(input.validate(1).is_ok());
    }

    #[test]
    fn hot_fork_and_changed_original_intervals_refuse_the_fixed_family() {
        let mut input = projection(2);
        input.hot_fork = Some(IgnoredAny);
        assert!(input.validate(2).is_err());

        input.hot_fork = None;
        input.service_profile.preparation_seconds = 3601;
        assert!(input.validate(2).is_err());
    }
}
