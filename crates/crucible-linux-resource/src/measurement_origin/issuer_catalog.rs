//! Provisions the two trusted disposable filesystem projects before actor birth.
//!
//! The caller first authenticates the parent and the exact pinned workflow.
//! This slot owns installation results and typed failures through kernel/VM
//! teardown; quota readback verifies enforcement and never issues a resource
//! grant. The original externally retained boot/Source purpose must cover
//! these allocations, descriptors and effects before boot. This module does
//! not establish the completeness or peak of that original purpose.

use super::{MeasurementOriginError, OriginalInterval};
use crate::{LinuxProjectQuotaInstallError, LinuxProjectQuotaLimits, LinuxProjectQuotaReservation};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek};

const CATALOG_PATH: &str = "/var/lib/crucible/measurement/catalog";
const REGISTRY_PATH: &str = "/var/lib/crucible/measurement/registry";
const CATALOG_BYTES: u64 = 8 << 30;
const CATALOG_INODES: u64 = 1 << 20;
const MAX_WORKFLOW_BYTES: u64 = 1 << 20;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Workflow<'a> {
    #[serde(borrow)]
    schema: &'a str,
    service_profile: Profile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    operator: Operator,
    catalog: Vector,
    catalog_maximum_inodes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Operator {
    catalog_project_id: u32,
    registry_project_id: u32,
    registry: Vector,
    registry_maximum_inodes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    backing_peak_bytes: u64,
}

impl Workflow<'_> {
    fn check(&self) -> Result<(), SetupFailure> {
        let policy = &self.service_profile.operator;
        if self.schema != "crucible.measurement-resident-workflow.v2"
            || !valid_projects(policy.catalog_project_id, policy.registry_project_id)
            || self.service_profile.catalog.backing_peak_bytes != CATALOG_BYTES
            || self.service_profile.catalog_maximum_inodes != CATALOG_INODES
            || policy.registry.backing_peak_bytes < 1024
            || policy.registry.backing_peak_bytes > (64 << 30) - CATALOG_BYTES
            || policy.registry_maximum_inodes == 0
            || policy.registry_maximum_inodes > CATALOG_INODES
        {
            return Err(SetupFailure::Contract("installed quota partition"));
        }
        Ok(())
    }
}

fn check_capacity(
    bytes: u64,
    inodes: u64,
    required_bytes: u64,
    required_inodes: u64,
) -> Result<(), SetupFailure> {
    if bytes < required_bytes || inodes < required_inodes {
        return Err(SetupFailure::Contract(
            "insufficient disposable project capacity",
        ));
    }
    Ok(())
}

fn valid_projects(catalog: u32, registry: u32) -> bool {
    catalog != 0
        && registry != 0
        && catalog != registry
        && catalog <= i32::MAX as u32
        && registry <= i32::MAX as u32
}

/// Keeps the complete setup custody beside its first error and original cut.
pub(super) struct IssuerCatalog {
    input: Option<Vec<u8>>,
    catalog: Option<LinuxProjectQuotaReservation>,
    registry: Option<LinuxProjectQuotaReservation>,
    pending_filesystem: Option<File>,
    pending_directory: Option<File>,
    first: Option<SetupFailure>,
    original_after: Option<MeasurementOriginError>,
}

impl IssuerCatalog {
    /// Creates an unoccupied inline custody slot.
    pub(super) const fn empty() -> Self {
        Self {
            input: None,
            catalog: None,
            registry: None,
            pending_filesystem: None,
            pending_directory: None,
            first: None,
            original_after: None,
        }
    }

    /// Installs both authenticated projects while retaining every completed outcome.
    ///
    /// # Errors
    ///
    /// Returns a closed refusal when the workflow, kernel or original interval
    /// refuses. The complete first cause and any partial owner remain in this slot.
    pub(super) fn install(
        &mut self,
        workflow: &mut File,
        original: OriginalInterval,
    ) -> Result<(), MeasurementOriginError> {
        let result = self.install_inner(workflow, original);
        if let Err(error) = result {
            self.first.get_or_insert(error);
        }
        // Retain actual successful owners or the whole originating failure
        // before evaluating this independent final original decision.
        if let Err(error) = original.before() {
            self.original_after.get_or_insert(error);
        }
        if self.first.is_some() || self.original_after.is_some() {
            return Err(MeasurementOriginError::Authentication(
                "retained catalog quota setup",
            ));
        }
        Ok(())
    }

    // This helper accepts only scalar or unit outcomes. Effect owners are
    // published in their slots before calling it; it never carries a File or
    // quota owner across a refusing postcut.
    fn observe<T>(
        &mut self,
        result: Result<T, SetupFailure>,
        original: OriginalInterval,
    ) -> Result<T, SetupFailure> {
        let value = match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.first.get_or_insert(error);
                None
            }
        };
        if let Err(error) = original.before() {
            self.original_after.get_or_insert(error);
        }
        if self.first.is_some() || self.original_after.is_some() {
            return Err(SetupFailure::Contract("retained quota setup outcome"));
        }
        value.ok_or(SetupFailure::Contract("quota setup outcome"))
    }

    fn install_inner(
        &mut self,
        workflow: &mut File,
        original: OriginalInterval,
    ) -> Result<(), SetupFailure> {
        if self.input.is_some()
            || self.catalog.is_some()
            || self.registry.is_some()
            || self.first.is_some()
            || self.original_after.is_some()
        {
            return Err(SetupFailure::Contract("quota initializer replay"));
        }
        original.before()?;
        let result = workflow
            .metadata()
            .map(|metadata| metadata.len())
            .map_err(SetupFailure::Io);
        let length = self.observe(result, original)?;
        if length == 0 || length > MAX_WORKFLOW_BYTES {
            return Err(SetupFailure::Contract("quota workflow extent"));
        }
        let length = usize::try_from(length)
            .map_err(|_| SetupFailure::Contract("quota workflow target extent"))?;
        let mut input = Vec::new();
        let allocation = input.try_reserve_exact(length);
        if allocation.is_ok() {
            input.resize(length, 0);
            self.input = Some(input);
        }
        self.observe(allocation.map_err(SetupFailure::Allocation), original)?;

        original.before()?;
        let rewind = workflow.rewind().map_err(SetupFailure::Io);
        self.observe(rewind, original)?;
        original.before()?;
        let read = workflow
            .read_exact(
                self.input
                    .as_mut()
                    .ok_or(SetupFailure::Contract("quota input custody"))?,
            )
            .map_err(SetupFailure::Io);
        self.observe(read, original)?;
        let input = self
            .input
            .as_ref()
            .ok_or(SetupFailure::Contract("quota input custody"))?;
        let parameters: Workflow<'_> = serde_json::from_slice(input)?;
        parameters.check()?;
        let catalog_project = parameters.service_profile.operator.catalog_project_id;
        let registry_project = parameters.service_profile.operator.registry_project_id;
        let registry_bytes = parameters
            .service_profile
            .operator
            .registry
            .backing_peak_bytes;
        let registry_inodes = parameters.service_profile.operator.registry_maximum_inodes;

        original.before()?;
        self.open_filesystem(original)?;
        let filesystem = self
            .pending_filesystem
            .as_ref()
            .ok_or(SetupFailure::Contract("quota filesystem custody"))?;
        let capacity =
            rustix::fs::fstatvfs(filesystem).map_err(|error| SetupFailure::Io(error.into()));
        let capacity = self.observe(capacity, original)?;
        let usable_bytes = capacity
            .f_bavail
            .checked_mul(capacity.f_frsize)
            .ok_or(SetupFailure::Contract("quota free-byte overflow"))?;
        let required_bytes = CATALOG_BYTES
            .checked_add(registry_bytes)
            .ok_or(SetupFailure::Contract("quota backing overflow"))?;
        let required_inodes = CATALOG_INODES
            .checked_add(registry_inodes)
            .ok_or(SetupFailure::Contract("quota inode overflow"))?;
        check_capacity(
            usable_bytes,
            capacity.f_favail,
            required_bytes,
            required_inodes,
        )?;

        // Scalars select installed physical limits, not an account or grant.
        // The same already-authenticated external owner retains their backing.
        self.install_project(
            CATALOG_PATH,
            catalog_project,
            CATALOG_BYTES,
            CATALOG_INODES,
            true,
            original,
        )?;
        self.open_filesystem(original)?;
        self.install_project(
            REGISTRY_PATH,
            registry_project,
            registry_bytes,
            registry_inodes,
            false,
            original,
        )?;
        Ok(())
    }

    fn open_filesystem(&mut self, original: OriginalInterval) -> Result<(), SetupFailure> {
        original.before()?;
        let result = match File::open("/") {
            Ok(file) => {
                self.pending_filesystem = Some(file);
                Ok(())
            }
            Err(error) => Err(SetupFailure::Io(error)),
        };
        self.observe(result, original)
    }

    fn install_project(
        &mut self,
        path: &str,
        project: u32,
        bytes: u64,
        inodes: u64,
        catalog: bool,
        original: OriginalInterval,
    ) -> Result<(), SetupFailure> {
        original.before()?;
        // Fresh siblings keep every catalog child under PROJINHERIT while the
        // registry remains outside the catalog's same-project audit namespace.
        let result = std::fs::create_dir(path).map_err(SetupFailure::Io);
        self.observe(result, original)?;
        original.before()?;
        let opened = match File::open(path) {
            Ok(file) => {
                self.pending_directory = Some(file);
                Ok(())
            }
            Err(error) => Err(SetupFailure::Io(error)),
        };
        self.observe(opened, original)?;
        let limits = LinuxProjectQuotaLimits::new(bytes, inodes)?;
        original.before()?;
        let filesystem = self
            .pending_filesystem
            .take()
            .ok_or(SetupFailure::Contract("quota filesystem custody"))?;
        let directory = self
            .pending_directory
            .take()
            .ok_or(SetupFailure::Contract("quota directory custody"))?;
        let result = match LinuxProjectQuotaReservation::install(
            filesystem.into(),
            directory.into(),
            path,
            project,
            limits,
        ) {
            Ok(owner) => {
                if catalog {
                    self.catalog = Some(owner);
                } else {
                    self.registry = Some(owner);
                }
                Ok(())
            }
            Err(error) => Err(SetupFailure::Install(error)),
        };
        // Successful quota custody or the complete install error (including
        // partial cleanup authority) precedes the independent original postcut.
        self.observe(result, original)?;
        original.before()?;
        let owner = if catalog {
            &self.catalog
        } else {
            &self.registry
        };
        let verified = owner
            .as_ref()
            .ok_or(SetupFailure::Contract("installed quota custody"))?
            .verify_usage()
            .map_err(SetupFailure::Verify);
        self.observe(verified.map(|_| ()), original)
    }

    /// Formats retained causes while the caller already holds the issuer lock.
    ///
    /// # Errors
    ///
    /// Returns the supplied formatter's output error.
    pub(super) fn format_refusal(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.first {
            write!(formatter, "; catalog setup: {error}")?;
        }
        if let Some(error) = &self.original_after {
            write!(formatter, "; catalog original postcut: {error}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum SetupFailure {
    #[error("quota kernel I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("quota input allocation: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("quota workflow decode: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("quota contract: {0}")]
    Contract(&'static str),
    #[error("quota installation: {0}")]
    Install(#[from] LinuxProjectQuotaInstallError),
    #[error("quota verification: {0}")]
    Verify(#[from] crate::LinuxProjectQuotaError),
    #[error("quota original interval: {0}")]
    Original(#[from] MeasurementOriginError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expired_original() -> OriginalInterval {
        OriginalInterval {
            start_ns: 0,
            end_ns: 1,
        }
    }

    fn parameters() -> Workflow<'static> {
        Workflow {
            schema: "crucible.measurement-resident-workflow.v2",
            service_profile: Profile {
                operator: Operator {
                    catalog_project_id: 12,
                    registry_project_id: 13,
                    registry: Vector {
                        backing_peak_bytes: 1 << 20,
                    },
                    registry_maximum_inodes: 128,
                },
                catalog: Vector {
                    backing_peak_bytes: CATALOG_BYTES,
                },
                catalog_maximum_inodes: CATALOG_INODES,
            },
        }
    }

    #[test]
    fn projects_are_distinct_and_fit_the_real_kernel_interface() {
        assert!(valid_projects(1, 2));
        assert!(!valid_projects(0, 2));
        assert!(!valid_projects(1, 1));
        assert!(!valid_projects(u32::MAX, 2));
    }

    #[test]
    fn installed_workflow_preserves_exact_catalog_and_whole_backing_partition() {
        let mut workflow = parameters();
        assert!(workflow.check().is_ok());

        workflow.service_profile.operator.registry_project_id = 12;
        assert!(workflow.check().is_err());
        workflow.service_profile.operator.registry_project_id = 13;
        workflow.service_profile.catalog.backing_peak_bytes -= 1024;
        assert!(workflow.check().is_err());
        workflow.service_profile.catalog.backing_peak_bytes = CATALOG_BYTES;
        workflow
            .service_profile
            .operator
            .registry
            .backing_peak_bytes = 64 << 30;
        assert!(workflow.check().is_err());
    }

    #[test]
    fn missing_authored_project_is_rejected_by_the_actual_borrowed_decoder() {
        let missing = br#"{"schema":"crucible.measurement-resident-workflow.v2","serviceProfile":{"operator":{"registryProjectId":13,"registry":{"backingPeakBytes":1048576},"registryMaximumInodes":128},"catalog":{"backingPeakBytes":8589934592},"catalogMaximumInodes":1048576}}"#;
        assert!(serde_json::from_slice::<Workflow<'_>>(missing).is_err());
    }

    #[test]
    fn free_filesystem_capacity_must_cover_both_projects() {
        assert!(check_capacity(100, 20, 100, 20).is_ok());
        assert!(check_capacity(99, 20, 100, 20).is_err());
        assert!(check_capacity(100, 19, 100, 20).is_err());
    }

    #[test]
    fn actual_io_cause_is_retained_beside_later_original_refusal() {
        let mut slot = IssuerCatalog::empty();
        let error = File::open("/proc/self/this-file-does-not-exist").unwrap_err();
        let raw_code = error.raw_os_error();
        assert!(
            slot.observe::<()>(Err(SetupFailure::Io(error)), expired_original())
                .is_err()
        );

        let Some(SetupFailure::Io(retained)) = &slot.first else {
            panic!("actual I/O failure was not published");
        };
        assert_eq!(retained.raw_os_error(), raw_code);
        assert!(matches!(
            slot.original_after,
            Some(MeasurementOriginError::Clock)
        ));
        // Subsequent refusal cannot substitute its cause for the first one.
        assert!(
            slot.observe::<()>(Err(SetupFailure::Contract("later")), expired_original())
                .is_err()
        );
        assert!(matches!(slot.first, Some(SetupFailure::Io(_))));
    }

    #[test]
    fn real_non_ext4_install_failure_remains_owned_after_expiry() {
        let filesystem = File::open("/proc").unwrap();
        let directory = File::open("/proc").unwrap();
        assert_ne!(
            rustix::fs::fstatfs(&filesystem).unwrap().f_type,
            libc::EXT4_SUPER_MAGIC
        );
        let limits = LinuxProjectQuotaLimits::new(CATALOG_BYTES, CATALOG_INODES).unwrap();
        let error = LinuxProjectQuotaReservation::install(
            filesystem.into(),
            directory.into(),
            CATALOG_PATH,
            12,
            limits,
        )
        .expect_err("procfs must refuse before quota effects");
        assert!(matches!(
            error.source_error(),
            crate::LinuxProjectQuotaError::UnsupportedFilesystem { .. }
        ));

        let mut slot = IssuerCatalog::empty();
        assert!(
            slot.observe::<()>(Err(SetupFailure::Install(error)), expired_original())
                .is_err()
        );
        let Some(SetupFailure::Install(retained)) = &slot.first else {
            panic!("complete quota install error was not published");
        };
        assert!(matches!(
            retained.source_error(),
            crate::LinuxProjectQuotaError::UnsupportedFilesystem { .. }
        ));
        assert!(matches!(
            slot.original_after,
            Some(MeasurementOriginError::Clock)
        ));
    }
}
