//! Signed-policy-committed declaration for a whole-ODB upload bootstrap.
//!
//! The values describe immutable identity and finite policy ceilings. They do
//! not prove a live export, total project usage, enforcement, funding or admission.

use crate::{
    AccountingError, ExportId, FeatureRef, ObjectDigest, ProjectId, ResourceAccount,
    ResourceCeilings, ResourceDimension, ResourceId, ResourceVector,
};

/// Bounds the canonical fourteen-field capacity declaration.
pub const MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1: usize = 645;

/// Reports invalid identity, finite arithmetic or enforcement declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidGitUploadCapacityV1 {
    /// A required identity, generation, commitment or scalar is zero.
    #[error("Git upload capacity contains an invalid identity or scalar")]
    Identity,
    /// The declared concurrency pool or uniform reservation is invalid.
    #[error("Git upload capacity concurrency or I/O slice is invalid")]
    UniformSlice,
    /// The exact two enforcement declarations are absent or noncanonical.
    #[error("Git upload capacity enforcement declarations are invalid")]
    Enforcement,
    /// Checked resource arithmetic rejected the worst-case full pool.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

/// Holds bounded bootstrap DATA, never an execution or reservation permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitUploadCapacityV1 {
    project: ProjectId,
    resource: ResourceId,
    export: ExportId,
    generation: u64,
    generation_commitment: ObjectDigest,
    audience_commitment: ObjectDigest,
    ceilings: ResourceVector,
    uniform_reservation: ResourceVector,
    cpu_period_micros: u64,
    project_io_bytes_per_second: u64,
    uniform_io_bytes_per_second: u64,
    maximum_duration_nanoseconds: u64,
    enforcement: [FeatureRef; 2],
}

impl GitUploadCapacityV1 {
    /// Validates one finite declaration without establishing live authority.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, invalid intervals, unknown enforcement tuples,
    /// a nonuniform concurrency slice, overflow or full-pool ceiling excess.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        resource: ResourceId,
        export: ExportId,
        generation: u64,
        generation_commitment: ObjectDigest,
        audience_commitment: ObjectDigest,
        ceilings: ResourceVector,
        uniform_reservation: ResourceVector,
        cpu_period_micros: u64,
        project_io_bytes_per_second: u64,
        uniform_io_bytes_per_second: u64,
        maximum_duration_nanoseconds: u64,
        enforcement: [FeatureRef; 2],
    ) -> Result<Self, InvalidGitUploadCapacityV1> {
        if project.as_bytes() == &[0; 16]
            || resource.as_bytes() == &[0; 16]
            || export.as_bytes() == &[0; 16]
            || generation == 0
            || generation_commitment.as_bytes() == &[0; 32]
            || audience_commitment.as_bytes() == &[0; 32]
            || cpu_period_micros == 0
            || project_io_bytes_per_second == 0
            || uniform_io_bytes_per_second == 0
            || maximum_duration_nanoseconds == 0
        {
            return Err(InvalidGitUploadCapacityV1::Identity);
        }

        let slots = ceilings.get(ResourceDimension::ConcurrentOperations);
        if slots == 0 || uniform_reservation.get(ResourceDimension::ConcurrentOperations) != 1 {
            return Err(InvalidGitUploadCapacityV1::UniformSlice);
        }
        let total_io = uniform_io_bytes_per_second
            .checked_mul(slots)
            .ok_or(InvalidGitUploadCapacityV1::UniformSlice)?;
        if total_io > project_io_bytes_per_second {
            return Err(InvalidGitUploadCapacityV1::UniformSlice);
        }

        // Multiplication supplies DATA to the existing account check; no
        // independent ceiling or zero-as-unlimited interpretation is added.
        let mut full_pool = ResourceVector::ZERO;
        for dimension in ResourceDimension::ALL {
            let amount = uniform_reservation.get(dimension)
                .checked_mul(slots)
                .ok_or(AccountingError::ArithmeticOverflow { dimension })?;
            full_pool = full_pool.with(dimension, amount);
        }
        ResourceAccount::from_usage(
            ResourceCeilings::bounded(ceilings),
            ResourceVector::ZERO,
            full_pool,
        )?;

        let expected = [
            "aos.sandbox.enforcement.broker-ledger",
            "aos.sandbox.enforcement.cgroup-v2",
        ];
        if enforcement.iter().zip(expected).any(|(actual, namespace)| {
            actual.namespace() != namespace || actual.major() != 1 || actual.minor() != 0
        }) {
            return Err(InvalidGitUploadCapacityV1::Enforcement);
        }

        Ok(Self {
            project,
            resource,
            export,
            generation,
            generation_commitment,
            audience_commitment,
            ceilings,
            uniform_reservation,
            cpu_period_micros,
            project_io_bytes_per_second,
            uniform_io_bytes_per_second,
            maximum_duration_nanoseconds,
            enforcement,
        })
    }

    /// Returns the signed project as DATA.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the distinct whole-ODB resource as DATA.
    #[must_use]
    pub const fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Returns the immutable export declaration as DATA.
    #[must_use]
    pub const fn export(&self) -> ExportId {
        self.export
    }

    /// Returns the immutable export generation as DATA.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the complete generation commitment as DATA.
    #[must_use]
    pub const fn generation_commitment(&self) -> ObjectDigest {
        self.generation_commitment
    }

    /// Returns the complete readable audience commitment as DATA.
    #[must_use]
    pub const fn audience_commitment(&self) -> ObjectDigest {
        self.audience_commitment
    }

    /// Returns the finite project ceiling declaration as DATA.
    #[must_use]
    pub const fn ceilings(&self) -> ResourceVector {
        self.ceilings
    }

    /// Returns the uniform operation slice declaration as DATA.
    #[must_use]
    pub const fn uniform_reservation(&self) -> ResourceVector {
        self.uniform_reservation
    }

    /// Returns the declared CPU period as DATA.
    #[must_use]
    pub const fn cpu_period_micros(&self) -> u64 {
        self.cpu_period_micros
    }

    /// Returns the declared aggregate I/O rate as DATA.
    #[must_use]
    pub const fn project_io_bytes_per_second(&self) -> u64 {
        self.project_io_bytes_per_second
    }

    /// Returns the declared uniform I/O slice as DATA.
    #[must_use]
    pub const fn uniform_io_bytes_per_second(&self) -> u64 {
        self.uniform_io_bytes_per_second
    }

    /// Returns the nonadditive original-cut maximum as DATA.
    #[must_use]
    pub const fn maximum_duration_nanoseconds(&self) -> u64 {
        self.maximum_duration_nanoseconds
    }

    /// Borrows the exact canonical enforcement declarations.
    #[must_use]
    pub fn enforcement(&self) -> &[FeatureRef; 2] {
        &self.enforcement
    }
}
