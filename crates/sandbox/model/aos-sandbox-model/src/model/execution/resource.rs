//! Exact execution-local limits and nonauthorizing output reservation claims.

use crate::model::spec::{LimitDimension, LimitValue, ResourceProfile};
use crate::{
    CanonicalAssignmentManifestV1, FeatureRef, ObjectDigest, ResourceDimension, ResourceVector,
};

use super::validation::{
    execution_enforcement_feature, output_enforcement_feature, output_reservation_commitment,
    strictly_increasing_by_dimension, validate_admitted_resource_value,
    validate_execution_enforcement, validate_parent_resource_value, validate_resource_admission,
    validate_resource_value,
};
use super::{
    InvalidExecutionSpec, MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES, MAX_EXECUTION_RESOURCE_SETTINGS,
};

/// Selects whether a requested resource inherits policy or supplies a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionResourceRequestValueV1 {
    /// Requests admission under the resolved parent setting for this dimension.
    Inherit,
    /// Requests a finite maximum for an absolute resource dimension.
    Maximum(u64),
    /// Requests a cgroup-v2 relative weight in the inclusive range 1..=10,000.
    RelativeWeight(u16),
}

/// Stores one caller-requested execution resource setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResourceRequestV1 {
    dimension: LimitDimension,
    value: ExecutionResourceRequestValueV1,
    enforcement: FeatureRef,
}

impl ExecutionResourceRequestV1 {
    /// Constructs one requested resource setting with typed value semantics.
    ///
    /// The required enforcement feature is derived from the dimension's closed
    /// v1 mapping rather than accepted from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for a dimension/value mismatch or a
    /// value outside the closed range.
    pub fn new(
        dimension: LimitDimension,
        value: ExecutionResourceRequestValueV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        validate_resource_value(dimension, value)?;
        let enforcement = execution_enforcement_feature(dimension)?;
        Ok(Self {
            dimension,
            value,
            enforcement,
        })
    }

    /// Returns the requested closed resource dimension.
    #[must_use]
    pub const fn dimension(&self) -> LimitDimension {
        self.dimension
    }

    /// Returns the requested inherited, maximum, or relative value.
    #[must_use]
    pub const fn value(&self) -> ExecutionResourceRequestValueV1 {
        self.value
    }

    /// Returns the exact dimension-derived enforcement feature.
    #[must_use]
    pub const fn enforcement(&self) -> &FeatureRef {
        &self.enforcement
    }
}

/// Selects the exact admitted finite semantics for a resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionResourceSublimitValueV1 {
    /// Admits a finite upper bound for an absolute dimension.
    Maximum(u64),
    /// Admits a cgroup-v2 relative weight in the inclusive range 1..=10,000.
    RelativeWeight(u16),
}

/// Stores one admitted execution-local resource sublimit or relative weight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResourceSublimitV1 {
    dimension: LimitDimension,
    value: ExecutionResourceSublimitValueV1,
    enforcement: FeatureRef,
}

impl ExecutionResourceSublimitV1 {
    /// Constructs one admitted resource setting with typed value semantics.
    ///
    /// The required enforcement feature is derived from the dimension's closed
    /// v1 mapping rather than accepted from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for a dimension/value mismatch or a
    /// value outside the closed range.
    pub fn new(
        dimension: LimitDimension,
        value: ExecutionResourceSublimitValueV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        validate_admitted_resource_value(dimension, value)?;
        let enforcement = execution_enforcement_feature(dimension)?;
        Ok(Self {
            dimension,
            value,
            enforcement,
        })
    }

    /// Returns the admitted closed resource dimension.
    #[must_use]
    pub const fn dimension(&self) -> LimitDimension {
        self.dimension
    }

    /// Returns the admitted maximum or relative weight.
    #[must_use]
    pub const fn value(&self) -> ExecutionResourceSublimitValueV1 {
        self.value
    }

    /// Returns the exact dimension-derived enforcement feature.
    #[must_use]
    pub const fn enforcement(&self) -> &FeatureRef {
        &self.enforcement
    }
}

/// Stores a nonauthorizing output-byte claim bound to an exact assignment.
///
/// This value proves internal consistency only. Before execution or capture
/// effects, a protected adapter must obtain broker-ledger admission bound to
/// the exact execution ID, revalidate that the embedded assignment is current,
/// and reserve the admitted [`ResourceDimension::OutputBytes`].
/// Effectful adapter APIs must require that protected evidence separately and
/// must not accept this value as authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutputByteAdmissionV1 {
    requested_bytes: u64,
    admitted_bytes: u64,
    assignment: CanonicalAssignmentManifestV1,
    reservation_commitment: ObjectDigest,
    enforcement: FeatureRef,
}

impl ExecutionOutputByteAdmissionV1 {
    /// Constructs an internally consistent output-byte reservation claim.
    ///
    /// The claim uses [`ResourceDimension::OutputBytes`] and derives the
    /// broker-ledger 1.0 enforcement feature. The canonical assignment supplies
    /// the exact claimed parent reservation vector but does not prove current
    /// authority or reserve ledger capacity.
    /// The reservation SHA-256 preimage is the purpose domain, the one-byte
    /// output dimension, `u64be(requested)`, `u64be(admitted)`, all 22 parent
    /// reservation values in registry order, the assignment digest, and the
    /// length-delimited enforcement feature with big-endian versions.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] when the canonical assignment exceeds
    /// the execution bound, the admitted claim exceeds the request, or the
    /// admitted claim exceeds the assignment's exact output-byte reservation.
    pub fn new(
        requested_bytes: u64,
        admitted_bytes: u64,
        assignment: CanonicalAssignmentManifestV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        let parent_reservations = assignment.manifest().reservations();
        if assignment.canonical_bytes().len() > MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES
            || admitted_bytes > requested_bytes
            || admitted_bytes > parent_reservations.get(ResourceDimension::OutputBytes)
        {
            return Err(InvalidExecutionSpec::InvalidOutputAdmission);
        }
        let enforcement = output_enforcement_feature()?;
        let reservation_commitment = output_reservation_commitment(
            requested_bytes,
            admitted_bytes,
            parent_reservations,
            assignment.digest(),
            &enforcement,
        );
        Ok(Self {
            requested_bytes,
            admitted_bytes,
            assignment,
            reservation_commitment,
            enforcement,
        })
    }

    /// Returns the requested output-retention bytes.
    #[must_use]
    pub const fn requested_bytes(&self) -> u64 {
        self.requested_bytes
    }

    /// Returns the exact admitted output-retention bytes.
    #[must_use]
    pub const fn admitted_bytes(&self) -> u64 {
        self.admitted_bytes
    }

    /// Returns the complete claimed parent reservation vector.
    #[must_use]
    pub const fn parent_reservations(&self) -> ResourceVector {
        self.assignment.manifest().reservations()
    }

    /// Returns the canonical assignment bound into the claim.
    #[must_use]
    pub const fn assignment(&self) -> &CanonicalAssignmentManifestV1 {
        &self.assignment
    }

    /// Returns the assignment digest bound to the parent-vector claim.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment.digest()
    }

    /// Returns the purpose-domain commitment to the complete nonauthorizing claim.
    #[must_use]
    pub const fn reservation_commitment(&self) -> ObjectDigest {
        self.reservation_commitment
    }

    /// Returns broker-ledger 1.0 as the required protected reservation mechanism.
    #[must_use]
    pub const fn enforcement(&self) -> &FeatureRef {
        &self.enforcement
    }
}

/// Retains requested settings, admitted sublimits, and their exact parent policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResourceAdmissionV1 {
    requested: Vec<ExecutionResourceRequestV1>,
    admitted: Vec<ExecutionResourceSublimitV1>,
    parent_profile: ResourceProfile,
    parent_profile_commitment: ObjectDigest,
    output_bytes: ExecutionOutputByteAdmissionV1,
}

impl ExecutionResourceAdmissionV1 {
    /// Validates an execution resource decision against its exact parent profile.
    ///
    /// Requested and admitted vectors must have identical dimensions. Absolute
    /// admitted maxima cannot exceed either an explicit request or finite
    /// parent maximum. CPU and I/O weights are mandatory exact request/admission
    /// pairs selected independently of parent ceilings. Parent weight entries
    /// may be absent; when retained, they must be finite valid weights with the
    /// closed enforcement feature but do not constrain the child pair. Every
    /// execution-local dimension uses its closed v1 enforcement mapping; parent
    /// enforcement must match for the remaining bounded dimensions. Output
    /// retention is a distinct, nonauthorizing broker-ledger claim under the
    /// canonical assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for a noncanonical set, mismatched
    /// commitment, unresolved/missing parent setting, malformed parent weight,
    /// enforcement mismatch, dimension/value mismatch, or value exceeding its
    /// governing bound.
    pub fn new(
        requested: Vec<ExecutionResourceRequestV1>,
        admitted: Vec<ExecutionResourceSublimitV1>,
        parent_profile: ResourceProfile,
        parent_profile_commitment: ObjectDigest,
        output_bytes: ExecutionOutputByteAdmissionV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        if requested.len() > MAX_EXECUTION_RESOURCE_SETTINGS
            || admitted.len() > MAX_EXECUTION_RESOURCE_SETTINGS
            || parent_profile.limits().len() > MAX_EXECUTION_RESOURCE_SETTINGS
            || !strictly_increasing_by_dimension(&requested, |entry| entry.dimension())
            || !strictly_increasing_by_dimension(&admitted, |entry| entry.dimension())
        {
            return Err(InvalidExecutionSpec::ResourceSettingsNotCanonical);
        }
        if parent_profile.contains_inherited() {
            return Err(InvalidExecutionSpec::ParentResourceUnavailable);
        }
        for feature in requested
            .iter()
            .map(ExecutionResourceRequestV1::enforcement)
            .chain(
                admitted
                    .iter()
                    .map(ExecutionResourceSublimitV1::enforcement),
            )
            .chain(
                parent_profile
                    .limits()
                    .iter()
                    .map(|limit| limit.enforcement()),
            )
            .chain(std::iter::once(output_bytes.enforcement()))
        {
            crate::validate_required_features(std::slice::from_ref(feature))?;
        }
        if parent_profile.limits().iter().any(|limit| {
            matches!(limit.value(), LimitValue::Unlimited(grant) if grant.as_bytes() == &[0; 16])
        }) {
            return Err(InvalidExecutionSpec::ParentResourceUnavailable);
        }
        for parent_weight in parent_profile.limits().iter().filter(|limit| {
            matches!(
                limit.dimension(),
                LimitDimension::CpuWeight | LimitDimension::IoWeight
            )
        }) {
            validate_execution_enforcement(parent_weight.dimension(), parent_weight.enforcement())?;
            validate_parent_resource_value(parent_weight.dimension(), parent_weight.value())?;
        }
        if parent_profile_commitment.as_bytes() == &[0; 32]
            || crate::format::resource_profile_digest_v1(&parent_profile)
                != parent_profile_commitment
        {
            return Err(InvalidExecutionSpec::ParentResourceCommitmentMismatch);
        }
        if requested.len() != admitted.len()
            || requested
                .iter()
                .zip(&admitted)
                .any(|(request, result)| request.dimension() != result.dimension())
        {
            return Err(InvalidExecutionSpec::ResourceAdmissionShapeMismatch);
        }
        for required_weight in [LimitDimension::CpuWeight, LimitDimension::IoWeight] {
            let explicit_weight = requested
                .iter()
                .zip(&admitted)
                .find(|(request, _)| request.dimension() == required_weight)
                .is_some_and(|(request, admitted)| {
                    matches!(
                        (request.value(), admitted.value()),
                        (
                            ExecutionResourceRequestValueV1::RelativeWeight(requested),
                            ExecutionResourceSublimitValueV1::RelativeWeight(admitted),
                        ) if requested == admitted
                    )
                });
            if !explicit_weight {
                return Err(InvalidExecutionSpec::RequiredWeightAdmissionMissing);
            }
        }
        for (request, result) in requested.iter().zip(&admitted) {
            validate_resource_admission(request, result, &parent_profile)?;
        }
        Ok(Self {
            requested,
            admitted,
            parent_profile,
            parent_profile_commitment,
            output_bytes,
        })
    }

    /// Returns caller-requested settings in strict dimension order.
    #[must_use]
    pub fn requested(&self) -> &[ExecutionResourceRequestV1] {
        &self.requested
    }

    /// Returns admitted execution-local settings in strict dimension order.
    #[must_use]
    pub fn admitted(&self) -> &[ExecutionResourceSublimitV1] {
        &self.admitted
    }

    /// Returns the exact parent profile used for non-weight admission bounds.
    #[must_use]
    pub const fn parent_profile(&self) -> &ResourceProfile {
        &self.parent_profile
    }

    /// Returns the domain-separated commitment to the exact parent profile.
    #[must_use]
    pub const fn parent_profile_commitment(&self) -> ObjectDigest {
        self.parent_profile_commitment
    }

    /// Returns the distinct nonauthorizing broker-ledger output-byte claim.
    #[must_use]
    pub const fn output_bytes(&self) -> &ExecutionOutputByteAdmissionV1 {
        &self.output_bytes
    }

    /// Returns the assignment-bound claimed aggregate capture ceiling.
    pub(super) fn output_retention_bound(&self) -> u64 {
        self.output_bytes.admitted_bytes()
    }
}
