//! Describes the installed Controller's reached startup carriers as passive DATA.
//!
//! Runtime and its trusted application assembly know their concrete Rust types.
//! They pass these representation widths to the same original Controller owner;
//! neither structure contains a resource vector, descriptor, payer or grant. The
//! closed original receiver computes demand and retains its own admission result.

use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::ControllerReceivingErrorV1;

/// Describes the concrete fixed carriers of one installed Controller startup.
///
/// These widths do not prove currentness or authorize allocation. The original
/// Controller C owner must join the actual admitted profile and accept the full
/// fixed requirement before any of these owners are constructed.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerRuntimeStartupShapeV1 {
    /// Inline parent destination, including its concrete application slots.
    pub parent_bytes: usize,
    /// Actual worker custody allocation, excluding separately named pointees.
    pub worker_bytes: usize,
    /// Checked fixed pointees and simultaneous constructor carriers, before allocation.
    pub fixed_destination_bytes: Option<usize>,
    /// The actual separate shared bank allocation and its Arc control words.
    pub bank_bytes: usize,
    /// Actual sessions allocation and its Arc control words.
    pub sessions_bytes: usize,
    /// Actual capability allocation and its Arc control words.
    pub capability_bytes: usize,
    /// Two concrete capability service allocations and their Arc control words.
    pub service_bytes: usize,
    /// One actual command enum, including its inline payload variants.
    pub command_bytes: usize,
    /// One actual worker event enum, including its inline payload variants.
    pub event_bytes: usize,
    /// Concrete public and diagnostic application values.
    pub application_bytes: usize,
    /// Concrete current-thread runtime representation, excluding provider heap.
    pub runtime_bytes: usize,
    /// Actual single Publisher observation future allocation, when installed.
    pub publisher_future_bytes: usize,
    /// Actual selected one-slot Publisher registry backing allocation.
    pub publisher_session_bytes: usize,
    /// Whether this actual parsed invocation installs Publisher ingress.
    pub publisher: bool,
    /// Whether this actual parsed invocation enables its public listener.
    pub public_listener: bool,
}

/// Describes credential input and decoder carriers reached during startup.
///
/// Raw input extent is reserved before opening or reading any credential.
/// Later typed extents include failed but structurally valid parser prefixes.
/// This DATA has no generic owner index, account or reservation operation.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerRuntimeCredentialShapeV1 {
    /// Sum of the actual fixed-name readers' encoded input ceilings.
    pub raw_bytes: usize,
    /// Sum of actual retained credential owner representations.
    pub owner_bytes: usize,
    /// Peak simultaneous policy key slots, including invalid CBOR schemas and selected keys.
    pub trust_key_slots: usize,
    /// Peak simultaneous policy feature vector slots, including invalid schemas.
    pub trust_feature_slots: usize,
    /// Aggregate policy strings across actual concurrently decoded copies.
    pub trust_text_bytes: usize,
    /// Actual known key/JSON/TLS parser output and scratch representations.
    pub parser_bytes: usize,
    /// Fixed protected pathname and directory traversal carriers.
    pub path_bytes: usize,
    /// Distinct original leaf files retained by the fixed read destinations.
    pub credential_files: usize,
    /// Supplemental raw/native/typed bytes from actual rich initial producers.
    /// An absent checked extent closes the same original admission before growth.
    pub extra_memory_bytes: Option<usize>,
    /// Supplemental resident collection/result carriers from those producers.
    pub extra_metadata_entries: Option<usize>,
    /// Supplemental simultaneous proof descriptors in actual startup order.
    pub extra_open_files: Option<usize>,
    /// Actual Source startup proof descriptors disposed before construction.
    pub source_proof_files: Option<usize>,
    /// Actual late public TLS producer's total supplemental dynamic bytes.
    pub public_tls_memory_bytes: Option<usize>,
    /// Actual late public TLS producer's supplemental collection entries.
    pub public_tls_metadata_entries: Option<usize>,
    /// Actual late public TLS native proof descriptors, before positive disposal.
    pub public_tls_proof_files: Option<usize>,
}

/// Reports the same receiving demand engine's resource comparison counts.
///
/// These comparison DATA contain no vector, payer, descriptor, admission or
/// original join. They cannot create an account or authorize an allocation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ControllerRuntimeRequestedCountsV1 {
    /// Dominant requested bytes, including actual reached parser carriers.
    pub memory_bytes: u64,
    /// Distinct requested descriptors at the described receiving peak.
    pub open_files: u64,
    /// Requested native tasks excluding separately paid original role tasks.
    pub pids: u64,
    /// Requested retained metadata/collection/result carriers.
    pub metadata_entries: u64,
    /// Full-shape operation traffic capacity, including AUTH and all RPCs.
    pub network_bytes: u64,
    /// Full-shape operation log capacity.
    pub log_bytes: u64,
    /// Full-shape operation output capacity.
    pub output_bytes: u64,
    /// Exclusive operation slots represented by this same checked demand.
    pub concurrent_operations: u64,
}

impl ControllerRuntimeRequestedCountsV1 {
    /// Projects already-derived requested resource counts as readonly DATA.
    ///
    /// This performs no admission, reservation or native effect and creates no
    /// account, capacity, original, loan or permission to enter a role.
    #[doc(hidden)]
    #[must_use]
    pub fn from_demand(demand: ResourceVector) -> Self {
        Self {
            memory_bytes: demand.get(D::MemoryBytes),
            open_files: demand.get(D::OpenFiles),
            pids: demand.get(D::Pids),
            metadata_entries: demand.get(D::MetadataEntries),
            network_bytes: demand.get(D::NetworkBytes),
            log_bytes: demand.get(D::LogBytes),
            output_bytes: demand.get(D::OutputBytes),
            concurrent_operations: demand.get(D::ConcurrentOperations),
        }
    }
}

/// Uses the selected role's eight-task contract rather than Tokio's default 512.
pub const CONTROLLER_RUNTIME_TASKS_V1: usize = 8;
/// Reserves main, reconciler and one sequential original property observer.
pub const CONTROLLER_RUNTIME_ROLE_TASKS_V1: usize = 3;
/// Leaves the measured role's remaining tasks to the actual blocking pool.
pub const CONTROLLER_RUNTIME_BLOCKING_THREADS_V1: usize =
    CONTROLLER_RUNTIME_TASKS_V1 - CONTROLLER_RUNTIME_ROLE_TASKS_V1;
/// Requests the standard finite two-MiB stack explicitly for selected workers.
pub const CONTROLLER_RUNTIME_STACK_BYTES_V1: usize = 2 * 1024 * 1024;

/// Describes the actual selected Controller's immutable task scheduling mode.
///
/// The closed Runtime admission derives this DATA only from its same measured
/// profile and publishes it only after its complete native/funding posts. It
/// creates no task permit, payer, helper or authority to enter Required mode.
/// Actual ModePin/launch-image equality must still pass before physical entry.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ControllerRuntimeTaskEnvelopeV1 {
    floor_helper_tasks: usize,
}

impl ControllerRuntimeTaskEnvelopeV1 {
    pub(in crate::controller_receiving) fn from_profile_v1(
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Self {
        Self::from_image_delivery_v1(profile.has_tpm_image_delivery())
    }

    fn from_image_delivery_v1(delivered: bool) -> Self {
        Self { floor_helper_tasks: usize::from(delivered) }
    }

    /// Reports the persistent helper task reserved by the measured mode.
    #[must_use]
    pub const fn floor_helper_tasks_v1(self) -> usize {
        self.floor_helper_tasks
    }

    /// Reports the blocking pool width within the unchanged eight-task policy.
    #[must_use]
    pub const fn blocking_threads_v1(self) -> usize {
        CONTROLLER_RUNTIME_BLOCKING_THREADS_V1 - self.floor_helper_tasks
    }

    pub(in crate::controller_receiving) fn require_same_profile_v1(
        self,
        profile: &super::profile::ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.floor_helper_tasks == usize::from(profile.has_tpm_image_delivery()) {
            Ok(())
        } else {
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    fn runtime_stack_workers_v1(self) -> usize {
        self.blocking_threads_v1() + 1
    }
}

impl ControllerRuntimeStartupShapeV1 {
    /// Projects the actual checked engine's counts without Native admission.
    ///
    /// Arbitrary structural DATA establish no original/profile association;
    /// only the closed same-original receiving owner can admit actual growth.
    ///
    /// # Errors
    /// Rejects incomplete or overflowing structural extents.
    #[doc(hidden)]
    pub fn requested_counts_v1(
        self,
    ) -> Result<ControllerRuntimeRequestedCountsV1, ControllerReceivingErrorV1> {
        self.fixed_demand().map(ControllerRuntimeRequestedCountsV1::from_demand)
    }

    pub(in crate::controller_receiving) fn fixed_demand(self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        // Unbound public representation queries retain the conservative old
        // ordinary envelope. Actual selected admission supplies its own mode.
        self.fixed_demand_with_task_envelope_v1(
            ControllerRuntimeTaskEnvelopeV1::from_image_delivery_v1(false),
        )
    }

    pub(in crate::controller_receiving) fn fixed_demand_with_task_envelope_v1(
        self,
        envelope: ControllerRuntimeTaskEnvelopeV1,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let unavailable = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        let stack_workers = envelope.runtime_stack_workers_v1();
        // std's bounded command channel contains at most64 actual enum cells;
        // one Ready and one terminal event can coexist in its distinct channel.
        // Control links are provisioned beside each reached queue cell. This is
        // dominant carrier admission; the installed cgroup also backs runtime,
        // allocator and native-thread overhead, which size_of does not measure.
        let command_cells = self.command_bytes.checked_add(16 * size_of::<usize>())
            .and_then(|bytes| bytes.checked_mul(64)).ok_or_else(unavailable)?;
        let event_cells = self.event_bytes.checked_add(16 * size_of::<usize>())
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(unavailable)?;
        let inline = [
            self.parent_bytes, self.worker_bytes, self.bank_bytes, self.sessions_bytes,
            // bank_bytes contains the Arc handle, not its private pointee.
            // The same original's real inline owner/control allocation is
            // retained beside every later startup and operation phase.
            size_of::<super::original::ControllerReceivingOriginalV1>() + 2 * size_of::<usize>(),
            self.capability_bytes, self.service_bytes, self.application_bytes,
            self.runtime_bytes, self.publisher_future_bytes, self.publisher_session_bytes,
            command_cells, event_cells,
        ].into_iter().try_fold(0_usize, usize::checked_add).ok_or_else(unavailable)?;
        let memory = CONTROLLER_RUNTIME_STACK_BYTES_V1.checked_mul(stack_workers)
            .and_then(|bytes| bytes.checked_add(inline))
            .and_then(|bytes| bytes.checked_add(self.fixed_destination_bytes?))
            .ok_or_else(unavailable)?;
        // epoll, Registry clone, Waker and signal pair are five distinct driver
        // FDs. Diagnostic/public listeners and the notifier remain resident;
        // two fixed bind/path probes can coexist with an earlier listener.
        // The fixed one-slot Publisher destination can own one accepted socket,
        // its actual peer pidfd and the normal transferred cgroup anchor.
        let files = 5 + 1 + usize::from(self.public_listener) + 1 + 2
            + 3 * usize::from(self.publisher);
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| unavailable())?)
            .with(D::Pids, u64::try_from(stack_workers).map_err(|_| unavailable())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| unavailable())?);

        // Host and Mount each own two independent bounded PID1 observations.
        // All four may remain after an optional role's negative. Their actual
        // dynamic decoder/request geometry comes from the SAME shared supplier.
        // This Runtime's five driver descriptors were paid above, once; each
        // observation retains its own socket plus the supplier's conservative
        // allowance. No observer worker or second Tokio runtime is constructed.
        let observer = super::profile::fixed_property_observer_demand_v1(64 * 1024)
            .map_err(|_| unavailable())?;
        let observer_files = observer.get(D::OpenFiles).checked_sub(5)
            .ok_or_else(unavailable)?;
        let observer = observer.with(D::OpenFiles, observer_files).with(D::Pids, 0);
        for _ in 0..4 {
            demand = demand.checked_add(observer).map_err(|_| unavailable())?;
        }

        // Each role retains six fixed root/cgroup/probe FDs, one exact pidfd,
        // and two separate membership readbacks with two retained probes each.
        // Actual native owner cells are already included in parent_bytes.
        // Fixed path CStrings/error windows and the shared membership supplier
        // are separate dominant requested carriers, not transitive heap claims.
        let membership = aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
            dominant_requested_bytes_v1().ok_or_else(unavailable)?;
        let native_memory = membership.checked_mul(4)
            .and_then(|bytes| bytes.checked_add(2 * 6 * (64 + 128)))
            .ok_or_else(unavailable)?;
        demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(native_memory).map_err(|_| unavailable())?)
            .with(D::OpenFiles, 2 * (6 + 1 + 2 * 2)))
            .map_err(|_| unavailable())
    }
}

impl ControllerRuntimeCredentialShapeV1 {
    /// Projects the actual checked engine's counts without Native admission.
    ///
    /// Arbitrary structural DATA establish no original/profile association;
    /// only the closed same-original receiving owner can admit actual growth.
    ///
    /// # Errors
    /// Rejects incomplete or overflowing structural extents.
    #[doc(hidden)]
    pub fn requested_counts_v1(
        self,
    ) -> Result<ControllerRuntimeRequestedCountsV1, ControllerReceivingErrorV1> {
        self.credential_demand().map(ControllerRuntimeRequestedCountsV1::from_demand)
    }

    pub(in crate::controller_receiving) fn public_tls_demand(self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let unavailable = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(self.public_tls_memory_bytes.ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?)
            .with(D::MetadataEntries, u64::try_from(self.public_tls_metadata_entries.ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?)
            .with(D::OpenFiles, u64::try_from(self.public_tls_proof_files.ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?))
    }

    // The same concrete runtime recipe keeps Source's raw/model memory live
    // conservatively, while its and TLS's temporary proof files use the pool.
    pub(in crate::controller_receiving) fn resident_credential_demand(self) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let public = self.public_tls_demand()?;
        let complete = self.credential_demand()?;
        let public = public.with(D::OpenFiles, u64::try_from(self.extra_open_files
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?)
            .map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)?);
        complete.checked_sub(public).map_err(Into::into)
    }

    pub(in crate::controller_receiving) fn credential_demand(
        self,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        let unavailable = || ControllerReceivingErrorV1::EnrollmentUnavailable;
        let key_cells = self.trust_key_slots.checked_mul(size_of::<aos_sandbox_model::model::KeyReference>())
            .ok_or_else(unavailable)?;
        let feature_cells = self.trust_feature_slots.checked_mul(size_of::<aos_sandbox_model::FeatureRef>())
            .ok_or_else(unavailable)?;
        let memory = [self.raw_bytes, self.owner_bytes, self.trust_text_bytes,
            self.parser_bytes, self.path_bytes, key_cells, feature_cells,
            self.extra_memory_bytes.ok_or_else(unavailable)?]
            .into_iter().try_fold(0_usize, usize::checked_add).ok_or_else(unavailable)?;
        // Keys and FeatureRef rows identify actual resident trust namespaces;
        // fixed owner/parser/result headers remain in their byte suppliers.
        let entries = self.trust_key_slots.checked_add(self.trust_feature_slots)
            .and_then(|entries| entries.checked_add(self.extra_metadata_entries?))
            .ok_or_else(unavailable)?;
        let files = self.credential_files.checked_add(2)
            .and_then(|files| files.checked_add(self.extra_open_files?))
            .ok_or_else(unavailable)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| unavailable())?)
            .with(D::MetadataEntries, u64::try_from(entries).map_err(|_| unavailable())?)
            // Two traversal probes coexist with all earlier original leaves.
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| unavailable())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_required_helper_uses_its_own_task_within_the_same_eight() {
        let ordinary = ControllerRuntimeTaskEnvelopeV1::from_image_delivery_v1(false);
        let required = ControllerRuntimeTaskEnvelopeV1::from_image_delivery_v1(true);

        assert_eq!(ordinary.blocking_threads_v1(), 5);
        assert_eq!(required.blocking_threads_v1(), 4);
        for envelope in [ordinary, required] {
            // The profile owns main plus one sequential observer. Runtime
            // owns blocking workers plus reconciler; the physical owner must
            // separately debit the persistent helper before actual spawn.
            assert_eq!(2 + envelope.runtime_stack_workers_v1()
                + envelope.floor_helper_tasks_v1(), CONTROLLER_RUNTIME_TASKS_V1);
        }
    }

    #[test]
    fn fixed_runtime_overflow_refuses_before_a_shape_can_be_admitted() {
        let shape = ControllerRuntimeStartupShapeV1 {
            parent_bytes: usize::MAX, worker_bytes: 1, fixed_destination_bytes: Some(0), bank_bytes: 1, sessions_bytes: 1,
            capability_bytes: 1, service_bytes: 1, command_bytes: 1,
            event_bytes: 1, application_bytes: 1, runtime_bytes: 1,
            publisher_future_bytes: 0, publisher_session_bytes: 0, publisher: false,
            public_listener: false,
        };

        assert!(shape.fixed_demand().is_err());
    }

    #[test]
    fn fixed_destination_backing_is_memory_only_and_missing_geometry_refuses() {
        let mut shape = ControllerRuntimeStartupShapeV1 {
            parent_bytes: 1, worker_bytes: 1, fixed_destination_bytes: Some(0),
            bank_bytes: 1, sessions_bytes: 1, capability_bytes: 1,
            service_bytes: 1, command_bytes: 1, event_bytes: 1,
            application_bytes: 1, runtime_bytes: 1,
            publisher_future_bytes: 0, publisher_session_bytes: 0,
            publisher: false, public_listener: false,
        };
        let before = shape.fixed_demand();

        shape.fixed_destination_bytes = Some(37);
        let after = shape.fixed_demand();
        match before {
            Ok(before) => {
                let after = after.unwrap();
                assert_eq!(after.get(D::MemoryBytes), before.get(D::MemoryBytes) + 37);
                for dimension in [D::OpenFiles, D::Pids, D::MetadataEntries] {
                    assert_eq!(after.get(dimension), before.get(dimension));
                }
            }
            // Missing qualified native geometry stays unavailable; added DATA
            // cannot turn that original guard into an admissible shape.
            Err(_) => assert!(after.is_err()),
        }

        shape.fixed_destination_bytes = None;
        assert!(shape.fixed_demand().is_err());
        shape.fixed_destination_bytes = Some(usize::MAX);
        assert!(shape.fixed_demand().is_err());
    }

    #[test]
    fn credential_frontier_arithmetic_refuses_without_saturating() {
        let shape = ControllerRuntimeCredentialShapeV1 {
            raw_bytes: 1, owner_bytes: 1, trust_key_slots: usize::MAX,
            trust_feature_slots: 0, trust_text_bytes: 0, parser_bytes: 0,
            path_bytes: 0, credential_files: 1,
            extra_memory_bytes: Some(0), extra_metadata_entries: Some(0),
            extra_open_files: Some(0), source_proof_files: Some(0),
            public_tls_memory_bytes: Some(0), public_tls_metadata_entries: Some(0),
            public_tls_proof_files: Some(0),
        };

        assert!(shape.credential_demand().is_err());
    }
}
