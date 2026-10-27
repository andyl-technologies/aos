//! Keeps actual Controller/Storage physical representation on its original payer.
//!
//! Fixed and request arithmetic remain with the opaque original. No amount,
//! shape, identity link or scheduling slot becomes an IO or completion grant.

use std::error::Error;
use aos_sandbox_controller_domain::{ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialBrokerSessionClosedV1, ControllerStorageFloorPhysicalReceivingV1, Journal};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_systemd_client::FixedPid1PropertyArchiveV1;
use crate::production_startup::Pid1LaunchImageV1;
use crate::recovery::{FloorErrorV1, HelperImageAcquisitionOriginalV1,
    HelperExecutedImageOriginalV1, FloorServiceAcquisitionOriginalV1};
use super::super::RetainedBrokerPhysicalTpmOwnerV1;
use super::currentness::BrokerPhysicalCurrentnessOriginalV2;

// Actual initial28 policy comparisons plus final cold-retirement1 and two
// independently owed lanes. Each fixed comparison has Controller-before,
// floor-unit, Controller-after PID1 rows, all on the same sequential slot.
const INITIAL_POLICY_COMPARISONS: u64 = 31;
const PROPERTY_ROWS_PER_COMPARISON: u64 = 3;
const INITIAL_TPM_REQUESTS: u64 = 12;
const INDEPENDENT_POLICY_POSTS_V2: usize = 2;
const REQUEST_POLICY_COMPARISONS: u64 = 4; // before/after +independently owed lanes
const MATERIALIZED_BYTES: usize = 64 * 1024;
// Initial service policy3 +its first full revalidation3 can remain together;
// either failure still owes two full independent three-query comparisons.
const SHARED_WINDOW_QUERIES: usize = 12;

#[derive(Clone, Copy)]
enum FirstV1 { Transfer, Profile, Geometry, Debit, Pair, Row, Stack, Disposal, Provider, Reentry, PrimaryPolicy, PolicyPost(usize) }

pub(crate) struct BrokerPhysicalPaymentOriginalV2 {
    receiving: Option<Result<ControllerStorageFloorPhysicalReceivingV1, ControllerInitialBrokerSessionClosedV1>>,
    storage_layout: Option<Result<aos_sandbox_linux::cgroup::StorageCgroupLayoutV1, crate::BrokerSessionSecurityError>>,
    storage_receiving: Option<Result<aos_sandbox_controller_domain::StorageFloorPhysicalProgramReceivingV2, aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    storage_pair: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    storage_renewal: Option<Result<aos_sandbox_controller_domain::StorageFloorPhysicalProgramReceivingV2, aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    storage_growth: Option<Result<(u64, u64, ResourceVector), FloorErrorV1>>,
    storage_disposal: Option<Result<(), FloorErrorV1>>,
    storage_finish: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    profile: Option<Result<(), crate::BrokerSessionSecurityError>>,
    shared_provider: Option<aos_systemd_client::Result<std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>>>,
    shared_disposition: Option<Result<(), FloorErrorV1>>,
    stack: Option<rustix::process::Rlimit>,
    stack_before_spawn: Option<rustix::process::Rlimit>,
    stack_binding: Option<Result<(), FloorErrorV1>>,
    fixed: Option<Result<ResourceVector, FloorErrorV1>>,
    complete: Option<Result<ResourceVector, FloorErrorV1>>,
    debit: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    pair: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    disposal: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    comparisons_paid: u64,
    comparisons_used: u64,
    tpm_requests: u64,
    requests_used: u64,
    request_result: Option<Result<(), FloorErrorV1>>,
    primary_policy: Option<Result<u64, FloorErrorV1>>,
    policy_posts: [Option<Result<u64, FloorErrorV1>>; INDEPENDENT_POLICY_POSTS_V2],
    initial_complete: bool,
    closed: bool,
    first: Option<FirstV1>,
    refusal: Option<FloorErrorV1>,
}

impl BrokerPhysicalPaymentOriginalV2 {
    pub(crate) const fn new() -> Self {
        Self { receiving: None, storage_layout: None, storage_receiving: None, storage_pair: None, storage_renewal: None, storage_growth: None,
            storage_disposal: None, storage_finish: None, profile: None, shared_provider: None, shared_disposition: None, stack: None, stack_before_spawn: None,
            stack_binding: None, fixed: None, complete: None, debit: None, pair: None,
            disposal: None, comparisons_paid: 0, comparisons_used: 0, tpm_requests: 0, requests_used: 0, request_result: None, primary_policy: None, policy_posts: [None; INDEPENDENT_POLICY_POSTS_V2],
            initial_complete: false, closed: false, first: None, refusal: None }
    }

    pub(crate) fn prepare_once(
        &mut self, loan: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>,
        main: &Journal, sidecar: &Journal, image: &Pid1LaunchImageV1,
    ) -> Result<(), FloorErrorV1> {
        if self.receiving.is_some() {
            self.first.get_or_insert(FirstV1::Reentry);
            self.refusal.get_or_insert(FloorErrorV1::Unavailable);
            self.closed = true;
            return Err(FloorErrorV1::Unavailable);
        }
        self.receiving = Some(loan.take_storage_floor_physical_receiving_once_v1(main, sidecar));
        if !matches!(self.receiving, Some(Ok(_))) {
            self.first = Some(FirstV1::Transfer);
            return Err(FloorErrorV1::Unavailable);
        }
        let original = self.receiving.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
        self.profile = Some(image.require_controller_physical_receiving_v1(original));
        if !matches!(self.profile, Some(Ok(()))) {
            self.first = Some(FirstV1::Profile);
            return Err(FloorErrorV1::Unavailable);
        }
        // This small infallible native DATA sample is resident before physical
        // demand derivation. The actual child inherits this same main stack
        // limit; the spawn frontier samples/compares it again before exec.
        self.stack = Some(rustix::process::getrlimit(rustix::process::Resource::Stack));
        self.fixed = Some(Self::fixed_demand(image, self.stack.ok_or(FloorErrorV1::Encoding)?, false));
        self.comparisons_paid = INITIAL_POLICY_COMPARISONS;
        self.tpm_requests = INITIAL_TPM_REQUESTS;
        self.raise_complete(main, sidecar)?;
        // The actual same-C complete debit precedes receiver construction.
        // This keeps the SAME admitted main reactor; no driver/thread is made.
        let runtime = self.receiving.as_ref().and_then(|value| value.as_ref().ok())
            .map(|original| std::sync::Arc::clone(original.runtime_mechanics_v1()))
            .ok_or(FloorErrorV1::Unavailable)?;
        self.shared_provider = Some(aos_systemd_client::SharedFixedPid1PropertyProviderV1::new(
            runtime, SHARED_WINDOW_QUERIES, MATERIALIZED_BYTES,
        ).map(std::sync::Arc::new));
        if matches!(self.shared_provider, Some(Ok(_))) { Ok(()) } else {
            self.first = Some(FirstV1::Provider);
            self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(crate) fn prepare_storage_once_v2(
        &mut self, receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        main: &Journal, sidecar: &Journal, image: &Pid1LaunchImageV1,
    ) -> Result<(), FloorErrorV1> {
        if self.receiving.is_some() || self.storage_layout.is_some() {
            self.first.get_or_insert(FirstV1::Reentry);
            self.refusal.get_or_insert(FloorErrorV1::Unavailable);
            self.closed = true;
            return Err(FloorErrorV1::Unavailable);
        }
        // This genuine image method applies the fixed Storage role/process
        // gate, prepays its two native metadata samples on the SAME F and
        // compares its real held image with the original PID1 delivery.
        self.storage_layout = Some(image.associate_original_storage_receiving_layout_v1(receiving));
        if !matches!(self.storage_layout, Some(Ok(_))) {
            self.first = Some(FirstV1::Profile);
            return Err(FloorErrorV1::Unavailable);
        }
        self.stack = Some(rustix::process::getrlimit(rustix::process::Resource::Stack));
        self.fixed = Some(Self::fixed_demand(image, self.stack.ok_or(FloorErrorV1::Encoding)?, true));
        self.comparisons_paid = INITIAL_POLICY_COMPARISONS;
        self.tpm_requests = INITIAL_TPM_REQUESTS;
        self.complete = Some(self.complete_requirement_v2());
        let complete = match self.complete {
            Some(Ok(value)) => value,
            _ => {
                self.first = Some(FirstV1::Geometry);
                self.closed = true;
                return Err(FloorErrorV1::Encoding);
            }
        };
        self.storage_receiving = Some(receiving.begin_floor_physical_program_v2(main, sidecar, complete));
        if matches!(self.storage_receiving, Some(Ok(_))) { Ok(()) } else {
            self.first = Some(FirstV1::Debit);
            self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(super) fn begin_storage_primitive_v2(&mut self,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2,
        main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.is_storage_v2() || !self.is_prepared() || !self.initial_complete
            || !matches!(self.storage_finish, Some(Ok(())))
        { return Err(FloorErrorV1::Unavailable); }
        // One actual Read or Extend has a custody comparison before and after,
        // plus the two separately prearmed negative policy comparisons. Each
        // selected primitive calls this before any new native destination/IO.
        self.storage_growth = Some((|| {
            let comparisons = self.comparisons_paid.checked_add(REQUEST_POLICY_COMPARISONS)
                .ok_or(FloorErrorV1::Encoding)?;
            let requests = self.tpm_requests.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
            let complete = self.complete_requirement_counts_v2(comparisons, requests)?;
            Ok((comparisons, requests, complete))
        })());
        let Some(Ok((comparisons, requests, complete))) = self.storage_growth.as_ref() else {
            self.first.get_or_insert(FirstV1::Geometry);
            self.closed = true;
            return Err(FloorErrorV1::Encoding);
        };
        let (comparisons, requests, complete) = (*comparisons, *requests, *complete);
        self.storage_renewal = Some(receiving.begin_primitive_v2(main, sidecar, complete));
        if !matches!(self.storage_renewal, Some(Ok(_))) {
            self.first.get_or_insert(FirstV1::Debit);
            self.closed = true;
            return Err(FloorErrorV1::Unavailable);
        }
        // The prior financial receipt has its actual native positive finish.
        // No failed native prefix, traffic or resident high water is discarded.
        self.comparisons_paid = comparisons;
        self.tpm_requests = requests;
        self.complete = Some(Ok(complete));
        self.storage_receiving = self.storage_renewal.take();
        self.storage_disposal = None;
        self.storage_finish = None;
        self.primary_policy = None;
        self.policy_posts = [None; INDEPENDENT_POLICY_POSTS_V2];
        self.initial_complete = false;
        Ok(())
    }

    pub(in crate::tpm_nv_custody::physical) fn require_primary_program_v2(&self) -> Result<(), FloorErrorV1> {
        if !self.is_prepared() || (self.is_storage_v2() && self.initial_complete) {
            Err(FloorErrorV1::Unavailable)
        } else { Ok(()) }
    }

    pub(super) fn is_storage_v2(&self) -> bool { self.storage_layout.is_some() }

    pub(super) fn new_currentness_v2(&self) -> Result<BrokerPhysicalCurrentnessOriginalV2, FloorErrorV1> {
        if self.is_storage_v2() {
            let receiving = self.storage_receiving.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(FloorErrorV1::Unavailable)?;
            Ok(BrokerPhysicalCurrentnessOriginalV2::with_storage_layout_v2(receiving.associated_layout_data_v2()))
        } else {
            let provider = self.shared_provider_v1().cloned().ok_or(FloorErrorV1::Unavailable)?;
            Ok(BrokerPhysicalCurrentnessOriginalV2::with_shared_provider_v1(provider))
        }
    }

    pub(in crate::tpm_nv_custody::physical) fn new_service_acquisition_v2(&self) -> Result<FloorServiceAcquisitionOriginalV1, FloorErrorV1> {
        if self.is_storage_v2() {
            let receiving = self.storage_receiving.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(FloorErrorV1::Unavailable)?;
            Ok(FloorServiceAcquisitionOriginalV1::with_storage_layout_v2(receiving.associated_layout_data_v2()))
        } else {
            let provider = self.shared_provider_v1().cloned().ok_or(FloorErrorV1::Unavailable)?;
            Ok(FloorServiceAcquisitionOriginalV1::with_shared_provider_v1(provider))
        }
    }

    pub(in crate::tpm_nv_custody::physical) fn shared_provider_v1(&self)
        -> Option<&std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>>
    {
        self.shared_provider.as_ref()?.as_ref().ok()
    }

    pub(in crate::tpm_nv_custody::physical) fn preserve_failed_shared_interval_v1(&self) {
        if let Some(provider) = self.shared_provider_v1() {
            provider.preserve_failed_interval_v1();
        }
    }

    pub(in crate::tpm_nv_custody::physical) fn retire_completed_shared_interval_v1(&mut self) -> Result<(), FloorErrorV1> {
        if self.is_storage_v2() {
            // Individual fixed rows already joined their worker and disposed
            // the positive native transport before their typed owner returned.
            // A failed row remains in its actual currentness/acquisition owner.
            return Ok(());
        }
        let provider = self.shared_provider_v1().ok_or(FloorErrorV1::Unavailable)?;
        self.shared_disposition = Some(provider.retire_completed_interval_v1()
            .map_err(|_| FloorErrorV1::Unavailable));
        if matches!(self.shared_disposition, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(FirstV1::Provider);
            self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    fn fixed_demand(image: &Pid1LaunchImageV1, stack: rustix::process::Rlimit, storage: bool)
        -> Result<ResourceVector, FloorErrorV1>
    {
        let image_demand = HelperImageAcquisitionOriginalV1::receiving_demand_v1()
            .ok_or(FloorErrorV1::Encoding)?;
        let image_comparison = crate::recovery::HelperImageRevalidationOriginalV1::receiving_demand_v1()
            .ok_or(FloorErrorV1::Encoding)?;
        let executed = HelperExecutedImageOriginalV1::receiving_demand_v1()
            .ok_or(FloorErrorV1::Encoding)?;
        let service = if storage { FloorServiceAcquisitionOriginalV1::receiving_demand_v1(image) }
            else { FloorServiceAcquisitionOriginalV1::receiving_shared_demand_v1(image) }
            .ok_or(FloorErrorV1::Encoding)?;
        let owner = crate::recovery::OwnerConfinementOriginalV1::receiving_demand_v1()
            .ok_or(FloorErrorV1::Encoding)?;
        let current = if storage { BrokerPhysicalCurrentnessOriginalV2::receiving_demand_v1(image) }
            else { BrokerPhysicalCurrentnessOriginalV2::receiving_shared_demand_v1(image) }
            .ok_or(FloorErrorV1::Encoding)?;
        let primary_current = if storage { BrokerPhysicalCurrentnessOriginalV2::receiving_primary_demand_v1(image) }
            else { BrokerPhysicalCurrentnessOriginalV2::receiving_primary_shared_demand_v1(image) }
            .ok_or(FloorErrorV1::Encoding)?;
        let (receive_bytes, receive_files) = SeqpacketSocket::closed_zero_rights_receive_obligations_v1(
            crate::recovery::RESPONSE_BYTES,
        ).ok_or(FloorErrorV1::Encoding)?;
        let (shared_bytes, shared_files) = if storage { (0, 0) } else {
            aos_systemd_client::SharedFixedPid1PropertyProviderV1::receiving_footprint_v1(
                SHARED_WINDOW_QUERIES, MATERIALIZED_BYTES,
            ).ok_or(FloorErrorV1::Encoding)?
        };
        let own_bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|value| value.checked_add(std::mem::size_of::<RetainedBrokerPhysicalTpmOwnerV1>().checked_mul(2)?))
            .and_then(|value| value.checked_add(receive_bytes.checked_mul(2)?))
            .and_then(|value| value.checked_add(std::mem::size_of::<aos_sandbox_linux::seqpacket::RecordSubjectSeqpacketPairOriginalV2>().checked_mul(2)?))
            .and_then(|value| value.checked_add(aos_sandbox_linux::pidfd::PidFdProcOriginalsV1::receiving_bytes_v1()?.checked_mul(2)?))
            .ok_or(FloorErrorV1::Encoding)?;
        // An unlimited inherited stack requests an unbounded permit; checked
        // arithmetic/capacity refuses it rather than inventing a new limit.
        let memory = u64::try_from(own_bytes).map_err(|_| FloorErrorV1::Encoding)?
            .checked_add(u64::try_from(shared_bytes).map_err(|_| FloorErrorV1::Encoding)?)
            .and_then(|value| value.checked_add(super::super::native_receiving::helper_runtime_bytes_v1(stack)?))
            .ok_or(FloorErrorV1::Encoding)?;
        // Parent/child channel2, child pidfd1, held stat/context2, parent lock
        // loans2 +child lock loans2, child stdio/native loader/device/config6,
        // retained ACK/observation subjects2 and actual spawn/exec overlap2.
        let files = 19usize.checked_add(receive_files.checked_mul(2)
            .ok_or(FloorErrorV1::Encoding)?).ok_or(FloorErrorV1::Encoding)?;
        let own = ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| FloorErrorV1::Encoding)?)
            .with(D::Pids, 1).with(D::ConcurrentOperations, 1);
        let complete = own.checked_add(image_demand).and_then(|value| value.checked_add(executed))
            .and_then(|value| value.checked_add(image_comparison))
            .and_then(|value| value.checked_add(service))
            .and_then(|value| value.checked_add(owner))
            .and_then(|value| value.checked_add(owner))
            .and_then(|value| value.checked_add(current))
            .and_then(|value| value.checked_add(current))
            .and_then(|value| value.checked_add(current)).map_err(|_| FloorErrorV1::Encoding)?;
        // The sole PID1 worker is already paid by the same actual Controller
        // selected profile. The actual4a20 slot serializes all those flights.
        // This phase adds exactly the one persistent helper, never another
        // observer grant, task cap, physical CPU envelope or field metadata.
        // At most one failed healthy primary remains. Its independent
        // physical-after and outer-floor-after use the two full negative
        // destinations. Positive healthy samples actually drop before reuse;
        // neither negative result is discarded, even if its comparison passes.
        // Every actual failed receive retains its FULL configured native prefix.
        // ACK failure stops before Observation; successful receive returns
        // only its accepted subject (already in fixed19) after the temporary
        // raw attempt's ordinary success-only disposition. No failed rights,
        // Runtime, socket or error owner is disposed for this peak argument.
        let core = 19u64;
        let shared = u64::try_from(shared_files).map_err(|_| FloorErrorV1::Encoding)?;
        let receive = u64::try_from(receive_files).map_err(|_| FloorErrorV1::Encoding)?;
        let owed = current.get(D::OpenFiles).checked_mul(2).ok_or(FloorErrorV1::Encoding)?;
        // Service take succeeds only after its complete typed and initial
        // native post; take retires its positive root/stat/probe/pin owners.
        // The late carrier owns helper executable+loader2 and service's
        // manager/fragment/pidfd/cgroup4 actual identity anchors.
        let held = 6u64;
        let acquisition = image_demand.get(D::OpenFiles)
            .checked_add(service.get(D::OpenFiles)).and_then(|value| value.checked_add(owed));
        let early_process = held.checked_add(executed.get(D::OpenFiles))
            .and_then(|value| value.checked_add(owner.get(D::OpenFiles).checked_mul(2)?))
            .and_then(|value| value.checked_add(owed));
        let failed_primary = held.checked_add(primary_current.get(D::OpenFiles))
            .and_then(|value| value.checked_add(owed));
        // An IO failure follows a positive before-comparison, so no failed
        // healthy sample coexists with this full receive and its two posts.
        // A failed healthy before-comparison prevents entry into that IO.
        let failed_io = held.checked_add(receive).and_then(|value| value.checked_add(owed));
        let reached_peak = acquisition.and_then(|value| Some(value.max(early_process?)
            .max(failed_primary?).max(failed_io?))).ok_or(FloorErrorV1::Encoding)?;
        let files = core.checked_add(shared).and_then(|value| value.checked_add(reached_peak))
            .ok_or(FloorErrorV1::Encoding)?;
        let named = if storage {
            // The fixed property parser bounds actual requested property names
            // and decoded map/list entries. Acquisition policy+initial rows and
            // each primary/owed owner retain separate response namespaces.
            let row = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES)
                .map_err(|_| FloorErrorV1::Encoding)?;
            row.metadata_entries.checked_mul(2 + 3 * 2).ok_or(FloorErrorV1::Encoding)?
        } else { 0 };
        // Both selected parents already pay the same actual process-wide,
        // synchronously joined PID1 worker slot. Every positive row physically
        // retires its worker before the next. This adds only the persistent
        // helper; no physical worker spends the existing main/observer slots.
        Ok(complete.with(D::OpenFiles, files).with(D::Pids, 1)
            .with(D::NetworkBytes, 0).with(D::LogBytes, 0)
            .with(D::OutputBytes, 0).with(D::MetadataEntries, named))
    }

    fn complete_requirement_v2(&self) -> Result<ResourceVector, FloorErrorV1> {
        self.complete_requirement_counts_v2(self.comparisons_paid, self.tpm_requests)
    }

    fn complete_requirement_counts_v2(&self, comparisons: u64, requests: u64)
        -> Result<ResourceVector, FloorErrorV1>
    {
        let fixed = self.fixed.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        let row = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES)
            .map_err(|_| FloorErrorV1::Encoding)?;
        let helper_bytes = requests.checked_mul(84 + 128)
            .and_then(|value| value.checked_add(160 + 80 + 48)).ok_or(FloorErrorV1::Encoding)?;
        let rows = comparisons.checked_mul(PROPERTY_ROWS_PER_COMPARISON)
            .ok_or(FloorErrorV1::Encoding)?;
        let network = row.wire_io_bytes.checked_mul(rows)
            .and_then(|value| value.checked_add(helper_bytes)).ok_or(FloorErrorV1::Encoding)?;
        let logs = row.maximum_log_bytes.checked_mul(rows).ok_or(FloorErrorV1::Encoding)?;
        let output = requests.checked_mul(84)
            .and_then(|value| value.checked_add(160 + 80)).ok_or(FloorErrorV1::Encoding)?;
        Ok(fixed.with(D::NetworkBytes, network).with(D::LogBytes, logs).with(D::OutputBytes, output))
    }

    fn raise_complete(&mut self, main: &Journal, sidecar: &Journal) -> Result<(), FloorErrorV1> {
        self.complete = Some(self.complete_requirement_v2());
        let complete = match self.complete { Some(Ok(value)) => value, _ => {
            self.first.get_or_insert(FirstV1::Geometry); self.closed = true;
            return Err(FloorErrorV1::Encoding);
        }};
        self.debit = Some(self.receiving.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(FloorErrorV1::Unavailable)?.debit_physical_representation_v1(main, sidecar, complete));
        if matches!(self.debit, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(FirstV1::Debit); self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(crate) fn prepare_request(
        &mut self, main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.is_prepared() {
            self.first.get_or_insert(FirstV1::Pair);
            self.refusal.get_or_insert(FloorErrorV1::Unavailable);
            self.closed = true;
            return Err(FloorErrorV1::Unavailable);
        }
        // Every primitive uses the actual held pair, even while the finite
        // initial program consumes its already-paid request/observer roster.
        if self.is_storage_v2() {
            self.storage_pair = Some(self.storage_receiving.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(FloorErrorV1::Unavailable)?.require_held_pair_v2(main, sidecar));
            if !matches!(self.storage_pair, Some(Ok(()))) || self.initial_complete {
                self.first.get_or_insert(FirstV1::Pair);
                self.refusal.get_or_insert(FloorErrorV1::Unavailable);
                self.closed = true;
                return Err(FloorErrorV1::Unavailable);
            }
        } else {
            self.pair = Some(self.receiving.as_mut().and_then(|value| value.as_mut().ok())
                .ok_or(FloorErrorV1::Unavailable)?.require_held_pair_v1(main, sidecar));
            if !matches!(self.pair, Some(Ok(()))) {
                self.first = Some(FirstV1::Pair); self.closed = true;
                return Err(FloorErrorV1::Unavailable);
            }
        }
        self.request_result = Some((|| {
            if self.initial_complete && !self.is_storage_v2() {
                let rows = self.comparisons_paid.checked_add(REQUEST_POLICY_COMPARISONS).ok_or(FloorErrorV1::Encoding)?;
                let requests = self.tpm_requests.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
                self.comparisons_paid = rows;
                self.tpm_requests = requests;
                self.raise_complete(main, sidecar)?;
            }
            Ok(())
        })());
        match self.request_result {
            Some(Ok(())) => Ok(()),
            _ => {
                self.first.get_or_insert(FirstV1::Row);
                self.closed = true;
                self.refusal.get_or_insert(FloorErrorV1::Encoding);
                Err(FloorErrorV1::Encoding)
            }
        }
    }

    pub(crate) fn consume_tpm_request_v1(&mut self) -> Result<(), FloorErrorV1> {
        self.request_result = Some((|| {
            let next = self.requests_used.checked_add(1).ok_or(FloorErrorV1::Encoding)?;
            if self.closed || next > self.tpm_requests { return Err(FloorErrorV1::Unavailable); }
            self.requests_used = next;
            Ok(())
        })());
        match self.request_result {
            Some(Ok(())) => Ok(()),
            _ => {
                self.first.get_or_insert(FirstV1::Row);
                self.closed = true;
                self.refusal.get_or_insert(FloorErrorV1::Unavailable);
                Err(FloorErrorV1::Unavailable)
            }
        }
    }

    fn next_policy_ordinal_v2(&self, rows: u64, reserve_posts: bool) -> Result<u64, FloorErrorV1> {
        let next = self.comparisons_used.checked_add(rows).ok_or(FloorErrorV1::Encoding)?;
        let limit = if reserve_posts {
            self.comparisons_paid.checked_sub(INDEPENDENT_POLICY_POSTS_V2 as u64)
                .ok_or(FloorErrorV1::Unavailable)?
        } else { self.comparisons_paid };
        if next > limit { Err(FloorErrorV1::Unavailable) } else { Ok(next) }
    }

    pub(crate) fn consume_primary_policy_comparisons_v2(&mut self, rows: u64) -> Result<(), FloorErrorV1> {
        if let Some(Err(cause)) = self.primary_policy { return Err(cause); }
        self.primary_policy = Some(self.next_policy_ordinal_v2(rows, true));
        match self.primary_policy {
            Some(Ok(next)) => { self.comparisons_used = next; Ok(()) }
            Some(Err(cause)) => {
                self.first.get_or_insert(FirstV1::PrimaryPolicy);
                self.closed = true;
                self.refusal.get_or_insert(cause);
                Err(cause)
            }
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(crate) fn consume_policy_comparisons_v1(&mut self, rows: u64) -> Result<(), FloorErrorV1> {
        let index = self.policy_posts.iter().position(Option::is_none)
            .ok_or(FloorErrorV1::Unavailable)?;
        self.policy_posts[index] = Some(self.next_policy_ordinal_v2(rows, false));
        match self.policy_posts[index] {
            Some(Ok(next)) => { self.comparisons_used = next; Ok(()) }
            Some(Err(cause)) => {
                self.first.get_or_insert(FirstV1::PolicyPost(index));
                self.closed = true;
                self.refusal.get_or_insert(cause);
                Err(cause)
            }
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    pub(crate) fn require_spawn_stack(&mut self) -> Result<(), FloorErrorV1> {
        self.stack_before_spawn = Some(rustix::process::getrlimit(rustix::process::Resource::Stack));
        self.stack_binding = Some(if self.stack_before_spawn == self.stack { Ok(()) }
            else { Err(FloorErrorV1::Unavailable) });
        if matches!(self.stack_binding, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(FirstV1::Stack); self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(crate) fn finish_initial_once(&mut self) -> Result<(), FloorErrorV1> {
        if self.closed || self.first.is_some() || self.initial_complete {
            return Err(FloorErrorV1::Unavailable);
        }
        self.initial_complete = true;
        Ok(())
    }

    pub(crate) fn retire_request_after_disposal(&mut self) -> Result<(), FloorErrorV1> {
        if self.is_storage_v2() {
            self.storage_disposal = Some(if self.is_prepared() { Ok(()) } else { Err(FloorErrorV1::Unavailable) });
            return self.storage_disposal.unwrap_or(Err(FloorErrorV1::Unavailable));
        }
        self.disposal = Some(self.receiving.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(FloorErrorV1::Unavailable)?.retire_physical_request_after_native_disposal_v1());
        if matches!(self.disposal, Some(Ok(()))) { Ok(()) } else {
            self.first.get_or_insert(FirstV1::Disposal); self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(super) fn finish_storage_program_v2(&mut self,
        receiving: &mut dyn crate::recovery::StorageFloorFinancialSourceV2, main: &Journal, sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.is_storage_v2() || !self.is_prepared() || self.initial_complete
            || !matches!(self.storage_disposal, Some(Ok(())))
        { return Err(FloorErrorV1::Unavailable); }
        let receipt = self.storage_receiving.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
        self.storage_finish = Some(receiving.finish_primitive_v2(receipt, main, sidecar));
        if matches!(self.storage_finish, Some(Ok(()))) {
            self.initial_complete = true;
            Ok(())
        } else {
            self.first.get_or_insert(FirstV1::Disposal);
            self.closed = true;
            Err(FloorErrorV1::Unavailable)
        }
    }

    pub(crate) fn fence(&mut self) { self.closed = true; }
    pub(crate) fn is_prepared(&self) -> bool {
        let paid = if self.is_storage_v2() { matches!(self.storage_receiving, Some(Ok(_))) }
            else { matches!(self.debit, Some(Ok(()))) };
        paid && self.first.is_none() && !self.closed
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Transfer => error(&self.receiving).or_else(|| error(&self.storage_receiving)),
            FirstV1::Profile => self.receiving.as_ref().and_then(|value| value.as_ref().ok())
                .and_then(|original| original.failure()).or_else(|| error(&self.profile))
                .or_else(|| error(&self.storage_layout)),
            FirstV1::Geometry => error(&self.fixed).or_else(|| error(&self.complete)).or_else(|| error(&self.request_result)).or_else(|| error(&self.storage_growth)),
            FirstV1::Debit => self.receiving.as_ref().and_then(|value| value.as_ref().ok())
                .and_then(|original| original.failure()).or_else(|| error(&self.debit))
                .or_else(|| error(&self.storage_receiving)).or_else(|| error(&self.storage_renewal)),
            FirstV1::Pair => error(&self.pair).or_else(|| error(&self.storage_pair)).or_else(|| self.refusal.as_ref().map(|cause| cause as _)),
            FirstV1::Provider => error(&self.shared_provider)
                .or_else(|| self.shared_provider_v1().and_then(|provider| provider.retirement_failure_v1())
                    .map(|cause| cause as &dyn Error))
                .or_else(|| error(&self.shared_disposition)),
            FirstV1::Stack => error(&self.stack_binding),
            FirstV1::Disposal => error(&self.disposal).or_else(|| error(&self.storage_disposal))
                .or_else(|| error(&self.storage_finish)),
            FirstV1::PrimaryPolicy => error(&self.primary_policy),
            FirstV1::PolicyPost(index) => error(&self.policy_posts[index]),
            FirstV1::Row | FirstV1::Reentry => error(&self.request_result)
                .or_else(|| self.refusal.as_ref().map(|cause| cause as _)),
        }
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl BrokerPhysicalPaymentOriginalV2 {
    pub(super) fn require_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &Journal,
        sidecar: &Journal,
    ) -> Result<(), FloorErrorV1> {
        if !self.initial_complete || !self.is_prepared()
            || !matches!(self.shared_disposition, Some(Ok(())))
            || !matches!(self.disposal, Some(Ok(())))
        {
            return Err(FloorErrorV1::Unavailable);
        }
        self.receiving.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(FloorErrorV1::Unavailable)?
            .require_completed_initial_pair_v1(completed, main, sidecar)
            .map_err(|_| FloorErrorV1::Unavailable)
    }
}

#[cfg(test)]
mod policy_post_budget_tests {
    use super::*;

    #[test]
    fn primary_exhaustion_preserves_both_paid_posts_and_its_exact_first_cause() {
        // Only accounting counters are populated. No physical receiving owner,
        // helper, profile, TPM or readiness can be constructed by these DATA.
        let mut payment = BrokerPhysicalPaymentOriginalV2::new();
        payment.comparisons_paid = INITIAL_POLICY_COMPARISONS;
        payment.comparisons_used = INITIAL_POLICY_COMPARISONS - 3;

        payment.consume_primary_policy_comparisons_v2(1).unwrap();
        assert!(payment.consume_primary_policy_comparisons_v2(1).is_err());
        let primary = payment.failure().unwrap() as *const dyn Error as *const ();
        assert_eq!(payment.comparisons_used, INITIAL_POLICY_COMPARISONS - 2);
        assert!(payment.closed);
        assert!(!payment.is_prepared());

        payment.consume_policy_comparisons_v1(1).unwrap();
        payment.consume_policy_comparisons_v1(1).unwrap();

        assert_eq!(payment.comparisons_used, INITIAL_POLICY_COMPARISONS);
        assert_eq!(payment.failure().unwrap() as *const dyn Error as *const (), primary);
        assert!(payment.consume_policy_comparisons_v1(1).is_err());
        assert!(payment.consume_primary_policy_comparisons_v2(1).is_err());
        assert_eq!(payment.comparisons_used, INITIAL_POLICY_COMPARISONS);
        assert!(!payment.is_prepared());
    }

    #[test]
    fn primary_counter_overflow_retains_the_whole_arithmetic_refusal() {
        let mut payment = BrokerPhysicalPaymentOriginalV2::new();
        payment.comparisons_paid = u64::MAX;
        payment.comparisons_used = u64::MAX;

        assert!(matches!(payment.consume_primary_policy_comparisons_v2(1), Err(FloorErrorV1::Encoding)));
        assert!(matches!(payment.primary_policy, Some(Err(FloorErrorV1::Encoding))));
        assert!(payment.closed);
        assert_eq!(payment.comparisons_used, u64::MAX);
        assert!(matches!(payment.consume_primary_policy_comparisons_v2(0), Err(FloorErrorV1::Encoding)));
    }
}
