//! Publishes live Stop-disposal evidence through the existing signed Inventory.
//!
//! This branch never consults a durable Complete row as physical evidence.
//! It owns every entered read/clock/response result and uses the same original
//! consumed Host control owner, with no new effect permission or Launch clock.

use super::*;
use aos_sandbox_broker::paired_clock::{PairedClockBaselineV1, PairedClockSamplesV1};
use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::ValidatedHeader;
use aos_sandbox_protocol::host_stopped_namespace::HOST_STOPPED_NAMESPACE_BYTES_V4;

pub(crate) struct HostTerminalInventoryShapeV4 {
    demand: ResourceVector,
}

impl HostTerminalInventoryShapeV4 {
    fn derive_v4(maximum_response: u32) -> Option<Self> {
        let carriers = std::mem::size_of::<HostTerminalInventoryOriginalV4>().checked_mul(3)?;
        let boot = aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        let bytes = carriers.checked_add(3 * HOST_STOPPED_NAMESPACE_BYTES_V4)?
            .checked_add(4 * std::mem::size_of::<Vec<u8>>())?
            .checked_add(5_usize.checked_mul(boot)?)?
            .checked_add(3 * std::mem::size_of::<InventoryRuntimeResponse>())?
            .checked_add(usize::try_from(maximum_response).ok()?.checked_mul(3)?)?;
        let demand = PairedClockSamplesV1::receiving_demand_v1()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OutputBytes, u64::from(maximum_response))) .ok()?;
        Some(Self { demand })
    }

    pub(crate) fn receiving_demand_v4(&self) -> Result<ResourceVector> { Ok(self.demand) }
}

pub(super) struct HostTerminalInventoryOriginalV4 {
    funding: Option<Result<()>>,
    baseline: Option<PairedClockBaselineV1>,
    samples: Option<PairedClockSamplesV1>,
    before: Option<Result<()>>,
    clocks: [Option<Result<RawPairedClockSample>>; 2],
    body: Option<Result<Vec<u8>>>,
    after: Option<Result<()>>,
    clock_disposed: Option<Result<()>>,
    disposed: Option<Result<()>>,
    pub(super) first: Option<usize>,
    complete: bool,
}

impl HostTerminalInventoryOriginalV4 {
    fn new() -> Self {
        Self { funding: None, baseline: None, samples: None, before: None,
            clocks: [None, None], body: None, after: None, clock_disposed: None, disposed: None,
            first: None, complete: false }
    }

    fn sample_v4(&mut self, index: usize, header: &ValidatedHeader, boot: &[u8; 16]) {
        self.clocks[index] = Some((|| {
            let sample = self.samples.as_mut().ok_or(HostError::ResourceExhausted)?
                .sample(self.baseline.as_mut().ok_or(HostError::ResourceExhausted)?)
                .map_err(|_| HostError::Fence("Host terminal Inventory paired clock failed"))?;
            if sample.host_boot_id() != *boot
                || sample.boottime_nanoseconds() >= header.deadline_boottime_nanoseconds()
            {
                return Err(HostError::Fence("Host terminal Inventory read deadline expired"));
            }
            Ok(sample)
        })());
        if !matches!(self.clocks[index], Some(Ok(_))) { self.first.get_or_insert(2 + index * 3); }
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn retire_terminal_inventory_payloads_before_launch_v4(&mut self) -> Result<()> {
        if self.terminal_inventory_v4.as_ref().is_some_and(|read| !read.complete) {
            return Err(HostError::Fence("Host terminal Inventory still owns a refused interval"));
        }
        // These pure payloads survive until the actual positive native/clock
        // disposals. Their retirement grants no refund to the control invoice.
        if self.native_inventory_v5.as_ref().is_some_and(|read| !read.completed_v5()) {
            return Err(HostError::Fence("Host native inventory still owns a refused interval"));
        }
        drop(self.native_inventory_v5.take());
        drop(self.terminal_inventory_v4.take());
        Ok(())
    }

    pub(crate) async fn inventory_runtime_authenticated_v4(&mut self, header: &ValidatedHeader)
        -> Result<Vec<u8>>
    {
        if self.stopped_namespace_v4.is_none() {
            // An empty known-State map is never evidence of native absence.
            // The actual selected read uses the complete paid native producer.
            return Err(HostError::Fence("Host native inventory requires its paid authenticated entry"));
        }
        self.ensure_healthy()?;
        if self.launch_original.is_some() || !self.runtime_pins.is_empty()
            || !self.observed_leaders.is_empty()
            || self.terminal_inventory_v4.as_ref().is_some_and(|read| !read.complete)
        {
            return Err(HostError::Fence("Host terminal Inventory has occupied native custody"));
        }
        let shape = HostTerminalInventoryShapeV4::derive_v4(header.maximum_response_bytes()).ok_or(HostError::ResourceExhausted)?;
        let control = self.component_control.as_ref().cloned()
            .ok_or(HostError::Fence("Host terminal Inventory original is absent"))?;
        let mut control = control.lock().map_err(|_| HostError::Fence("Host terminal Inventory original is poisoned"))?;
        let proof = self.stopped_namespace_v4.as_ref().ok_or(HostError::ResourceExhausted)?;
        let scope = *proof.scope_v4();
        // The fixed inline destination parks a negative admission too. Only
        // completely positive prior pure payloads may be retired at reentry;
        // all spent control traffic remains in its same cumulative invoice.
        self.terminal_inventory_v4 = Some(HostTerminalInventoryOriginalV4::new());
        let read = self.terminal_inventory_v4.as_mut().ok_or(HostError::ResourceExhausted)?;
        let mut loan = match control.begin_terminal_inventory_v4(header, proof, &shape) {
            Ok(loan) => { read.funding = Some(Ok(())); loan }
            Err(cause) => {
                read.first = Some(0);
                read.funding = Some(Err(cause));
                return Err(HostError::Fence("Host terminal Inventory funding failed; original retained"));
            }
        };
        // The same consumed control original admitted every dynamic clock and
        // response plane before capture/allocation or native entry.
        read.baseline = Some(PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::KERNEL_CLOCK_PROVENANCE)));
        read.samples = Some(PairedClockSamplesV1::new());
        read.before = Some(loan.observe_before_once_v5().await);
        if !matches!(read.before, Some(Ok(()))) { read.first.get_or_insert(1); }
        read.sample_v4(0, header, scope.boot_v4());
        if read.first.is_none() {
            read.body = Some((|| {
                let mut rows = Vec::with_capacity(1);
                rows.push(scope.encode_v4().to_vec());
                let bytes = InventoryRuntimeResponse { runtimes: Vec::new(),
                    stopped_namespaces_v4: rows, ..Default::default() }.encode_to_vec();
                ensure_response_bound(&bytes, header.maximum_response_bytes())?;
                Ok(bytes)
            })());
            if !matches!(read.body, Some(Ok(_))) { read.first.get_or_insert(3); }
        }
        // These remain independently owed if either the first native/clock or
        // body branch failed; no healthy admission or effect clock is retried.
        read.after = Some(loan.observe_after_once_v5().await);
        if !matches!(read.after, Some(Ok(()))) { read.first.get_or_insert(4); }
        read.sample_v4(1, header, scope.boot_v4());
        if read.first.is_none() {
            read.clock_disposed = Some((|| {
                read.baseline.as_mut().ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_file_v2()
                    .map_err(|_| HostError::Fence("Host terminal Inventory baseline disposal failed"))?;
                read.samples.as_mut().ok_or(HostError::ResourceExhausted)?
                    .retire_positive_native_files_v2()
                    .map_err(|_| HostError::Fence("Host terminal Inventory clock disposal failed"))
            })());
            if !matches!(read.clock_disposed, Some(Ok(()))) { read.first.get_or_insert(6); }
        }
        if read.first.is_none() {
            read.disposed = Some(loan.dispose_positive_once_v5());
            if !matches!(read.disposed, Some(Ok(()))) { read.first.get_or_insert(7); }
        }
        if read.first.is_some() {
            return Err(HostError::Fence("Host terminal Inventory original failed; causes retained"));
        }
        read.complete = true;
        read.body.as_ref().and_then(|body| body.as_ref().ok()).cloned()
            .ok_or(HostError::ResourceExhausted)
    }
}

impl HostTerminalInventoryOriginalV4 {
    pub(super) fn pure_failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            0 => cause(&self.funding),
            1 => cause(&self.before),
            2 | 5 => {
                let index = usize::from(self.first == Some(5));
                self.baseline.as_ref().and_then(|clock| clock.failure())
                    .or_else(|| self.samples.as_ref().and_then(|samples| samples.observation_failure(index)))
                    .or_else(|| self.clocks[index].as_ref().and_then(|value| value.as_ref().err())
                        .map(|cause| cause as _))
            }
            3 => self.body.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _),
            4 => cause(&self.after),
            6 => self.baseline.as_ref().and_then(|clock| clock.failure())
                .or_else(|| self.samples.as_ref().and_then(|samples| samples.observation_failure(1)))
                .or_else(|| cause(&self.clock_disposed)),
            7 => cause(&self.disposed),
            _ => None,
        }
    }
}

fn cause(value: &Option<Result<()>>) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
