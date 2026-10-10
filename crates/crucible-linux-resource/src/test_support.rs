//! Explicit disposable-kernel fault capabilities for managed native tests.
//!
//! These capabilities are absent from default builds. The caller retains the
//! original admitted descriptor/memory credit and supervision guard; a test
//! capability never creates a resource pool or authorizes native guest resume.

mod allocation_observer;
mod device_mapper;

pub use device_mapper::LinuxDeviceMapperFaultTarget;

pub use allocation_observer::{
    AllocationCounts, AllocationEvent, AllocationEvents, AllocationEventsSetupError,
    AllocationExtent, AllocationIdentity, AllocationRoster, AllocationRosterOutcome,
    AllocationRosterSetupError, AllocationTrace, AllocationTraceEntry, AllocationTraceSetupError,
    BeforeFreeMarkerOutcome, CloseMarkerOutcome, CloseMarkerSetupError, ControlObservation,
    ControlSample, GlobalAllocationTraceSession, MemoryNodeCounters, MemoryNodeReport,
    MemoryNodeSession, OriginalControlObservation, OriginalControlReport, OriginalControlSelection,
    OriginalControlSession, OriginalControlSlot, OriginalControlSnapshot, OriginalControlsOutcome,
    OriginalStaticCounters, ProbeAllocationLayout, ResidentProbeOutcome, ResidentProbeReport,
    ResidentProbeSetupError, TestAllocationObserver, ThroughFreeMarkerOutcome,
};
