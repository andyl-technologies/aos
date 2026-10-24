//! Projects the original Observe grammar from the actual pre-child launch.
//!
//! The projection borrows the installed source tuple. Unknown future identifiers,
//! cursors and counters use their closed wire extents; no Control, Envelope,
//! receipt, report, hash or native owner is manufactured. The actual publisher
//! must reconcile its owning fields against these bounds before copying them.

use super::*;
use crate::reference_packet::service::capture_allocation::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;

type Projection = OriginalSerializationStorageProjection;

pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_shapes::OriginalObserveStartupShapes;
use crucible_source_birth_data::profile::reference_packet::service::{PacketNative5LaunchValidationFields, native_startup::report_shapes};
use report_shapes::{object, reference};

pub(super) fn original(
    projection: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    report_shapes::original(projection, &fields)
}

fn receipt(
    projection: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    report_shapes::receipt(projection, &fields)
}

fn terminal(
    projection: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    report_shapes::terminal(projection, &fields)
}

fn report(
    projection: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    report_shapes::report(projection, &fields)
}

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalObserveStartupShapes, ProviderError> {
    if launch.capture_allocation_selection
        != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        || !matches!(
            launch.capture_profile,
            crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        )
        || launch.protocol_metadata_limits.is_none()
    {
        return Err(refused());
    }
    let counter = |write: &dyn Fn(&mut Projection) -> Result<(), ProviderError>| {
        let mut projection = Projection::new(maximum)?;
        write(&mut projection)?;
        projection.finish(maximum)
    };
    Ok(OriginalObserveStartupShapes {
        original: counter(&|p| original(p, launch))?,
        terminal: counter(&|p| terminal(p, launch))?,
        receipt: counter(&|p| receipt(p, launch))?,
        wrapper: counter(&|p| {
            object(p, &["schema", "native", "allocation"])?;
            p.add_string(PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD)?;
            receipt(p, launch)?;
            reference(p, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)
        })?,
        report: counter(&|p| report(p, launch))?,
        raw: super::raw_record::project(launch, maximum)?,
    })
}

/// Keeps the same report grammar while bounding the guarded initial raw child.
pub(super) fn project_initial(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalObserveStartupShapes, ProviderError> {
    let mut shapes = project(launch, maximum)?;
    shapes.raw = super::raw_record::project_initial(launch, maximum)?;
    Ok(shapes)
}

// One reusable sequential wrapper window: Fields constructor initializer,
// return and retained binding; its original-launch input and two Fields loans;
// then the additional lower call's Result return. The four wrappers never nest:
// lower receipt/terminal/report call the sole lower original helper directly.
// Raw reactive delegation adds two real facts windows, caller/formal loans and
// one nested Result. The original model-limit header remains where it was.
pub(super) const fn counter_scratch_data() -> usize {
    3 * size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + 2 * size_of::<&PacketNative5LaunchValidationFields<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<report_shapes::raw::StoppedInventoryRowLimitsData>()
        + 2 * size_of::<&report_shapes::raw::StoppedInventoryRowLimitsData>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
#[path = "observe/tests.rs"]
mod shape_tests;
