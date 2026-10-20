//! Constructs Control6 only for the same registered original Capture.
//!
//! The endpoint supplies its private completed-Observe currency and immutable
//! Report. The complete actual model/control serializer is counted before any
//! model snapshot or DOM allocation. This producer supplies bytes, never the
//! Source whole-budget ticket, a cold seal or restoration authority.

use super::*;
use crate::reference_packet::control::{
    PacketLiveCaptureControlCurrency, PacketOriginalCaptureReservation,
};
use crate::reference_packet::serialization_storage::{
    NativeControlCaptureEncodingData, actual_serialization_storage_data,
    encode_original_precharged_serialization,
};
use crate::reference_packet::service::capture_allocation::{
    PacketNative5CaptureAllocationSelection, PacketNativeCaptureAllocationReport,
};

#[derive(Serialize)]
struct StartupSnapshotView<'a, C> {
    schema: &'static str,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: &'a Value,
    control: C,
}

#[derive(Serialize)]
struct StartupSnapshotShape<C> {
    schema: &'static str,
    captured_process: U64,
    administrative_cut: Position,
    local_cursor: Position,
    model: (),
    control: C,
}

impl PacketControl {
    pub(in crate::reference_packet::control) fn capture_registered_startup_control(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        maximum_bytes: usize,
    ) -> Result<
        (
            PacketOriginalControlSnapshot,
            crate::reference_packet::serialization_storage::NativeSerializationStorageData,
        ),
        ProviderError,
    > {
        self.authenticate_registered_startup_capture(reservation, currency, report)?;
        let maximum = usize::try_from(report.transients.model_control_encoding_bytes.get())
            .map_err(|_| refused())?;
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_BYTES || maximum == 0 {
            return Err(refused());
        }
        let local_cursor = currency.cursor();
        let administrative_cut = reservation.arguments().cut;
        administrative_cut.validate()?;
        if administrative_cut < local_cursor {
            return Err(refused());
        }
        let model = match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.quote_original_live_capture_encoding(maximum)?
            }
            NativeProgram::Connected(program) => {
                program.quote_original_live_capture_encoding(maximum)?
            }
            NativeProgram::RestorationInProgress => return Err(refused()),
        };
        let shape = StartupSnapshotShape {
            schema: "source-owned.packet-native-control-state/6",
            captured_process: U64::new(u64::from(std::process::id())),
            administrative_cut,
            local_cursor,
            model: (),
            control: self.borrowed_capture_control_data(),
        };
        let control = actual_serialization_storage_data(&shape, Default::default(), maximum)?;
        // The actual producer streams its row adapters directly, so it owns no
        // old Control5 row Vecs. Model parsing and both independent full-root
        // Value/output phases remain in the shared compiled phase calculator.
        let bound = NativeControlCaptureEncodingData::from_original_parts(
            model,
            control,
            0,
            self.content.len(),
            maximum,
        )?;
        if bound.maximum_encoded_bytes > maximum_bytes || bound.requested_bytes > maximum {
            return Err(refused());
        }
        self.authenticate_registered_startup_capture(reservation, currency, report)?;

        let model = match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.capture_state(local_cursor, maximum_bytes)?
            }
            NativeProgram::Connected(program) => {
                program.capture_state(local_cursor, maximum_bytes)?
            }
            NativeProgram::RestorationInProgress => return Err(refused()),
        };
        model.reference().verify(model.bytes())?;
        let model_value = canonical::parse_json(model.bytes(), maximum_bytes)?;
        let view = StartupSnapshotView {
            schema: "source-owned.packet-native-control-state/6",
            captured_process: U64::new(u64::from(std::process::id())),
            administrative_cut,
            local_cursor,
            model: &model_value,
            control: self.borrowed_capture_control_data(),
        };
        let actual = actual_serialization_storage_data(&view, Default::default(), maximum)?;
        if actual.maximum_encoded_bytes > bound.maximum_encoded_bytes {
            return Err(refused());
        }
        let bytes = encode_original_precharged_serialization(&view, &actual)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        self.authenticate_registered_startup_capture(reservation, currency, report)?;
        Ok((
            PacketOriginalControlSnapshot {
                reference,
                bytes,
                administrative_cut,
                local_cursor,
            },
            actual,
        ))
    }

    fn authenticate_registered_startup_capture(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
    ) -> Result<(), ProviderError> {
        if self.complete_capture_allocation_selection
            != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || report.scope.native_pid.get() != u64::from(std::process::id())
            || report.scope.control_originals_before.get() != currency.originals_before() as u64
            || report.scope.model_cursor != currency.cursor()
        {
            return Err(refused());
        }
        currency.authenticate_capture_boundary(self, Some(reservation.request()))?;
        self.authenticate_startup_capture_reservation_data(
            reservation,
            usize::try_from(report.transients.model_control_encoding_bytes.get())
                .map_err(|_| refused())?,
        )
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native Control6 original capture producer or phase differs")
}
