//! Checks borrowed frame identity and the shared pre-write admission rules.
// SPDX-License-Identifier: GPL-2.0-only

use crucible_qemu_protocol::guest_introspection_doorbell::GuestIntrospectionDoorbellFrame;

use super::*;

struct CheckingWriter<'a> {
    payload: &'a [u8],
    range: GuestMemoryRange,
    calls: usize,
    refusal: Option<WhiteboxGuestInputWriteError>,
}

impl WhiteboxGuestInputWriter for CheckingWriter<'_> {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError> {
        self.calls += 1;
        assert_eq!(delivery_icount, 88);
        assert_eq!(range, self.range);
        assert_eq!(payload.as_ptr(), self.payload.as_ptr());
        assert_eq!(payload, self.payload);

        match self.refusal.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn doorbell(maximum: usize) -> PluginWhiteboxDoorbell {
    PluginWhiteboxDoorbell::new(
        PluginSwitch::On,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        maximum,
    )
}

#[test]
fn borrowed_guest_input_preserves_frame_storage_at_exact_delivery() {
    let payload = GuestIntrospectionDoorbellFrame::idle().encode().unwrap();
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x3000, payload.len());
    let doorbell = doorbell(MAX_FRAME_DATA);
    let capability = doorbell
        .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
        .unwrap();
    let mut writer = CheckingWriter {
        payload: &payload,
        range,
        calls: 0,
        refusal: None,
    };

    let outcome = doorbell
        .inject_guest_input_slice(&capability, &mut writer, 88, 88, range, &payload)
        .unwrap();

    assert_eq!(writer.calls, 1);
    assert_eq!(
        outcome,
        WhiteboxGuestInputOutcome::Delivered(WhiteboxGuestInputInjection {
            delivery_icount: 88,
            payload_range: range,
            payload_len: payload.len(),
        })
    );
    assert_eq!(
        GuestIntrospectionDoorbellFrame::decode(&payload)
            .unwrap()
            .kind(),
        crucible_qemu_protocol::guest_introspection_doorbell::GuestIntrospectionDoorbellKind::Idle
    );
}

#[test]
fn borrowed_guest_input_refuses_before_writing_and_preserves_writer_failure() {
    let payload = b"ack";
    let range = GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x3000, payload.len());
    let capability = doorbell(128)
        .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
        .unwrap();
    let mut writer = CheckingWriter {
        payload,
        range,
        calls: 0,
        refusal: None,
    };
    let disabled = PluginWhiteboxDoorbell::new(
        PluginSwitch::Off,
        WhiteboxDoorbellTrap::X86PortIo { port: 0xe7 },
        128,
    );

    assert_eq!(
        disabled.inject_guest_input_slice(&capability, &mut writer, 88, 88, range, payload),
        Err(WhiteboxDoorbellError::InputWhileDisabled)
    );
    assert_eq!(
        doorbell(128).inject_guest_input_slice(
            &capability,
            &mut writer,
            88,
            88,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x3000, 2),
            payload
        ),
        Err(WhiteboxDoorbellError::InputPayloadLengthMismatch {
            range_len: 2,
            payload_len: 3
        })
    );
    assert_eq!(
        doorbell(2).inject_guest_input_slice(&capability, &mut writer, 88, 88, range, payload),
        Err(WhiteboxDoorbellError::PayloadTooLarge {
            len: 3,
            max_payload_len: 2
        })
    );
    assert_eq!(
        doorbell(0).inject_guest_input_slice(&capability, &mut writer, 88, 88, range, payload),
        Err(WhiteboxDoorbellError::InvalidMaxPayloadLen {
            max_payload_len: 0,
            max_frame_data: MAX_FRAME_DATA
        })
    );
    assert_eq!(
        doorbell(128).inject_guest_input_slice(&capability, &mut writer, 87, 88, range, payload),
        Ok(WhiteboxGuestInputOutcome::NotReady {
            delivery_icount: 88
        })
    );
    assert_eq!(
        doorbell(128).inject_guest_input_slice(&capability, &mut writer, 89, 88, range, payload),
        Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
            delivery_icount: 88,
            current_icount: 89
        })
    );
    assert_eq!(writer.calls, 0);

    let cause = WhiteboxGuestInputWriteError::new("injected borrowed write refusal");
    writer.refusal = Some(cause.clone());

    let refused =
        doorbell(128).inject_guest_input_slice(&capability, &mut writer, 88, 88, range, payload);

    assert_eq!(
        refused,
        Err(WhiteboxDoorbellError::GuestInputWrite {
            delivery_icount: 88,
            source: cause,
        })
    );
    assert_eq!(writer.calls, 1);
    assert!(writer.refusal.is_none());
}
