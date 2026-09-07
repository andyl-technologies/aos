//! Selectable callback authority and writeback tests.

use crucible_protocol::{
    SELECTABLE_DIGEST_BYTES, SelectableRegister, SelectionReply, SelectionReplyStatus,
    SelectionRequest,
};

use super::*;
use crate::{
    GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, PluginSwitch,
    WHITEBOX_DOORBELL_X86_64_ABI, WhiteboxDoorbellCapabilities, WhiteboxGuestInputWriteError,
};

struct Memory {
    read: Vec<u8>,
    writes: Vec<(u64, GuestMemoryRange, Vec<u8>)>,
}

impl Memory {
    fn new(read: Vec<u8>) -> Self {
        Self {
            read,
            writes: Vec::new(),
        }
    }
}

impl GuestMemoryReader for Memory {
    fn read_guest_memory(
        &mut self,
        _vcpu_index: u32,
        _current_icount: u64,
        _range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        Ok(self.read.clone())
    }
}

impl WhiteboxGuestInputWriter for Memory {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError> {
        self.writes.push((delivery_icount, range, payload.to_vec()));
        Ok(())
    }
}

struct Service {
    registrations: Vec<(SelectableRegister, SelectableCallbackCoordinate)>,
    requests: Vec<(SelectionRequest, SelectableCallbackCoordinate)>,
    reply: SelectionReply,
}

impl SelectableRegistrationService for Service {
    fn register_selectable(
        &mut self,
        registration: &SelectableRegister,
        coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError> {
        self.registrations.push((registration.clone(), coordinate));
        Ok(())
    }
}

impl SelectableReplyService for Service {
    fn serve_selection(
        &mut self,
        request: &SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
        _reply_range: GuestMemoryRange,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        self.requests.push((request.clone(), coordinate));
        Ok(self.reply.clone().into())
    }
}

struct PendingService {
    request: Option<(SelectionRequest, SelectableCallbackCoordinate)>,
}

impl SelectableRegistrationService for PendingService {
    fn register_selectable(
        &mut self,
        _registration: &SelectableRegister,
        _coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError> {
        Ok(())
    }
}

impl SelectableReplyService for PendingService {
    fn serve_selection(
        &mut self,
        request: &SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
        _reply_range: GuestMemoryRange,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        self.request = Some((request.clone(), coordinate));
        Ok(SelectableReplyDisposition::Pending)
    }
}

fn doorbell() -> PluginWhiteboxDoorbell {
    PluginWhiteboxDoorbell::from_abi(PluginSwitch::On, WHITEBOX_DOORBELL_X86_64_ABI, 4_608)
}

fn event(len: usize) -> WhiteboxDoorbellTrapEvent {
    WhiteboxDoorbellTrapEvent::from_register_pointer_length(
        2,
        77,
        GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x1000, len),
    )
}

fn capability(
    doorbell: &PluginWhiteboxDoorbell,
) -> Result<WhiteboxGuestInputCapability, WhiteboxDoorbellError> {
    doorbell.require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
}

fn registration() -> Result<SelectableRegister, SelectableProtocolError> {
    SelectableRegister::new(1, "network.policy", vec![1], vec![2], Vec::new())
}

fn request(sequence: u64, capacity: usize) -> Result<SelectionRequest, SelectableProtocolError> {
    SelectionRequest::new(sequence, "network.policy", "epoch/7", None, capacity)
}

fn reply(sequence: u64, value_len: usize) -> Result<SelectionReply, SelectableProtocolError> {
    SelectionReply::selected(
        sequence,
        [1; SELECTABLE_DIGEST_BYTES],
        [2; SELECTABLE_DIGEST_BYTES],
        vec![3; value_len],
    )
}

#[test]
fn registration_is_observational_and_keeps_exact_coordinate()
-> Result<(), Box<dyn std::error::Error>> {
    let doorbell = doorbell();
    let registration = registration()?;
    let bytes = registration.encode()?;
    let mut memory = Memory::new(bytes.clone());
    let mut service = Service {
        registrations: Vec::new(),
        requests: Vec::new(),
        reply: SelectionReply::rejected(
            1,
            SelectionReplyStatus::Unavailable,
            [0; SELECTABLE_DIGEST_BYTES],
            [0; SELECTABLE_DIGEST_BYTES],
        )?,
    };

    let outcome = handle_whitebox_selectable_callback(
        &doorbell,
        &capability(&doorbell)?,
        &mut memory,
        &mut service,
        &mut Memory::new(Vec::new()),
        event(bytes.len()),
    )?;

    assert!(matches!(
        outcome,
        SelectableDoorbellOutcome::Registered { .. }
    ));
    assert_eq!(
        service.registrations,
        vec![(
            registration,
            SelectableCallbackCoordinate {
                icount: 77,
                vcpu_index: 2
            }
        )]
    );
    assert!(service.requests.is_empty());
    assert!(memory.writes.is_empty());
    Ok(())
}

#[test]
fn request_writes_one_sequence_bound_zero_padded_reply_at_trap()
-> Result<(), Box<dyn std::error::Error>> {
    let doorbell = doorbell();
    let request = request(9, 160)?;
    let request_bytes = request.encode()?;
    let reply = reply(9, 3)?;
    let reply_bytes = reply.encode()?;
    let mut reader = Memory::new(request_bytes.clone());
    let mut writer = Memory::new(Vec::new());
    let mut service = Service {
        registrations: Vec::new(),
        requests: Vec::new(),
        reply: reply.clone(),
    };

    let outcome = handle_whitebox_selectable_callback(
        &doorbell,
        &capability(&doorbell)?,
        &mut reader,
        &mut service,
        &mut writer,
        event(request_bytes.len()),
    )?;

    assert!(matches!(outcome, SelectableDoorbellOutcome::Replied { .. }));
    assert_eq!(
        service.requests,
        vec![(
            request,
            SelectableCallbackCoordinate {
                icount: 77,
                vcpu_index: 2
            }
        )]
    );
    assert_eq!(writer.writes.len(), 1);
    let (icount, range, written) = &writer.writes[0];
    assert_eq!(*icount, 77);
    assert_eq!(*range, event(160).payload_range());
    assert_eq!(&written[..reply_bytes.len()], reply_bytes);
    assert!(written[reply_bytes.len()..].iter().all(|byte| *byte == 0));
    assert_eq!(written.len(), 160);
    Ok(())
}

#[test]
fn pending_request_keeps_the_zero_filled_guest_reservation_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let doorbell = doorbell();
    let request = request(9, 160)?;
    let request_bytes = request.encode()?;
    let mut reader = Memory::new(request_bytes.clone());
    let mut writer = Memory::new(Vec::new());
    let mut service = PendingService { request: None };

    let outcome = handle_whitebox_selectable_callback(
        &doorbell,
        &capability(&doorbell)?,
        &mut reader,
        &mut service,
        &mut writer,
        event(request_bytes.len()),
    )?;

    assert_eq!(
        outcome,
        SelectableDoorbellOutcome::Pending {
            request: request.clone(),
            coordinate: SelectableCallbackCoordinate::new(77, 2),
        }
    );
    assert_eq!(
        service.request,
        Some((request, SelectableCallbackCoordinate::new(77, 2)))
    );
    assert!(writer.writes.is_empty());
    Ok(())
}

#[test]
fn callback_rejects_guest_reply_stale_service_reply_and_oversized_value()
-> Result<(), Box<dyn std::error::Error>> {
    let doorbell = doorbell();
    let capability = capability(&doorbell)?;
    let guest_reply = reply(1, 1)?.encode()?;
    let mut reader = Memory::new(guest_reply.clone());
    let mut writer = Memory::new(Vec::new());
    let mut service = Service {
        registrations: Vec::new(),
        requests: Vec::new(),
        reply: reply(1, 1)?,
    };
    assert_eq!(
        handle_whitebox_selectable_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut service,
            &mut writer,
            event(guest_reply.len()),
        ),
        Err(SelectableDoorbellError::GuestSuppliedReply)
    );

    let request = request(7, 128)?;
    let request_bytes = request.encode()?;
    reader.read = request_bytes.clone();
    service.reply = reply(8, 1)?;
    assert_eq!(
        handle_whitebox_selectable_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut service,
            &mut writer,
            event(request_bytes.len()),
        ),
        Err(SelectableDoorbellError::ReplySequenceMismatch {
            expected: 7,
            actual: 8,
        })
    );

    service.reply = reply(7, 33)?;
    assert_eq!(
        handle_whitebox_selectable_callback(
            &doorbell,
            &capability,
            &mut reader,
            &mut service,
            &mut writer,
            event(request_bytes.len()),
        ),
        Err(SelectableDoorbellError::ReplyExceedsReservation {
            reply_len: 129,
            capacity: 128,
        })
    );
    assert!(writer.writes.is_empty());
    Ok(())
}
