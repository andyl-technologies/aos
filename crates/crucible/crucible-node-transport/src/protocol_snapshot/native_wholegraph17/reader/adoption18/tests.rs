//! Checks custody of actual failed native decoder banks through18 preparation.

use super::*;
use crate::reference_packet::{PacketEvent, PacketProgram};
use crucible_node_format::{Id, Phase, Position};
use std::os::fd::AsRawFd;

fn definition() -> Result<PacketConnectedSourceProgram, ProviderError> {
    let (effect, _peer) = UnixDatagram::pair()?;
    let event = PacketEvent {
        id: Id::new("decoder-prefix-event")?,
        evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
        completion: Position::new(U64::new(2), U64::new(0), Phase::Publication),
        payload: None,
    };
    let program = PacketProgram::new(vec![event], effect)?;
    Ok(PacketConnectedSourceProgram::Producer {
        program: program.definition(),
    })
}

fn failed_graph() -> Vec<Option<NativeCurrentGraph17DecodeAttempt>> {
    let mut graphs = Vec::with_capacity(1);
    graphs.resize_with(1, || None);
    assert!(read_native_current_graph17_into_data(b"[false]", &mut graphs[0], 4096).is_err());
    graphs
}

#[test]
fn graph18_model_adoption_keeps_actual_failed_decoder_and_original_heap_bank()
-> Result<(), ProviderError> {
    let mut graphs = failed_graph();
    let bank = graphs.as_ptr();
    let capacity = graphs.capacity();
    let raw = graphs[0].as_ref().ok_or_else(refused)?.raw.as_ptr();
    let mut output = None;

    assert!(
        NativeCurrentGraph18ModelAdoption::prepare_into(&mut graphs, &definition()?, &mut output)
            .is_err()
    );

    assert!(graphs.is_empty());
    assert_eq!(graphs.capacity(), 0);
    let owner = output.as_mut().ok_or_else(refused)?;
    assert_eq!(owner.graphs.as_ptr(), bank);
    assert_eq!(owner.graphs.capacity(), capacity);
    assert!(owner.stage == Stage::Failed);
    let decoder = owner.graphs[0].as_ref().ok_or_else(refused)?;
    assert_eq!(decoder.raw, b"[false]");
    assert_eq!(decoder.raw.as_ptr(), raw);
    assert!(decoder.failed);
    assert!(decoder.completed_data().is_none());
    assert!(owner.model.is_none());

    let requested = owner.retained_requested_storage_data(usize::MAX)?;
    assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
    assert!(
        owner
            .retained_requested_storage_data(requested - 1)
            .is_err()
    );
    let (socket, _peer) = UnixDatagram::pair()?;
    let descriptor = socket.as_raw_fd();
    let mut socket = Some(socket);
    assert!(owner.bind_effect_socket(&mut socket).is_err());
    assert_eq!(socket.as_ref().ok_or_else(refused)?.as_raw_fd(), descriptor);
    let mut completed = None;
    assert!(owner.take_completed_into(&mut completed).is_err());
    assert!(completed.is_none());
    assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
    Ok(())
}

#[test]
fn graph18_model_adoption_spends_empty_bank_and_preserves_replacement_prefix()
-> Result<(), ProviderError> {
    let mut empty = Vec::with_capacity(1);
    let bank = empty.as_ptr();
    let mut output = None;
    let program = definition()?;

    assert!(
        NativeCurrentGraph18ModelAdoption::prepare_into(&mut empty, &program, &mut output).is_err()
    );

    let owner = output.as_ref().ok_or_else(refused)?;
    assert!(owner.stage == Stage::Failed);
    assert_eq!(owner.graphs.as_ptr(), bank);
    let requested = owner.retained_requested_storage_data(usize::MAX)?;
    assert_eq!(
        requested,
        size_of::<NativeCurrentGraph18ModelAdoption>()
            + size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
    );
    let mut replacement = failed_graph();
    let replacement_bank = replacement.as_ptr();
    let replacement_raw = replacement[0].as_ref().ok_or_else(refused)?.raw.as_ptr();
    assert!(
        NativeCurrentGraph18ModelAdoption::prepare_into(&mut replacement, &program, &mut output)
            .is_err()
    );
    assert_eq!(replacement.as_ptr(), replacement_bank);
    assert_eq!(
        replacement[0].as_ref().ok_or_else(refused)?.raw.as_ptr(),
        replacement_raw
    );
    assert_eq!(
        output
            .as_ref()
            .ok_or_else(refused)?
            .retained_requested_storage_data(requested)?,
        requested
    );
    assert!(NativeCurrentGraph18ModelAdoption::inline_header_bytes_data() > 0);
    assert!(NativeCurrentGraph18ModelAdoption::counter_scratch_data() > 0);
    Ok(())
}
