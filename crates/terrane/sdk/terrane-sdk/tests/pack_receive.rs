//! Checks complete PutPack framing and independent private artifact verification.
//!
//! These tests supply no backend publication or authentication acknowledgements.

#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use std::sync::atomic::{AtomicUsize, Ordering};

use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_sdk::{
    pack::{
        BodyDecoder, EntryKind, PackClass, PackError, PackId, PackWriter, RawBodyDecoder,
        SealedPack,
    },
    store::{ContentValidator, InvalidReason, MetaUpload, StoreErrorKind, StoreFailure},
    wire::{
        upload::{MAX_BODY_FRAME_BYTES, PackReceiver, UploadError, UploadLimits},
        v1::{self, put_pack_frame::Frame},
    },
};

fn limits() -> UploadLimits {
    UploadLimits::new(
        8 * 1024 * 1024,
        1024 * 1024,
        8 * 1024 * 1024,
        16 * 1024 * 1024,
        64,
    )
    .unwrap()
}

fn pack() -> SealedPack {
    let mut writer = PackWriter::new(PackId::from_random_bytes([7; 16]), PackClass::Data, false);
    writer.append_raw(EntryKind::Chunk, b"alpha").unwrap();
    writer.append_raw(EntryKind::Chunk, b"beta").unwrap();
    writer.seal().unwrap()
}

fn frame(frame: Frame) -> v1::PutPackFrame {
    v1::PutPackFrame {
        frame: Some(frame),
        ..Default::default()
    }
}

fn header(pack: &SealedPack) -> v1::PutPackFrame {
    frame(Frame::Header(Box::new(v1::PutPackHeader {
        pack: v1::PackId {
            value: pack.header().id().as_bytes().to_vec(),
            ..Default::default()
        }
        .into(),
        size: pack.bytes().len() as u64,
        format_version: 1,
        meta: pack.header().class() == PackClass::Meta,
        ..Default::default()
    })))
}

fn trailer(index: &[u8]) -> v1::PutPackFrame {
    let hash = TERRANE_V1
        .calculate(IdentityKind::Index, index)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    frame(Frame::Trailer(Box::new(v1::PutPackTrailer {
        index: index.to_vec(),
        index_hash: v1::Hash {
            value: hash.to_vec(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })))
}

fn receive(pack: &SealedPack, limits: UploadLimits) -> PackReceiver {
    let mut receiver = PackReceiver::new(limits);
    receiver.push(header(pack)).unwrap();
    for chunk in pack.bytes().chunks(MAX_BODY_FRAME_BYTES) {
        receiver.push(frame(Frame::Body(chunk.to_vec()))).unwrap();
    }
    receiver.push(trailer(pack.index_object())).unwrap();
    receiver
}

#[derive(Default)]
struct Decoder(AtomicUsize);

impl BodyDecoder for Decoder {
    fn decode(
        &self,
        encoded: &[u8],
        size: u32,
        dictionary: u16,
        hash: &[u8; 32],
    ) -> Result<Vec<u8>, PackError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        RawBodyDecoder.decode(encoded, size, dictionary, hash)
    }
}

#[derive(Default)]
struct RejectMetadata(AtomicUsize);

impl ContentValidator for RejectMetadata {
    fn validate_meta(&self, _upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(StoreFailure::new(StoreErrorKind::Invalid(
            InvalidReason::Upload {
                rule_id: "fixture-schema",
            },
        )))
    }
}

#[test]
fn complete_pack_keeps_exact_artifacts_and_verifies_every_body() {
    let pack = pack();
    let receiver = receive(&pack, limits());
    let declaration = receiver.header().unwrap();
    assert_eq!(declaration.id(), pack.header().id());
    assert_eq!(declaration.bytes(), pack.bytes().len());
    assert_eq!(declaration.class(), PackClass::Data);

    let decoder = Decoder::default();
    let validator = RejectMetadata::default();
    let received = receiver.finish(&decoder, &validator).unwrap();

    assert_eq!(received.header(), declaration);
    assert_eq!(received.bytes(), pack.bytes());
    assert_eq!(received.index(), pack.index_object());
    assert_eq!(decoder.0.load(Ordering::SeqCst), 2);
    assert_eq!(validator.0.load(Ordering::SeqCst), 0);
}

#[test]
fn reordered_missing_and_repeated_frames_latch_terminal_rejection() {
    let pack = pack();
    let complete = [
        header(&pack),
        frame(Frame::Body(pack.bytes().to_vec())),
        trailer(pack.index_object()),
    ];
    for frames in [
        vec![complete[1].clone()],
        vec![complete[2].clone()],
        vec![complete[0].clone(), complete[0].clone()],
        vec![complete[0].clone(), complete[2].clone()],
        vec![complete[0].clone(), v1::PutPackFrame::default()],
        vec![
            complete[0].clone(),
            complete[1].clone(),
            complete[2].clone(),
            complete[1].clone(),
        ],
        vec![
            complete[0].clone(),
            complete[1].clone(),
            complete[2].clone(),
            complete[2].clone(),
        ],
    ] {
        let mut receiver = PackReceiver::new(limits());
        let mut rejected = false;
        for frame in frames {
            if receiver.push(frame).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert_eq!(receiver.buffered_bytes(), 0);
        assert!(receiver.header().is_none());
        assert!(matches!(
            receiver.push(complete[0].clone()),
            Err(UploadError::Terminated)
        ));
        assert!(matches!(
            receiver.finish(&RawBodyDecoder, &RejectMetadata::default()),
            Err(UploadError::Terminated)
        ));
    }
    for frames in [
        Vec::new(),
        vec![complete[0].clone()],
        vec![complete[0].clone(), complete[1].clone()],
    ] {
        let mut receiver = PackReceiver::new(limits());
        for frame in frames {
            receiver.push(frame).unwrap();
        }
        assert!(matches!(
            receiver.finish(&RawBodyDecoder, &RejectMetadata::default()),
            Err(UploadError::Incomplete)
        ));
    }
}

#[test]
fn declared_limits_and_actual_frame_size_are_enforced_before_retention() {
    let pack = pack();
    for mutation in 0..5 {
        let mut request = header(&pack);
        let Some(Frame::Header(header)) = &mut request.frame else {
            panic!("fixture header");
        };
        match mutation {
            0 => header.size = u64::MAX,
            1 => header.size = 1,
            2 => header.format_version = 2,
            3 => header.pack = Default::default(),
            _ => header.pack.as_option_mut().unwrap().value.push(0),
        }
        let mut receiver = PackReceiver::new(limits());
        assert!(receiver.push(request).is_err());
        assert_eq!(receiver.buffered_bytes(), 0);
    }
    let mut receiver = PackReceiver::new(limits());
    receiver.push(header(&pack)).unwrap();
    assert!(matches!(
        receiver.push(frame(Frame::Body(vec![0; pack.bytes().len() + 1]))),
        Err(UploadError::Limit)
    ));
    assert_eq!(receiver.buffered_bytes(), 0);

    let mut writer = PackWriter::new(PackId::from_random_bytes([8; 16]), PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, &vec![9; MAX_BODY_FRAME_BYTES])
        .unwrap();
    let large = writer.seal().unwrap();
    let received = receive(&large, limits())
        .finish(&RawBodyDecoder, &RejectMetadata::default())
        .unwrap();
    assert_eq!(received.bytes(), large.bytes());

    let mut receiver = PackReceiver::new(limits());
    receiver.push(header(&large)).unwrap();
    assert!(matches!(
        receiver.push(frame(Frame::Body(vec![0; MAX_BODY_FRAME_BYTES + 1]))),
        Err(UploadError::Limit)
    ));
    assert_eq!(receiver.buffered_bytes(), 0);
}

#[test]
fn index_digest_embedded_index_and_pack_declarations_must_all_agree() {
    let pack = pack();
    for mutation in 0..4 {
        let mut receiver = PackReceiver::new(limits());
        let mut declaration = header(&pack);
        if let Some(Frame::Header(header)) = &mut declaration.frame {
            if mutation == 2 {
                header.meta = true;
            }
            if mutation == 3 {
                header.pack.as_option_mut().unwrap().value[0] ^= 1;
            }
        }
        receiver.push(declaration).unwrap();
        receiver
            .push(frame(Frame::Body(pack.bytes().to_vec())))
            .unwrap();
        let mut final_frame = trailer(pack.index_object());
        if let Some(Frame::Trailer(trailer)) = &mut final_frame.frame
            && mutation == 0
        {
            trailer.index_hash.as_option_mut().unwrap().value[0] ^= 1;
        }
        if mutation == 1 {
            let mut altered = pack.index_object().to_vec();
            altered[0] ^= 1;
            final_frame = trailer(&altered);
        }
        if mutation == 0 {
            assert!(matches!(
                receiver.push(final_frame),
                Err(UploadError::IndexHash)
            ));
        } else {
            receiver.push(final_frame).unwrap();
            assert!(
                receiver
                    .finish(&RawBodyDecoder, &RejectMetadata::default())
                    .is_err()
            );
        }
    }
}

#[test]
fn one_corrupt_member_rejects_the_entire_upload_without_partial_success() {
    let pack = pack();
    for offset in [
        terrane_sdk::pack::HEADER_SIZE + 1,
        terrane_sdk::pack::HEADER_SIZE + 7,
    ] {
        let mut bytes = pack.bytes().to_vec();
        bytes[offset] ^= 1;
        let mut receiver = PackReceiver::new(limits());
        receiver.push(header(&pack)).unwrap();
        receiver.push(frame(Frame::Body(bytes))).unwrap();
        receiver.push(trailer(pack.index_object())).unwrap();

        let error = receiver
            .finish(&RawBodyDecoder, &RejectMetadata::default())
            .err()
            .unwrap();
        assert!(matches!(error, UploadError::Pack(_)));
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn decoded_work_bounds_are_checked_before_calling_any_decoder() {
    let pack = pack();
    for bounds in [
        UploadLimits::new(4096, 4096, 4, 128, 16).unwrap(),
        UploadLimits::new(4096, 4096, 8, 8, 16).unwrap(),
    ] {
        let receiver = receive(&pack, bounds);
        let decoder = Decoder::default();

        assert!(matches!(
            receiver.finish(&decoder, &RejectMetadata::default()),
            Err(UploadError::Limit)
        ));
        assert_eq!(decoder.0.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn configured_metadata_validation_cannot_be_replaced_by_canonical_cbor() {
    let mut writer = PackWriter::new(PackId::from_random_bytes([6; 16]), PackClass::Meta, false);
    writer.append_raw(EntryKind::Node, &[0xa0]).unwrap();
    let pack = writer.seal().unwrap();
    let validator = RejectMetadata::default();

    let error = receive(&pack, limits())
        .finish(&RawBodyDecoder, &validator)
        .err()
        .unwrap();

    assert!(matches!(error, UploadError::Validation(_)));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(validator.0.load(Ordering::SeqCst), 1);
}

#[test]
fn invalid_configuration_index_and_frame_budgets_fail_closed() {
    for values in [
        (0, 128, 8, 16, 4),
        (128, 0, 8, 16, 4),
        (128, 128, 0, 16, 4),
        (128, 128, 17, 16, 4),
        (128, 128, 8, u64::MAX, 4),
        (usize::MAX, 128, 8, 16, 4),
        (128, usize::MAX, 8, 16, 4),
        (128, 128, 8, 16, 2),
        (128, 128, 8, 16, u64::MAX),
    ] {
        assert!(matches!(
            UploadLimits::new(values.0, values.1, values.2, values.3, values.4),
            Err(UploadError::Limits)
        ));
    }
    let pack = pack();
    let mut receiver = PackReceiver::new(UploadLimits::new(4096, 36, 128, 128, 16).unwrap());
    receiver.push(header(&pack)).unwrap();
    receiver
        .push(frame(Frame::Body(pack.bytes().to_vec())))
        .unwrap();
    assert!(matches!(
        receiver.push(trailer(pack.index_object())),
        Err(UploadError::Limit)
    ));

    let mut receiver = PackReceiver::new(UploadLimits::new(4096, 4096, 128, 128, 3).unwrap());
    receiver.push(header(&pack)).unwrap();
    receiver
        .push(frame(Frame::Body(pack.bytes().to_vec())))
        .unwrap();
    receiver.push(frame(Frame::Body(Vec::new()))).unwrap();
    assert!(matches!(
        receiver.push(trailer(pack.index_object())),
        Err(UploadError::Limit)
    ));
    assert_eq!(receiver.buffered_bytes(), 0);
}
