//! Hashes closed receiver/input fields without generic serialization.
//!
//! These private transcripts bind DATA correspondence, never Source permission.
//! Every semantic/custody field and byte capacity is included. Actual Rc and
//! supervisor correspondence remains a separate real owner check.

use super::*;

struct Transcript(blake3::Hasher);
impl Transcript {
    fn new(domain: &'static str) -> Self {
        Self(blake3::Hasher::new_derive_key(domain))
    }

    fn number(&mut self, value: usize) -> Result<(), ProviderError> {
        self.0
            .update(&u64::try_from(value).map_err(|_| exhausted())?.to_be_bytes());
        Ok(())
    }

    fn integer(&mut self, value: u64) {
        self.0.update(&value.to_be_bytes());
    }

    fn tag(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        self.number(bytes.len())?;
        self.0.update(bytes);
        Ok(())
    }

    fn id(&mut self, id: &Id) -> Result<(), ProviderError> {
        self.bytes(id.as_str().as_bytes())
    }

    fn retained_id(&mut self, id: &Id) -> Result<(), ProviderError> {
        self.number(id.allocated_capacity())?;
        self.id(id)
    }

    fn reference(&mut self, reference: &ContentRef) -> Result<(), ProviderError> {
        let ContentRef {
            hash,
            length,
            media_type,
        } = reference;
        let crucible_node_format::HashRef {
            algorithm,
            domain,
            digest,
        } = hash;
        self.bytes(algorithm.as_bytes())?;
        self.bytes(domain.as_bytes())?;
        self.bytes(digest.as_bytes())?;
        self.integer(length.get());
        self.bytes(media_type.as_bytes())
    }

    fn retained_reference(&mut self, reference: &ContentRef) -> Result<(), ProviderError> {
        let ContentRef {
            hash,
            length: _,
            media_type,
        } = reference;
        let crucible_node_format::HashRef {
            algorithm,
            domain,
            digest,
        } = hash;
        self.number(algorithm.capacity())?;
        self.number(domain.capacity())?;
        self.number(digest.capacity())?;
        self.number(media_type.capacity())?;
        self.reference(reference)
    }

    fn origin(&mut self, origin: RequestOrigin) {
        self.tag(match origin {
            RequestOrigin::Controller => 0,
            RequestOrigin::Provider => 1,
        });
    }

    fn key(&mut self, key: &TransferKey) -> Result<(), ProviderError> {
        let TransferKey {
            origin,
            session,
            incarnation,
            transfer,
        } = key;
        self.origin(*origin);
        self.retained_id(session)?;
        self.retained_id(incarnation)?;
        self.retained_id(transfer)
    }

    fn finish(self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

pub(super) fn input_data(input: NativeCapture17UploadInput<'_>) -> Result<[u8; 32], ProviderError> {
    let mut transcript = Transcript::new("source-private.capture17-upload-input/17");
    let key = input.key_data();
    transcript.origin(key.origin);
    transcript.id(key.session)?;
    transcript.id(key.incarnation)?;
    transcript.id(key.transfer)?;
    match input {
        NativeCapture17UploadInput::Begin { content, .. } => {
            transcript.tag(0);
            transcript.reference(content)?;
        }
        NativeCapture17UploadInput::Chunk { offset, bytes, .. } => {
            transcript.tag(1);
            transcript.integer(offset.get());
            transcript.bytes(bytes.as_slice())?;
        }
        NativeCapture17UploadInput::Finish { .. } => transcript.tag(2),
    }
    Ok(transcript.finish())
}

pub(super) fn receiver_data(receiver: &BlobReceiver) -> Result<[u8; 32], ProviderError> {
    let BlobReceiver {
        session,
        incarnation,
        limits,
        state,
        supervisor: _,
    } = receiver;
    let mut transcript = Transcript::new("source-private.capture17-upload-receiver/17");
    transcript.retained_id(session)?;
    transcript.retained_id(incarnation)?;
    let BlobLimits {
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    } = limits;
    transcript.number(*reserved_bytes)?;
    transcript.number(*content_bytes)?;
    transcript.number(*chunk_bytes)?;
    transcript.number(*transfers_per_origin)?;
    transcript.number(*tombstones_per_origin)?;
    transcript.number(*chunks_per_transfer)?;
    transcript.number(*operation_pins)?;
    let state = state.try_borrow().map_err(|_| refused())?;
    let ReceiverState {
        records,
        reserved,
        next_pin,
        pins_created,
    } = &*state;
    transcript.number(*reserved)?;
    transcript.integer(*next_pin);
    transcript.number(*pins_created)?;
    transcript.number(records.len())?;
    for (key, record) in records {
        transcript.key(key)?;
        let TransferRecord {
            content,
            length,
            bytes,
            chunks,
            verified,
            quarantined,
            exposed,
            retirement,
            pins,
            charged,
        } = record;
        transcript.retained_reference(content)?;
        transcript.number(*length)?;
        transcript.number(bytes.capacity())?;
        transcript.bytes(bytes)?;
        transcript.number(chunks.len())?;
        for (offset, length) in chunks {
            transcript.number(*offset)?;
            transcript.number(*length)?;
        }
        transcript.tag(u8::from(*verified));
        transcript.tag(u8::from(*quarantined));
        transcript.tag(u8::from(*exposed));
        match retirement {
            None => transcript.tag(0),
            Some(BlobRetirement::AbandonInert) => transcript.tag(1),
            Some(BlobRetirement::Operation { owner, receipt }) => {
                transcript.tag(2);
                transcript.retained_id(owner)?;
                transcript.retained_reference(receipt)?;
            }
            Some(BlobRetirement::DurableStore { receipt }) => {
                transcript.tag(3);
                transcript.retained_reference(receipt)?;
            }
        }
        transcript.number(pins.len())?;
        for (id, pin) in pins {
            transcript.integer(*id);
            let PinRecord {
                owner,
                schema,
                state,
                receipt,
            } = pin;
            transcript.retained_id(owner)?;
            transcript.retained_reference(schema)?;
            transcript.tag(match state {
                PinState::Held => 0,
                PinState::Quarantined => 1,
                PinState::Settled => 2,
            });
            match receipt {
                None => transcript.tag(0),
                Some(receipt) => {
                    transcript.tag(1);
                    transcript.retained_reference(receipt)?;
                }
            }
        }
        transcript.tag(u8::from(*charged));
    }
    Ok(transcript.finish())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Transcript>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 8]>()
        + size_of::<[u8; 1]>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Ref<'static, ReceiverState>>()
        + size_of::<&BlobReceiver>()
        + size_of::<&ReceiverState>()
        + size_of::<(&String, &String, &String)>()
        + size_of::<(&crucible_node_format::HashRef, &U64, &String)>()
        + size_of::<(
            &ContentRef,
            &usize,
            &Vec<u8>,
            &BTreeMap<usize, usize>,
            &bool,
            &bool,
            &bool,
            &Option<BlobRetirement>,
            &BTreeMap<u64, PinRecord>,
            &bool,
        )>()
        + size_of::<(&Id, &ContentRef, &PinState, &Option<ContentRef>)>()
        + size_of::<(&usize, &usize, &usize, &usize, &usize, &usize, &usize)>()
}
