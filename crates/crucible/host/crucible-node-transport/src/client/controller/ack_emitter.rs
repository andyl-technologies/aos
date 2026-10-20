//! Retains the original SDK success-or-no-send Blob acknowledgement mechanism.
//!
//! The private lease identifies one actual controller, connection, registrar and
//! installed codec. It is never serialized or transferred to the native process.
//! Its numeric bound covers complete canonical acknowledgement frames; a source
//! factory must separately issue the kernel/executable/Hello-bound peer marker
//! and the native reader must enforce its selected raw header limit before body
//! reads. A bound or this host lease alone supplies no native publication right.

use super::*;
use crate::{
    connection::Native5CodecOwner, handshake::RegistrationRead,
    protocol_snapshot::ProtocolCaptureOwner,
};
use std::rc::Rc;

/// Retains this controller's actual immutable canonical Blob acknowledgement path.
///
/// The lease has no decoder, clone or portable representation. The source must
/// reauthenticate it against the same owning controller before dispatch. It
/// promises only the installed SDK success-or-no-send emitter, not peer
/// behavior, source Capture, native read limits or restoration authority.
pub struct OriginalCanonicalBlobAckEmitter {
    controller: Rc<ProtocolCaptureOwner>,
    connection: Rc<ProtocolCaptureOwner>,
    registration: RegistrationRead,
    codec: Rc<Native5CodecOwner>,
}

impl OriginalCanonicalBlobAckEmitter {
    /// Reports actual retained emitter association fields without granting rights.
    ///
    /// # Errors
    /// Refuses foreign actors, a revoked registrar or traversal overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            controller,
            connection,
            registration,
            codec,
        } = self;
        controller.ensure_current()?;
        connection.ensure_current()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.shared_value(controller.as_ref())?;
        observer.shared_value(connection.as_ref())?;
        registration.observe_retained_metadata(&mut observer)?;
        observer.shared_value(codec.as_ref())?;
        codec.observe_retained_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    /// Rechecks the original actor, registrar and actual immutable writer owner.
    ///
    /// # Errors
    /// Refuses another original process/thread or controller, replaced connection
    /// or codec, revoked registrar, lost selection or a mutable loss callback.
    pub fn authenticate_original(&self, controller: &CnpController) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner) {
            return Err(ProviderError::Correlation(
                "canonical ACK original controller changed",
            ));
        }
        controller.authenticate_native5_source_codec()?;
        if controller.original_native5_ack_emitter_selection()?
            != Some(crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection::CanonicalSdkBlob5) {
            return Err(ProviderError::Correlation("canonical ACK original selection absent"));
        }
        self.registration.ensure_current()?;
        controller.session.authenticate_original_ack_emitter(
            &self.connection,
            &self.registration,
            &self.codec,
        )
    }

    /// Returns the complete canonical framed-byte ceiling after original checks.
    ///
    /// Four header bytes are included. The source must admit and enforce this
    /// bound through an authentic native peer association; it cannot replace the
    /// generic negotiated raw-frame ceiling with this scalar alone.
    ///
    /// # Errors
    /// Refuses changed original ownership/registration/codec or sizing overflow.
    pub fn maximum_framed_response_bytes(
        &self,
        controller: &CnpController,
    ) -> Result<usize, ProviderError> {
        self.authenticate_original(controller)?;
        maximum_canonical_ack_framed_bytes()
    }
}

impl CnpController {
    /// Retains the same installed canonical success-or-no-send ACK mechanism.
    ///
    /// Issuance clones only existing opaque owner, codec and registrar handles.
    /// The source separately charges this lease's inline fields/control blocks;
    /// it receives no native bound, source ticket or permission from a DTO.
    ///
    /// # Errors
    /// Refuses an absent selected codec, wrong actor, revoked original
    /// registration, replaced writer, mutable callback or fenced controller.
    pub fn retain_original_canonical_blob_ack_emitter(
        &self,
    ) -> Result<OriginalCanonicalBlobAckEmitter, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_native5_ack_emitter_selection()?
            != Some(crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection::CanonicalSdkBlob5) {
            return Err(ProviderError::Correlation("canonical ACK selected mechanism absent"));
        }
        let (connection, registration, codec) = self.session.retain_original_ack_emitter()?;
        let lease = OriginalCanonicalBlobAckEmitter {
            controller: self.protocol_owner.clone(),
            connection,
            registration,
            codec,
        };
        lease.authenticate_original(self)?;
        Ok(lease)
    }
}

const MAXIMUM_ID: &str = concat!(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
const MAXIMUM_MEDIA: &str = concat!(
    "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"",
    "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"",
    "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"",
    "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"",
);
const MAXIMUM_DIGEST: &str = concat!(
    "ffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffff"
);

#[derive(Serialize)]
struct AckEnvelope<T: Serialize> {
    protocol: &'static str,
    message: MessageKind,
    session_id: &'static str,
    incarnation_id: &'static str,
    node_id: &'static str,
    execution_owner_id: &'static str,
    capture_owner_id: &'static str,
    request_id: &'static str,
    operation_id: &'static str,
    sequence: U64,
    method: Method,
    body: AckBody<T>,
    extensions: Extensions,
}

#[derive(Serialize)]
struct AckBody<T: Serialize> {
    status: &'static str,
    operation_state: OperationState,
    result: T,
    extensions: Extensions,
}

#[derive(Serialize)]
struct BeginAck {
    transfer_id: &'static str,
    next_offset: U64,
    maximum_chunk_bytes: U64,
}

#[derive(Serialize)]
struct ChunkAck {
    transfer_id: &'static str,
    next_offset: U64,
}

#[derive(Serialize)]
struct FinishAck {
    transfer_id: &'static str,
    content: BorrowedContent,
}

#[derive(Serialize)]
struct BorrowedContent {
    hash: BorrowedHash,
    length: U64,
    media_type: &'static str,
}

#[derive(Serialize)]
struct BorrowedHash {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

fn framed_size(method: Method, result: impl Serialize) -> Result<usize, ProviderError> {
    // Present maximum-length nullable IDs conservatively cover every accepted
    // scope. It deliberately overcounts mutually exclusive execution/capture
    // owner fields. ID grammar needs no JSON escaping; printable media doubles
    // at most. All count scalars are string-encoded U64 maxima, never floats.
    let envelope = AckEnvelope {
        protocol: "CNP/1",
        message: MessageKind::Response,
        session_id: MAXIMUM_ID,
        incarnation_id: MAXIMUM_ID,
        node_id: MAXIMUM_ID,
        execution_owner_id: MAXIMUM_ID,
        capture_owner_id: MAXIMUM_ID,
        request_id: MAXIMUM_ID,
        operation_id: MAXIMUM_ID,
        sequence: U64::new(u64::MAX),
        method,
        body: AckBody {
            status: "completed",
            operation_state: OperationState::Completed,
            result,
            extensions: Extensions::new(),
        },
        extensions: Extensions::new(),
    };
    // The same numeric-aware canonical sizing machinery used by prepared sends
    // owns escaping and numeric policy; this is no second semantic encoder.
    crate::connection::serialized_credit(&envelope, 65_536)?
        .checked_add(4)
        .ok_or(ProviderError::ResourceExhausted(
            "canonical ACK framed size overflow",
        ))
}

pub(crate) fn maximum_canonical_ack_framed_bytes() -> Result<usize, ProviderError> {
    let begin = framed_size(
        Method::BlobBegin,
        BeginAck {
            transfer_id: MAXIMUM_ID,
            next_offset: U64::new(u64::MAX),
            maximum_chunk_bytes: U64::new(1_048_576),
        },
    )?;
    let chunk = framed_size(
        Method::BlobChunk,
        ChunkAck {
            transfer_id: MAXIMUM_ID,
            next_offset: U64::new(u64::MAX),
        },
    )?;
    let finish = framed_size(
        Method::BlobFinish,
        FinishAck {
            transfer_id: MAXIMUM_ID,
            content: BorrowedContent {
                hash: BorrowedHash {
                    algorithm: "blake3-256",
                    domain: "cnp.blob.v1",
                    digest: MAXIMUM_DIGEST,
                },
                length: U64::new(u64::MAX),
                media_type: MAXIMUM_MEDIA,
            },
        },
    )?;
    Ok(begin.max(chunk).max(finish))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test assertion panics are the control verdict.
mod bound_tests {
    use super::*;
    use crate::bodies::{BlobBeginResult, BlobChunkResult, BlobFinishResult, ResponseShape};
    use crucible_node_format::{ContentRef, HashRef, Validate};

    fn object(value: impl Serialize) -> serde_json::Map<String, Value> {
        serde_json::to_value(value)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    fn actual_ack(method: Method, result: impl Serialize, captured: bool) -> Envelope {
        let identifier = Id::new(MAXIMUM_ID).unwrap();
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Response,
            session_id: Nullable(Some(identifier.clone())),
            incarnation_id: Nullable(Some(identifier.clone())),
            node_id: Nullable(Some(identifier.clone())),
            execution_owner_id: Nullable((!captured).then_some(identifier.clone())),
            capture_owner_id: Nullable(captured.then_some(identifier.clone())),
            request_id: Nullable(Some(identifier.clone())),
            operation_id: Nullable(Some(identifier)),
            sequence: U64::new(u64::MAX),
            method,
            body: object(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: object(result),
                extensions: Extensions::new(),
            }),
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn canonical_ack_bound_covers_actual_full_typed_envelopes_and_escaping() {
        assert_eq!(MAXIMUM_ID.len(), 128);
        assert_eq!(MAXIMUM_MEDIA.len(), 128);
        let bound = maximum_canonical_ack_framed_bytes().unwrap();
        assert!(bound < 4096);

        for captured in [false, true] {
            for media in [MAXIMUM_MEDIA.to_owned(), "\\".repeat(128), "a".repeat(128)] {
                let content = ContentRef {
                    hash: HashRef {
                        algorithm: "blake3-256".into(),
                        domain: "cnp.blob.v1".into(),
                        digest: MAXIMUM_DIGEST.into(),
                    },
                    length: U64::new(u64::MAX),
                    media_type: media,
                };
                content.validate().unwrap();
                let frames = [
                    actual_ack(
                        Method::BlobBegin,
                        BlobBeginResult {
                            transfer_id: Id::new(MAXIMUM_ID).unwrap(),
                            next_offset: U64::new(u64::MAX),
                            maximum_chunk_bytes: U64::new(1_048_576),
                        },
                        captured,
                    ),
                    actual_ack(
                        Method::BlobChunk,
                        BlobChunkResult {
                            transfer_id: Id::new(MAXIMUM_ID).unwrap(),
                            next_offset: U64::new(u64::MAX),
                        },
                        captured,
                    ),
                    actual_ack(
                        Method::BlobFinish,
                        BlobFinishResult {
                            transfer_id: Id::new(MAXIMUM_ID).unwrap(),
                            content,
                        },
                        captured,
                    ),
                ];
                for frame in frames {
                    let encoded =
                        canonical::canonical_json(&serde_json::to_value(&frame).unwrap()).unwrap();
                    assert_eq!(
                        crate::connection::serialized_credit(&frame, 65_536).unwrap(),
                        encoded.len()
                    );
                    assert!(encoded.len() + 4 <= bound);
                    let transfer_id = Id::new(MAXIMUM_ID).unwrap();
                    let request = match frame.method {
                        Method::BlobBegin => {
                            crate::bodies::RequestBody::BlobBegin(crate::bodies::BlobBeginRequest {
                                transfer_id,
                                content: canonical::content_ref(
                                    b"bounded",
                                    "application/octet-stream",
                                )
                                .unwrap(),
                                extensions: Extensions::new(),
                            })
                        }
                        Method::BlobChunk => {
                            crate::bodies::RequestBody::BlobChunk(crate::bodies::BlobChunkRequest {
                                transfer_id,
                                offset: U64::new(u64::MAX - 1),
                                bytes: crucible_node_format::Bytes::new(vec![1]),
                                extensions: Extensions::new(),
                            })
                        }
                        Method::BlobFinish => crate::bodies::RequestBody::BlobFinish(
                            crate::bodies::BlobFinishRequest {
                                transfer_id,
                                extensions: Extensions::new(),
                            },
                        ),
                        _ => panic!("fixture contains only closed Blob methods"),
                    };
                    // Begin always starts at zero. The U64 maximum above is a
                    // conservative sizing proposal, not a valid resumed Begin.
                    let mut correlated = frame.clone();
                    if frame.method == Method::BlobBegin {
                        correlated.body["result"]["next_offset"] = Value::String("0".into());
                    }
                    crate::bodies::decode_response(&request, &correlated.body).unwrap();
                    let canonical =
                        canonical::canonical_json(&serde_json::to_value(&correlated).unwrap())
                            .unwrap();
                    assert!(canonical.len() + 4 <= bound);
                }
            }
        }
        eprintln!("canonical ACK maximum framed bytes: {bound}");
    }
}
