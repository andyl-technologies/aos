//! Explicit native channel editions fixed by supervised preparation.
//!
//! The edition is pinned before any request is emitted. Packet contents never
//! negotiate or upgrade a live endpoint. Edition selection establishes codec
//! compatibility only; it does not qualify a native capability or owner cut.

use super::codec::{Cursor, MAGIC, integer};
use super::{
    NODE_CONTROL_HEADER_BYTES, NODE_CONTROL_MAX_BODY_BYTES, NativeCommandError, NativeFrame,
};
use crucible_node_contract::U64;

/// Selects one explicitly prepared native process-protocol edition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeControlEdition {
    /// Selects separately pinned original prefix acknowledgements and continuation.
    PrefixEffect,
    /// Selects independently pinned source-native finite effect command custody.
    FiniteEffect,
    /// Preserves original command, stop, acknowledgement and timer packet bytes.
    Original,
    /// Selects the opt-in protocol for retained writer and complete custody records.
    OwnedCustody,
    /// Selects raw source phase projection with a fresh original pinned mapping.
    PhaseProjection,
    /// Recovers original post-initialization observations with separate identities.
    PreparationSuccessor,
    /// Enrolls the original source-observed reader without modeled-source coverage.
    Administration,
    /// Selects construction-only original administrative effects, never compute.
    Construction,
    /// Pins complete source-root preparation before separately authorized native effects.
    ///
    /// Its bootstrap rejects legacy compute commands. Source enrollment, an owned
    /// input epoch and a finite original effect cut remain independent requirements.
    FixedMicrovm,
}

impl NativeControlEdition {
    /// Returns the exact portable header version selected before native launch.
    pub const fn version(self) -> u16 {
        match self {
            Self::PrefixEffect => 9,
            Self::FiniteEffect => 8,
            Self::Original => 1,
            Self::OwnedCustody => 2,
            Self::PhaseProjection => 3,
            Self::PreparationSuccessor => 4,
            Self::Administration => 5,
            Self::Construction => 6,
            Self::FixedMicrovm => 7,
        }
    }
}

/// Encodes a native record for the already pinned endpoint edition.
///
/// Original record bodies and kinds remain identical between editions. New
/// custody records require their separately verified native capability; the
/// edition itself grants neither execution nor source coverage.
///
/// # Errors
/// Rejects malformed records or a body exceeding the finite wire allowance.
pub fn encode_frame_for_edition(
    edition: NativeControlEdition,
    frame: &NativeFrame,
) -> Result<Vec<u8>, NativeCommandError> {
    if edition == NativeControlEdition::PrefixEffect {
        return super::prefix_frames::encode(frame);
    }
    if matches!(
        frame,
        NativeFrame::PreparePrefix(_)
            | NativeFrame::AcknowledgePrefix(_)
            | NativeFrame::PrefixAcknowledged(_)
            | NativeFrame::ContinuePrefix(_)
            | NativeFrame::PrefixProgress(_)
    ) {
        return Err(NativeCommandError::UnsupportedVersion(9));
    }
    if edition == NativeControlEdition::FiniteEffect {
        return super::effect_frames::encode(frame);
    }
    if matches!(
        frame,
        NativeFrame::PrepareEffect(_)
            | NativeFrame::EffectCompute(_)
            | NativeFrame::EffectProgress(_)
    ) {
        return Err(NativeCommandError::UnsupportedVersion(8));
    }
    if edition == NativeControlEdition::FixedMicrovm {
        return super::fixed_microvm_frames::encode(frame);
    }
    if matches!(frame, NativeFrame::PrepareFixedMicrovm(_)) {
        return Err(NativeCommandError::UnsupportedVersion(7));
    }
    if edition == NativeControlEdition::Construction {
        if !construction_frame(frame) {
            return Err(NativeCommandError::Invalid(
                "construction profile refuses compute",
            ));
        }
        let mut bytes = encode_frame_for_edition(NativeControlEdition::Administration, frame)?;
        bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
        return Ok(bytes);
    }
    if edition == NativeControlEdition::Administration {
        let (kind, body) = match frame {
            NativeFrame::PrepareAdministration(preparation) => (26u16, preparation.encode()?),
            NativeFrame::QueryAdministration {
                prepared_scope_hash,
                administration_commitment,
            } => {
                if *prepared_scope_hash == [0; 32] || *administration_commitment == [0; 32] {
                    return Err(NativeCommandError::Invalid(
                        "administrative query identity is empty",
                    ));
                }
                let mut body = prepared_scope_hash.to_vec();
                body.extend_from_slice(administration_commitment);
                (27u16, body)
            }
            NativeFrame::AdministrationFacts(facts) => (28u16, facts.encode()?.to_vec()),
            _ => {
                let mut bytes =
                    encode_frame_for_edition(NativeControlEdition::PreparationSuccessor, frame)?;
                bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
                return Ok(bytes);
            }
        };
        if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&edition.version().to_be_bytes());
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        return Ok(bytes);
    }
    if edition == NativeControlEdition::PreparationSuccessor {
        let (kind, body) = match frame {
            NativeFrame::QueryPreparationSuccessor(query) => (24u16, query.encode()?.to_vec()),
            NativeFrame::PreparationSuccessorChunk(chunk) => (25u16, chunk.encode()?),
            _ => {
                let mut bytes =
                    encode_frame_for_edition(NativeControlEdition::PhaseProjection, frame)?;
                bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
                return Ok(bytes);
            }
        };
        if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&edition.version().to_be_bytes());
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        return Ok(bytes);
    }
    if edition == NativeControlEdition::PhaseProjection {
        let (kind, body) = match frame {
            NativeFrame::PreparePhase(preparation) => (21u16, preparation.encode()?),
            NativeFrame::QueryPhaseTimers(query) => (22u16, query.encode()?.to_vec()),
            NativeFrame::PhaseTimerChunk(chunk) => (23u16, chunk.encode()?),
            _ => {
                // Prior bodies remain byte-identical; only the pinned header changes.
                let mut bytes =
                    encode_frame_for_edition(NativeControlEdition::OwnedCustody, frame)?;
                bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
                return Ok(bytes);
            }
        };
        if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&edition.version().to_be_bytes());
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        return Ok(bytes);
    }
    if edition == NativeControlEdition::OwnedCustody {
        let (kind, body) = match frame {
            NativeFrame::PrepareInitialization(preparation) => (14, preparation.encode()?),
            NativeFrame::QueryInitialization(query) => (15, query.encode()?.to_vec()),
            NativeFrame::InitializationCut(cut) => (16, cut.encode()?),
            NativeFrame::Initialize(command) => (17, command.encode()?.to_vec()),
            NativeFrame::InitializationStopped(receipt) => (18, receipt.encode()?.to_vec()),
            NativeFrame::AcknowledgeInitialization(ack) => (19, ack.encode()?.to_vec()),
            NativeFrame::InitializationAcknowledged(ack) => (20, ack.encode()?.to_vec()),
            NativeFrame::SourceFault(facts) => (13u16, facts.encode()?.to_vec()),
            NativeFrame::QueryWriters(query) => {
                query.validate()?;
                let mut body = query.prepared_scope_hash.to_vec();
                integer(&mut body, query.sequence.get());
                integer(&mut body, query.offset.get());
                (11u16, body)
            }
            NativeFrame::WriterChunk(chunk) => {
                chunk.validate()?;
                let mut body = chunk.prepared_scope_hash.to_vec();
                integer(&mut body, chunk.sequence.get());
                body.extend_from_slice(&chunk.object_digest);
                integer(&mut body, chunk.total_bytes.get());
                integer(&mut body, chunk.offset.get());
                body.extend_from_slice(&chunk.bytes);
                (12u16, body)
            }
            _ => {
                let mut bytes = super::encode_frame(frame)?;
                bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
                return Ok(bytes);
            }
        };
        if body.len() > NODE_CONTROL_MAX_BODY_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(NODE_CONTROL_HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&edition.version().to_be_bytes());
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        return Ok(bytes);
    }
    let mut bytes = super::encode_frame(frame)?;
    bytes[8..10].copy_from_slice(&edition.version().to_be_bytes());
    Ok(bytes)
}

/// Decodes a record only for its immutable supervised endpoint edition.
///
/// A peer cannot upgrade or downgrade the receiver by sending another version.
/// This function bounds the datagram before copying the edition-two body
/// into the unchanged edition-one record decoder.
///
/// # Errors
/// Rejects oversized, truncated, foreign-edition, malformed and trailing bytes.
pub fn decode_frame_for_edition(
    edition: NativeControlEdition,
    bytes: &[u8],
) -> Result<NativeFrame, NativeCommandError> {
    if bytes.len() > NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    if bytes.len() < NODE_CONTROL_HEADER_BYTES {
        return Err(NativeCommandError::Invalid("truncated native frame header"));
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != edition.version() {
        return Err(NativeCommandError::UnsupportedVersion(version));
    }
    if edition == NativeControlEdition::Original {
        return super::decode_frame(bytes);
    }
    if edition == NativeControlEdition::PrefixEffect {
        return super::prefix_frames::decode(bytes);
    }
    if edition == NativeControlEdition::FiniteEffect {
        return super::effect_frames::decode(bytes);
    }
    if edition == NativeControlEdition::FixedMicrovm {
        return super::fixed_microvm_frames::decode(bytes);
    }

    if edition == NativeControlEdition::Construction {
        let mut previous = bytes.to_vec();
        previous[8..10]
            .copy_from_slice(&NativeControlEdition::Administration.version().to_be_bytes());
        let frame = decode_frame_for_edition(NativeControlEdition::Administration, &previous)?;
        if !construction_frame(&frame) {
            return Err(NativeCommandError::Invalid(
                "construction profile refuses compute",
            ));
        }
        return Ok(frame);
    }
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC {
        return Err(NativeCommandError::Invalid("wrong native command magic"));
    }
    cursor.u16()?;
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if cursor.0.len() != length {
        return Err(NativeCommandError::Invalid("native frame length mismatch"));
    }
    if edition == NativeControlEdition::Administration {
        let frame = match kind {
            26 => NativeFrame::PrepareAdministration(Box::new(
                super::NativeAdministrativePreparation::decode(cursor.take(length)?)?,
            )),
            27 => {
                let prepared_scope_hash = cursor.array()?;
                let administration_commitment = cursor.array()?;
                if prepared_scope_hash == [0; 32] || administration_commitment == [0; 32] {
                    return Err(NativeCommandError::Invalid(
                        "administrative query identity is empty",
                    ));
                }
                NativeFrame::QueryAdministration {
                    prepared_scope_hash,
                    administration_commitment,
                }
            }
            28 => NativeFrame::AdministrationFacts(Box::new(
                super::NativeAdministrativeFacts::decode(cursor.take(length)?)?,
            )),
            _ => {
                let mut prior = bytes.to_vec();
                prior[8..10].copy_from_slice(
                    &NativeControlEdition::PreparationSuccessor
                        .version()
                        .to_be_bytes(),
                );
                return decode_frame_for_edition(
                    NativeControlEdition::PreparationSuccessor,
                    &prior,
                );
            }
        };
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Invalid(
                "trailing administration frame bytes",
            ));
        }
        return Ok(frame);
    }
    if edition == NativeControlEdition::PreparationSuccessor {
        return match kind {
            24 => Ok(NativeFrame::QueryPreparationSuccessor(
                super::NativePreparationSuccessorQuery::decode(cursor.take(length)?)?,
            )),
            25 => Ok(NativeFrame::PreparationSuccessorChunk(Box::new(
                super::NativePreparationSuccessorChunk::decode(cursor.take(length)?)?,
            ))),
            _ => {
                let mut prior = bytes.to_vec();
                prior[8..10].copy_from_slice(
                    &NativeControlEdition::PhaseProjection
                        .version()
                        .to_be_bytes(),
                );
                decode_frame_for_edition(NativeControlEdition::PhaseProjection, &prior)
            }
        };
    }
    if edition == NativeControlEdition::PhaseProjection {
        let frame = match kind {
            21 => NativeFrame::PreparePhase(Box::new(super::NativePhasePreparation::decode(
                cursor.take(cursor.0.len())?,
            )?)),
            22 => NativeFrame::QueryPhaseTimers(super::NativePhaseTimerQuery::decode(
                cursor.take(cursor.0.len())?,
            )?),
            23 => NativeFrame::PhaseTimerChunk(Box::new(super::NativePhaseTimerChunk::decode(
                cursor.take(cursor.0.len())?,
            )?)),
            _ => {
                let mut prior = bytes.to_vec();
                prior[8..10]
                    .copy_from_slice(&NativeControlEdition::OwnedCustody.version().to_be_bytes());
                return decode_frame_for_edition(NativeControlEdition::OwnedCustody, &prior);
            }
        };
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Invalid("trailing phase frame bytes"));
        }
        return Ok(frame);
    }
    let frame = match kind {
        26..=28 => return Err(NativeCommandError::UnsupportedVersion(5)),
        24..=25 => return Err(NativeCommandError::UnsupportedVersion(4)),
        21..=23 => return Err(NativeCommandError::UnsupportedVersion(3)),
        14 => NativeFrame::PrepareInitialization(Box::new(
            super::NativeInitializationPreparation::decode(cursor.take(cursor.0.len())?)?,
        )),
        15 => NativeFrame::QueryInitialization(super::NativeInitializationQuery::decode(
            cursor.take(cursor.0.len())?,
        )?),
        16 => NativeFrame::InitializationCut(Box::new(super::NativeInitializationCut::decode(
            cursor.take(cursor.0.len())?,
        )?)),
        17 => NativeFrame::Initialize(Box::new(super::NativeInitializationCommand::decode(
            cursor.take(cursor.0.len())?,
        )?)),
        18 => NativeFrame::InitializationStopped(Box::new(
            super::NativeInitializationReceipt::decode(cursor.take(cursor.0.len())?)?,
        )),
        19 => NativeFrame::AcknowledgeInitialization(
            super::NativeInitializationAcknowledgement::decode(cursor.take(cursor.0.len())?)?,
        ),
        20 => NativeFrame::InitializationAcknowledged(
            super::NativeInitializationAcknowledgement::decode(cursor.take(cursor.0.len())?)?,
        ),
        13 => NativeFrame::SourceFault(Box::new(super::SourceFaultFacts::decode(
            cursor.take(cursor.0.len())?,
        )?)),
        11 => {
            let query = super::NativeWriterQuery {
                prepared_scope_hash: cursor.array()?,
                sequence: U64::new(cursor.u64()?),
                offset: U64::new(cursor.u64()?),
            };
            query.validate()?;
            NativeFrame::QueryWriters(query)
        }
        12 => {
            let chunk = super::NativeWriterChunk {
                prepared_scope_hash: cursor.array()?,
                sequence: U64::new(cursor.u64()?),
                object_digest: cursor.array()?,
                total_bytes: U64::new(cursor.u64()?),
                offset: U64::new(cursor.u64()?),
                bytes: cursor.take(cursor.0.len())?.to_vec(),
            };
            chunk.validate()?;
            NativeFrame::WriterChunk(chunk)
        }
        _ => {
            let mut original = bytes.to_vec();
            original[8..10]
                .copy_from_slice(&NativeControlEdition::Original.version().to_be_bytes());
            return super::decode_frame(&original);
        }
    };
    if !cursor.0.is_empty() {
        return Err(NativeCommandError::Invalid("trailing writer frame bytes"));
    }
    Ok(frame)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These edition tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn writer_slices_require_pinned_edition_two_and_checked_original_offsets() {
        let chunk = NativeFrame::WriterChunk(super::super::NativeWriterChunk {
            prepared_scope_hash: [7; 32],
            sequence: U64::new(1),
            object_digest: [8; 32],
            total_bytes: U64::new(4),
            offset: U64::new(0),
            bytes: vec![1, 2, 3, 4],
        });
        assert!(super::super::encode_frame(&chunk).is_err());
        assert!(encode_frame_for_edition(NativeControlEdition::Original, &chunk).is_err());
        let bytes = encode_frame_for_edition(NativeControlEdition::OwnedCustody, &chunk).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::OwnedCustody, &bytes).unwrap(),
            chunk
        );
        assert!(super::super::decode_frame(&bytes).is_err());
        for length in 0..bytes.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::OwnedCustody, &bytes[..length])
                    .is_err()
            );
        }
        let mut foreign = bytes;
        foreign[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(super::super::decode_frame(&foreign).is_err());
    }

    #[test]
    fn opt_in_edition_preserves_original_body_and_refuses_peer_version_changes() {
        let frame = NativeFrame::QueryCpuPark([7; 32]);
        let original = super::super::encode_frame(&frame).unwrap();
        assert_eq!(
            encode_frame_for_edition(NativeControlEdition::Original, &frame).unwrap(),
            original
        );
        let custody = encode_frame_for_edition(NativeControlEdition::OwnedCustody, &frame).unwrap();
        assert_eq!(&custody[..8], &original[..8]);
        assert_eq!(&custody[10..], &original[10..]);
        assert_eq!(&custody[8..10], &[0, 2]);

        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::OwnedCustody, &custody).unwrap(),
            frame
        );
        assert!(decode_frame_for_edition(NativeControlEdition::Original, &custody).is_err());
        assert!(decode_frame_for_edition(NativeControlEdition::OwnedCustody, &original).is_err());
        assert!(super::super::decode_frame(&custody).is_err());
    }

    #[test]
    fn new_edition_rejects_oversize_and_every_truncated_frame() {
        let bytes = encode_frame_for_edition(
            NativeControlEdition::OwnedCustody,
            &NativeFrame::QueryCpuPark([7; 32]),
        )
        .unwrap();
        for length in 0..bytes.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::OwnedCustody, &bytes[..length])
                    .is_err()
            );
        }
        let oversized = vec![0; NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES + 1];
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::OwnedCustody, &oversized),
            Err(NativeCommandError::ResourceLimit)
        );
    }
}

#[cfg(test)]
#[path = "initialization_frame_tests.rs"]
mod initialization_tests;

#[cfg(test)]
#[path = "phase_frame_tests.rs"]
mod phase_frame_tests;

fn construction_frame(frame: &NativeFrame) -> bool {
    matches!(
        frame,
        NativeFrame::PrepareAdministration(_)
            | NativeFrame::QueryAdministration { .. }
            | NativeFrame::AdministrationFacts(_)
            | NativeFrame::QueryInitialization(_)
            | NativeFrame::InitializationCut(_)
            | NativeFrame::Initialize(_)
            | NativeFrame::InitializationStopped(_)
            | NativeFrame::AcknowledgeInitialization(_)
            | NativeFrame::InitializationAcknowledged(_)
            | NativeFrame::SourceFault(_)
            | NativeFrame::QueryPreparationSuccessor(_)
            | NativeFrame::PreparationSuccessorChunk(_)
    )
}
