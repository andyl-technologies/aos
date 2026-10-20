//! Explicit controller-nine prefix preparation, requests and immutable replies.
//!
//! Prior preparation bytes and command bodies remain unchanged ancestors. A
//! packet cannot select this edition for an already prepared older endpoint.
//! Offered ACK bytes are separate from the native consumed-ACK reply.
//!
//! ```text
//! Envelope: CNQEMU01 | edition:u16be=9 | kind:u16be | length:u32be | body
//! 33 PreparePrefix | 34 AcknowledgePrefix | 35 PrefixAcknowledged
//! 36 ContinuePrefix | 37 PrefixProgress
//! 38 QueryPrefixPreparation | 39 PrefixPreparationFacts
//! 40 AcknowledgePrefixPreparation | 41 PrefixPreparationAcknowledged
//! Kinds 38-41 require a separately installed initial preparation contract.
//! 31 EffectCompute and 32 first EffectProgress retain their original bodies.
//! ```

// SPDX-License-Identifier: Apache-2.0

use super::codec::{Cursor, MAGIC};
use super::{NativeCommandError, NativeControlEdition, NativeFrame};

pub(super) fn encode(frame: &NativeFrame) -> Result<Vec<u8>, NativeCommandError> {
    let (kind, body) = match frame {
        NativeFrame::QueryPrefixPreparation {
            scope,
            prefix_preparation,
        } => {
            if *scope == [0; 32] || *prefix_preparation == [0; 32] {
                return Err(NativeCommandError::Conflict);
            }
            let mut body = scope.to_vec();
            body.extend_from_slice(prefix_preparation);
            (38, body)
        }
        NativeFrame::PrefixPreparationFacts(facts) => (39, facts.canonical_bytes().to_vec()),
        NativeFrame::AcknowledgePrefixPreparation(ack) => (40, ack.encode()?.to_vec()),
        NativeFrame::PrefixPreparationAcknowledged(ack) => (41, ack.encode()?.to_vec()),
        NativeFrame::PreparePrefix(preparation) => (33u16, preparation.encode()?),
        NativeFrame::AcknowledgePrefix(acknowledgement) => (34, acknowledgement.encode()?),
        NativeFrame::PrefixAcknowledged(acknowledgement) => (35, acknowledgement.encode()?),
        NativeFrame::ContinuePrefix(continuation) => (36, continuation.encode()?),
        NativeFrame::PrefixProgress(progress) => (37, progress.encode()?),
        NativeFrame::PrepareEffect(_) => {
            return Err(NativeCommandError::Invalid(
                "prefix controller requires complete prefix preparation",
            ));
        }
        _ => {
            let mut bytes =
                super::encode_frame_for_edition(NativeControlEdition::FiniteEffect, frame)?;
            bytes[8..10].copy_from_slice(&9u16.to_be_bytes());
            return Ok(bytes);
        }
    };
    if body.len() > super::NODE_CONTROL_MAX_BODY_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(super::NODE_CONTROL_HEADER_BYTES + body.len())
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&9u16.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<NativeFrame, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.take(8)? != MAGIC || cursor.u16()? != 9 {
        return Err(NativeCommandError::UnsupportedVersion(9));
    }
    let kind = cursor.u16()?;
    let length = cursor.u32()? as usize;
    if length > super::NODE_CONTROL_MAX_BODY_BYTES || cursor.0.len() != length {
        return Err(NativeCommandError::ResourceLimit);
    }
    Ok(match kind {
        38 => {
            let scope = cursor.array()?;
            let prefix_preparation = cursor.array()?;
            if !cursor.0.is_empty() || scope == [0; 32] || prefix_preparation == [0; 32] {
                return Err(NativeCommandError::Conflict);
            }
            NativeFrame::QueryPrefixPreparation {
                scope,
                prefix_preparation,
            }
        }
        39 => NativeFrame::PrefixPreparationFacts(Box::new(
            super::NativePrefixPreparationFacts::decode(cursor.take(length)?)?,
        )),
        40 => NativeFrame::AcknowledgePrefixPreparation(
            super::NativePrefixPreparationAcknowledgement::decode_record(cursor.take(length)?)?,
        ),
        41 => NativeFrame::PrefixPreparationAcknowledged(
            super::NativePrefixPreparationAcknowledgement::decode_record(cursor.take(length)?)?,
        ),
        33 => NativeFrame::PreparePrefix(Box::new(super::NativePrefixPreparation::decode(
            cursor.take(length)?,
        )?)),
        34 => NativeFrame::AcknowledgePrefix(super::NativePrefixAcknowledgement::decode(
            cursor.take(length)?,
        )?),
        35 => NativeFrame::PrefixAcknowledged(super::NativePrefixAcknowledgement::decode(
            cursor.take(length)?,
        )?),
        36 => NativeFrame::ContinuePrefix(Box::new(super::NativePrefixContinuation::decode(
            cursor.take(length)?,
        )?)),
        37 => NativeFrame::PrefixProgress(Box::new(super::NativePrefixProgress::decode(
            cursor.take(length)?,
        )?)),
        30 => {
            return Err(NativeCommandError::Invalid(
                "prefix controller requires complete prefix preparation",
            ));
        }
        _ => {
            let mut previous = bytes.to_vec();
            previous[8..10].copy_from_slice(&8u16.to_be_bytes());
            return super::decode_frame_for_edition(NativeControlEdition::FiniteEffect, &previous);
        }
    })
}
