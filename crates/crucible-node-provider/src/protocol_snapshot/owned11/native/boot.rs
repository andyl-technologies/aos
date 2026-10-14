//! Reconstructs successful native boot history without creating a key issuer.
//!
//! Historical private bytes remain inert archive data. No decoded value creates
//! an original process, thread, physical cut, socket, registrar or live marker.

use super::super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use super::{bytes::bank, policy::HistoricalNativePolicy, shared::NativeLedger};
use crate::envelope::Envelope;
use crate::{
    ProviderError,
    reference_packet::service::{
        PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
    },
};
use crucible_node_contract::{Bytes, ContentRef, Id};
use serde_json::Value;
use std::rc::Rc;

/// Retains the complete historical private boot declaration as data.
pub struct HistoricalNativeBootData {
    /// Retains the original closed bootstrap schema string and its capacity.
    pub schema: String,
    /// Retains the original private key bytes; these cannot activate a fresh peer.
    pub private_key: Bytes,
    /// Retains the original birth identity bytes and their capacity.
    pub birth_id: Bytes,
    /// Retains the complete source birth declaration.
    pub source_birth: Value,
    /// Retains the complete expected host registration declaration.
    pub expected_host_registration: Value,
    /// Retains the original private launch identity.
    pub private_launch: Id,
    /// Retains the complete original host executable reference.
    pub host_executable: ContentRef,
}

impl HistoricalType for HistoricalNativeBootData {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.native-ack-boot-data/11")?;
        let raw_schema = next(&mut fields)?;
        if plain_string(raw_schema)? != "source-owned.packet-canonical-ack-private-boot/5" {
            return Err(invalid());
        }
        let schema = ledger.read::<String>(raw_schema, build)?;
        let private_key = bank(next(&mut fields)?, ledger, build, Some(32))?;
        let birth_id = bank(next(&mut fields)?, ledger, build, Some(32))?;
        let source_birth = ledger.read::<Value>(next(&mut fields)?, build)?;
        let expected_host_registration = ledger.read::<Value>(next(&mut fields)?, build)?;
        let private_launch = ledger.read::<Id>(next(&mut fields)?, build)?;
        let host_executable = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            private_key: Bytes::new(private_key.ok_or_else(invalid)?),
            birth_id: Bytes::new(birth_id.ok_or_else(invalid)?),
            source_birth: source_birth.ok_or_else(invalid)?,
            expected_host_registration: expected_host_registration.ok_or_else(invalid)?,
            private_launch: private_launch.ok_or_else(invalid)?,
            host_executable: host_executable.ok_or_else(invalid)?,
        }))
    }
}

/// Retains every successful native admission boot field as inert history.
pub struct HistoricalNativeBoot {
    /// Records the historical creator PID without enrolling that process.
    pub creator: u32,
    /// Retains the full private boot declaration and its original capacities.
    pub data: HistoricalNativeBootData,
    /// Retains the exact canonical launch body and original Vec capacity.
    pub launch_body: Vec<u8>,
    /// Shares the reconstructed historical policy within its recorded group.
    pub policy: Rc<HistoricalNativePolicy>,
    /// Retains the exact normalized source body bytes.
    pub source_body: Vec<u8>,
    /// Retains the exact normalized host body bytes.
    pub host_body: Vec<u8>,
    /// Retains all five complete normalized declarations.
    pub normalized: [Value; 5],
    /// Retains all five canonical declaration banks with spare capacities.
    pub banks: [Vec<u8>; 5],
    /// Retains the complete original MAC context without authenticating a peer.
    pub context: PacketCanonicalAckAdmissionContext,
    /// Retains the original keyed proof without reactivating it.
    pub proof: PacketCanonicalAckAdmissionProof,
    /// Retains the exact assigned Admit including its proof and sequence.
    pub original: Envelope,
}

fn present<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    let value = next(fields)?;
    if value == b"null" {
        return Err(invalid());
    }
    Ok(value)
}

fn five<T>(values: [Option<T>; 5]) -> Result<[T; 5], ProviderError> {
    let [a, b, c, d, e] = values;
    Ok([
        a.ok_or_else(invalid)?,
        b.ok_or_else(invalid)?,
        c.ok_or_else(invalid)?,
        d.ok_or_else(invalid)?,
        e.ok_or_else(invalid)?,
    ])
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeBoot>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "source-private.native-ack-boot/11")?;
    let creator = ledger.ledger.read::<u32>(next(&mut fields)?, build)?;
    tag(&mut fields, "same-original-thread")?;
    let data = ledger
        .ledger
        .read::<HistoricalNativeBootData>(next(&mut fields)?, build)?;
    let launch_body = bank(next(&mut fields)?, ledger.ledger, build, None)?;
    let policy = ledger.policy(next(&mut fields)?, build)?;
    let source_body = bank(next(&mut fields)?, ledger.ledger, build, None)?;
    let host_body = bank(next(&mut fields)?, ledger.ledger, build, None)?;

    let mut normalized_fields = Fields::array(next(&mut fields)?)?;
    let mut normalized = std::array::from_fn(|_| None);
    for value in &mut normalized {
        *value = ledger
            .ledger
            .read::<Value>(present(&mut normalized_fields)?, build)?;
    }
    normalized_fields.finish()?;
    let mut bank_fields = Fields::array(next(&mut fields)?)?;
    let mut banks = std::array::from_fn(|_| None);
    for value in &mut banks {
        *value = bank(next(&mut bank_fields)?, ledger.ledger, build, None)?;
    }
    bank_fields.finish()?;

    let context = ledger
        .ledger
        .read::<PacketCanonicalAckAdmissionContext>(present(&mut fields)?, build)?;
    let proof = ledger
        .ledger
        .read::<PacketCanonicalAckAdmissionProof>(present(&mut fields)?, build)?;
    let original = ledger
        .ledger
        .read::<Envelope>(present(&mut fields)?, build)?;
    for _ in 0..3 {
        if next(&mut fields)? != b"true" {
            return Err(invalid());
        }
    }
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeBoot {
        creator: creator.ok_or_else(invalid)?,
        data: data.ok_or_else(invalid)?,
        launch_body: launch_body.ok_or_else(invalid)?,
        policy: policy.ok_or_else(invalid)?,
        source_body: source_body.ok_or_else(invalid)?,
        host_body: host_body.ok_or_else(invalid)?,
        normalized: five(normalized)?,
        banks: five(banks)?,
        context: context.ok_or_else(invalid)?,
        proof: proof.ok_or_else(invalid)?,
        original: original.ok_or_else(invalid)?,
    }))
}
