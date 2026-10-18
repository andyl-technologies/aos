//! Restores typed inert native context/proof digests with original Vec capacities.

use super::super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use super::bytes::bank;
use crate::{
    ProviderError,
    reference_packet::service::{
        PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
    },
};
use crucible_node_contract::Bytes;

fn text(
    fields: &mut Fields<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    expected: &str,
) -> Result<Option<String>, ProviderError> {
    let raw = next(fields)?;
    if plain_string(raw)? != expected {
        return Err(invalid());
    }
    ledger.read::<String>(raw, build)
}

fn digest(
    fields: &mut Fields<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Bytes>, ProviderError> {
    Ok(bank(next(fields)?, ledger, build, Some(32))?.map(Bytes::new))
}

impl HistoricalType for PacketCanonicalAckAdmissionContext {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.native-ack-context/11")?;
        let schema = text(
            &mut fields,
            ledger,
            build,
            "source-owned.packet-canonical-ack-admission-context/5",
        )?;
        let algorithm = text(&mut fields, ledger, build, "blake3-keyed-canonical/1")?;
        let source_birth = digest(&mut fields, ledger, build)?;
        let kernel_binding = digest(&mut fields, ledger, build)?;
        let policy_binding = digest(&mut fields, ledger, build)?;
        let host_registration = digest(&mut fields, ledger, build)?;
        let native_registration = digest(&mut fields, ledger, build)?;
        let hello_request = digest(&mut fields, ledger, build)?;
        let hello_response = digest(&mut fields, ledger, build)?;
        let assigned_admit = digest(&mut fields, ledger, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            source_birth: source_birth.ok_or_else(invalid)?,
            kernel_binding: kernel_binding.ok_or_else(invalid)?,
            policy_binding: policy_binding.ok_or_else(invalid)?,
            host_registration: host_registration.ok_or_else(invalid)?,
            native_registration: native_registration.ok_or_else(invalid)?,
            hello_request: hello_request.ok_or_else(invalid)?,
            hello_response: hello_response.ok_or_else(invalid)?,
            assigned_admit: assigned_admit.ok_or_else(invalid)?,
        }))
    }
}

impl HistoricalType for PacketCanonicalAckAdmissionProof {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.native-ack-proof/11")?;
        let schema = text(
            &mut fields,
            ledger,
            build,
            "source-owned.packet-canonical-ack-admission/5",
        )?;
        let algorithm = text(&mut fields, ledger, build, "blake3-keyed-canonical/1")?;
        let context_digest = digest(&mut fields, ledger, build)?;
        let mac = digest(&mut fields, ledger, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            mac: mac.ok_or_else(invalid)?,
        }))
    }
}

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<String>()
        + header::<String>()
        + header::<String>()
        + header::<String>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<Bytes>()
        + header::<PacketCanonicalAckAdmissionContext>()
        + header::<PacketCanonicalAckAdmissionProof>()
}
