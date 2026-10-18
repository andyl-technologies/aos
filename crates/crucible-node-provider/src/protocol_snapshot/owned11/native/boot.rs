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
        read_data(input, ledger, build, false, false)
    }
}

struct HistoricalStartupBootData(HistoricalNativeBootData);

impl HistoricalType for HistoricalStartupBootData {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_data(input, ledger, build, true, false).map(|data| data.map(Self))
    }
}

struct HistoricalInvocationBootData(HistoricalNativeBootData);

impl HistoricalType for HistoricalInvocationBootData {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_data(input, ledger, build, true, true).map(|data| data.map(Self))
    }
}

fn read_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    startup: bool,
    invocation: bool,
) -> Result<Option<HistoricalNativeBootData>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if invocation {
            "source-private.native-ack-boot-data/15"
        } else if startup {
            "source-private.native-ack-boot-data/14"
        } else {
            "source-private.native-ack-boot-data/11"
        },
    )?;
    let raw_schema = next(&mut fields)?;
    if plain_string(raw_schema)?
        != if invocation {
            "source-owned.packet-canonical-ack-private-boot/7"
        } else if startup {
            "source-owned.packet-canonical-ack-private-boot/6"
        } else {
            "source-owned.packet-canonical-ack-private-boot/5"
        }
    {
        return Err(invalid());
    }
    let schema = ledger.read::<String>(raw_schema, build)?;
    let private_key = bank(next(&mut fields)?, ledger, build, Some(32))?;
    let birth_id = bank(next(&mut fields)?, ledger, build, Some(32))?;
    let raw_source = next(&mut fields)?;
    if invocation {
        super::invocation::authenticate_source_syntax(raw_source)?;
    }
    let source_birth = ledger.read::<Value>(raw_source, build)?;
    let expected_host_registration = ledger.read::<Value>(next(&mut fields)?, build)?;
    let private_launch = ledger.read::<Id>(next(&mut fields)?, build)?;
    let host_executable = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeBootData {
        schema: schema.ok_or_else(invalid)?,
        private_key: Bytes::new(private_key.ok_or_else(invalid)?),
        birth_id: Bytes::new(birth_id.ok_or_else(invalid)?),
        source_birth: source_birth.ok_or_else(invalid)?,
        expected_host_registration: expected_host_registration.ok_or_else(invalid)?,
        private_launch: private_launch.ok_or_else(invalid)?,
        host_executable: host_executable.ok_or_else(invalid)?,
    }))
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
    /// Retains the distinct complete boot6 startup owner, never a live issuer.
    pub startup: Option<super::startup::HistoricalNativeStartupBoot>,
    /// Retains only the explicit genuine-original phase in invocation class15.
    /// Historical data never creates a private issuer, target or live gate.
    pub invocation: Option<super::invocation::HistoricalNativeInvocationPhase>,
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
    let startup_class = ledger.requires_startup_class()?;
    let invocation_class = ledger.requires_invocation_class()?;
    let (input, startup_input, phase_input) = if startup_class {
        let mut wrapper = Fields::array(input)?;
        tag(
            &mut wrapper,
            if invocation_class {
                "source-private.native-ack-boot-invocation/15"
            } else {
                "source-private.native-ack-boot-startup/14"
            },
        )?;
        let base = next(&mut wrapper)?;
        let startup = next(&mut wrapper)?;
        let phase = if invocation_class {
            Some(next(&mut wrapper)?)
        } else {
            None
        };
        wrapper.finish()?;
        (base, Some(startup), phase)
    } else {
        (input, None, None)
    };
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if invocation_class {
            "source-private.native-ack-boot/15"
        } else if startup_class {
            "source-private.native-ack-boot/14"
        } else {
            "source-private.native-ack-boot/11"
        },
    )?;
    let creator = ledger.ledger.read::<u32>(next(&mut fields)?, build)?;
    tag(&mut fields, "same-original-thread")?;
    let raw_data = next(&mut fields)?;
    let data = if invocation_class {
        ledger
            .ledger
            .read::<HistoricalInvocationBootData>(raw_data, build)?
            .map(|value| value.0)
    } else if startup_class {
        ledger
            .ledger
            .read::<HistoricalStartupBootData>(raw_data, build)?
            .map(|value| value.0)
    } else {
        ledger
            .ledger
            .read::<HistoricalNativeBootData>(raw_data, build)?
    };
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
    let startup = if let Some(input) = startup_input {
        if invocation_class {
            super::startup::read_invocation_boot(input, ledger.ledger, build)?
        } else {
            super::startup::read_boot(input, ledger.ledger, build)?
        }
    } else {
        None
    };
    let invocation = phase_input
        .map(|input| {
            super::invocation::read_phase(input, ledger.ledger.limits.maximum_input_bytes, build)
        })
        .transpose()?
        .flatten();
    if !build {
        return Ok(None);
    }
    let owner = HistoricalNativeBoot {
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
        startup,
        invocation,
    };
    // New invocation semantic correspondence runs only after the outer
    // reconstruction has retained the complete owning result. Its phase and
    // Source syntax were checked before allocation; a later full target/hash
    // mismatch must leave this owner in that caller's output slot.
    if owner.invocation.is_none()
        && let Some(startup) = &owner.startup
    {
        startup.authenticate(&owner)?;
    }
    Ok(Some(owner))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeBootData,
    schema,
    private_key,
    birth_id,
    source_birth,
    expected_host_registration,
    private_launch,
    host_executable
);
super::super::retained_storage::fields!(
    HistoricalNativeBoot,
    creator,
    data,
    launch_body,
    policy,
    source_body,
    host_body,
    normalized,
    banks,
    context,
    proof,
    original,
    startup,
    invocation
);

pub(crate) mod current17;

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
        + field::<Value>()
        + field::<Value>()
        + field::<Id>()
        + field::<ContentRef>()
        + field::<u32>()
        + field::<HistoricalInvocationBootData>()
        + field::<HistoricalStartupBootData>()
        + field::<HistoricalNativeBootData>()
        + field::<Value>()
        + field::<PacketCanonicalAckAdmissionContext>()
        + field::<PacketCanonicalAckAdmissionProof>()
        + field::<Envelope>()
        + header::<HistoricalNativeBootData>()
        + header::<HistoricalStartupBootData>()
        + header::<HistoricalInvocationBootData>()
        + header::<HistoricalNativeBoot>()
        + header::<super::startup::HistoricalNativeStartupBoot>()
        + header::<super::invocation::HistoricalNativeInvocationPhase>()
        + header::<[u8; 32]>()
        + header::<std::rc::Rc<super::policy::HistoricalNativePolicy>>()
        + header::<Vec<u8>>()
        + header::<Vec<u8>>()
        + header::<Vec<u8>>()
        + size_of::<[u8; 32]>()
        + size_of::<[Option<serde_json::Value>; 5]>()
        + size_of::<[Option<Vec<u8>>; 5]>()
}
