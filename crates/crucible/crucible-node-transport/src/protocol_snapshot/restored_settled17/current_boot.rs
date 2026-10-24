//! Reads the complete actual native17 Boot root beneath one aggregate ledger.
//!
//! The full root is begun once. Its exact historical alias group is passed only
//! to concrete service-quote and reserve children that retain a real Boot
//! backedge. No decoded role creates a live Boot, private key issuer or token.

use super::{
    current_commit::CurrentCommit17,
    current_contracts::*,
    current_fixed::role17,
    current_inline::FixedArray32Field17,
    current_prepare::CurrentPrepare17,
    current_reserve::CurrentReserve17,
    current_shared::{CurrentShared17, read_reference17, shared_row17},
    current_stages::CurrentStages17,
    current_suffix::CurrentSuffix17,
};
use crate::{
    ProviderError,
    connection::settled17::HistoricalByteBank17,
    envelope::Envelope,
    protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid},
    reference_packet::{
        Native5Policy,
        service::{
            PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
            ack_emitter::NativeAckBoot, native_startup::PacketNativeStartupAllocation,
        },
    },
    retained_metadata::aliases::MetadataSharedKind,
};
use crucible_node_format::{Bytes, ContentRef, Id};
use serde_json::Value;
use std::mem::{align_of, size_of};

type CurrentBootFieldLoans17<'a> = (
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
    &'a [u8],
);

/// Retains the complete private declaration strictly as inert historical data.
pub(crate) struct CurrentBootData17 {
    pub(crate) schema: String,
    pub(crate) private_key: Bytes,
    pub(crate) birth_id: Bytes,
    pub(crate) source_birth: Value,
    pub(crate) expected_host_registration: Value,
    pub(crate) private_launch: Id,
    pub(crate) host_executable: ContentRef,
}
impl HistoricalType for CurrentBootData17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema = ledger.read::<String>(fields.named("schema")?, build)?;
        let private_key = ledger.read::<Bytes>(fields.named("private_key")?, build)?;
        let birth_id = ledger.read::<Bytes>(fields.named("birth_id")?, build)?;
        let source_birth = ledger.read::<Value>(fields.named("source_birth")?, build)?;
        let expected_host_registration =
            ledger.read::<Value>(fields.named("expected_host_registration")?, build)?;
        let private_launch = ledger.read::<Id>(fields.named("private_launch")?, build)?;
        let host_executable = ledger.read::<ContentRef>(fields.named("host_executable")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            private_key: private_key.ok_or_else(invalid)?,
            birth_id: birth_id.ok_or_else(invalid)?,
            source_birth: source_birth.ok_or_else(invalid)?,
            expected_host_registration: expected_host_registration.ok_or_else(invalid)?,
            private_launch: private_launch.ok_or_else(invalid)?,
            host_executable: host_executable.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentStartup17 {
    pub(crate) allocation: PacketNativeStartupAllocation,
    pub(crate) source_digest: [u8; 32],
    pub(crate) launch_digest: [u8; 32],
    pub(crate) birth_id: [u8; 32],
    pub(crate) native_birth_issued: bool,
    pub(crate) baseline_complete: bool,
    pub(crate) prepare_startup_issued: bool,
    pub(crate) restored_suffix: Option<CurrentSuffix17>,
}
impl HistoricalType for CurrentStartup17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let allocation =
            ledger.read::<PacketNativeStartupAllocation>(fields.named("allocation")?, build)?;
        let source_digest =
            FixedArray32Field17::read(fields.named("source_digest")?, ledger, build)?;
        let launch_digest =
            FixedArray32Field17::read(fields.named("launch_digest")?, ledger, build)?;
        let birth_id = FixedArray32Field17::read(fields.named("birth_id")?, ledger, build)?;
        let native_birth_issued =
            ledger.read::<bool>(fields.named("native_birth_issued")?, build)?;
        let baseline_complete = ledger.read::<bool>(fields.named("baseline_complete")?, build)?;
        let prepare_startup_issued =
            ledger.read::<bool>(fields.named("prepare_startup_issued")?, build)?;
        let restored_suffix =
            ledger.read::<Option<CurrentSuffix17>>(fields.named("restored_suffix")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            allocation: allocation.ok_or_else(invalid)?,
            source_digest: source_digest.ok_or_else(invalid)?,
            launch_digest: launch_digest.ok_or_else(invalid)?,
            birth_id: birth_id.ok_or_else(invalid)?,
            native_birth_issued: native_birth_issued.ok_or_else(invalid)?,
            baseline_complete: baseline_complete.ok_or_else(invalid)?,
            prepare_startup_issued: prepare_startup_issued.ok_or_else(invalid)?,
            restored_suffix: restored_suffix.ok_or_else(invalid)?,
        }))
    }
}

/// Retains the current complete Boot graph without any originating live owner.
pub(crate) struct CurrentBoot17Data {
    pub(crate) creator: u32,
    pub(crate) data: CurrentBootData17,
    pub(crate) launch: Vec<u8>,
    pub(crate) policy_group: usize,
    pub(crate) source: Vec<u8>,
    pub(crate) host: Vec<u8>,
    pub(crate) normalized: [Option<Value>; 5],
    pub(crate) banks: [Vec<u8>; 5],
    pub(crate) context: Option<PacketCanonicalAckAdmissionContext>,
    pub(crate) proof: Option<PacketCanonicalAckAdmissionProof>,
    pub(crate) original: Option<Envelope>,
    pub(crate) ready: bool,
    pub(crate) attempted: bool,
    pub(crate) verified: bool,
    pub(crate) commit: Option<CurrentShared17<CurrentCommit17>>,
    pub(crate) prepare: Option<CurrentShared17<CurrentPrepare17>>,
    pub(crate) startup: Option<CurrentStartup17>,
    pub(crate) restoration_stages: CurrentStages17,
    pub(crate) settled_reserve: CurrentReserve17,
}
impl CurrentBoot17Data {
    /// Begins and completes this exact full native Boot alias definition.
    pub(crate) fn read_shared_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<CurrentShared17<Self>>, ProviderError> {
        let start = ledger.rows.encoded_position();
        let layout = NativeAckBoot::current_boot_shared_layout17_data();
        shared_row17(ledger, layout)?;
        let group = ledger.shared_begin(MetadataSharedKind::NativeBoot)?;
        let payload = Self::read_with_native_parent_data(input, ledger, build, group)?;
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, layout.0, input, rows)?;
        Ok(payload.map(|payload| CurrentShared17 { group, payload }))
    }

    fn read_with_native_parent_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        boot_group: usize,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-current-boot/17",
        )?;
        let creator_raw = fields.named("creator")?;
        role17(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        let data_raw = fields.named("data")?;
        let launch_raw = fields.named("launch")?;
        role17(fields.named("policy_role")?, "native-policy")?;
        let source_raw = fields.named("source")?;
        let host_raw = fields.named("host")?;
        let normalized_raw = fields.named("normalized")?;
        let banks_raw = fields.named("banks")?;
        let context_raw = fields.named("context")?;
        let proof_raw = fields.named("proof")?;
        let original_raw = fields.named("original")?;
        let ready_raw = fields.named("ready")?;
        let attempted_raw = fields.named("attempted")?;
        let verified_raw = fields.named("verified")?;
        let commit_raw = fields.named("commit")?;
        let prepare_raw = fields.named("prepare")?;
        let startup_raw = fields.named("startup")?;
        let stages_raw = fields.named("restoration_stages")?;
        let reserve_raw = fields.named("settled_reserve")?;
        fields.finish()?;
        let field_loans: CurrentBootFieldLoans17<'_> = (
            creator_raw,
            data_raw,
            launch_raw,
            source_raw,
            host_raw,
            normalized_raw,
            banks_raw,
            context_raw,
            proof_raw,
            original_raw,
            ready_raw,
            attempted_raw,
            verified_raw,
            commit_raw,
            prepare_raw,
            startup_raw,
            stages_raw,
            reserve_raw,
        );
        let (
            creator_raw,
            data_raw,
            launch_raw,
            source_raw,
            host_raw,
            normalized_raw,
            banks_raw,
            context_raw,
            proof_raw,
            original_raw,
            ready_raw,
            attempted_raw,
            verified_raw,
            commit_raw,
            prepare_raw,
            startup_raw,
            stages_raw,
            reserve_raw,
        ) = field_loans;

        let creator = ledger.read::<u32>(creator_raw, build)?;
        let data = ledger.read::<CurrentBootData17>(data_raw, build)?;
        let launch = ledger
            .read::<HistoricalByteBank17>(launch_raw, build)?
            .map(|bank| bank.0);
        let policy_group = read_reference17(
            ledger,
            MetadataSharedKind::NativePolicy,
            (size_of::<Native5Policy>(), align_of::<Native5Policy>()),
        )?;
        let source = ledger
            .read::<HistoricalByteBank17>(source_raw, build)?
            .map(|bank| bank.0);
        let host = ledger
            .read::<HistoricalByteBank17>(host_raw, build)?
            .map(|bank| bank.0);
        let normalized = read_normalized17(normalized_raw, ledger, build)?;
        let banks = read_banks17(banks_raw, ledger, build)?;
        let context =
            <Optional17<CurrentDto17<PacketCanonicalAckAdmissionContext>> as CurrentField17>::read(
                context_raw,
                ledger,
                build,
            )?;
        let proof =
            <Optional17<CurrentDto17<PacketCanonicalAckAdmissionProof>> as CurrentField17>::read(
                proof_raw, ledger, build,
            )?;
        let original = ledger.read::<Option<Envelope>>(original_raw, build)?;
        let ready = ledger.read::<bool>(ready_raw, build)?;
        let attempted = ledger.read::<bool>(attempted_raw, build)?;
        let verified = ledger.read::<bool>(verified_raw, build)?;
        let commit = if commit_raw == b"null" {
            Some(None)
        } else {
            CurrentCommit17::read_shared_data(commit_raw, ledger, build)?.map(Some)
        };
        let prepare = if prepare_raw == b"null" {
            Some(None)
        } else {
            CurrentPrepare17::read_shared_with_native_parent_data(
                prepare_raw,
                ledger,
                build,
                boot_group,
            )?
            .map(Some)
        };
        // Full first-observation roots precede the suffix's weak role reference.
        let restoration_stages = ledger.read::<CurrentStages17>(stages_raw, build)?;
        let startup = ledger.read::<Option<CurrentStartup17>>(startup_raw, build)?;
        let settled_reserve =
            CurrentReserve17::read_with_native_parent_data(reserve_raw, ledger, build, boot_group)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            data: data.ok_or_else(invalid)?,
            launch: launch.ok_or_else(invalid)?,
            policy_group,
            source: source.ok_or_else(invalid)?,
            host: host.ok_or_else(invalid)?,
            normalized: normalized.ok_or_else(invalid)?,
            banks: banks.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            proof: proof.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            ready: ready.ok_or_else(invalid)?,
            attempted: attempted.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
            commit: commit.ok_or_else(invalid)?,
            prepare: prepare.ok_or_else(invalid)?,
            startup: startup.ok_or_else(invalid)?,
            restoration_stages: restoration_stages.ok_or_else(invalid)?,
            settled_reserve: settled_reserve.ok_or_else(invalid)?,
        }))
    }

    /// Conjoins intrinsic byte and root relationships without native eligibility.
    pub(crate) fn authenticate_data(&self, boot_group: usize) -> Result<(), ProviderError> {
        self.restoration_stages.authenticate_data()?;
        self.settled_reserve.authenticate_data()?;
        if self.creator == 0
            || self.data.private_key.as_slice().len() != 32
            || self.data.birth_id.as_slice().len() != 32
            || self.settled_reserve.boot_group != boot_group
        {
            return Err(invalid());
        }
        if let Some(startup) = &self.startup {
            if self.data.birth_id.as_slice() != startup.birth_id
                || blake3::hash(&self.source).as_bytes() != &startup.source_digest
                || blake3::hash(&self.launch).as_bytes() != &startup.launch_digest
            {
                return Err(invalid());
            }
            if let Some(suffix) = &startup.restored_suffix
                && suffix.first_observation_group.is_some_and(|group| {
                    self.restoration_stages
                        .first_observation
                        .as_ref()
                        .is_none_or(|first| first.group != group)
                })
            {
                return Err(invalid());
            }
        }
        if let Some(prepare) = &self.prepare
            && (prepare.payload.service_quote.as_ref().is_some_and(|quote| {
                quote.boot_group != boot_group || quote.policy_group != self.policy_group
            }) || prepare.payload.control_quote.as_ref().is_some_and(|quote| {
                quote.policy_group != self.policy_group
                    || quote.endpoint.policy_group != self.policy_group
            }))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn read_normalized17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<[Option<Value>; 5]>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut values: [Option<Option<Value>>; 5] = std::array::from_fn(|_| None);
    for value in &mut values {
        *value = ledger.read::<Option<Value>>(fields.next_value()?.ok_or_else(invalid)?, build)?;
    }
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    let [a, b, c, d, e] = values;
    Ok(Some([
        a.ok_or_else(invalid)?,
        b.ok_or_else(invalid)?,
        c.ok_or_else(invalid)?,
        d.ok_or_else(invalid)?,
        e.ok_or_else(invalid)?,
    ]))
}
fn read_banks17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<[Vec<u8>; 5]>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut values: [Option<Vec<u8>>; 5] = std::array::from_fn(|_| None);
    for value in &mut values {
        *value = ledger
            .read::<HistoricalByteBank17>(fields.next_value()?.ok_or_else(invalid)?, build)?
            .map(|bank| bank.0);
    }
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    let [a, b, c, d, e] = values;
    Ok(Some([
        a.ok_or_else(invalid)?,
        b.ok_or_else(invalid)?,
        c.ok_or_else(invalid)?,
        d.ok_or_else(invalid)?,
        e.ok_or_else(invalid)?,
    ]))
}

/// Names the exact concrete reader, fixed arrays, borrow and fallible headers.
pub(crate) fn current_boot17_counter_scratch_data() -> usize {
    size_of::<CurrentBoot17Data>()
        + size_of::<CurrentBootData17>()
        + size_of::<CurrentStartup17>()
        + size_of::<CurrentCommit17>()
        + size_of::<CurrentPrepare17>()
        + size_of::<CurrentStages17>()
        + size_of::<CurrentSuffix17>()
        + size_of::<CurrentReserve17>()
        + size_of::<[Option<Option<Value>>; 5]>()
        + size_of::<[Option<Vec<u8>>; 5]>()
        + size_of::<Fields<'static>>()
        + size_of::<CurrentBootFieldLoans17<'static>>()
        + size_of::<Option<CurrentShared17<CurrentBoot17Data>>>()
        + size_of::<Result<Option<CurrentShared17<CurrentBoot17Data>>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + super::current_capture17_borrowed::historical_capture17_counter_scratch_data()
}

/// Names each concrete historical payload layout used by current Boot children.
///
/// The whole-family plan separately charges variable populations, raw banks,
/// parser work, exact String/Vec backing and tree allocation geometry.
pub(crate) fn current_boot17_inline_layouts_data() -> [usize; 27] {
    [
        size_of::<CurrentBoot17Data>(),
        size_of::<CurrentBootData17>(),
        size_of::<CurrentStartup17>(),
        size_of::<CurrentCommit17>(),
        size_of::<CurrentPrepare17>(),
        size_of::<CurrentStages17>(),
        size_of::<super::current_stages::CurrentActivation17>(),
        size_of::<super::current_stages::CurrentUpload17>(),
        size_of::<super::current_stages::CurrentFirstObservation17>(),
        size_of::<CurrentSuffix17>(),
        size_of::<super::current_suffix::CurrentSuffixObserve17>(),
        size_of::<super::current_suffix::CurrentSuffixProducer17>(),
        size_of::<super::current_suffix::CurrentSealedSuffix17>(),
        size_of::<CurrentReserve17>(),
        size_of::<super::current_reserve::CurrentSealedReserve17>(),
        size_of::<super::current_actions::HistoricalRestoredAction17>(),
        size_of::<super::current_actions::CurrentSelectedAction17>(),
        size_of::<super::current_actions::CurrentCaptureAttempt17>(),
        size_of::<super::current_actions::CurrentInputAttempt17>(),
        size_of::<super::current_actions::CurrentInputCheckpoint17>(),
        size_of::<super::current_actions::CurrentObservationAction17>(),
        size_of::<super::current_actions::CurrentObservationCheckpoint17>(),
        size_of::<super::current_actions::CurrentObservationProduction17>(),
        size_of::<super::current_quotes::CurrentServiceQuote17>(),
        size_of::<super::current_quotes::CurrentControlQuote17>(),
        size_of::<super::current_quotes::CurrentEndpointQuote17>(),
        size_of::<super::current_purpose::CurrentPurpose17>(),
    ]
}
