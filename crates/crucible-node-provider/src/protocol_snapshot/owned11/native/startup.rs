//! Reconstructs explicit boot6 and invocation boot7 startup history as data.
//!
//! Fixed digests and the complete secret336-byte prefix remain inline owners.
//! Their compact encoding has no independent Vec allocation or metadata row.
//! The allocation schema String retains its actual separately recorded capacity.
//! No historical Boolean can issue native birth, renew a cut or reopen Prepare.

use super::super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA, PacketNativeStartupAllocation,
    PacketNativeStartupAllocationRow,
};
use crate::{ProviderError, protocol_snapshot::compact_bytes::ValidatedCompactBytes};
use crucible_node_contract::U64;

/// Retains the complete original startup declaration as inert historical data.
pub struct HistoricalNativeStartupBoot {
    /// Retains the independent typed allocation and schema backing.
    pub allocation: PacketNativeStartupAllocation,
    /// Binds exact canonical Source bytes, including their allocation declaration.
    pub source_digest: [u8; 32],
    /// Binds the original canonical launch bytes.
    pub launch_digest: [u8; 32],
    /// Binds the same private birth identity.
    pub birth_id: [u8; 32],
    /// Preserves the spent native birth occurrence without issuing one.
    pub native_birth_issued: bool,
    /// Preserves completed baseline history without reopening a live gate.
    pub baseline_complete: bool,
    /// Preserves whether the independently selected Prepare occurrence was spent.
    pub prepare_startup_issued: bool,
}

/// Retains the complete fixed private startup owner without its live identities.
pub struct HistoricalNativeStartupBootstrap {
    /// Retains the original native process identifier as data.
    pub creator: u32,
    /// Retains every original prefix byte, including its private key and MAC.
    pub preamble: [u8; 336],
    /// Retains the original private-bootstrap phase data.
    pub private_bootstrap: PacketNativeStartupAllocationRow,
    /// Retains the independent native construction phase data.
    pub native_birth: PacketNativeStartupAllocationRow,
    /// Retains the exact nullable Prepare phase data.
    pub restore_prepare: Option<PacketNativeStartupAllocationRow>,
    /// Retains the actual expected controller identifier as history.
    pub expected_controller_pid: u64,
    /// Retains the actual expected controller user as history.
    pub expected_controller_uid: u64,
    /// Retains the pre-parser's original launch extent.
    pub maximum_launch_bytes: usize,
    /// Retains the pre-parser's original boot extent.
    pub maximum_boot_bytes: usize,
    /// Preserves the native occurrence without issuing one.
    pub native_issued: bool,
    /// Preserves the original sticky failure state.
    pub failed: bool,
}

pub(super) fn fixed<const N: usize>(
    input: &[u8],
    maximum_input: usize,
    build: bool,
) -> Result<Option<[u8; N]>, ProviderError> {
    let plan = ValidatedCompactBytes::validate(input, maximum_input, N)?;
    if plan.decoded_length() != N {
        return Err(invalid());
    }
    if !build {
        return Ok(None);
    }
    let mut bytes = [0; N];
    plan.copy_range(0, &mut bytes)?;
    Ok(Some(bytes))
}

impl HistoricalType for PacketNativeStartupAllocationRow {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let retained = ledger
            .read::<U64>(fields.named("retained_requested_bytes")?, true)?
            .ok_or_else(invalid)?;
        let transient = ledger
            .read::<U64>(fields.named("maximum_simultaneous_transient_bytes")?, true)?
            .ok_or_else(invalid)?;
        let scratch = ledger
            .read::<U64>(fields.named("declared_counter_scratch_bytes")?, true)?
            .ok_or_else(invalid)?;
        fields.finish()?;
        let row = Self {
            retained_requested_bytes: retained,
            maximum_simultaneous_transient_bytes: transient,
            declared_counter_scratch_bytes: scratch,
        };
        row.requested_peak_data()?;
        Ok(build.then_some(row))
    }
}

impl HistoricalType for PacketNativeStartupAllocation {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let raw_schema = fields.named("schema")?;
        if plain_string(raw_schema)? != PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA {
            return Err(invalid());
        }
        let schema = ledger.read::<String>(raw_schema, build)?;
        let private_bootstrap = ledger
            .read::<PacketNativeStartupAllocationRow>(fields.named("private_bootstrap")?, true)?
            .ok_or_else(invalid)?;
        let native_birth = ledger
            .read::<PacketNativeStartupAllocationRow>(fields.named("native_birth")?, true)?
            .ok_or_else(invalid)?;
        let restore_prepare = ledger
            .read::<Option<PacketNativeStartupAllocationRow>>(
                fields.named("restore_prepare")?,
                true,
            )?
            .ok_or_else(invalid)?;
        fields.finish()?;
        // The first pass checks the complete scalar sum without constructing
        // the schema String or any native owner.
        let mut retained = 0u64;
        let mut phase = 0u64;
        for row in [Some(private_bootstrap), Some(native_birth), restore_prepare]
            .into_iter()
            .flatten()
        {
            retained = retained
                .checked_add(row.retained_requested_bytes.get())
                .ok_or_else(invalid)?;
            phase = phase.max(
                row.maximum_simultaneous_transient_bytes
                    .get()
                    .checked_add(row.declared_counter_scratch_bytes.get())
                    .ok_or_else(invalid)?,
            );
        }
        retained.checked_add(phase).ok_or_else(invalid)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            private_bootstrap,
            native_birth,
            restore_prepare,
        }))
    }
}

pub(super) fn read_boot(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeStartupBoot>, ProviderError> {
    read_boot_at_edition(input, ledger, build, false)
}

pub(super) fn read_invocation_boot(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeStartupBoot>, ProviderError> {
    read_boot_at_edition(input, ledger, build, true)
}

fn read_boot_at_edition(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    invocation: bool,
) -> Result<Option<HistoricalNativeStartupBoot>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if invocation {
            "source-private.native-startup-owner/15"
        } else {
            "source-private.native-startup-owner/14"
        },
    )?;
    let allocation_input = next(&mut fields)?;
    let allocation = ledger.read::<PacketNativeStartupAllocation>(allocation_input, build)?;
    let source_digest = fixed::<32>(next(&mut fields)?, ledger.limits.maximum_input_bytes, build)?;
    let launch_digest = fixed::<32>(next(&mut fields)?, ledger.limits.maximum_input_bytes, build)?;
    let birth_id = fixed::<32>(next(&mut fields)?, ledger.limits.maximum_input_bytes, build)?;
    if next(&mut fields)? != b"true" || next(&mut fields)? != b"true" {
        return Err(invalid());
    }
    let prepare_startup_issued = ledger
        .read::<bool>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    fields.finish()?;
    if invocation && prepare_startup_issued {
        return Err(invalid());
    }
    if prepare_startup_issued {
        let mut allocation_fields = Fields::object(allocation_input)?;
        allocation_fields.named("schema")?;
        allocation_fields.named("private_bootstrap")?;
        allocation_fields.named("native_birth")?;
        if allocation_fields.named("restore_prepare")? == b"null" {
            return Err(invalid());
        }
        allocation_fields.finish()?;
    }
    if !build {
        return Ok(None);
    }
    let owner = HistoricalNativeStartupBoot {
        allocation: allocation.ok_or_else(invalid)?,
        source_digest: source_digest.ok_or_else(invalid)?,
        launch_digest: launch_digest.ok_or_else(invalid)?,
        birth_id: birth_id.ok_or_else(invalid)?,
        native_birth_issued: true,
        baseline_complete: true,
        prepare_startup_issued,
    };
    if owner.prepare_startup_issued && owner.allocation.restore_prepare.is_none() {
        return Err(invalid());
    }
    Ok(Some(owner))
}

pub(super) fn read_bootstrap(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeStartupBootstrap>, ProviderError> {
    read_bootstrap_at_edition(input, ledger, build, false)
}

pub(super) fn read_invocation_bootstrap(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeStartupBootstrap>, ProviderError> {
    read_bootstrap_at_edition(input, ledger, build, true)
}

fn read_bootstrap_at_edition(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    invocation: bool,
) -> Result<Option<HistoricalNativeStartupBootstrap>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if invocation {
            "source-private.native-startup-bootstrap-owner/15"
        } else {
            "source-private.native-startup-bootstrap-owner/14"
        },
    )?;
    let creator = ledger.read::<u32>(next(&mut fields)?, build)?;
    tag(&mut fields, "same-original-thread")?;
    let preamble = fixed::<336>(next(&mut fields)?, ledger.limits.maximum_input_bytes, build)?;
    let private_bootstrap =
        ledger.read::<PacketNativeStartupAllocationRow>(next(&mut fields)?, build)?;
    let native_birth =
        ledger.read::<PacketNativeStartupAllocationRow>(next(&mut fields)?, build)?;
    let restore_prepare =
        ledger.read::<Option<PacketNativeStartupAllocationRow>>(next(&mut fields)?, build)?;
    let expected_controller_pid = ledger.read::<u64>(next(&mut fields)?, build)?;
    let expected_controller_uid = ledger.read::<u64>(next(&mut fields)?, build)?;
    let maximum_launch_bytes = ledger.read::<usize>(next(&mut fields)?, build)?;
    let maximum_boot_bytes = ledger.read::<usize>(next(&mut fields)?, build)?;
    tag(&mut fields, "original-startup-cut-transferred")?;
    if next(&mut fields)? != b"true" || next(&mut fields)? != b"false" {
        return Err(invalid());
    }
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeStartupBootstrap {
        creator: creator.ok_or_else(invalid)?,
        preamble: preamble.ok_or_else(invalid)?,
        private_bootstrap: private_bootstrap.ok_or_else(invalid)?,
        native_birth: native_birth.ok_or_else(invalid)?,
        restore_prepare: restore_prepare.ok_or_else(invalid)?,
        expected_controller_pid: expected_controller_pid.ok_or_else(invalid)?,
        expected_controller_uid: expected_controller_uid.ok_or_else(invalid)?,
        maximum_launch_bytes: maximum_launch_bytes.ok_or_else(invalid)?,
        maximum_boot_bytes: maximum_boot_bytes.ok_or_else(invalid)?,
        native_issued: true,
        failed: false,
    }))
}

impl HistoricalNativeStartupBoot {
    pub(super) fn authenticate(
        &self,
        boot: &super::boot::HistoricalNativeBoot,
    ) -> Result<(), ProviderError> {
        if !self.native_birth_issued
            || !self.baseline_complete
            || self.prepare_startup_issued && self.allocation.restore_prepare.is_none()
            || boot.data.schema != "source-owned.packet-canonical-ack-private-boot/6"
            || boot.data.birth_id.as_slice() != self.birth_id
            || blake3::hash(&boot.source_body).as_bytes() != &self.source_digest
            || blake3::hash(&boot.launch_body).as_bytes() != &self.launch_digest
        {
            return Err(invalid());
        }
        let source = boot.data.source_birth.as_object().ok_or_else(invalid)?;
        const KEYS: [&str; 18] = [
            "schema",
            "selection",
            "program",
            "coordinator",
            "limits",
            "storage",
            "capture_profile",
            "confirmation_selection",
            "ack_emitter_selection",
            "codec_metadata_extent",
            "native_codec_metadata_extent",
            "protocol_metadata_limits",
            "complete_restore_selection",
            "restore_input_emitter_selection",
            "capture_allocation_selection",
            "fresh_restore_allocation_selection",
            "report_startup_allocation",
            "native_startup_allocation",
        ];
        if source.len() != KEYS.len()
            || KEYS.iter().any(|key| !source.contains_key(*key))
            || source.get("schema").and_then(serde_json::Value::as_str)
                != Some("source-owned.packet-canonical-ack-source-binding/14")
        {
            return Err(invalid());
        }
        let fresh = match boot.policy.fresh_restore_allocation_selection {
            None => source.get("fresh_restore_allocation_selection") == Some(&serde_json::Value::Null),
            Some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13) =>
                source.get("fresh_restore_allocation_selection").and_then(serde_json::Value::as_str) == Some("completed_admit13"),
        };
        if !fresh {
            return Err(invalid());
        }
        self.allocation
            .authenticate_owned_codec_source_data(&boot.data.source_birth)?;
        super::super::correspondence::json_value(&boot.data.source_birth, &boot.source_body)?;
        Ok(())
    }
}

impl HistoricalNativeStartupBootstrap {
    pub(super) fn authenticate(
        &self,
        bootstrap: &super::bootstrap::HistoricalNativeBootstrap,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::service::native_startup::{
            authenticate_original_native_startup_preamble_data,
            decode_original_native_startup_preamble_data,
        };
        let boot = &bootstrap.boot;
        let owner = boot.startup.as_ref().ok_or_else(invalid)?;
        owner.authenticate(boot)?;
        authenticate_original_native_startup_preamble_data(
            &self.preamble,
            boot.data.private_key.as_slice(),
        )?;
        let facts = decode_original_native_startup_preamble_data(&self.preamble)?;
        if !self.native_issued
            || self.failed
            || self.creator != boot.creator
            || self.private_bootstrap != owner.allocation.private_bootstrap
            || self.native_birth != owner.allocation.native_birth
            || self.restore_prepare != owner.allocation.restore_prepare
            || facts.private_bootstrap != self.private_bootstrap
            || facts.native_birth != self.native_birth
            || facts.restore_prepare != self.restore_prepare
            || facts.controller_pid != self.expected_controller_pid
            || facts.controller_uid != self.expected_controller_uid
            || facts.launch_bytes as usize != self.maximum_launch_bytes
            || facts.maximum_boot_bytes as usize != self.maximum_boot_bytes
            || facts.birth_id != owner.birth_id
            || facts.launch_digest != owner.launch_digest
            || facts.source_digest != owner.source_digest
            || blake3::hash(&boot.host_body).as_bytes() != &facts.registration_digest
            || blake3::hash(boot.data.private_launch.as_str().as_bytes()).as_bytes()
                != &facts.private_launch_digest
            || bootstrap.launch_bytes.len() != self.maximum_launch_bytes
            || bootstrap
                .literals
                .frames()
                .nth(1)
                .ok_or_else(invalid)?
                .bytes
                .len()
                .checked_sub(4)
                .ok_or_else(invalid)?
                > self.maximum_boot_bytes
        {
            return Err(invalid());
        }
        let launch = bootstrap.launch_value.as_object().ok_or_else(invalid)?;
        for (key, expected) in [
            ("controller_pid", self.expected_controller_pid),
            ("controller_uid", self.expected_controller_uid),
        ] {
            let raw = launch
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(invalid)?;
            if raw.is_empty()
                || (raw != "0" && raw.starts_with('0'))
                || !raw.bytes().all(|byte| byte.is_ascii_digit())
                || raw.parse::<u64>() != Ok(expected)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub(super) const fn declared_scratch_bytes() -> usize {
    std::mem::size_of::<HistoricalNativeStartupBootstrap>()
        + std::mem::size_of::<
            crate::reference_packet::service::native_startup::PacketNativeStartupPreambleData,
        >()
        + std::mem::size_of::<[u8; 336]>()
        + 3 * std::mem::size_of::<[u8; 32]>()
        + std::mem::size_of::<blake3::Hasher>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 8192,
            maximum_nodes: 256,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 8192,
            maximum_tree_entries: 64,
        }
    }

    fn allocation() -> PacketNativeStartupAllocation {
        let mut schema = String::with_capacity(113);
        schema.push_str(PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA);
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(101),
            maximum_simultaneous_transient_bytes: U64::new(53),
            declared_counter_scratch_bytes: U64::new(29),
        };
        PacketNativeStartupAllocation {
            schema,
            private_bootstrap: row,
            native_birth: row,
            restore_prepare: Some(row),
        }
    }

    #[test]
    fn original_startup_allocation_data_roundtrip_preserves_actual_schema_capacity() {
        let original = allocation();
        let mut bank = MetadataRecordBank::reserve(8).unwrap();
        // The typed allocation owns only its schema String; row values and
        // nullable row wrappers have no independent backing.
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&original.schema).unwrap();
        observer.finish();
        let encoded = serde_json::to_vec(&original).unwrap();
        let encoded_rows = serde_json::to_vec(&bank).unwrap();
        let records = ValidatedMetadataRecords::validate(&encoded_rows, 8, 8192).unwrap();

        let mut preflight = Ledger::new(records.rows(), limits());
        assert!(
            preflight
                .read::<PacketNativeStartupAllocation>(&encoded, false)
                .unwrap()
                .is_none()
        );
        assert!(preflight.rows.next().is_none());
        let mut rebuild = Ledger::new(records.rows(), limits());
        let restored = rebuild
            .read::<PacketNativeStartupAllocation>(&encoded, true)
            .unwrap()
            .unwrap();

        assert_eq!(restored, original);
        assert_eq!(restored.schema.capacity(), original.schema.capacity());
        assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded);
        assert!(rebuild.rows.next().is_none());
    }

    #[test]
    fn original_startup_compact_fixed_preamble_preserves_every_byte_and_rejects_wrong_extent() {
        // This is an inert byte-codec control, not an authenticated prefix or
        // a constructed live startup owner.
        let bytes = std::array::from_fn::<_, 336, _>(|index| (index % 251) as u8);
        let encoded = serde_json::to_vec(
            &crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&bytes),
        )
        .unwrap();
        assert!(fixed::<336>(&encoded, 8192, false).unwrap().is_none());
        assert_eq!(fixed::<336>(&encoded, 8192, true).unwrap(), Some(bytes));
        assert!(fixed::<335>(&encoded, 8192, false).is_err());
        assert!(fixed::<337>(&encoded, 8192, false).is_err());
    }

    #[test]
    fn original_startup_allocation_preflight_refuses_zero_row_and_unselected_prepare_claim() {
        let mut original = allocation();
        original.native_birth.retained_requested_bytes = U64::new(0);
        let mut bank = MetadataRecordBank::reserve(8).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&original.schema).unwrap();
        observer.finish();
        let encoded_rows = serde_json::to_vec(&bank).unwrap();
        let records = ValidatedMetadataRecords::validate(&encoded_rows, 8, 8192).unwrap();
        let encoded = serde_json::to_vec(&original).unwrap();
        let mut ledger = Ledger::new(records.rows(), limits());
        assert!(
            ledger
                .read::<PacketNativeStartupAllocation>(&encoded, false)
                .is_err()
        );

        original.native_birth.retained_requested_bytes = U64::new(101);
        original.restore_prepare = None;
        let digest = [0u8; 32];
        let compact = crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&digest);
        let owner = serde_json::to_vec(&(
            "source-private.native-startup-owner/14",
            &original,
            &compact,
            &compact,
            &compact,
            true,
            true,
            true,
        ))
        .unwrap();
        let mut ledger = Ledger::new(records.rows(), limits());
        assert!(read_boot(&owner, &mut ledger, false).is_err());
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeStartupBoot,
    allocation,
    source_digest,
    launch_digest,
    birth_id,
    native_birth_issued,
    baseline_complete,
    prepare_startup_issued
);
super::super::retained_storage::fields!(
    HistoricalNativeStartupBootstrap,
    creator,
    preamble,
    private_bootstrap,
    native_birth,
    restore_prepare,
    expected_controller_pid,
    expected_controller_uid,
    maximum_launch_bytes,
    maximum_boot_bytes,
    native_issued,
    failed
);

pub(crate) mod current17;
