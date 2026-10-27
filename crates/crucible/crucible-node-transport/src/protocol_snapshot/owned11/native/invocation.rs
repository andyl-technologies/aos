//! Validates original invocation history without reconstructing live authority.
//!
//! ```text
//! ["source-private.native-invocation-phase/15", "original_never_queried",
//!  compact_birth32, false, false, false]
//! ```
//!
//! Only class15 selects these strict boot7/Source15/prefix15 readers. Parsed
//! original-purpose history cannot issue a native claim, fresh target, Query,
//! installation or Arm right. In-flight and settled transfers remain refused.

use super::super::{
    state::{next, tag},
    typed::{Fields, invalid, plain_string},
};
use super::{boot::HistoricalNativeBoot, connection::HistoricalNativeConnection};
use crate::ProviderError;
use crate::reference_packet::service::native_startup::{
    PacketNativeInvocationPurposeData, authenticate_original_native_invocation_preamble_data,
    decode_original_native_invocation_preamble_data,
};

/// Retains one fixed historical original-execution phase, never a live claim.
pub struct HistoricalNativeInvocationPhase {
    birth_id: [u8; 32],
}

impl HistoricalNativeInvocationPhase {
    /// Borrows the entire historical birth digest without issuing its occurrence.
    pub fn birth_id_data(&self) -> &[u8; 32] {
        &self.birth_id
    }

    pub(super) fn authenticate_boot(
        &self,
        boot: &HistoricalNativeBoot,
    ) -> Result<(), ProviderError> {
        let owner = boot.startup.as_ref().ok_or_else(invalid)?;
        if boot.data.schema != "source-owned.packet-canonical-ack-private-boot/7"
            || !owner.native_birth_issued
            || !owner.baseline_complete
            || owner.prepare_startup_issued
            || owner.birth_id != self.birth_id
            || boot.data.birth_id.as_slice() != self.birth_id
            || blake3::hash(&boot.source_body).as_bytes() != &owner.source_digest
            || blake3::hash(&boot.launch_body).as_bytes() != &owner.launch_digest
        {
            return Err(invalid());
        }
        let source = boot.data.source_birth.as_object().ok_or_else(invalid)?;
        if source.len() != SOURCE_KEYS.len()
            || SOURCE_KEYS.iter().any(|key| !source.contains_key(*key))
            || source["schema"].as_str() != Some("source-owned.packet-canonical-ack-source-binding/15")
            || source["fresh_restore_allocation_selection"].as_str() != Some("completed_admit13")
            || boot.policy.fresh_restore_allocation_selection != Some(
                crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || boot.policy.capture_allocation_selection != Some(
                crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
        { return Err(invalid()); }
        let purpose =
            PacketNativeInvocationPurposeData::from_original_value_data(&source["invocation"])?;
        if !purpose.is_original_execution_data() {
            return Err(invalid());
        }
        purpose.authenticate_control_target_data(&boot.policy.selection)?;
        owner
            .allocation
            .authenticate_owned_codec_source_data(&boot.data.source_birth)?;
        super::super::correspondence::json_value(&boot.data.source_birth, &boot.source_body)
    }

    pub(super) fn authenticate_connection(
        &self,
        connection: &HistoricalNativeConnection,
    ) -> Result<(), ProviderError> {
        self.authenticate_boot(&connection.admission.boot)?;
        let mut slot = 0usize;
        while let Some(frame) = connection.frames.frame(slot) {
            if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
                return Err(invalid());
            }
            crate::connection::authenticate_original_invocation_protocol_literal_data(
                &frame.bytes[4..],
            )?;
            slot = slot.checked_add(1).ok_or_else(invalid)?;
        }
        Ok(())
    }
}

pub(super) fn read_phase(
    input: &[u8],
    maximum: usize,
    build: bool,
) -> Result<Option<HistoricalNativeInvocationPhase>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "source-private.native-invocation-phase/15")?;
    tag(&mut fields, "original_never_queried")?;
    let birth_id = super::startup::fixed::<32>(next(&mut fields)?, maximum, build)?;
    for _ in 0..3 {
        if next(&mut fields)? != b"false" {
            return Err(invalid());
        }
    }
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeInvocationPhase {
        birth_id: birth_id.ok_or_else(invalid)?,
    }))
}

// serde_json's actual Map writer and canonical JSON both order these ASCII
// field names lexically. Fields::named consumes that exact ordered occurrence;
// this roster must not use the typed declaration's field order.
const SOURCE_KEYS: [&str; 19] = [
    "ack_emitter_selection",
    "capture_allocation_selection",
    "capture_profile",
    "codec_metadata_extent",
    "complete_restore_selection",
    "confirmation_selection",
    "coordinator",
    "fresh_restore_allocation_selection",
    "invocation",
    "limits",
    "native_codec_metadata_extent",
    "native_startup_allocation",
    "program",
    "protocol_metadata_limits",
    "report_startup_allocation",
    "restore_input_emitter_selection",
    "schema",
    "selection",
    "storage",
];

// This first pass checks only exact syntax before allocating historical Values.
// Full world/target/owner equality is checked after the actual final owner has
// reached its retained output slot; no syntax-only success escapes as authority.
pub(super) fn authenticate_source_syntax(input: &[u8]) -> Result<(), ProviderError> {
    let mut source = Fields::object(input)?;
    for key in SOURCE_KEYS {
        let value = source.named(key)?;
        if key == "schema"
            && plain_string(value)? != "source-owned.packet-canonical-ack-source-binding/15"
        {
            return Err(invalid());
        }
        if key == "invocation" {
            authenticate_original_purpose_syntax(value)?;
        }
    }
    source.finish()
}

fn authenticate_original_purpose_syntax(input: &[u8]) -> Result<(), ProviderError> {
    let mut purpose = Fields::object(input)?;
    if plain_string(purpose.named("purpose")?)? != "original_execution"
        || plain_string(purpose.named("schema")?)?
            != "source-owned.packet-native-invocation-purpose/1"
        || purpose.named("source")? != b"null"
    {
        return Err(invalid());
    }
    let mut target = Fields::object(purpose.named("target")?)?;
    for key in [
        "admission",
        "binding",
        "incarnation",
        "node",
        "owner",
        "owner_generation",
        "prepared_token",
        "session",
        "world",
    ] {
        let value = target.named(key)?;
        match key {
            "binding" | "world" => {
                let domain = if key == "world" {
                    "cnp.world-binding.v1"
                } else {
                    "cnp.node-binding.v1"
                };
                let mut hash = Fields::object(value)?;
                let algorithm = plain_string(hash.named("algorithm")?)?;
                let digest = plain_string(hash.named("digest")?)?;
                let actual_domain = plain_string(hash.named("domain")?)?;
                if algorithm != "blake3-256"
                    || actual_domain != domain
                    || digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(invalid());
                }
                hash.finish()?;
            }
            "owner_generation" => {
                let generation = plain_string(value)?;
                if generation.is_empty()
                    || generation.len() > 20
                    || generation.starts_with('0')
                    || !generation.bytes().all(|byte| byte.is_ascii_digit())
                    || generation.parse::<u64>().is_err()
                {
                    return Err(invalid());
                }
            }
            _ => {
                let text = plain_string(value)?;
                if text.is_empty()
                    || text.len() > 128
                    || !text.as_bytes()[0].is_ascii_alphanumeric()
                    || !text
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
                {
                    return Err(invalid());
                }
            }
        }
    }
    target.finish()?;
    purpose.finish()
}

pub(super) fn authenticate_bootstrap(
    original: &super::startup::HistoricalNativeStartupBootstrap,
    bootstrap: &super::bootstrap::HistoricalNativeBootstrap,
) -> Result<(), ProviderError> {
    let boot = &bootstrap.boot;
    let phase = boot.invocation.as_ref().ok_or_else(invalid)?;
    phase.authenticate_boot(boot)?;
    let owner = boot.startup.as_ref().ok_or_else(invalid)?;
    authenticate_original_native_invocation_preamble_data(
        &original.preamble,
        boot.data.private_key.as_slice(),
    )?;
    let facts = decode_original_native_invocation_preamble_data(&original.preamble)?;
    if !original.native_issued
        || original.failed
        || original.creator != boot.creator
        || original.private_bootstrap != owner.allocation.private_bootstrap
        || original.native_birth != owner.allocation.native_birth
        || original.restore_prepare != owner.allocation.restore_prepare
        || facts.private_bootstrap != original.private_bootstrap
        || facts.native_birth != original.native_birth
        || facts.restore_prepare != original.restore_prepare
        || facts.controller_pid != original.expected_controller_pid
        || facts.controller_uid != original.expected_controller_uid
        || facts.launch_bytes as usize != original.maximum_launch_bytes
        || facts.maximum_boot_bytes as usize != original.maximum_boot_bytes
        || facts.birth_id != owner.birth_id
        || facts.launch_digest != owner.launch_digest
        || facts.source_digest != owner.source_digest
        || blake3::hash(&boot.host_body).as_bytes() != &facts.registration_digest
        || blake3::hash(boot.data.private_launch.as_str().as_bytes()).as_bytes()
            != &facts.private_launch_digest
        || bootstrap.launch_bytes.len() != original.maximum_launch_bytes
        || bootstrap
            .literals
            .frames()
            .nth(1)
            .ok_or_else(invalid)?
            .bytes
            .len()
            .checked_sub(4)
            .ok_or_else(invalid)?
            > original.maximum_boot_bytes
    {
        return Err(invalid());
    }
    let wrapper = bootstrap.launch_value.as_object().ok_or_else(invalid)?;
    if wrapper.len() != 3
        || wrapper
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(6)
        || wrapper.get("invocation") != boot.data.source_birth.get("invocation")
    {
        return Err(invalid());
    }
    let launch = wrapper
        .get("launch")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if launch
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(5)
    {
        return Err(invalid());
    }
    for (key, expected) in [
        ("controller_pid", original.expected_controller_pid),
        ("controller_uid", original.expected_controller_uid),
    ] {
        let text = launch
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        if text.is_empty()
            || (text != "0" && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || text.parse::<u64>() != Ok(expected)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn declared_scratch_bytes() -> usize {
    [
        super::startup::declared_scratch_bytes(),
        crate::reference_packet::service::native_startup::original_native_invocation_counter_scratch_data(),
        crate::connection::original_native_invocation_history_counter_scratch_data(),
        super::super::correspondence::envelope_comparison_scratch_data(),
        // Outer/connection/token/boot/data cursors coexist with Source,
        // purpose, target and hash cursors. Sixteen explicitly covers those
        // nested fixed views; none borrows the encoded or tree backing budget.
        16 * std::mem::size_of::<Fields<'static>>(),
        4 * std::mem::size_of::<[u8; 128]>(),
        std::mem::size_of::<HistoricalNativeInvocationPhase>(),
        std::mem::size_of::<Option<HistoricalNativeInvocationPhase>>(),
        std::mem::size_of::<Result<Option<HistoricalNativeInvocationPhase>, ProviderError>>(),
        std::mem::size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>(),
        std::mem::size_of::<Result<(), ProviderError>>(),
        std::mem::size_of::<[(&str, &str); 2]>(),
        std::mem::size_of::<[(&str, u64); 2]>(),
        std::mem::size_of::<crate::reference_packet::service::native_startup::PacketNativeInvocationPreambleData>(),
        std::mem::size_of::<Result<crate::reference_packet::service::native_startup::PacketNativeInvocationPreambleData, ProviderError>>(),
        std::mem::size_of::<[&str; 19]>(),
        std::mem::size_of::<[&str; 6]>(),
        std::mem::size_of::<[&str; 9]>(), // actual ordered target roster
        3 * std::mem::size_of::<&str>(), // nested hash algorithm/digest/domain

    ].into_iter().try_fold(0usize, usize::checked_add).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;

    #[test]
    fn invocation_phase_data_refuses_target_started_flags_wrong_birth_extent_and_prototype_grammar()
    {
        let birth = [13; 32];
        let encoded = serde_json::to_vec(&(
            "source-private.native-invocation-phase/15",
            "original_never_queried",
            BorrowedCompactBytes::new(&birth),
            false,
            false,
            false,
        ))
        .unwrap();
        assert!(read_phase(&encoded, 8192, false).unwrap().is_none());
        assert_eq!(
            read_phase(&encoded, 8192, true)
                .unwrap()
                .unwrap()
                .birth_id_data(),
            &birth
        );
        for index in 3..6 {
            let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            changed[index] = true.into();
            assert!(read_phase(&serde_json::to_vec(&changed).unwrap(), 8192, false).is_err());
        }
        for name in ["restoration_target", "settled_transfer", "never_queried"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            changed[1] = name.into();
            assert!(read_phase(&serde_json::to_vec(&changed).unwrap(), 8192, false).is_err());
        }
        let changed = serde_json::to_vec(&(
            "source-private.native-invocation-phase/15",
            "original_never_queried",
            BorrowedCompactBytes::new(&birth[..31]),
            false,
            false,
            false,
        ))
        .unwrap();
        assert!(read_phase(&changed, 8192, false).is_err());
    }
}

// Exhaustive at the defining module: future owning phase fields must join the
// same closed retained-owner graph instead of disappearing behind a label.
super::super::retained_storage::fields!(HistoricalNativeInvocationPhase, birth_id);

#[cfg(test)]
mod source_syntax_tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    // This is only a parser-input bank. It is deliberately not an enrolled
    // Source, validated launch, native constructor, action or signed archive.
    fn source_shape() -> serde_json::Value {
        let mut source = serde_json::Map::new();
        for key in SOURCE_KEYS {
            source.insert(key.into(), serde_json::Value::Null);
        }
        source.insert(
            "schema".into(),
            "source-owned.packet-canonical-ack-source-binding/15".into(),
        );
        source.insert(
            "invocation".into(),
            json!({
                "schema":"source-owned.packet-native-invocation-purpose/1",
                "purpose":"original_execution", "source":null,
                "target":{
                    "world":canonical::hash("cnp.world-binding.v1", b"syntax").unwrap(),
                    "binding":canonical::hash("cnp.node-binding.v1", b"syntax").unwrap(),
                    "node":"node", "owner":"owner", "session":"session",
                    "incarnation":"incarnation", "owner_generation":"1",
                    "prepared_token":"prepared", "admission":"admission"
                }
            }),
        );
        serde_json::Value::Object(source)
    }

    #[test]
    fn source15_syntax_uses_actual_sorted_writers_and_refuses_reordered_duplicate_or_unknown_keys()
    -> Result<(), ProviderError> {
        let source = source_shape();
        let canonical = canonical::canonical_json(&source)?;
        let serde =
            serde_json::to_vec(&source).map_err(crucible_node_format::ContractError::from)?;

        authenticate_source_syntax(&canonical)?;
        authenticate_source_syntax(&serde)?;
        assert_eq!(canonical, serde);
        assert!(canonical.starts_with(br#"{"ack_emitter_selection":"#));
        let purpose = canonical::canonical_json(&source["invocation"])?;
        authenticate_original_purpose_syntax(&purpose)?;

        let source_text = std::str::from_utf8(&canonical).unwrap();
        let reordered = source_text.replacen(
            "\"ack_emitter_selection\":null,\"capture_allocation_selection\":null",
            "\"capture_allocation_selection\":null,\"ack_emitter_selection\":null",
            1,
        );
        assert_ne!(reordered, source_text);
        assert!(authenticate_source_syntax(reordered.as_bytes()).is_err());
        for extra in ["\"ack_emitter_selection\":null,", "\"unknown\":null,"] {
            let mut changed = String::from("{");
            changed.push_str(extra);
            changed.push_str(&source_text[1..]);
            assert!(authenticate_source_syntax(changed.as_bytes()).is_err());
        }
        assert_eq!(canonical::canonical_json(&source)?, canonical);
        Ok(())
    }

    #[test]
    fn source15_syntax_requires_full_original_purpose_and_exact_field_rosters() {
        let original = source_shape();
        let raw = canonical::canonical_json(&original).unwrap();
        authenticate_source_syntax(&raw).unwrap();
        for axis in 0..8 {
            let mut changed = original.clone();
            match axis {
                0 => {
                    changed
                        .as_object_mut()
                        .unwrap()
                        .remove("native_startup_allocation");
                }
                1 => {
                    changed["unknown_source_field"] = true.into();
                }
                2 => {
                    changed["schema"] =
                        "source-owned.packet-canonical-ack-source-binding/14".into();
                }
                3 => {
                    changed["invocation"]["purpose"] = "restoration_target".into();
                }
                4 => {
                    changed["invocation"]["source"] = json!({"runtime":"foreign"});
                }
                5 => {
                    changed["invocation"]["target"]
                        .as_object_mut()
                        .unwrap()
                        .remove("incarnation");
                }
                6 => {
                    changed["invocation"]["target"]["world"]["domain"] = "cnp.foreign.v1".into();
                }
                _ => {
                    changed["invocation"]["target"]["owner_generation"] = "01".into();
                }
            }
            assert!(
                authenticate_source_syntax(&canonical::canonical_json(&changed).unwrap()).is_err()
            );
        }
        assert_eq!(canonical::canonical_json(&original).unwrap(), raw);
    }
}

pub(crate) mod current17;
