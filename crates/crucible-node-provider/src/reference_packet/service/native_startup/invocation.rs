//! Keeps complete invocation provenance in fixed, allocation-free DATA views.
//!
//! ```json
//! {"schema":"source-owned.packet-native-invocation-purpose/1",
//!  "purpose":"original_execution","source":null,"target":{}}
//! ```
//!
//! A real target contains the complete current node/owner/authority projection.
//! A restoration source contains full Runtime and native-state references. These
//! inert values cannot construct a Source member, bootstrap claim or live token.

use super::super::PacketNative5SourceLaunch;
use crate::ProviderError;
use crucible_node_contract::{ContentRef, HashRef, Id, Validate};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};

const SCHEMA: &str = "source-owned.packet-native-invocation-purpose/1";

fn invalid() -> ProviderError {
    ProviderError::Correlation("native invocation purpose DATA")
}

// Contract identifiers, domains and media types are bounded at 128 bytes. Fixed
// banks retain complete spellings; no digest-only reference substitution occurs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Text {
    bytes: [u8; 128],
    length: u8,
}

impl Text {
    fn new(value: &str) -> Result<Self, ProviderError> {
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(invalid());
        }
        let mut bytes = [0; 128];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            length: value.len() as u8,
        })
    }

    fn text(&self) -> Result<&str, ProviderError> {
        std::str::from_utf8(&self.bytes[..usize::from(self.length)]).map_err(|_| invalid())
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.text().map_err(serde::ser::Error::custom)?)
    }
}

// U64's general serializer creates a decimal String. This fixed borrowed view
// uses the same canonical spelling while keeping precredit projection pure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Decimal(u64);

impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut digits = [0u8; 20];
        let mut first = digits.len();
        let mut value = self.0;
        loop {
            first -= 1;
            digits[first] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let text = std::str::from_utf8(&digits[first..]).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct HashData {
    algorithm: &'static str,
    domain: Text,
    digest: Text,
}

impl HashData {
    fn original(value: &HashRef) -> Result<Self, ProviderError> {
        if value.algorithm != "blake3-256"
            || value.domain.is_empty()
            || value.domain.len() > 128
            || !value.domain.is_ascii()
            || value.digest.len() != 64
            || !value
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        Ok(Self {
            algorithm: "blake3-256",
            domain: Text::new(&value.domain)?,
            digest: Text::new(&value.digest)?,
        })
    }

    fn read(value: &Value) -> Result<Self, ProviderError> {
        let fields = object(value, &["algorithm", "domain", "digest"])?;
        if fields["algorithm"].as_str() != Some("blake3-256") {
            return Err(invalid());
        }
        let domain = string(&fields["domain"])?;
        let digest = string(&fields["digest"])?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        Ok(Self {
            algorithm: "blake3-256",
            domain: Text::new(domain)?,
            digest: Text::new(digest)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct ReferenceData {
    hash: HashData,
    length: Decimal,
    media_type: Text,
}

impl ReferenceData {
    fn original(value: &ContentRef) -> Result<Self, ProviderError> {
        let hash = HashData::original(&value.hash)?;
        if hash.domain.text()? != "cnp.blob.v1"
            || value.media_type.is_empty()
            || value.media_type.len() > 128
            || !value.media_type.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(invalid());
        }
        Ok(Self {
            hash,
            length: Decimal(value.length.get()),
            media_type: Text::new(&value.media_type)?,
        })
    }

    fn read(value: &Value) -> Result<Self, ProviderError> {
        let fields = object(value, &["hash", "length", "media_type"])?;
        let hash = HashData::read(&fields["hash"])?;
        let media = string(&fields["media_type"])?;
        if hash.domain.text()? != "cnp.blob.v1"
            || !media.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(invalid());
        }
        Ok(Self {
            hash,
            length: unsigned(&fields["length"])?,
            media_type: Text::new(media)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct TargetData {
    world: HashData,
    binding: HashData,
    node: Text,
    owner: Text,
    session: Text,
    incarnation: Text,
    owner_generation: Decimal,
    prepared_token: Text,
    admission: Text,
}

impl TargetData {
    fn original(launch: &PacketNative5SourceLaunch) -> Result<Self, ProviderError> {
        Self::control(&launch.selection)
    }

    fn control(
        selection: &crate::reference_packet::control::PacketControlSelection,
    ) -> Result<Self, ProviderError> {
        // Full launch/source correspondence and live authority are independently
        // checked by the issuer. This projection makes no serializer or callback.
        let [binding] = selection.realization.bindings.as_slice() else {
            return Err(invalid());
        };
        let [owner] = selection.realization.owner_bindings.as_slice() else {
            return Err(invalid());
        };
        let [reference] = owner.node_bindings.as_slice() else {
            return Err(invalid());
        };
        if reference.node_id != binding.compatibility.node_id
            || binding.authority.owner_generation.get() == 0
            || selection.world.domain != "cnp.world-binding.v1"
            || reference.binding_hash.domain != "cnp.node-binding.v1"
        {
            return Err(invalid());
        }
        Ok(Self {
            world: HashData::original(&selection.world)?,
            binding: HashData::original(&reference.binding_hash)?,
            node: identifier(&reference.node_id)?,
            owner: identifier(&owner.owner.id)?,
            session: identifier(&binding.authority.session_id)?,
            incarnation: identifier(&binding.authority.incarnation_id)?,
            owner_generation: Decimal(binding.authority.owner_generation.get()),
            prepared_token: identifier(&selection.prepared_token)?,
            admission: identifier(&selection.admission)?,
        })
    }

    fn read(value: &Value) -> Result<Self, ProviderError> {
        let f = object(
            value,
            &[
                "world",
                "binding",
                "node",
                "owner",
                "session",
                "incarnation",
                "owner_generation",
                "prepared_token",
                "admission",
            ],
        )?;
        let result = Self {
            world: HashData::read(&f["world"])?,
            binding: HashData::read(&f["binding"])?,
            node: id_value(&f["node"])?,
            owner: id_value(&f["owner"])?,
            session: id_value(&f["session"])?,
            incarnation: id_value(&f["incarnation"])?,
            owner_generation: unsigned(&f["owner_generation"])?,
            prepared_token: id_value(&f["prepared_token"])?,
            admission: id_value(&f["admission"])?,
        };
        if result.world.domain.text()? != "cnp.world-binding.v1"
            || result.binding.domain.text()? != "cnp.node-binding.v1"
            || result.owner_generation.0 == 0
        {
            return Err(invalid());
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct SourceData {
    runtime: ReferenceData,
    native_state: ReferenceData,
    owner: Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    Original,
    Restoration(SourceData),
}

/// Retains complete bounded invocation provenance without allocating or issuing rights.
///
/// Only Core's registered-holder action can issue a private member. Constructing,
/// copying, parsing or serializing this DATA never chooses a live native purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeInvocationPurposeData {
    target: TargetData,
    purpose: Purpose,
}

impl PacketNativeInvocationPurposeData {
    /// Projects an original target from the same immutable typed launch.
    ///
    /// # Errors
    /// Refuses invalid identifiers/references or a non-singleton target roster.
    pub fn original_execution_data(
        launch: &PacketNative5SourceLaunch,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            target: TargetData::original(launch)?,
            purpose: Purpose::Original,
        })
    }

    /// Projects historical references beside the actual fresh typed launch.
    ///
    /// The caller separately authenticates the original archive ticket and target.
    /// This constructor is DATA plumbing and cannot issue an invocation member.
    ///
    /// # Errors
    /// Refuses invalid full references, a different original owner or target.
    pub fn restoration_target_data(
        launch: &PacketNative5SourceLaunch,
        runtime: &ContentRef,
        native_state: &ContentRef,
        owner: &Id,
    ) -> Result<Self, ProviderError> {
        let target = TargetData::original(launch)?;
        let source = SourceData {
            runtime: ReferenceData::original(runtime)?,
            native_state: ReferenceData::original(native_state)?,
            owner: identifier(owner)?,
        };
        if source.owner != target.owner {
            return Err(invalid());
        }
        Ok(Self {
            target,
            purpose: Purpose::Restoration(source),
        })
    }

    /// Reads one exact purpose object without allocating a typed owner.
    ///
    /// The containing raw/Value owner must remain retained by the caller. Parsed
    /// history never creates an actual Source member, bootstrap claim or token.
    ///
    /// # Errors
    /// Refuses omitted/null/unknown fields, invalid complete references or target.
    pub fn from_original_value_data(value: &Value) -> Result<Self, ProviderError> {
        let f = object(value, &["schema", "purpose", "source", "target"])?;
        if f["schema"].as_str() != Some(SCHEMA) {
            return Err(invalid());
        }
        let target = TargetData::read(&f["target"])?;
        let purpose = match f["purpose"].as_str() {
            Some("original_execution") if f["source"].is_null() => Purpose::Original,
            Some("restoration_target") => {
                let s = object(&f["source"], &["runtime", "native_state", "owner"])?;
                let source = SourceData {
                    runtime: ReferenceData::read(&s["runtime"])?,
                    native_state: ReferenceData::read(&s["native_state"])?,
                    owner: id_value(&s["owner"])?,
                };
                if source.owner != target.owner {
                    return Err(invalid());
                }
                Purpose::Restoration(source)
            }
            _ => return Err(invalid()),
        };
        Ok(Self { target, purpose })
    }

    /// Compares the entire current target projection without replacing authority.
    ///
    /// # Errors
    /// Refuses any current node, binding, world, owner, incarnation or Admit change.
    pub fn authenticate_target_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        if self.target != TargetData::original(launch)? {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares full target DATA with an already retained control selection.
    ///
    /// This borrowed comparison does not enroll or activate historical owners.
    ///
    /// # Errors
    /// Refuses any changed world, binding, node, owner, session, incarnation,
    /// generation, prepared token or admission, or a non-singleton roster.
    pub fn authenticate_control_target_data(
        &self,
        selection: &crate::reference_packet::control::PacketControlSelection,
    ) -> Result<(), ProviderError> {
        if self.target != TargetData::control(selection)? {
            return Err(invalid());
        }
        Ok(())
    }

    /// Reports the explicit original-execution DATA tag, never an inferred absence.
    pub const fn is_original_execution_data(&self) -> bool {
        matches!(self.purpose, Purpose::Original)
    }

    /// Compares the complete original archive references and owner.
    ///
    /// # Errors
    /// Refuses original-execution purpose or any full historical reference change.
    pub fn authenticate_restoration_source_data(
        &self,
        runtime: &ContentRef,
        native_state: &ContentRef,
        owner: &Id,
    ) -> Result<(), ProviderError> {
        let expected = SourceData {
            runtime: ReferenceData::original(runtime)?,
            native_state: ReferenceData::original(native_state)?,
            owner: identifier(owner)?,
        };
        if self.purpose != Purpose::Restoration(expected) {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Serialize for PacketNativeInvocationPurposeData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("NativeInvocationPurpose", 4)?;
        fields.serialize_field("schema", SCHEMA)?;
        match &self.purpose {
            Purpose::Original => {
                fields.serialize_field("purpose", "original_execution")?;
                fields.serialize_field("source", &Option::<SourceData>::None)?;
            }
            Purpose::Restoration(source) => {
                fields.serialize_field("purpose", "restoration_target")?;
                fields.serialize_field("source", &Some(source))?;
            }
        }
        fields.serialize_field("target", &self.target)?;
        fields.end()
    }
}

fn identifier(value: &Id) -> Result<Text, ProviderError> {
    value.validate()?;
    Text::new(value.as_str())
}

fn id_value(value: &Value) -> Result<Text, ProviderError> {
    let value = string(value)?;
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(invalid());
    }
    Text::new(value)
}

fn string(value: &Value) -> Result<&str, ProviderError> {
    value.as_str().ok_or_else(invalid)
}

fn unsigned(value: &Value) -> Result<Decimal, ProviderError> {
    let text = string(value)?;
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(invalid());
    }
    text.parse::<u64>().map(Decimal).map_err(|_| invalid())
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let fields = value.as_object().ok_or_else(invalid)?;
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(fields)
}

/// Names fixed purpose/borrow views; recursive and allocator costs are separate.
pub const fn original_native_invocation_counter_scratch_data() -> usize {
    std::mem::size_of::<PacketNativeInvocationPurposeData>()
        + std::mem::size_of::<TargetData>() + std::mem::size_of::<SourceData>()
        + std::mem::size_of::<ReferenceData>() + std::mem::size_of::<HashData>()
        + 6 * std::mem::size_of::<&Map<String, Value>>()
        + std::mem::size_of::<[u8; 20]>()
        // Root4, target9, source3, reference3 and hash3 names are explicit
        // logical arrays; all are summed even when branches do not overlap.
        + std::mem::size_of::<[&str; 4]>()
        + std::mem::size_of::<[&str; 9]>()
        + 3 * std::mem::size_of::<[&str; 3]>()
        + crate::reference_packet::service::report_startup::original_invocation_report_startup_allocation_counter_scratch_data()
        + wire::counter_scratch_data()
        + storage::counter_scratch_data()
        // New native claim/first-baseline views coexist with the complete old
        // counter. None of these headers borrows heap/tree backing as credit.
        + 2 * std::mem::size_of::<super::PacketNativeInvocationPreambleData>()
        + 4 * std::mem::size_of::<PacketNativeInvocationPurposeData>()
        + std::mem::size_of::<Option<PacketNativeInvocationPurposeData>>()
        + std::mem::size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>()
        + std::mem::size_of::<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'_>>()
        + std::mem::size_of::<[&[u8]; 3]>()
        + std::mem::size_of::<[u8; 128]>() // actual borrowed Fields::span cursor
        + std::mem::size_of::<[bool; 11]>()
        + std::mem::size_of::<[usize; 10]>()
        + 2 * std::mem::size_of::<fn(&[u8], usize) -> Result<(), ProviderError>>()
}

/// Names fixed views for the allocation-free complete invocation-value reader.
///
/// The caller retains the original Value and credits these views before reading
/// it. All text is copied only into bounded inline arrays. No metadata decoder,
/// serializer, owner clone, callback, file access or live permission is involved.
pub const fn original_native_invocation_value_counter_scratch_data() -> usize {
    use std::mem::size_of;

    original_native_invocation_counter_scratch_data()
        + size_of::<Result<TargetData, ProviderError>>()
        + size_of::<Result<SourceData, ProviderError>>()
        + size_of::<Result<ReferenceData, ProviderError>>()
        + size_of::<Result<HashData, ProviderError>>()
        + size_of::<Result<Text, ProviderError>>()
        + size_of::<Result<Decimal, ProviderError>>()
        + size_of::<Result<Decimal, std::num::ParseIntError>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + 6 * size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<&Value>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<&[u8]>()
        + size_of::<u8>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{U64, canonical};
    use serde_json::json;

    // Inert closed DATA, not a constructor of a Source, ticket or live boot.
    pub(super) fn target() -> TargetData {
        let hash =
            |domain| HashData::original(&canonical::hash(domain, b"original").unwrap()).unwrap();
        TargetData {
            world: hash("cnp.world-binding.v1"),
            binding: hash("cnp.node-binding.v1"),
            node: Text::new("node").unwrap(),
            owner: Text::new("owner").unwrap(),
            session: Text::new("session").unwrap(),
            incarnation: Text::new("incarnation").unwrap(),
            owner_generation: Decimal(2),
            prepared_token: Text::new("prepared").unwrap(),
            admission: Text::new("admission").unwrap(),
        }
    }

    #[test]
    fn explicit_original_and_target_shapes_roundtrip_without_absence_inference() {
        let original = PacketNativeInvocationPurposeData {
            target: target(),
            purpose: Purpose::Original,
        };
        let value = serde_json::to_value(original).unwrap();
        assert_eq!(
            PacketNativeInvocationPurposeData::from_original_value_data(&value).unwrap(),
            original
        );
        for field in ["schema", "purpose", "source", "target"] {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(PacketNativeInvocationPurposeData::from_original_value_data(&changed).is_err());
        }
        let mut changed = value.clone();
        changed["purpose"] = json!("restoration_target");
        assert!(PacketNativeInvocationPurposeData::from_original_value_data(&changed).is_err());
        changed = value;
        changed["extra"] = json!(false);
        assert!(PacketNativeInvocationPurposeData::from_original_value_data(&changed).is_err());
    }

    #[test]
    fn restoration_checks_every_full_reference_axis_and_owner() {
        let runtime = canonical::content_ref(b"runtime", "application/runtime").unwrap();
        let native = canonical::content_ref(b"native", "application/native").unwrap();
        let owner = Id::new("owner").unwrap();
        let source = SourceData {
            runtime: ReferenceData::original(&runtime).unwrap(),
            native_state: ReferenceData::original(&native).unwrap(),
            owner: identifier(&owner).unwrap(),
        };
        let original = PacketNativeInvocationPurposeData {
            target: target(),
            purpose: Purpose::Restoration(source),
        };
        let value = serde_json::to_value(original).unwrap();
        assert_eq!(
            PacketNativeInvocationPurposeData::from_original_value_data(&value).unwrap(),
            original
        );
        original
            .authenticate_restoration_source_data(&runtime, &native, &owner)
            .unwrap();
        for change_native in [false, true] {
            for axis in 0..5 {
                let mut runtime = runtime.clone();
                let mut native = native.clone();
                let reference = if change_native {
                    &mut native
                } else {
                    &mut runtime
                };
                match axis {
                    0 => reference.hash.algorithm = "other".into(),
                    1 => reference.hash.domain = "different.domain".into(),
                    2 => {
                        let first = if &reference.hash.digest[..1] == "0" {
                            "1"
                        } else {
                            "0"
                        };
                        reference.hash.digest.replace_range(0..1, first);
                    }
                    3 => reference.length = U64::new(reference.length.get() + 1),
                    _ => reference.media_type.push('x'),
                }
                assert!(
                    original
                        .authenticate_restoration_source_data(&runtime, &native, &owner)
                        .is_err()
                );
            }
        }
        assert!(
            original
                .authenticate_restoration_source_data(
                    &runtime,
                    &native,
                    &Id::new("foreign").unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn target_field_changes_remain_visible_and_invalid_identity_spelling_refuses() {
        let original = PacketNativeInvocationPurposeData {
            target: target(),
            purpose: Purpose::Original,
        };
        let value = serde_json::to_value(original).unwrap();
        for field in [
            "node",
            "owner",
            "session",
            "incarnation",
            "prepared_token",
            "admission",
        ] {
            let mut changed = value.clone();
            changed["target"][field] = json!("other");
            assert_ne!(
                PacketNativeInvocationPurposeData::from_original_value_data(&changed).unwrap(),
                original
            );
            changed["target"][field] = json!("-invalid-first");
            assert!(PacketNativeInvocationPurposeData::from_original_value_data(&changed).is_err());
        }
        for (field, replacement) in [
            ("owner_generation", json!("3")),
            (
                "world",
                json!({"algorithm":"blake3-256","domain":"cnp.world-binding.v1","digest":"a".repeat(64)}),
            ),
            (
                "binding",
                json!({"algorithm":"blake3-256","domain":"cnp.node-binding.v1","digest":"b".repeat(64)}),
            ),
        ] {
            let mut changed = value.clone();
            changed["target"][field] = replacement;
            assert_ne!(
                PacketNativeInvocationPurposeData::from_original_value_data(&changed).unwrap(),
                original
            );
        }
        for value in [
            json!("00"),
            json!("-1"),
            json!(1),
            json!("18446744073709551616"),
        ] {
            assert!(unsigned(&value).is_err());
        }
    }

    #[test]
    fn fixed_decimal_view_matches_the_actual_contract_for_all_boundaries() {
        for value in [0, 1, 9, 10, u64::MAX] {
            assert_eq!(
                serde_json::to_vec(&Decimal(value)).unwrap(),
                serde_json::to_vec(&U64::new(value)).unwrap()
            );
        }
    }
}

#[path = "invocation/wire.rs"]
mod wire;
pub use wire::{
    PacketNativeInvocationLaunchIdentityData, original_native_invocation_launch_identity_data,
    write_original_native_invocation_launch_data, write_original_native_invocation_purpose_data,
};

#[path = "invocation/storage.rs"]
mod storage;
pub use storage::{
    PacketNativeInvocationConstructionStorageData,
    original_native_invocation_construction_storage_data,
};

impl PacketNativeInvocationPurposeData {
    /// Names fixed views for borrowing the same canonical nested launch literal.
    ///
    /// The private boot or Source owner authenticates provenance independently.
    /// This layout DATA grants no decoder, Prepare, Commit or installation scope.
    pub const fn original_launch_literal_counter_scratch_data() -> usize {
        std::mem::size_of::<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>>()
            + std::mem::size_of::<[u8; 128]>()
            + std::mem::size_of::<[&[u8]; 3]>()
    }
}

#[path = "invocation/settled17.rs"]
mod settled17;
