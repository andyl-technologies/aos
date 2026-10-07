//! One strict selected-image comparison contract shared by Root and Controller.
//!
//! `profile.json` is image-built JSON, not a signed or transferable authority.
//! Its one self-referencing OpenFile pathname is normalized to the documented
//! placeholder; all other bytes of the actual selected unit remain committed.
//!
//! ```text
//! AOS_NORMAL_ROOT_STARTUP_1: unit/context/identities + image pins +
//! canonical policy/source policy/effective checker pins + normalized unit SHA256
//! ```

use std::path::Path;

use serde::Deserialize;

use super::NormalRootStartupErrorV1;

pub(super) const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
pub(super) const MAXIMUM_RUNTIME_FILES: usize = 512;
pub(super) const PROFILE_PLACEHOLDER: &str = "@AOS_NORMAL_ROOT_PROFILE@";
pub(super) const UNIT: &str = "aos-sandbox-policy-authorityd.service";
pub(super) const CONTEXT: &str = "system_u:system_r:aos_sandbox_policy_authority_t";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImagePinV1 {
    pub(super) path: String,
    pub(super) sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NormalRootProfileV1 {
    format: String,
    unit: String,
    context: String,
    pub(super) identities: [u32; 4],
    pub(super) executable: ImagePinV1,
    pub(super) pid1: ImagePinV1,
    pub(super) loader: ImagePinV1,
    pub(super) runtime_files: Vec<ImagePinV1>,
    pub(super) closure_roots: Vec<String>,
    pub(super) canonical_policy: ImagePinV1,
    pub(super) source_policy: ImagePinV1,
    pub(super) effective_matrix: ImagePinV1,
    pub(super) unit_sha256: [u8; 32],
}

impl NormalRootProfileV1 {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, NormalRootStartupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        let profile: Self =
            serde_json::from_slice(bytes).map_err(|_| NormalRootStartupErrorV1::Profile)?;
        require_profile(&profile)?;
        Ok(profile)
    }
}

// Ordinary and selected decoding share the same complete validation kernel.
fn require_profile(profile: &NormalRootProfileV1) -> Result<(), NormalRootStartupErrorV1> {
    if profile.format != "AOS_NORMAL_ROOT_STARTUP_1"
        || profile.unit != UNIT
        || profile.context != CONTEXT
        || profile.identities[0] == 0
        || profile.identities[1] == 0
        || profile.unit_sha256 == [0; 32]
        || profile.runtime_files.is_empty()
        || profile.runtime_files.len() > MAXIMUM_RUNTIME_FILES
        || profile.closure_roots.is_empty()
        || profile.closure_roots.len() > MAXIMUM_RUNTIME_FILES
        || profile
            .closure_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || profile
            .runtime_files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(NormalRootStartupErrorV1::Profile);
    }
    for root in &profile.closure_roots {
        require_store_path(root)?;
        if Path::new(root).components().count() != 4 {
            return Err(NormalRootStartupErrorV1::Profile);
        }
    }
    for pin in profile.runtime_files.iter().chain([
        &profile.executable,
        &profile.pid1,
        &profile.loader,
        &profile.canonical_policy,
        &profile.source_policy,
        &profile.effective_matrix,
    ]) {
        require_store_path(&pin.path)?;
        if pin.sha256 == [0; 32] {
            return Err(NormalRootStartupErrorV1::Profile);
        }
    }
    for pin in &profile.runtime_files {
        if !profile.closure_roots.iter().any(|root| {
            Path::new(&pin.path)
                .strip_prefix(root)
                .is_ok_and(|suffix| suffix.components().count() > 0)
        }) {
            return Err(NormalRootStartupErrorV1::Profile);
        }
    }
    for pin in [&profile.executable, &profile.loader] {
        if !profile
            .runtime_files
            .iter()
            .any(|member| member.path == pin.path && member.sha256 == pin.sha256)
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
    }
    if Path::new(&profile.executable.path)
        .file_name()
        .is_none_or(|name| name != "aos-sandbox-policy-authorityd")
        || !profile
            .canonical_policy
            .path
            .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
        || !profile
            .effective_matrix
            .path
            .ends_with("-aos-normal-root-startup-profile-1/effective-policy.tsv")
        || !profile
            .source_policy
            .path
            .ends_with("-aos-normal-root-startup-profile-1/source-policy.33")
        || Path::new(&profile.source_policy.path).parent()
            != Path::new(&profile.effective_matrix.path).parent()
    {
        return Err(NormalRootStartupErrorV1::Profile);
    }
    Ok(())
}


// This destination is reusable custody, not a positive receiving admission.
// It retains the actual Serde/allocator results. Allocator abort/OOM, escaped
// JSON scratch, and enclosing runtime/native costs still need their suppliers.
#[derive(Default)]
pub(super) struct RootProfileDecodeAttemptV1 {
    returned: Option<Result<NormalRootProfileV1, serde_json::Error>>,
    trailing: Option<Result<(), serde_json::Error>>,
    validation: Option<Result<(), NormalRootStartupErrorV1>>,
    allocations: ProfileStringAllocations,
    attempted: bool,
}

impl RootProfileDecodeAttemptV1 {
    pub(super) fn decode_once(
        &mut self,
        bytes: &[u8],
    ) -> Result<&NormalRootProfileV1, NormalRootStartupErrorV1> {
        if self.attempted {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.attempted = true;
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            self.validation = Some(Err(NormalRootStartupErrorV1::Profile));
            return Err(NormalRootStartupErrorV1::Profile);
        }

        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        self.returned = Some(NormalRootProfileV1::deserialize(BoundedProfileDeserializer {
            inner: &mut decoder,
            allocations: &mut self.allocations,
        }));
        if !matches!(self.returned, Some(Ok(_))) {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        self.trailing = Some(decoder.end());
        if !matches!(self.trailing, Some(Ok(()))) {
            return Err(NormalRootStartupErrorV1::Profile);
        }

        let profile = self.returned.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(NormalRootStartupErrorV1::Profile)?;
        self.validation = Some(require_profile(profile));
        if !matches!(self.validation, Some(Ok(()))) {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        Ok(profile)
    }
}

// The adapter intercepts collection/string admission only. The existing
// derived model remains the sole schema and Serde remains the sole JSON engine.
struct BoundedProfileDeserializer<'original, D> {
    inner: D,
    allocations: &'original mut ProfileStringAllocations,
}

macro_rules! profile_deserializer_methods {
    ($($method:ident),* $(,)?) => {
        $(fn $method<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.inner.$method(BoundedProfileVisitor {
                inner: visitor,
                allocations: self.allocations,
                owned_string: false,
            })
        })*
    };
}

impl<'de, D: serde::Deserializer<'de>> serde::Deserializer<'de>
    for BoundedProfileDeserializer<'_, D>
{
    type Error = D::Error;

    profile_deserializer_methods!(
        deserialize_any, deserialize_bool, deserialize_i8, deserialize_i16,
        deserialize_i32, deserialize_i64, deserialize_i128, deserialize_u8,
        deserialize_u16, deserialize_u32, deserialize_u64, deserialize_u128,
        deserialize_f32, deserialize_f64, deserialize_char, deserialize_str,
        deserialize_bytes, deserialize_byte_buf, deserialize_option,
        deserialize_unit, deserialize_seq, deserialize_map,
        deserialize_identifier, deserialize_ignored_any,
    );

    fn deserialize_string<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_string(BoundedProfileVisitor {
            inner: visitor,
            allocations: self.allocations,
            owned_string: true,
        })
    }

    fn deserialize_unit_struct<V: serde::de::Visitor<'de>>(
        self, name: &'static str, visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_unit_struct(name, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self, name: &'static str, visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_newtype_struct(name, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn deserialize_tuple<V: serde::de::Visitor<'de>>(
        self, length: usize, visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple(length, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn deserialize_tuple_struct<V: serde::de::Visitor<'de>>(
        self, name: &'static str, length: usize, visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple_struct(name, length, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self, name: &'static str, fields: &'static [&'static str], visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_struct(name, fields, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self, name: &'static str, variants: &'static [&'static str], visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_enum(name, variants, BoundedProfileVisitor {
            inner: visitor, allocations: self.allocations, owned_string: false,
        })
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

struct BoundedProfileVisitor<'original, V> {
    inner: V,
    allocations: &'original mut ProfileStringAllocations,
    owned_string: bool,
}

macro_rules! profile_scalar_visits {
    ($($method:ident($value:ty)),* $(,)?) => {
        $(fn $method<E: serde::de::Error>(self, value: $value) -> Result<Self::Value, E> {
            self.inner.$method(value)
        })*
    };
}

impl<'de, V: serde::de::Visitor<'de>> serde::de::Visitor<'de>
    for BoundedProfileVisitor<'_, V>
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }

    profile_scalar_visits!(
        visit_bool(bool), visit_i8(i8), visit_i16(i16), visit_i32(i32),
        visit_i64(i64), visit_i128(i128), visit_u8(u8), visit_u16(u16),
        visit_u32(u32), visit_u64(u64), visit_u128(u128), visit_f32(f32),
        visit_f64(f64), visit_char(char), visit_bytes(&[u8]),
        visit_borrowed_bytes(&'de [u8]), visit_byte_buf(Vec<u8>),
    );

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        require_profile_string(value)?;
        if self.owned_string {
            self.inner.visit_string(reserve_profile_string(value, self.allocations)?)
        } else {
            self.inner.visit_str(value)
        }
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        require_profile_string(value)?;
        if self.owned_string {
            self.inner.visit_string(reserve_profile_string(value, self.allocations)?)
        } else {
            self.inner.visit_borrowed_str(value)
        }
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        require_profile_string(&value)?;
        self.inner.visit_string(value)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(BoundedProfileDeserializer {
            inner: decoder, allocations: self.allocations,
        })
    }

    fn visit_newtype_struct<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(BoundedProfileDeserializer {
            inner: decoder, allocations: self.allocations,
        })
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, sequence: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(BoundedProfileSequence {
            inner: sequence, allocations: self.allocations, count: 0,
        })
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(BoundedProfileMap {
            inner: map, allocations: self.allocations,
        })
    }

    // The current profile model has no enum-valued fields. This preserves
    // Serde's native type refusal instead of inventing another schema.
    fn visit_enum<A: serde::de::EnumAccess<'de>>(self, value: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(value)
    }
}

fn require_profile_string<E: serde::de::Error>(value: &str) -> Result<(), E> {
    if value.len() > 1024 {
        return Err(E::custom("Root profile string exceeds its fixed extent"));
    }
    Ok(())
}

// Six fixed image paths, three fixed labels, and both 512-entry collections
// bound the number of owned strings in the same derived model.
const MAXIMUM_PROFILE_STRINGS: usize = 6 + 3 + 2 * MAXIMUM_RUNTIME_FILES;

#[derive(Default)]
struct ProfileStringAllocations {
    failure: Option<std::collections::TryReserveError>,
    failed_capacity: Option<String>,
    admitted_capacity: usize,
    count: usize,
}

fn reserve_profile_string<E: serde::de::Error>(
    value: &str,
    original: &mut ProfileStringAllocations,
) -> Result<String, E> {
    if original.count >= MAXIMUM_PROFILE_STRINGS {
        return Err(E::custom("Root profile string count exceeds its fixed extent"));
    }
    let mut retained = String::new();
    if let Err(error) = retained.try_reserve_exact(value.len()) {
        original.failure = Some(error);
        return Err(E::custom("Root profile string reservation failed"));
    }
    if retained.capacity() > 1024 {
        original.failed_capacity = Some(retained);
        return Err(E::custom("Root profile string capacity exceeds its fixed extent"));
    }
    original.admitted_capacity += retained.capacity();
    original.count += 1;
    retained.push_str(value);
    Ok(retained)
}

struct BoundedProfileSeed<'original, S> {
    inner: S,
    allocations: &'original mut ProfileStringAllocations,
    admitted: bool,
}

impl<'de, S: serde::de::DeserializeSeed<'de>> serde::de::DeserializeSeed<'de>
    for BoundedProfileSeed<'_, S>
{
    type Value = S::Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        if !self.admitted {
            return Err(serde::de::Error::custom("Root profile collection exceeds 512 entries"));
        }
        self.inner.deserialize(BoundedProfileDeserializer {
            inner: decoder, allocations: self.allocations,
        })
    }
}

struct BoundedProfileSequence<'original, A> {
    inner: A,
    allocations: &'original mut ProfileStringAllocations,
    count: usize,
}

impl<'de, A: serde::de::SeqAccess<'de>> serde::de::SeqAccess<'de>
    for BoundedProfileSequence<'_, A>
{
    type Error = A::Error;

    fn next_element_seed<S: serde::de::DeserializeSeed<'de>>(
        &mut self, seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        // Serde checks the closing delimiter before calling the seed. Thus a
        // valid 512-element collection ends normally, while entry 513 cannot
        // decode or allocate its first field.
        let returned = self.inner.next_element_seed(BoundedProfileSeed {
            inner: seed,
            allocations: self.allocations,
            admitted: self.count < MAXIMUM_RUNTIME_FILES,
        })?;
        if returned.is_some() {
            self.count += 1;
        }
        Ok(returned)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint().map(|size| size.min(MAXIMUM_RUNTIME_FILES - self.count))
    }
}

struct BoundedProfileMap<'original, A> {
    inner: A,
    allocations: &'original mut ProfileStringAllocations,
}

impl<'de, A: serde::de::MapAccess<'de>> serde::de::MapAccess<'de>
    for BoundedProfileMap<'_, A>
{
    type Error = A::Error;

    fn next_key_seed<S: serde::de::DeserializeSeed<'de>>(
        &mut self, seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        self.inner.next_key_seed(BoundedProfileSeed {
            inner: seed, allocations: self.allocations, admitted: true,
        })
    }

    fn next_value_seed<S: serde::de::DeserializeSeed<'de>>(
        &mut self, seed: S,
    ) -> Result<S::Value, Self::Error> {
        self.inner.next_value_seed(BoundedProfileSeed {
            inner: seed, allocations: self.allocations, admitted: true,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

pub(crate) fn require_store_path(path: &str) -> Result<(), NormalRootStartupErrorV1> {
    let relative = path
        .strip_prefix("/nix/store/")
        .filter(|value| !value.is_empty() && path.len() <= 1024)
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    let root = relative
        .split('/')
        .next()
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    let (hash, name) = root
        .split_once('-')
        .ok_or(NormalRootStartupErrorV1::Profile)?;
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        || name.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\\' | b'"'))
    {
        return Err(NormalRootStartupErrorV1::Profile);
    }
    Ok(())
}

pub(super) fn normalized_unit(
    bytes: &[u8],
    profile_path: &str,
) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NormalRootStartupErrorV1::Service)?;
    let actual = format!("OpenFile={profile_path}:aos-normal-root-profile:read-only\n");
    let placeholder = format!("OpenFile={PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count()
        != 1
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(text
        .split_inclusive('\n')
        .map(|line| {
            if line == actual {
                placeholder.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}
