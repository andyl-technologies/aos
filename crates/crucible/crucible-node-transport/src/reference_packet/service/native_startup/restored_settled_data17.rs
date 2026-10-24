//! Carries separately admitted Capture17 beside an unchanged suffix launch7.
//!
//! ```text
//! wrapper8 = {capture_reservation:<fixed Carrier17>,existing_rows:<actual pre-new17 rows>,schema_version:8,suffix:<exact7>}
//! prefix17 = baseline fields[328] Capture carrier[176] key[32] MAC[32]
//! ```
//!
//! The new private reader must authenticate the actual inherited parent and
//! Source MAC, reconcile the complete genuine quote, and retain its own reserve.
//! Parsing or comparing this DATA never installs credit or grants Capture.

use super::super::PacketNative5SourceLaunch;
use super::restored_suffix::{
    PacketNative7RestoredSuffixLaunch, PacketNativeSuffixLaunchIdentityData,
    PacketNativeSuffixPreambleData, PacketRestoredSuffixReservationData,
    decode_original_native_suffix_preamble_data, encode_original_native_suffix_preamble_data,
    write_original_native_suffix_launch_data,
};
use super::*;
use super::{PacketRestoredSettledNativeCarrierData, PacketRestoredSettledNativeExistingRowsData};
use crate::ProviderError;
use crucible_node_format::{Id, SchemaRef, U64, canonical};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::io::Write;

const SCHEMA: &str = "source-owned.packet-restored-settled-startup/17";
const CONTRACT: &[u8] = include_bytes!("restored_settled_contract17.json");
const MAGIC: &[u8; 8] = b"CNPNS17\0";
const DOMAIN: &str = "source-owned.packet-native-restored-settled-startup-preamble/17";
const KEY: std::ops::Range<usize> = 504..536;
const MAC: std::ops::Range<usize> = 536..568;

/// Names the complete explicitly encoded private prefix17 extent.
pub const ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES: usize = 568;

/// Borrows the complete compiled new carrier definition.
pub const fn restored_settled_startup_contract_data() -> &'static [u8] {
    CONTRACT
}

/// Returns the exact new private carrier schema without selecting it.
///
/// # Errors
/// Reports invalid compiled identifiers or full-reference construction failure.
pub fn restored_settled_startup_schema_data() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(SCHEMA)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares the complete immutable startup17 definition with fixed hash scratch.
///
/// # Errors
/// Refuses any changed schema identity, extension or full definition reference.
pub fn authenticate_restored_settled_startup_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let length = u64::try_from(CONTRACT.len()).map_err(|_| invalid())?;
    if schema.id.as_str() != SCHEMA
        || schema.version != 17
        || !schema.extensions.is_empty()
        || schema.definition.media_type != "application/json"
        || schema.definition.length.get() != length
        || schema.definition.hash.algorithm != "blake3-256"
        || schema.definition.hash.domain != "cnp.blob.v1"
    {
        return Err(invalid());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    hasher.update(CONTRACT);
    if hasher.finalize().to_hex().as_str() != schema.definition.hash.digest.as_str() {
        return Err(invalid());
    }
    Ok(())
}

/// Names only the fixed schema comparator, independently of full carrier work.
///
/// Keeping this leaf independent prevents a selection/output-policy quote cycle.
pub fn restored_settled_startup_schema_counter_scratch_data() -> usize {
    use std::mem::{size_of, size_of_val};
    size_of::<&SchemaRef>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<(), ProviderError>>()
}

/// Retains complete decoded wrapper8 DATA, including failed nested typed custody.
pub struct PacketNative8RestoredSettledLaunch {
    capture: PacketRestoredSettledNativeCarrierData,
    existing_rows: PacketRestoredSettledNativeExistingRowsData,
    suffix: Option<PacketNative7RestoredSuffixLaunch>,
    extracted: Option<(
        PacketNativeInvocationPurposeData,
        PacketRestoredSuffixReservationData,
    )>,
    complete: bool,
}

impl PacketNative8RestoredSettledLaunch {
    /// Retains a fresh fixed owner before decoding the unchanged nested launch7.
    ///
    /// The caller already retains its separately prepaid raw frame/DOM. This
    /// method does not validate a private MAC or install any native reservation.
    ///
    /// # Errors
    /// Refuses wrong/extra fields, an occupied destination, malformed fixed DATA,
    /// failed old7 correspondence or changed output policy/full17 declarations.
    pub fn decode_original_value_into(
        value: &serde_json::Value,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        let fields = value.as_object().ok_or_else(invalid)?;
        if fields.len() != 4
            || fields
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(8)
            || !fields.contains_key("existing_rows")
            || !fields.contains_key("capture_reservation")
            || !fields.contains_key("suffix")
        {
            return Err(invalid());
        }
        let capture =
            PacketRestoredSettledNativeCarrierData::deserialize(&fields["capture_reservation"])
                .map_err(crucible_node_format::ContractError::from)?;
        let existing_rows =
            PacketRestoredSettledNativeExistingRowsData::deserialize(&fields["existing_rows"])
                .map_err(crucible_node_format::ContractError::from)?;
        *output = Some(Self {
            capture,
            existing_rows,
            suffix: None,
            extracted: None,
            complete: false,
        });
        let retained = output.as_mut().ok_or_else(invalid)?;
        retained.capture.validate_data()?;
        PacketNative7RestoredSuffixLaunch::decode_original_value_into(
            &fields["suffix"],
            &mut retained.suffix,
        )?;
        let suffix = retained.suffix.as_ref().ok_or_else(invalid)?;
        if retained.existing_rows.suffix != suffix.suffix_reservation_data() {
            return Err(invalid());
        }
        retained
            .capture
            .output_limits
            .authenticate_same_launch_data(suffix.launch_data())?;
        if retained.capture.maximum_originals > suffix.launch_data().limits.requests {
            return Err(invalid());
        }
        retained.complete = true;
        Ok(())
    }

    /// Moves the exact decoded typed launch into retained service custody once.
    ///
    /// The fixed invocation/reservation identity remains in this owner beside
    /// the Capture carrier. No clone, deserialize or private grant is created.
    ///
    /// # Errors
    /// Refuses occupied destination, incomplete decoding or repeated transfer.
    /// All checks finish before any field is moved or destination is changed.
    pub fn take_launch_into(
        &mut self,
        output: &mut Option<PacketNative5SourceLaunch>,
    ) -> Result<(), ProviderError> {
        if output.is_some() || !self.complete || self.extracted.is_some() || self.suffix.is_none() {
            return Err(invalid());
        }
        let suffix = self.suffix.take().ok_or_else(invalid)?;
        let (purpose, launch, reservation) = suffix.into_parts_data();
        self.extracted = Some((purpose, reservation));
        *output = Some(launch);
        Ok(())
    }

    /// Copies retained invocation identity before or after the typed owner move.
    ///
    /// # Errors
    /// Refuses incomplete decoding. The returned value remains only DATA.
    pub fn invocation_data(&self) -> Result<PacketNativeInvocationPurposeData, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        match (&self.suffix, &self.extracted) {
            (Some(suffix), None) => Ok(suffix.invocation_data()),
            (None, Some((purpose, _))) => Ok(*purpose),
            _ => Err(invalid()),
        }
    }

    /// Copies the same independent old suffix reservation after transfer as DATA.
    ///
    /// # Errors
    /// Refuses incomplete or inconsistent owner movement, never supplies credit.
    pub fn suffix_reservation_data(
        &self,
    ) -> Result<PacketRestoredSuffixReservationData, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        match (&self.suffix, &self.extracted) {
            (Some(suffix), None) => Ok(suffix.suffix_reservation_data()),
            (None, Some((_, reservation))) => Ok(*reservation),
            _ => Err(invalid()),
        }
    }

    /// Borrows the genuinely complete old7 DATA child without changing its family.
    ///
    /// # Errors
    /// Refuses incomplete or failed decoding. This remains DATA, not a live boot.
    pub fn suffix_data(&self) -> Result<&PacketNative7RestoredSuffixLaunch, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        self.suffix.as_ref().ok_or_else(invalid)
    }

    /// Borrows the authenticated wrapper's actual pre-new17 row snapshot as DATA.
    ///
    /// # Errors
    /// Refuses incomplete decoding. Private MAC and real producer joins remain required.
    pub fn existing_rows_data(
        &self,
    ) -> Result<&PacketRestoredSettledNativeExistingRowsData, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        Ok(&self.existing_rows)
    }

    /// Borrows the exact complete separately admitted Capture advertisement.
    ///
    /// # Errors
    /// Refuses incomplete decoding; current quote/MAC/issuer checks remain required.
    pub fn capture_reservation_data(
        &self,
    ) -> Result<&PacketRestoredSettledNativeCarrierData, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        Ok(&self.capture)
    }
}

/// Holds fixed new-prefix DATA independently of its actual private issuer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketNativeSettledPreambleData {
    /// Preserves all old fields/rows; launch identity binds complete wrapper8.
    pub suffix: PacketNativeSuffixPreambleData,
    /// Carries new independent ingress/action/output quantities and identities.
    pub capture: PacketRestoredSettledNativeCarrierData,
}

/// Encodes every fixed field under the new complete private-MAC domain.
///
/// # Errors
/// Refuses invalid old fields, new carrier limits, extent or checked conversions.
pub fn encode_original_native_settled_preamble_data(
    data: &PacketNativeSettledPreambleData,
    key: &[u8; 32],
) -> Result<[u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES], ProviderError> {
    data.capture.validate_data()?;
    let old = encode_original_native_suffix_preamble_data(&data.suffix, key)?;
    let mut bytes = [0u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES];
    bytes[..328].copy_from_slice(&old[..328]);
    bytes[..8].copy_from_slice(MAGIC);
    encode_carrier(&data.capture, &mut bytes[328..504])?;
    bytes[KEY].copy_from_slice(key);
    let signature = signature(&bytes[..536], key);
    bytes[MAC].copy_from_slice(signature.as_bytes());
    Ok(bytes)
}

/// Decodes fixed prefix17 DATA without pretending an old MAC authorizes boot.
///
/// # Errors
/// Refuses other extents/families or invalid old/new fixed fields and quantities.
pub fn decode_original_native_settled_preamble_data(
    bytes: &[u8],
) -> Result<PacketNativeSettledPreambleData, ProviderError> {
    if bytes.len() != ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    let mut old = [0u8; 392];
    old[..328].copy_from_slice(&bytes[..328]);
    old[..8].copy_from_slice(b"CNPNS16\0");
    old[328..360].copy_from_slice(&bytes[KEY]);
    // The old helper only decodes DATA; it deliberately does not check its MAC.
    let suffix = decode_original_native_suffix_preamble_data(&old)?;
    let capture = decode_carrier(&bytes[328..504])?;
    Ok(PacketNativeSettledPreambleData { suffix, capture })
}

/// Authenticates the complete new prefix under its actual expected private key.
///
/// # Errors
/// Refuses changed version/fields/key/MAC. A valid MAC is still not parent,
/// Source, native boot, current quote or Capture admission authority by itself.
pub fn authenticate_original_native_settled_preamble_data(
    bytes: &[u8],
    expected_key: &[u8],
) -> Result<(), ProviderError> {
    let key: &[u8; 32] = expected_key.try_into().map_err(|_| invalid())?;
    decode_original_native_settled_preamble_data(bytes)?;
    if !equal(&bytes[KEY], key) || !equal(&bytes[MAC], signature(&bytes[..536], key).as_bytes()) {
        return Err(invalid());
    }
    Ok(())
}

fn signature(bytes: &[u8], key: &[u8; 32]) -> blake3::Hash {
    blake3::keyed_hash(&blake3::derive_key(DOMAIN, key), bytes)
}

fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn encode_carrier(
    data: &PacketRestoredSettledNativeCarrierData,
    out: &mut [u8],
) -> Result<(), ProviderError> {
    if out.len() != 176 {
        return Err(invalid());
    }
    out[..8].copy_from_slice(&data.version.get().to_be_bytes());
    out[8..40].copy_from_slice(&data.launch_identity);
    out[40..72].copy_from_slice(&data.import_identity);
    out[72..80].copy_from_slice(&data.normalization_maximum.get().to_be_bytes());
    out[80..88].copy_from_slice(&data.maximum_originals.get().to_be_bytes());
    for (offset, row) in [(88, data.ingress), (112, data.actions)] {
        for (at, value) in [
            row.retained_requested_bytes,
            row.maximum_simultaneous_transient_bytes,
            row.declared_counter_scratch_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            out[offset + at * 8..offset + (at + 1) * 8].copy_from_slice(&value.get().to_be_bytes());
        }
    }
    let limits = data.output_limits;
    for (at, value) in [
        limits.native_snapshot_bytes,
        limits.current_control_bytes,
        limits.native_before_bytes,
        limits.anchor_bytes,
        limits.native_after_bytes,
    ]
    .into_iter()
    .enumerate()
    {
        out[136 + at * 8..144 + at * 8].copy_from_slice(&value.get().to_be_bytes());
    }
    Ok(())
}

fn number(bytes: &[u8]) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::from_be_bytes(
        bytes.try_into().map_err(|_| invalid())?,
    )))
}

fn row(bytes: &[u8]) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: number(&bytes[..8])?,
        maximum_simultaneous_transient_bytes: number(&bytes[8..16])?,
        declared_counter_scratch_bytes: number(&bytes[16..24])?,
    })
}

fn decode_carrier(bytes: &[u8]) -> Result<PacketRestoredSettledNativeCarrierData, ProviderError> {
    if bytes.len() != 176 {
        return Err(invalid());
    }
    let data = PacketRestoredSettledNativeCarrierData {
        version: number(&bytes[..8])?,
        launch_identity: bytes[8..40].try_into().map_err(|_| invalid())?,
        import_identity: bytes[40..72].try_into().map_err(|_| invalid())?,
        normalization_maximum: number(&bytes[72..80])?,
        maximum_originals: number(&bytes[80..88])?,
        ingress: row(&bytes[88..112])?,
        actions: row(&bytes[112..136])?,
        output_limits: crate::reference_packet::service::complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits {
            native_snapshot_bytes: number(&bytes[136..144])?,
            current_control_bytes: number(&bytes[144..152])?,
            native_before_bytes: number(&bytes[152..160])?,
            anchor_bytes: number(&bytes[160..168])?,
            native_after_bytes: number(&bytes[168..176])?
        }
    };

    data.validate_data()?;
    Ok(data)
}

// Canonical scalar spelling uses stack digits rather than U64's owning String.
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
        serializer.serialize_str(
            std::str::from_utf8(&digits[first..]).map_err(serde::ser::Error::custom)?,
        )
    }
}

struct CanonicalRow<'a>(&'a PacketNativeStartupAllocationRow);

impl Serialize for CanonicalRow<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SettledRow", 3)?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            &Decimal(self.0.declared_counter_scratch_bytes.get()),
        )?;
        fields.serialize_field(
            "maximum_simultaneous_transient_bytes",
            &Decimal(self.0.maximum_simultaneous_transient_bytes.get()),
        )?;
        fields.serialize_field(
            "retained_requested_bytes",
            &Decimal(self.0.retained_requested_bytes.get()),
        )?;
        fields.end()
    }
}

struct CanonicalOutputs<'a>(&'a crate::reference_packet::service::complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits);

impl Serialize for CanonicalOutputs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SettledOutputs", 5)?;
        fields.serialize_field("anchor_bytes", &Decimal(self.0.anchor_bytes.get()))?;
        fields.serialize_field(
            "current_control_bytes",
            &Decimal(self.0.current_control_bytes.get()),
        )?;
        fields.serialize_field(
            "native_after_bytes",
            &Decimal(self.0.native_after_bytes.get()),
        )?;
        fields.serialize_field(
            "native_before_bytes",
            &Decimal(self.0.native_before_bytes.get()),
        )?;
        fields.serialize_field(
            "native_snapshot_bytes",
            &Decimal(self.0.native_snapshot_bytes.get()),
        )?;
        fields.end()
    }
}

pub(super) struct CanonicalCarrier<'a>(pub(super) &'a PacketRestoredSettledNativeCarrierData);

impl Serialize for CanonicalCarrier<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SettledCarrier", 8)?;
        fields.serialize_field("actions", &CanonicalRow(&self.0.actions))?;
        fields.serialize_field("import_identity", &self.0.import_identity)?;
        fields.serialize_field("ingress", &CanonicalRow(&self.0.ingress))?;
        fields.serialize_field("launch_identity", &self.0.launch_identity)?;
        fields.serialize_field(
            "maximum_originals",
            &Decimal(self.0.maximum_originals.get()),
        )?;
        fields.serialize_field(
            "normalization_maximum",
            &Decimal(self.0.normalization_maximum.get()),
        )?;
        fields.serialize_field("output_limits", &CanonicalOutputs(&self.0.output_limits))?;
        fields.serialize_field("version", &Decimal(self.0.version.get()))?;
        fields.end()
    }
}

struct CanonicalSuffixReservation<'a>(&'a PacketRestoredSuffixReservationData);

impl Serialize for CanonicalSuffixReservation<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("ExistingSuffix", 3)?;
        fields.serialize_field("actions", &CanonicalRow(&self.0.actions))?;
        fields.serialize_field("ingress", &CanonicalRow(&self.0.ingress))?;
        fields.serialize_field(
            "maximum_originals",
            &Decimal(self.0.maximum_originals.get()),
        )?;
        fields.end()
    }
}

pub(super) struct CanonicalExistingRows<'a>(
    pub(super) &'a PacketRestoredSettledNativeExistingRowsData,
);
impl Serialize for CanonicalExistingRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("ExistingRows", 3)?;
        fields.serialize_field("native_birth", &CanonicalRow(&self.0.native_birth))?;
        fields.serialize_field(
            "restore_prepare",
            &self.0.restore_prepare.as_ref().map(CanonicalRow),
        )?;
        fields.serialize_field("suffix", &CanonicalSuffixReservation(&self.0.suffix))?;
        fields.end()
    }
}

/// Streams complete canonical wrapper8 around the unchanged raw nested launch7.
///
/// The caller retains actual launch5 and partial destination through refusal.
///
/// # Errors
/// Refuses invalid fixed reservation or propagates the actual writer error.
pub fn write_original_native_settled_launch_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    suffix: &PacketRestoredSuffixReservationData,
    existing_rows: &PacketRestoredSettledNativeExistingRowsData,
    capture: &PacketRestoredSettledNativeCarrierData,
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    capture.validate_data()?;
    if existing_rows.suffix != *suffix {
        return Err(invalid());
    }
    output.write_all(b"{\"capture_reservation\":")?;
    serde_json::to_writer(&mut *output, &CanonicalCarrier(capture))
        .map_err(crucible_node_format::ContractError::from)?;
    output.write_all(b",\"existing_rows\":")?;
    serde_json::to_writer(&mut *output, &CanonicalExistingRows(existing_rows))
        .map_err(crucible_node_format::ContractError::from)?;
    output.write_all(b",\"schema_version\":8,\"suffix\":")?;
    write_original_native_suffix_launch_data(purpose, canonical_launch5, suffix, output)?;
    output.write_all(b"}")?;
    Ok(())
}

struct Identity {
    bytes: usize,
    hasher: blake3::Hasher,
}

impl Write for Identity {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Counts/hashes complete wrapper8 without a DOM or dynamic output bank.
///
/// # Errors
/// Refuses invalid geometry, overflow or the closed canonical writer failure.
pub fn original_native_settled_launch_identity_data(
    purpose: &PacketNativeInvocationPurposeData,
    raw5: &[u8],
    suffix: &PacketRestoredSuffixReservationData,
    existing_rows: &PacketRestoredSettledNativeExistingRowsData,
    capture: &PacketRestoredSettledNativeCarrierData,
) -> Result<PacketNativeSuffixLaunchIdentityData, ProviderError> {
    let mut output = Identity {
        bytes: 0,
        hasher: blake3::Hasher::new(),
    };
    write_original_native_settled_launch_data(
        purpose,
        raw5,
        suffix,
        existing_rows,
        capture,
        &mut output,
    )?;
    Ok(PacketNativeSuffixLaunchIdentityData {
        encoded_bytes: output.bytes,
        raw_digest: *output.hasher.finalize().as_bytes(),
    })
}

/// Names new fixed owners/cursors separately from every dynamic native quote.
pub fn original_native_settled_carrier_counter_scratch_data() -> usize {
    use std::mem::{size_of, size_of_val};
    let terms = [
        size_of::<PacketNative8RestoredSettledLaunch>(),
        size_of::<Option<PacketNative8RestoredSettledLaunch>>(),
        size_of::<Result<&PacketNative7RestoredSuffixLaunch, ProviderError>>(),
        size_of::<&PacketRestoredSettledNativeCarrierData>(),
        size_of::<Result<&PacketRestoredSettledNativeCarrierData, ProviderError>>(),
        size_of::<Result<PacketRestoredSettledNativeCarrierData, serde_json::Error>>(),
        size_of::<PacketRestoredSettledNativeCarrierData>(),
        size_of::<PacketNativeSettledPreambleData>(),
        size_of::<Result<PacketNativeSettledPreambleData, ProviderError>>(),
        2 * size_of::<[u8; 568]>(),
        size_of::<Result<[u8; 568], ProviderError>>(),
        size_of::<[u8; 392]>(),
        size_of::<[u8; 176]>(),
        size_of::<[u8; 32]>(),
        size_of::<[u8; 8]>(),
        size_of::<[u8; 20]>(),
        size_of::<Identity>(),
        size_of::<Decimal>(),
        size_of::<CanonicalRow<'static>>(),
        size_of::<CanonicalOutputs<'static>>(),
        size_of::<CanonicalCarrier<'static>>(),
        size_of::<Result<(), serde_json::Error>>(),
        size_of::<Result<(), ProviderError>>(),
        size_of::<std::io::Result<usize>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<Result<&str, std::str::Utf8Error>>(),
        size_of::<Result<U64, ProviderError>>(),
        size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>(),
        size_of::<[(usize, PacketNativeStartupAllocationRow); 2]>(),
        size_of::<std::array::IntoIter<(usize, PacketNativeStartupAllocationRow), 2>>(),
        size_of::<[U64; 3]>(),
        size_of::<[U64; 5]>(),
        size_of::<std::iter::Enumerate<std::array::IntoIter<U64, 3>>>(),
        size_of::<std::iter::Enumerate<std::array::IntoIter<U64, 5>>>(),
        size_of::<blake3::Hasher>(),
        size_of::<blake3::Hash>(),
        size_of::<super::super::complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits>(),
        size_of::<Option<&PacketNative8RestoredSettledLaunch>>(),
        size_of::<Option<&mut PacketNative8RestoredSettledLaunch>>(),
        size_of::<Result<&mut PacketNative8RestoredSettledLaunch, ProviderError>>(),
        size_of::<Result<PacketRestoredSettledNativeCarrierData, crucible_node_format::ContractError>>(),
        size_of::<Result<[u8; 392], ProviderError>>(),
        size_of::<Result<&[u8; 32], std::array::TryFromSliceError>>(),
        size_of::<Result<[u8; 32], std::array::TryFromSliceError>>(),
        size_of::<Result<[u8; 8], std::array::TryFromSliceError>>(),
        size_of::<Result<&[u8; 32], ProviderError>>(),
        size_of::<Result<[u8; 32], ProviderError>>(),
        size_of::<Result<[u8; 8], ProviderError>>(),
        size_of::<Option<&serde_json::Map<String, serde_json::Value>>>(),
        size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>(),
        size_of::<Result<u64, std::num::TryFromIntError>>(),
        size_of::<Result<u64, ProviderError>>(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, u8>>>(),
        size_of::<(&u8, &u8)>(),
        size_of::<(usize, U64)>(),
        size_of::<(usize, PacketNativeStartupAllocationRow)>(),
        original_native_suffix_counter_scratch_data(),
        restored_settled_startup_schema_counter_scratch_data(),
        super::settled_construction17::counter_scratch_data(),
        crate::reference_packet::service::ack_emitter::original_restored_settled_bootstrap_counter_scratch_data(),
        size_of::<Option<(PacketNativeInvocationPurposeData, PacketRestoredSuffixReservationData)>>(),
        size_of::<(PacketNativeInvocationPurposeData, PacketNative5SourceLaunch, PacketRestoredSuffixReservationData)>(),
        size_of::<(&Option<PacketNative7RestoredSuffixLaunch>, &Option<(PacketNativeInvocationPurposeData, PacketRestoredSuffixReservationData)>)>(),
        size_of::<Option<PacketNative5SourceLaunch>>(),
        size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>(),
        size_of::<Result<PacketRestoredSuffixReservationData, ProviderError>>(),
        size_of::<PacketRestoredSettledNativeExistingRowsData>(),
        size_of::<&PacketRestoredSettledNativeExistingRowsData>(),
        size_of::<Result<&PacketRestoredSettledNativeExistingRowsData, ProviderError>>(),
        size_of::<Result<PacketRestoredSettledNativeExistingRowsData, serde_json::Error>>(),
        size_of::<Result<PacketRestoredSettledNativeExistingRowsData, crucible_node_format::ContractError>>(),
        size_of::<CanonicalExistingRows<'static>>(),
        size_of::<CanonicalSuffixReservation<'static>>(),
        size_of::<Option<CanonicalRow<'static>>>(),
        size_of::<Option<&PacketNativeStartupAllocationRow>>(),
        size_of::<&PacketRestoredSettledNativeStorageData>(),
        size_of::<&PacketNativeSettledConstructionStorageData>(),
        size_of::<&Option<PacketNativeStartupAllocationRow>>(),
        size_of::<Option<PacketNativeStartupAllocationRow>>(),
        size_of::<(U64, usize, usize)>(),
        size_of::<Option<u64>>(),
        size_of::<(
            &PacketRestoredSettledNativeExistingRowsData,
            &PacketRestoredSettledNativeStorageData,
            &PacketNativeSettledConstructionStorageData,
            &PacketNativeStartupAllocationRow,
            &Option<PacketNativeStartupAllocationRow>
        )>(),
    ];
    size_of_val(&terms)
        + size_of::<std::array::IntoIter<usize, 83>>()
        + terms.into_iter().sum::<usize>()
}

pub(super) fn invalid() -> ProviderError {
    ProviderError::Correlation("settled startup17 carrier differs")
}
