//! Bounded canonical binary codec for pure manager-query records.
//!
//! Every integer is little-endian. Outer property records frame scalars with a
//! `u32` byte length and arrays with a `u16` element count plus one framed
//! scalar payload per element. The closed systemd-signature leaf grammar is:
//!
//! ```text
//! b: one byte, exactly 0 or 1       u/i: exactly 4 bytes
//! t: exactly 8 bytes                s/ay: raw bounded bytes (s is UTF-8)
//! (uo): u32 + text                  (bs): bool + text
//! (bas): bool + string-set          text: u16 length + UTF-8 bytes
//! a(sb) element: text + bool        a(ss) element: text + text
//! ExecStart element: text + string-array + b + t/t/t/t + u/i/i
//! ExecStartEx element: text + string-array + flag-string-set + t/t/t/t + u/i/i
//! string-array/set: u16 count + repeated text; sets are strictly byte-sorted
//! ```
//!
//! Static contract records stop each `Exec*` leaf after the boolean or flag
//! set. Snapshot records require the full suffix. Thus immutable command policy
//! is digest-bound without pretending to predict runtime timestamps, PID, exit
//! code, or status; the complete suffix remains byte-bound across A/B snapshots.
//!
//! No generic D-Bus value parser is accepted at this boundary. The descriptor
//! table selects exactly one of these layouts and fixes the actual systemd 259
//! signature against which the helper must decode its received variant.

use super::{
    CanonicalManagerPropertyValueV1, MANAGER_PROPERTY_TABLE_V1, ManagerPropertyBindingV1,
    ManagerPropertyDescriptorV1, ManagerPropertyObservationV1, ManagerPropertyShapeV1,
    NamespaceInspectorManagerQueryError, ObservedNamespaceInspectorActivationSnapshotV1,
    SNAPSHOT_KIND, SNAPSHOT_MAGIC,
};
use crate::namespace_inspector::launch_contract::{
    NamespaceInspectorDeploymentContractV1, NamespaceInspectorDeploymentDigestV1, contract_kind,
    contract_magic, decode_contract_body, encode_contract_body,
};

const VERSION: u16 = 1;
const HEADER_BYTES: usize = 16;

pub(in crate::namespace_inspector) const MAXIMUM_MANAGER_QUERY_FRAME_BYTES: usize = 128 * 1024;
pub(in crate::namespace_inspector) const MAXIMUM_COLLECTION_ELEMENTS: usize = 256;
pub(in crate::namespace_inspector) const MAXIMUM_TEXT_BYTES: usize = 2 * 1024;
const MAXIMUM_PROPERTY_ELEMENT_BYTES: usize = 4 * 1024;

pub(in crate::namespace_inspector) fn encode_contract(
    contract: &NamespaceInspectorDeploymentContractV1,
) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
    encode_frame(contract_magic(), contract_kind(), |encoder| {
        encode_contract_body(contract, encoder)
    })
}

pub(in crate::namespace_inspector) fn decode_contract(
    bytes: &[u8],
) -> Result<NamespaceInspectorDeploymentContractV1, NamespaceInspectorManagerQueryError> {
    let mut decoder = decode_frame(bytes, contract_magic(), contract_kind())?;
    let contract = decode_contract_body(&mut decoder)?;
    decoder.finish()?;
    if encode_contract(&contract)? != bytes {
        return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
    }
    Ok(contract)
}

pub(super) fn encode_snapshot(
    snapshot: &ObservedNamespaceInspectorActivationSnapshotV1,
) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
    encode_frame(SNAPSHOT_MAGIC, SNAPSHOT_KIND, |encoder| {
        encoder.bytes(snapshot.contract_digest.as_bytes());
        encoder.text(&snapshot.service_unit_id)?;
        encoder.text(&snapshot.service_instance)?;
        encoder.bytes(&snapshot.invocation_id);
        encoder.u32(snapshot.main_pid);
        encoder.text(&snapshot.control_group)?;
        encoder.u64(snapshot.control_group_id);
        encoder.u64(snapshot.accept_ordinal);
        encoder.u64(snapshot.accepted_socket_cookie);
        encoder.u32(snapshot.connecting_pid);
        encoder.u64(snapshot.connecting_pidfd_inode);
        encoder.u32(snapshot.connecting_uid);
        encoder.properties(&snapshot.properties)
    })
}

pub(super) fn decode_snapshot(
    bytes: &[u8],
) -> Result<ObservedNamespaceInspectorActivationSnapshotV1, NamespaceInspectorManagerQueryError> {
    let mut decoder = decode_frame(bytes, SNAPSHOT_MAGIC, SNAPSHOT_KIND)?;
    let snapshot = ObservedNamespaceInspectorActivationSnapshotV1 {
        contract_digest: NamespaceInspectorDeploymentDigestV1::from_bytes(decoder.array()?),
        service_unit_id: decoder.text(super::MAXIMUM_UNIT_ID_BYTES)?,
        service_instance: decoder.text(super::MAXIMUM_INSTANCE_BYTES)?,
        invocation_id: decoder.array()?,
        main_pid: decoder.u32()?,
        control_group: decoder.text(super::MAXIMUM_CGROUP_BYTES)?,
        control_group_id: decoder.u64()?,
        accept_ordinal: decoder.u64()?,
        accepted_socket_cookie: decoder.u64()?,
        connecting_pid: decoder.u32()?,
        connecting_pidfd_inode: decoder.u64()?,
        connecting_uid: decoder.u32()?,
        properties: decoder.properties(false)?,
    };
    decoder.finish()?;
    snapshot.validate()?;
    if encode_snapshot(&snapshot)? != bytes {
        return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
    }
    Ok(snapshot)
}

fn encode_frame(
    magic: &[u8; 8],
    kind: u8,
    body: impl FnOnce(&mut Encoder) -> Result<(), NamespaceInspectorManagerQueryError>,
) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
    let mut encoder = Encoder {
        bytes: Vec::with_capacity(HEADER_BYTES),
    };
    encoder.bytes(magic);
    encoder.u16(VERSION);
    encoder.u8(kind);
    encoder.u8(0);
    encoder.u32(0);
    body(&mut encoder)?;

    if encoder.bytes.len() > MAXIMUM_MANAGER_QUERY_FRAME_BYTES {
        return Err(NamespaceInspectorManagerQueryError::FrameTooLarge);
    }
    let length = u32::try_from(encoder.bytes.len())
        .map_err(|_| NamespaceInspectorManagerQueryError::FrameTooLarge)?;
    encoder.bytes[12..16].copy_from_slice(&length.to_le_bytes());
    Ok(encoder.bytes)
}

fn decode_frame<'bytes>(
    bytes: &'bytes [u8],
    magic: &[u8; 8],
    kind: u8,
) -> Result<Decoder<'bytes>, NamespaceInspectorManagerQueryError> {
    if bytes.len() > MAXIMUM_MANAGER_QUERY_FRAME_BYTES {
        return Err(NamespaceInspectorManagerQueryError::FrameTooLarge);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
    }

    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(8)? != magic
        || decoder.u16()? != VERSION
        || decoder.u8()? != kind
        || decoder.u8()? != 0
        || usize::try_from(decoder.u32()?)
            .map_err(|_| NamespaceInspectorManagerQueryError::InvalidFrame)?
            != bytes.len()
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
    }
    Ok(decoder)
}

pub(in crate::namespace_inspector) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(in crate::namespace_inspector) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(in crate::namespace_inspector) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(in crate::namespace_inspector) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(in crate::namespace_inspector) fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(in crate::namespace_inspector) fn count(
        &mut self,
        count: usize,
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        let count =
            u16::try_from(count).map_err(|_| NamespaceInspectorManagerQueryError::FieldTooLarge)?;
        self.u16(count);
        Ok(())
    }

    pub(in crate::namespace_inspector) fn text(
        &mut self,
        text: &str,
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        validate_text(text)?;
        let length = u16::try_from(text.len())
            .map_err(|_| NamespaceInspectorManagerQueryError::FieldTooLarge)?;
        self.u16(length);
        self.bytes(text.as_bytes());
        Ok(())
    }

    pub(in crate::namespace_inspector) fn strings(
        &mut self,
        values: &[String],
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        self.count(values.len())?;
        for value in values {
            self.text(value)?;
        }
        Ok(())
    }

    pub(in crate::namespace_inspector) fn properties(
        &mut self,
        properties: &[ManagerPropertyObservationV1],
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        self.count(properties.len())?;
        for property in properties {
            self.u16(property.descriptor_id);
            match &property.value {
                CanonicalManagerPropertyValueV1::Scalar(bytes) => {
                    self.u8(1);
                    self.blob(bytes)?;
                }
                CanonicalManagerPropertyValueV1::OrderedArray(elements) => {
                    self.u8(2);
                    self.elements(elements)?;
                }
                CanonicalManagerPropertyValueV1::UnorderedSet(elements) => {
                    self.u8(3);
                    self.elements(elements)?;
                }
            }
        }
        Ok(())
    }

    fn blob(&mut self, bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
        validate_value_bytes(bytes)?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| NamespaceInspectorManagerQueryError::FieldTooLarge)?;
        self.u32(length);
        self.bytes(bytes);
        Ok(())
    }

    fn elements(
        &mut self,
        elements: &[Vec<u8>],
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        if elements.len() > MAXIMUM_COLLECTION_ELEMENTS {
            return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
        }
        self.count(elements.len())?;
        for element in elements {
            self.blob(element)?;
        }
        Ok(())
    }
}

pub(in crate::namespace_inspector) struct Decoder<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Decoder<'bytes> {
    pub(in crate::namespace_inspector) fn finish(
        &self,
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        if self.offset != self.bytes.len() {
            return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
        }
        Ok(())
    }

    pub(in crate::namespace_inspector) fn u8(
        &mut self,
    ) -> Result<u8, NamespaceInspectorManagerQueryError> {
        Ok(self.take(1)?[0])
    }

    pub(in crate::namespace_inspector) fn u16(
        &mut self,
    ) -> Result<u16, NamespaceInspectorManagerQueryError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(in crate::namespace_inspector) fn u32(
        &mut self,
    ) -> Result<u32, NamespaceInspectorManagerQueryError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NamespaceInspectorManagerQueryError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(in crate::namespace_inspector) fn array<const SIZE: usize>(
        &mut self,
    ) -> Result<[u8; SIZE], NamespaceInspectorManagerQueryError> {
        self.take(SIZE)?
            .try_into()
            .map_err(|_| NamespaceInspectorManagerQueryError::InvalidFrame)
    }

    pub(in crate::namespace_inspector) fn count(
        &mut self,
        maximum: usize,
    ) -> Result<usize, NamespaceInspectorManagerQueryError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
        }
        Ok(count)
    }

    pub(in crate::namespace_inspector) fn text(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<String, NamespaceInspectorManagerQueryError> {
        let length = usize::from(self.u16()?);
        if length > maximum_bytes || length > self.remaining() {
            return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
        }
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| NamespaceInspectorManagerQueryError::InvalidText)?;
        validate_text(text)?;
        Ok(text.to_owned())
    }

    pub(in crate::namespace_inspector) fn strings(
        &mut self,
        maximum_elements: usize,
        maximum_element_bytes: usize,
    ) -> Result<Vec<String>, NamespaceInspectorManagerQueryError> {
        let count = self.count(maximum_elements)?;
        if count > self.remaining() / 2 {
            return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
        }

        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.text(maximum_element_bytes)?);
        }
        Ok(values)
    }

    pub(in crate::namespace_inspector) fn properties(
        &mut self,
        static_only: bool,
    ) -> Result<Vec<ManagerPropertyObservationV1>, NamespaceInspectorManagerQueryError> {
        let expected_count = MANAGER_PROPERTY_TABLE_V1
            .iter()
            .filter(|descriptor| {
                !static_only || descriptor.binding == ManagerPropertyBindingV1::StaticContract
            })
            .count();
        let count = self.count(expected_count)?;
        if count != expected_count || count > self.remaining() / 3 {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        }

        let mut properties = Vec::with_capacity(count);
        for _ in 0..count {
            let descriptor_id = self.u16()?;
            let value = match self.u8()? {
                1 => CanonicalManagerPropertyValueV1::Scalar(self.blob()?),
                2 => CanonicalManagerPropertyValueV1::OrderedArray(self.elements()?),
                3 => CanonicalManagerPropertyValueV1::UnorderedSet(self.elements()?),
                _ => return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch),
            };
            properties.push(ManagerPropertyObservationV1 {
                descriptor_id,
                value,
            });
        }
        super::validate_property_sequence(&properties, static_only)?;
        Ok(properties)
    }

    fn blob(&mut self) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| NamespaceInspectorManagerQueryError::FieldTooLarge)?;
        if length > MAXIMUM_PROPERTY_ELEMENT_BYTES {
            return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
        }
        if length > self.remaining() {
            return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn elements(&mut self) -> Result<Vec<Vec<u8>>, NamespaceInspectorManagerQueryError> {
        let count = self.count(MAXIMUM_COLLECTION_ELEMENTS)?;
        if count > self.remaining() / 4 {
            return Err(NamespaceInspectorManagerQueryError::InvalidFrame);
        }

        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            elements.push(self.blob()?);
        }
        Ok(elements)
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], NamespaceInspectorManagerQueryError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NamespaceInspectorManagerQueryError::InvalidFrame)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(NamespaceInspectorManagerQueryError::InvalidFrame)?;
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

pub(super) fn validate_property_value(
    descriptor: &ManagerPropertyDescriptorV1,
    value: &CanonicalManagerPropertyValueV1,
    static_projection: bool,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    match (descriptor.signature, value) {
        ("b", CanonicalManagerPropertyValueV1::Scalar(bytes)) => validate_bool(bytes),
        ("u" | "i", CanonicalManagerPropertyValueV1::Scalar(bytes)) => {
            validate_exact_width(bytes, 4)
        }
        ("t", CanonicalManagerPropertyValueV1::Scalar(bytes)) => validate_exact_width(bytes, 8),
        ("s", CanonicalManagerPropertyValueV1::Scalar(bytes)) => validate_string_bytes(bytes),
        ("ay", CanonicalManagerPropertyValueV1::Scalar(bytes)) => {
            validate_value_bytes(bytes)?;
            if descriptor.property == "InvocationID"
                && (bytes.len() != 16 || bytes.iter().all(|byte| *byte == 0))
            {
                return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
            }
            Ok(())
        }
        ("(uo)", CanonicalManagerPropertyValueV1::Scalar(bytes)) => validate_job_tuple(bytes),
        ("(bs)", CanonicalManagerPropertyValueV1::Scalar(bytes)) => {
            validate_bool_string_tuple(bytes)
        }
        ("(ss)", CanonicalManagerPropertyValueV1::Scalar(bytes)) => {
            validate_string_string_tuple(bytes)
        }
        ("(bas)", CanonicalManagerPropertyValueV1::Scalar(bytes)) => {
            validate_bool_string_set_tuple(bytes)
        }
        ("as", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            validate_string_elements(elements, false)
        }
        ("as", CanonicalManagerPropertyValueV1::UnorderedSet(elements)) => {
            validate_string_elements(elements, true)?;
            if descriptor.property == "Environment"
                && descriptor.object == super::ManagerQueryObjectV1::Manager
            {
                validate_environment_elements(elements)?;
            }
            Ok(())
        }
        ("a(sb)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            validate_tuple_elements(elements, validate_string_bool_tuple)
        }
        ("a(ss)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            validate_tuple_elements(elements, validate_string_string_tuple)
        }
        ("a(sasbttttuii)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            if static_projection {
                validate_tuple_elements(elements, validate_exec_command_projection)
            } else {
                validate_tuple_elements(elements, validate_exec_command)
            }
        }
        ("a(sasasttttuii)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            if static_projection {
                validate_tuple_elements(elements, validate_exec_command_ex_projection)
            } else {
                validate_tuple_elements(elements, validate_exec_command_ex)
            }
        }
        _ => Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch),
    }
}

fn validate_exact_width(
    bytes: &[u8],
    width: usize,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if bytes.len() != width {
        return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
    }
    Ok(())
}

fn validate_bool(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    if !matches!(bytes, [0] | [1]) {
        return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
    }
    Ok(())
}

fn validate_string_bytes(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    validate_value_bytes(bytes)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
    validate_text(text).map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)
}

fn validate_string_elements(
    elements: &[Vec<u8>],
    require_sorted: bool,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    validate_value_elements(elements, require_sorted)?;
    for element in elements {
        validate_string_bytes(element)?;
    }
    Ok(())
}

fn validate_environment_elements(
    elements: &[Vec<u8>],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut previous_name = None;
    for element in elements {
        let value = std::str::from_utf8(element)
            .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        let (name, _) = value
            .split_once('=')
            .ok_or(NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        validate_environment_name(name)
            .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        if previous_name == Some(name) {
            return Err(NamespaceInspectorManagerQueryError::NoncanonicalSet);
        }
        previous_name = Some(name);
    }
    Ok(())
}

fn validate_tuple_elements(
    elements: &[Vec<u8>],
    validate: fn(&[u8]) -> Result<(), NamespaceInspectorManagerQueryError>,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    validate_value_elements(elements, false)?;
    for element in elements {
        validate(element)?;
    }
    Ok(())
}

fn validate_job_tuple(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decoder.u32()?;
    let object_path = decoder.text()?;
    if !dbus_object_path_is_valid(object_path) {
        return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
    }
    decoder.finish()
}

fn validate_bool_string_tuple(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decoder.boolean()?;
    decoder.text()?;
    decoder.finish()
}

fn validate_bool_string_set_tuple(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decoder.boolean()?;
    decoder.string_array(true)?;
    decoder.finish()
}

fn validate_string_bool_tuple(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decoder.text()?;
    decoder.boolean()?;
    decoder.finish()
}

fn validate_string_string_tuple(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decoder.text()?;
    decoder.text()?;
    decoder.finish()
}

fn validate_exec_command(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decode_exec_command_projection(&mut decoder)?;
    for _ in 0..4 {
        decoder.u64()?;
    }
    decoder.u32()?;
    decoder.i32()?;
    decoder.i32()?;
    decoder.finish()
}

fn validate_exec_command_ex(bytes: &[u8]) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decode_exec_command_ex_projection(&mut decoder)?;
    for _ in 0..4 {
        decoder.u64()?;
    }
    decoder.u32()?;
    decoder.i32()?;
    decoder.i32()?;
    decoder.finish()
}

fn validate_exec_command_projection(
    bytes: &[u8],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decode_exec_command_projection(&mut decoder)?;
    decoder.finish()
}

fn validate_exec_command_ex_projection(
    bytes: &[u8],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    decode_exec_command_ex_projection(&mut decoder)?;
    decoder.finish()
}

fn decode_exec_command_projection(
    decoder: &mut LeafDecoder<'_>,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    decoder.text()?;
    decoder.string_array(false)?;
    decoder.boolean()
}

fn decode_exec_command_ex_projection(
    decoder: &mut LeafDecoder<'_>,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    decoder.text()?;
    decoder.string_array(false)?;
    decoder.string_array(true)
}

pub(super) fn static_contract_projection(
    descriptor: &ManagerPropertyDescriptorV1,
    observation: &ManagerPropertyObservationV1,
) -> Result<ManagerPropertyObservationV1, NamespaceInspectorManagerQueryError> {
    let value = match (descriptor.signature, &observation.value) {
        ("a(sasbttttuii)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            CanonicalManagerPropertyValueV1::OrderedArray(
                elements
                    .iter()
                    .map(|element| project_exec_command(element, false))
                    .collect::<Result<_, _>>()?,
            )
        }
        ("a(sasasttttuii)", CanonicalManagerPropertyValueV1::OrderedArray(elements)) => {
            CanonicalManagerPropertyValueV1::OrderedArray(
                elements
                    .iter()
                    .map(|element| project_exec_command(element, true))
                    .collect::<Result<_, _>>()?,
            )
        }
        _ => observation.value.clone(),
    };

    let projected = ManagerPropertyObservationV1 {
        descriptor_id: observation.descriptor_id,
        value,
    };
    validate_property_value(descriptor, &projected.value, true)?;
    Ok(projected)
}

fn project_exec_command(
    bytes: &[u8],
    extended: bool,
) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
    let mut decoder = LeafDecoder::new(bytes);
    if extended {
        decode_exec_command_ex_projection(&mut decoder)?;
        validate_exec_command_ex(bytes)?;
    } else {
        decode_exec_command_projection(&mut decoder)?;
        validate_exec_command(bytes)?;
    }
    Ok(bytes[..decoder.offset].to_vec())
}

fn dbus_object_path_is_valid(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    path.starts_with('/')
        && !path.ends_with('/')
        && path[1..].split('/').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

struct LeafDecoder<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> LeafDecoder<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        if self.offset != self.bytes.len() {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        }
        Ok(())
    }

    fn boolean(&mut self) -> Result<(), NamespaceInspectorManagerQueryError> {
        validate_bool(self.take(1)?)
    }

    fn u16(&mut self) -> Result<u16, NamespaceInspectorManagerQueryError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NamespaceInspectorManagerQueryError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, NamespaceInspectorManagerQueryError> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NamespaceInspectorManagerQueryError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<&'bytes str, NamespaceInspectorManagerQueryError> {
        let length = usize::from(self.u16()?);
        if length > MAXIMUM_TEXT_BYTES || length > self.remaining() {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        }
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        validate_text(text)
            .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        Ok(text)
    }

    fn string_array(
        &mut self,
        require_sorted: bool,
    ) -> Result<(), NamespaceInspectorManagerQueryError> {
        let count = usize::from(self.u16()?);
        if count > MAXIMUM_COLLECTION_ELEMENTS || count > self.remaining() / 2 {
            return Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch);
        }

        let mut previous = None;
        for _ in 0..count {
            let current = self.text()?;
            if require_sorted
                && previous.is_some_and(|value: &str| value.as_bytes() >= current.as_bytes())
            {
                return Err(NamespaceInspectorManagerQueryError::NoncanonicalSet);
            }
            previous = Some(current);
        }
        Ok(())
    }

    fn array<const SIZE: usize>(
        &mut self,
    ) -> Result<[u8; SIZE], NamespaceInspectorManagerQueryError> {
        self.take(SIZE)?
            .try_into()
            .map_err(|_| NamespaceInspectorManagerQueryError::PropertyTableMismatch)
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], NamespaceInspectorManagerQueryError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(NamespaceInspectorManagerQueryError::PropertyTableMismatch)?;
        self.offset = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

pub(in crate::namespace_inspector) fn validate_environment_name(
    name: &str,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidText);
    }
    Ok(())
}

pub(in crate::namespace_inspector) fn validate_text(
    text: &str,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if text.len() > MAXIMUM_TEXT_BYTES || text.as_bytes().contains(&0) {
        return Err(NamespaceInspectorManagerQueryError::InvalidText);
    }
    Ok(())
}

pub(in crate::namespace_inspector) fn validate_sorted_text_set(
    values: &[String],
    maximum_elements: usize,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if values.len() > maximum_elements {
        return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
    }
    for value in values {
        if value.is_empty() {
            return Err(NamespaceInspectorManagerQueryError::InvalidText);
        }
        validate_text(value)?;
    }
    if !values
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(NamespaceInspectorManagerQueryError::NoncanonicalSet);
    }
    Ok(())
}

pub(super) fn validate_value_bytes(
    bytes: &[u8],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if bytes.len() > MAXIMUM_PROPERTY_ELEMENT_BYTES {
        return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
    }
    Ok(())
}

pub(super) fn validate_value_elements(
    elements: &[Vec<u8>],
    require_sorted: bool,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if elements.len() > MAXIMUM_COLLECTION_ELEMENTS {
        return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
    }
    for element in elements {
        validate_value_bytes(element)?;
    }
    if require_sorted
        && !elements
            .windows(2)
            .all(|pair| pair[0].as_slice() < pair[1].as_slice())
    {
        return Err(NamespaceInspectorManagerQueryError::NoncanonicalSet);
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::namespace_inspector) fn test_property_value(
    descriptor: &ManagerPropertyDescriptorV1,
    static_projection: bool,
) -> CanonicalManagerPropertyValueV1 {
    let scalar = match descriptor.signature {
        "b" => vec![1],
        "u" | "i" => 0_u32.to_le_bytes().to_vec(),
        "t" => 0_u64.to_le_bytes().to_vec(),
        "s" => descriptor.property.as_bytes().to_vec(),
        "ay" => vec![3; 16],
        "(uo)" => {
            let mut bytes = 0_u32.to_le_bytes().to_vec();
            test_push_text(&mut bytes, "/");
            bytes
        }
        "(bs)" => {
            let mut bytes = vec![1];
            test_push_text(&mut bytes, "label");
            bytes
        }
        "(ss)" => {
            let mut bytes = Vec::new();
            test_push_text(&mut bytes, "yes");
            test_push_text(&mut bytes, "hostname");
            bytes
        }
        "(bas)" => vec![1, 0, 0],
        _ => Vec::new(),
    };
    if descriptor.shape == ManagerPropertyShapeV1::Scalar {
        return CanonicalManagerPropertyValueV1::Scalar(scalar);
    }

    let mut element = Vec::new();
    match descriptor.signature {
        "as" if descriptor.object == super::ManagerQueryObjectV1::Manager => {
            element.extend_from_slice(b"LANG=C")
        }
        "as" => element.extend_from_slice(descriptor.property.as_bytes()),
        "a(sb)" => {
            test_push_text(&mut element, "/etc/environment");
            element.push(0);
        }
        "a(ss)" => {
            test_push_text(&mut element, "SequentialPacket");
            test_push_text(&mut element, "/run/aos/control.sock");
        }
        "a(sasbttttuii)" => {
            test_push_text(&mut element, "/bin/inspector");
            test_push_strings(&mut element, &["/bin/inspector"]);
            element.push(0);
            if !static_projection {
                for value in [11_u64, 12, 13, 14] {
                    element.extend_from_slice(&value.to_le_bytes());
                }
                element.extend_from_slice(&113_u32.to_le_bytes());
                element.extend_from_slice(&1_i32.to_le_bytes());
                element.extend_from_slice(&2_i32.to_le_bytes());
            }
        }
        "a(sasasttttuii)" => {
            test_push_text(&mut element, "/bin/inspector");
            test_push_strings(&mut element, &["/bin/inspector"]);
            test_push_strings(&mut element, &["fully-privileged"]);
            if !static_projection {
                for value in [11_u64, 12, 13, 14] {
                    element.extend_from_slice(&value.to_le_bytes());
                }
                element.extend_from_slice(&113_u32.to_le_bytes());
                element.extend_from_slice(&1_i32.to_le_bytes());
                element.extend_from_slice(&2_i32.to_le_bytes());
            }
        }
        _ => unreachable!("test table contains a known signature"),
    }

    match descriptor.shape {
        ManagerPropertyShapeV1::Scalar => unreachable!("scalar returned above"),
        ManagerPropertyShapeV1::OrderedArray => {
            CanonicalManagerPropertyValueV1::OrderedArray(vec![element])
        }
        ManagerPropertyShapeV1::UnorderedSet => {
            CanonicalManagerPropertyValueV1::UnorderedSet(vec![element])
        }
    }
}

#[cfg(test)]
fn test_push_text(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(&(text.len() as u16).to_le_bytes());
    bytes.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
fn test_push_strings(bytes: &mut Vec<u8>, values: &[&str]) {
    bytes.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for value in values {
        test_push_text(bytes, value);
    }
}

#[cfg(test)]
pub(in crate::namespace_inspector) fn test_properties(
    static_only: bool,
) -> Vec<ManagerPropertyObservationV1> {
    MANAGER_PROPERTY_TABLE_V1
        .iter()
        .filter(|descriptor| {
            !static_only || descriptor.binding == ManagerPropertyBindingV1::StaticContract
        })
        .map(|descriptor| ManagerPropertyObservationV1 {
            descriptor_id: descriptor.id,
            value: match descriptor.id {
                1 => CanonicalManagerPropertyValueV1::Scalar(
                    b"aos-sandbox-network-namespace-inspector@accept.service".to_vec(),
                ),
                17 => CanonicalManagerPropertyValueV1::Scalar(
                    b"/aos.slice/aos-control.slice/inspector.service".to_vec(),
                ),
                18 => CanonicalManagerPropertyValueV1::Scalar(211_u64.to_le_bytes().to_vec()),
                24 => CanonicalManagerPropertyValueV1::Scalar(113_u32.to_le_bytes().to_vec()),
                _ => test_property_value(descriptor, static_only),
            },
        })
        .collect()
}

#[cfg(test)]
fn test_snapshot() -> ObservedNamespaceInspectorActivationSnapshotV1 {
    let contract = crate::namespace_inspector::launch_contract::tests::contract();
    ObservedNamespaceInspectorActivationSnapshotV1 {
        contract_digest: contract.digest().unwrap(),
        service_unit_id: "aos-sandbox-network-namespace-inspector@accept.service".into(),
        service_instance: "accept".into(),
        invocation_id: [3; 16],
        main_pid: 113,
        control_group: "/aos.slice/aos-control.slice/inspector.service".into(),
        control_group_id: 211,
        accept_ordinal: 7,
        accepted_socket_cookie: 311,
        connecting_pid: 411,
        connecting_pidfd_inode: 511,
        connecting_uid: 0,
        properties: test_properties(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_inspector::launch_contract::tests::contract;
    use crate::namespace_inspector::manager_query::{
        MANAGER_METHOD_TABLE_V1, ManagerMethodDescriptorV1, ManagerQueryObjectV1,
        match_namespace_inspector_activation_snapshots,
    };
    use sha2::{Digest as _, Sha256};

    fn descriptor(signature: &str) -> &'static ManagerPropertyDescriptorV1 {
        MANAGER_PROPERTY_TABLE_V1
            .iter()
            .find(|descriptor| descriptor.signature == signature)
            .unwrap()
    }

    #[test]
    fn method_table_uses_actual_systemd_interfaces_and_signatures() {
        assert_eq!(
            MANAGER_METHOD_TABLE_V1,
            &[
                ManagerMethodDescriptorV1 {
                    object: ManagerQueryObjectV1::Manager,
                    interface: "org.freedesktop.systemd1.Manager",
                    member: "GetUnitByPIDFD",
                    input_signature: "h",
                    output_signature: "osay",
                },
                ManagerMethodDescriptorV1 {
                    object: ManagerQueryObjectV1::Manager,
                    interface: "org.freedesktop.DBus.Properties",
                    member: "Get",
                    input_signature: "ss",
                    output_signature: "v",
                },
                ManagerMethodDescriptorV1 {
                    object: ManagerQueryObjectV1::InspectorService,
                    interface: "org.freedesktop.DBus.Properties",
                    member: "Get",
                    input_signature: "ss",
                    output_signature: "v",
                },
                ManagerMethodDescriptorV1 {
                    object: ManagerQueryObjectV1::InspectorSocket,
                    interface: "org.freedesktop.DBus.Properties",
                    member: "Get",
                    input_signature: "ss",
                    output_signature: "v",
                },
            ]
        );
    }

    #[test]
    fn property_table_uses_real_aggregate_interfaces() {
        for (expected_id, descriptor) in MANAGER_PROPERTY_TABLE_V1.iter().enumerate() {
            assert_eq!(usize::from(descriptor.id), expected_id);
            match descriptor.object {
                ManagerQueryObjectV1::Manager => {
                    assert_eq!(descriptor.interface, super::super::MANAGER_INTERFACE)
                }
                ManagerQueryObjectV1::InspectorService => assert!(
                    descriptor.interface == super::super::UNIT_INTERFACE
                        || descriptor.interface == super::super::SERVICE_INTERFACE
                ),
                ManagerQueryObjectV1::InspectorSocket => assert!(
                    descriptor.interface == super::super::UNIT_INTERFACE
                        || descriptor.interface == super::super::SOCKET_INTERFACE
                ),
            }
        }

        let exec_start = &MANAGER_PROPERTY_TABLE_V1[34];
        assert_eq!(exec_start.interface, super::super::SERVICE_INTERFACE);
        assert_eq!(exec_start.signature, "a(sasbttttuii)");
        let exec_start_ex = &MANAGER_PROPERTY_TABLE_V1[35];
        assert_eq!(exec_start_ex.signature, "a(sasasttttuii)");
        let listen = &MANAGER_PROPERTY_TABLE_V1[107];
        assert_eq!(listen.interface, super::super::SOCKET_INTERFACE);
        assert_eq!(listen.signature, "a(ss)");
    }

    #[test]
    fn property_table_schema_has_a_reviewed_golden_digest() {
        let mut digest = Sha256::new();
        for descriptor in MANAGER_PROPERTY_TABLE_V1 {
            digest.update(descriptor.id.to_le_bytes());
            digest.update([descriptor.object as u8]);
            digest.update(descriptor.interface.as_bytes());
            digest.update([0]);
            digest.update(descriptor.property.as_bytes());
            digest.update([0]);
            digest.update(descriptor.signature.as_bytes());
            digest.update([descriptor.binding as u8, descriptor.shape as u8]);
        }
        let actual: [u8; 32] = digest.finalize().into();
        assert_eq!(
            actual,
            [
                116, 242, 223, 173, 18, 235, 224, 170, 160, 88, 155, 79, 88, 28, 110, 116, 19, 12,
                27, 31, 143, 150, 14, 25, 153, 188, 92, 134, 151, 138, 20, 154,
            ]
        );
    }

    #[test]
    fn snapshot_round_trip_is_canonical_and_bounded() {
        let expected = test_snapshot();
        let bytes = expected.encode().unwrap();
        let decoded =
            ObservedNamespaceInspectorActivationSnapshotV1::decode_untrusted(&bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert!(bytes.len() <= MAXIMUM_MANAGER_QUERY_FRAME_BYTES);
    }

    #[test]
    fn matcher_is_nonminting_and_rejects_dynamic_drift() {
        let contract = contract();
        let first = test_snapshot();
        let second = first.clone();
        match_namespace_inspector_activation_snapshots(&contract, first, second).unwrap();

        let first = test_snapshot();
        let mut second = first.clone();
        second.control_group_id += 1;
        second.properties[18].value =
            CanonicalManagerPropertyValueV1::Scalar(second.control_group_id.to_le_bytes().to_vec());
        assert_eq!(
            match_namespace_inspector_activation_snapshots(&contract, first, second),
            Err(NamespaceInspectorManagerQueryError::SnapshotMismatch)
        );
    }

    #[test]
    fn snapshot_rejects_internal_dynamic_property_drift() {
        let mut expected = test_snapshot();
        expected.properties[24].value =
            CanonicalManagerPropertyValueV1::Scalar(999_u32.to_le_bytes().to_vec());
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidSnapshot)
        );
    }

    #[test]
    fn matcher_rejects_socket_invocation_drift() {
        let contract = contract();
        let first = test_snapshot();
        let mut second = first.clone();
        second.properties[106].value = CanonicalManagerPropertyValueV1::Scalar(vec![9; 16]);

        assert_eq!(
            match_namespace_inspector_activation_snapshots(&contract, first, second),
            Err(NamespaceInspectorManagerQueryError::SnapshotMismatch)
        );
    }

    #[test]
    fn nonzero_command_status_is_projected_but_still_bound_across_snapshots() {
        let contract = contract();
        let first = test_snapshot();
        let CanonicalManagerPropertyValueV1::OrderedArray(elements) = &first.properties[34].value
        else {
            panic!("ExecStart is an ordered command array");
        };
        assert!(elements[0].iter().rev().take(4).any(|byte| *byte != 0));

        match_namespace_inspector_activation_snapshots(&contract, first.clone(), first).unwrap();
    }

    #[test]
    fn changed_command_policy_fails_static_matching() {
        let contract = contract();
        let mut first = test_snapshot();
        let CanonicalManagerPropertyValueV1::OrderedArray(elements) =
            &mut first.properties[34].value
        else {
            panic!("ExecStart is an ordered command array");
        };
        elements[0][2] = b'x';
        let second = first.clone();

        assert_eq!(
            match_namespace_inspector_activation_snapshots(&contract, first, second),
            Err(NamespaceInspectorManagerQueryError::StaticPropertyMismatch)
        );
    }

    #[test]
    fn command_runtime_suffix_drift_fails_snapshot_matching() {
        let contract = contract();
        let first = test_snapshot();
        let mut second = first.clone();
        let CanonicalManagerPropertyValueV1::OrderedArray(elements) =
            &mut second.properties[34].value
        else {
            panic!("ExecStart is an ordered command array");
        };
        let last = elements[0].last_mut().unwrap();
        *last = last.wrapping_add(1);

        assert_eq!(
            match_namespace_inspector_activation_snapshots(&contract, first, second),
            Err(NamespaceInspectorManagerQueryError::SnapshotMismatch)
        );
    }

    #[test]
    fn matcher_rejects_static_property_drift() {
        let contract = contract();
        let mut first = test_snapshot();
        let static_index = MANAGER_PROPERTY_TABLE_V1
            .iter()
            .position(|descriptor| descriptor.binding == ManagerPropertyBindingV1::StaticContract)
            .unwrap();
        first.properties[static_index].value =
            CanonicalManagerPropertyValueV1::Scalar(b"changed".to_vec());
        let second = first.clone();

        assert_eq!(
            match_namespace_inspector_activation_snapshots(&contract, first, second),
            Err(NamespaceInspectorManagerQueryError::StaticPropertyMismatch)
        );
    }

    #[test]
    fn unordered_values_must_be_strictly_sorted() {
        let mut value = CanonicalManagerPropertyValueV1::UnorderedSet(vec![
            b"Z=value".to_vec(),
            b"A=value".to_vec(),
        ]);
        assert_eq!(
            validate_property_value(&MANAGER_PROPERTY_TABLE_V1[0], &value, false),
            Err(NamespaceInspectorManagerQueryError::NoncanonicalSet)
        );

        value = CanonicalManagerPropertyValueV1::UnorderedSet(vec![
            b"A=value".to_vec(),
            b"A=value".to_vec(),
        ]);
        assert_eq!(
            validate_property_value(&MANAGER_PROPERTY_TABLE_V1[0], &value, false),
            Err(NamespaceInspectorManagerQueryError::NoncanonicalSet)
        );
    }

    #[test]
    fn snapshot_decoder_rejects_oversized_frame_before_fields() {
        let bytes = vec![0; MAXIMUM_MANAGER_QUERY_FRAME_BYTES + 1];
        assert_eq!(
            ObservedNamespaceInspectorActivationSnapshotV1::decode_untrusted(&bytes),
            Err(NamespaceInspectorManagerQueryError::FrameTooLarge)
        );
    }

    #[test]
    fn corrupt_collection_count_is_rejected_before_allocation() {
        let bytes = contract().encode().unwrap();
        let mut corrupt = bytes.clone();

        // The first body field is the inspector argv count. A value above its
        // fixed maximum fails before `Vec::with_capacity` is reached.
        corrupt[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            NamespaceInspectorDeploymentContractV1::decode_untrusted(&corrupt),
            Err(NamespaceInspectorManagerQueryError::FieldTooLarge)
        );
    }

    #[test]
    fn header_rejects_unknown_version_kind_and_reserved_byte() {
        let bytes = contract().encode().unwrap();
        for (offset, replacement) in [(8, 2), (10, 99), (11, 1)] {
            let mut corrupt = bytes.clone();
            corrupt[offset] = replacement;
            assert_eq!(
                NamespaceInspectorDeploymentContractV1::decode_untrusted(&corrupt),
                Err(NamespaceInspectorManagerQueryError::InvalidFrame)
            );
        }
    }

    #[test]
    fn frame_length_and_trailing_bytes_are_terminal() {
        let bytes = contract().encode().unwrap();
        let mut corrupt = bytes.clone();
        corrupt.push(0);
        assert_eq!(
            NamespaceInspectorDeploymentContractV1::decode_untrusted(&corrupt),
            Err(NamespaceInspectorManagerQueryError::InvalidFrame)
        );

        let corrupt_length = corrupt.len() as u32;
        corrupt[12..16].copy_from_slice(&corrupt_length.to_le_bytes());
        assert_eq!(
            NamespaceInspectorDeploymentContractV1::decode_untrusted(&corrupt),
            Err(NamespaceInspectorManagerQueryError::InvalidFrame)
        );
    }

    #[test]
    fn scalar_widths_and_boolean_values_are_closed() {
        for (signature, invalid) in [
            ("b", vec![2]),
            ("b", vec![0, 0]),
            ("u", vec![0; 3]),
            ("i", vec![0; 5]),
            ("t", vec![0; 7]),
        ] {
            assert_eq!(
                validate_property_value(
                    descriptor(signature),
                    &CanonicalManagerPropertyValueV1::Scalar(invalid),
                    false,
                ),
                Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch)
            );
        }
    }

    #[test]
    fn strings_and_tuples_have_one_canonical_leaf_layout() {
        for invalid in [vec![0xff], b"embedded\0nul".to_vec()] {
            assert_eq!(
                validate_property_value(
                    descriptor("s"),
                    &CanonicalManagerPropertyValueV1::Scalar(invalid),
                    false,
                ),
                Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch)
            );
        }

        for signature in ["(uo)", "(bs)", "(ss)", "(bas)"] {
            let valid = test_property_value(descriptor(signature), false);
            validate_property_value(descriptor(signature), &valid, false).unwrap();

            let CanonicalManagerPropertyValueV1::Scalar(mut truncated) = valid else {
                panic!("tuple fixtures are scalars");
            };
            truncated.pop();
            assert!(
                validate_property_value(
                    descriptor(signature),
                    &CanonicalManagerPropertyValueV1::Scalar(truncated),
                    false,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn execution_and_socket_tuple_elements_are_framed() {
        for signature in ["a(sb)", "a(ss)", "a(sasbttttuii)", "a(sasasttttuii)"] {
            let descriptor = descriptor(signature);
            let valid = test_property_value(descriptor, false);
            validate_property_value(descriptor, &valid, false).unwrap();

            let CanonicalManagerPropertyValueV1::OrderedArray(mut elements) = valid else {
                panic!("tuple-array fixtures are ordered arrays");
            };
            elements[0].push(0);
            assert_eq!(
                validate_property_value(
                    descriptor,
                    &CanonicalManagerPropertyValueV1::OrderedArray(elements),
                    false,
                ),
                Err(NamespaceInspectorManagerQueryError::PropertyTableMismatch)
            );
        }
    }

    #[test]
    fn every_command_variant_has_closed_static_and_runtime_layouts() {
        let commands: Vec<_> = MANAGER_PROPERTY_TABLE_V1
            .iter()
            .filter(|descriptor| {
                matches!(descriptor.signature, "a(sasbttttuii)" | "a(sasasttttuii)")
            })
            .collect();
        assert_eq!(commands.len(), 16);

        for descriptor in commands {
            let expected = test_property_value(descriptor, true);
            validate_property_value(descriptor, &expected, true).unwrap();
            assert!(validate_property_value(descriptor, &expected, false).is_err());

            let observed = test_property_value(descriptor, false);
            validate_property_value(descriptor, &observed, false).unwrap();
            assert!(validate_property_value(descriptor, &observed, true).is_err());

            let CanonicalManagerPropertyValueV1::OrderedArray(mut malformed_prefix) = expected
            else {
                panic!("command projection is an ordered array");
            };
            malformed_prefix[0].pop();
            assert!(
                validate_property_value(
                    descriptor,
                    &CanonicalManagerPropertyValueV1::OrderedArray(malformed_prefix),
                    true,
                )
                .is_err()
            );

            let CanonicalManagerPropertyValueV1::OrderedArray(mut malformed_suffix) = observed
            else {
                panic!("observed command is an ordered array");
            };
            malformed_suffix[0].pop();
            assert!(
                validate_property_value(
                    descriptor,
                    &CanonicalManagerPropertyValueV1::OrderedArray(malformed_suffix),
                    false,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn manager_environment_rejects_invalid_and_duplicate_names() {
        for values in [
            vec![b"1BAD=value".to_vec()],
            vec![b"MISSING_EQUALS".to_vec()],
            vec![b"A=first".to_vec(), b"A=second".to_vec()],
        ] {
            assert!(
                validate_property_value(
                    &MANAGER_PROPERTY_TABLE_V1[0],
                    &CanonicalManagerPropertyValueV1::UnorderedSet(values),
                    false,
                )
                .is_err()
            );
        }
    }
}
