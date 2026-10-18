//! Allocation-aware canonical material for resolved fault targets.

use super::{ContentHash, FaultObjectId, ResolvedFaultTarget};

impl ResolvedFaultTarget {
    /// Returns the exact stable target material used by content identities.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        let mut material = String::new();
        self.append_canonical(&mut material);
        material
    }

    /// Returns the exact byte length of the stable target identity material.
    #[must_use]
    pub fn canonical_material_length(&self) -> usize {
        let mut length = 0;
        self.emit_canonical(|fragment| {
            length += fragment.encoded_length();
        });
        length
    }

    /// Appends stable target identity bytes into an already reserved buffer.
    ///
    /// This method never grows `material`: callers must reserve at least
    /// [`Self::canonical_material_length`] additional bytes first. That lets
    /// checkpoint owners perform typed resource admission before any target
    /// identity allocation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultCanonicalMaterialError`] when the buffer's spare capacity
    /// is smaller than the exact canonical target representation.
    pub fn append_canonical_material_bytes(
        &self,
        material: &mut Vec<u8>,
    ) -> Result<(), FaultCanonicalMaterialError> {
        let required = self.canonical_material_length();
        let available = material.capacity().saturating_sub(material.len());
        if available < required {
            return Err(FaultCanonicalMaterialError {
                available,
                required,
            });
        }
        self.emit_canonical(|fragment| fragment.append_bytes(material));
        Ok(())
    }

    pub(in crate::model::fault_signal) fn append_canonical(&self, material: &mut String) {
        self.emit_canonical(|fragment| fragment.append_string(material));
    }

    fn emit_canonical(&self, mut emit: impl FnMut(TargetCanonicalFragment<'_>)) {
        emit(TargetCanonicalFragment::Raw(self.kind().as_str()));
        emit(TargetCanonicalFragment::Raw(":"));
        match self {
            Self::NetworkInterface {
                endpoint,
                interface,
            } => emit_ids(&mut emit, &[endpoint, interface]),
            Self::NetworkSegment { segment, direction } => {
                emit_ids(&mut emit, &[segment]);
                emit(TargetCanonicalFragment::Text(direction.as_str()));
            }
            Self::NetworkMedium { medium, resource } => {
                emit_ids(&mut emit, &[medium, resource]);
            }
            Self::NetworkQueue { owner, queue } => emit_ids(&mut emit, &[owner, queue]),
            Self::NetworkForwarder { forwarder } => emit_ids(&mut emit, &[forwarder]),
            Self::NetworkPath {
                path_version,
                direction,
            } => {
                emit_ids(&mut emit, &[path_version]);
                emit(TargetCanonicalFragment::Text(direction.as_str()));
            }
            Self::NetworkAttachment {
                endpoint,
                interface,
                attachment,
            } => emit_ids(&mut emit, &[endpoint, interface, attachment]),
            Self::NetworkContact {
                plan,
                endpoint_a,
                endpoint_b,
                contact,
            } => emit_ids(&mut emit, &[plan, endpoint_a, endpoint_b, contact]),
            Self::BlockDevice { device } | Self::NinePDevice { device } => {
                emit(TargetCanonicalFragment::Hash(*device));
            }
            Self::BlockRange {
                device,
                start_byte,
                length_bytes,
            } => {
                emit(TargetCanonicalFragment::Hash(*device));
                emit(TargetCanonicalFragment::Integer(*start_byte));
                emit(TargetCanonicalFragment::Integer(*length_bytes));
            }
            Self::StorageController {
                controller,
                namespace_or_path,
            } => emit_ids(&mut emit, &[controller, namespace_or_path]),
            Self::StorageArray {
                array,
                member_or_path,
            } => emit_ids(&mut emit, &[array, member_or_path]),
            Self::Node { node } => emit_ids(&mut emit, &[node]),
            Self::Vcpu { node, vcpu } => {
                emit_ids(&mut emit, &[node]);
                emit(TargetCanonicalFragment::Integer(u64::from(*vcpu)));
            }
            Self::Register {
                node,
                vcpu,
                architecture,
                register,
                first_bit,
                bit_count,
            } => {
                emit_ids(&mut emit, &[node, architecture, register]);
                emit(TargetCanonicalFragment::Integer(u64::from(*vcpu)));
                emit(TargetCanonicalFragment::Integer(u64::from(*first_bit)));
                emit(TargetCanonicalFragment::Integer(u64::from(*bit_count)));
            }
            Self::MemoryRange {
                node,
                address_space,
                guest_address,
                vcpu,
                length_bytes,
            } => {
                emit_ids(&mut emit, &[node, address_space]);
                emit(TargetCanonicalFragment::Integer(*guest_address));
                emit(TargetCanonicalFragment::Integer(
                    vcpu.map_or(u64::MAX, u64::from),
                ));
                emit(TargetCanonicalFragment::Integer(*length_bytes));
            }
            Self::Interrupt {
                node,
                controller,
                source,
                target_vcpu,
                vector,
            } => {
                emit_ids(&mut emit, &[node, controller, source]);
                emit(TargetCanonicalFragment::Integer(u64::from(*target_vcpu)));
                emit(TargetCanonicalFragment::Integer(u64::from(*vector)));
            }
            Self::ClockSource { node, source } => emit_ids(&mut emit, &[node, source]),
            Self::Accelerator { node, device } => emit_ids(&mut emit, &[node, device]),
        }
    }
}

/// Failure to append canonical target material into a caller-owned reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "canonical target material reservation is too small: available={available}, required={required}"
)]
pub struct FaultCanonicalMaterialError {
    /// Unused bytes in the caller's current allocation.
    pub available: usize,
    /// Exact additional bytes required by the target material.
    pub required: usize,
}

enum TargetCanonicalFragment<'a> {
    Raw(&'a str),
    Text(&'a str),
    Integer(u64),
    Hash(ContentHash),
}

impl TargetCanonicalFragment<'_> {
    fn encoded_length(&self) -> usize {
        match self {
            Self::Raw(value) => value.len(),
            Self::Text(value) => decimal_length(value.len() as u64) + 1 + value.len() + 1,
            Self::Integer(value) => decimal_length(*value) + 1,
            Self::Hash(_hash) => 2 + 1 + 64 + 1,
        }
    }

    fn append_string(&self, material: &mut String) {
        match self {
            Self::Raw(value) => material.push_str(value),
            Self::Text(value) => super::push_text(material, value),
            Self::Integer(value) => super::push_u64(material, *value),
            Self::Hash(hash) => super::push_text(material, &hash.to_hex()),
        }
    }

    fn append_bytes(&self, material: &mut Vec<u8>) {
        match self {
            Self::Raw(value) => material.extend_from_slice(value.as_bytes()),
            Self::Text(value) => append_text_bytes(material, value.as_bytes()),
            Self::Integer(value) => {
                append_decimal_bytes(material, *value);
                material.push(b';');
            }
            Self::Hash(hash) => append_hash_text_bytes(material, hash),
        }
    }
}

fn emit_ids<'a>(emit: &mut impl FnMut(TargetCanonicalFragment<'a>), ids: &[&'a FaultObjectId]) {
    for id in ids {
        emit(TargetCanonicalFragment::Text(id.as_str()));
    }
}

fn decimal_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn append_decimal_bytes(material: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut offset = digits.len();
    loop {
        offset -= 1;
        digits[offset] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    material.extend_from_slice(&digits[offset..]);
}

fn append_text_bytes(material: &mut Vec<u8>, value: &[u8]) {
    append_decimal_bytes(material, value.len() as u64);
    material.push(b':');
    material.extend_from_slice(value);
    material.push(b';');
}

fn append_hash_text_bytes(material: &mut Vec<u8>, hash: &ContentHash) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    material.extend_from_slice(b"64:");
    for byte in hash.bytes {
        material.push(HEX[usize::from(byte >> 4)]);
        material.push(HEX[usize::from(byte & 0x0f)]);
    }
    material.push(b';');
}
