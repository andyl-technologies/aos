//! Closed-schema validation for typed node-fault payloads.

use super::*;

impl NodeFaultPayloadV1 {
    pub(super) fn validate_closed_schema(&self) -> Result<(), NodeFaultPayloadError> {
        use NodeFaultFieldTypeV1 as Ty;
        use node_fault_field::*;

        let target = match self.target_kind {
            NodeFaultTargetKindV1::Node => &[][..],
            NodeFaultTargetKindV1::Vcpu => &[(T1, Ty::U32)][..],
            NodeFaultTargetKindV1::Register => &[
                (T1, Ty::U32),
                (T2, Ty::Hash),
                (T3, Ty::Hash),
                (T4, Ty::U32),
                (T5, Ty::U32),
            ][..],
            NodeFaultTargetKindV1::Memory => &[
                (T1, Ty::Hash),
                (T2, Ty::U64),
                (T3, Ty::Bool),
                (T4, Ty::U32),
                (T5, Ty::U64),
            ][..],
            NodeFaultTargetKindV1::Interrupt => {
                &[(T1, Ty::Hash), (T2, Ty::Hash), (T3, Ty::U32), (T4, Ty::U32)][..]
            }
            NodeFaultTargetKindV1::Clock => &[(T1, Ty::Hash)][..],
            NodeFaultTargetKindV1::Accelerator => &[(T1, Ty::Hash)][..],
        };
        let parameters = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::Bytes),
                (P4, Ty::U32),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::NodeHang => &[
                (P1, Ty::U32),
                (P2, Ty::Bytes),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
            ][..],
            FaultCommandKind::CpuService => &[
                (P1, Ty::Bytes),
                (P2, Ty::Ratio),
                (P3, Ty::U64),
                (P4, Ty::U32),
            ][..],
            FaultCommandKind::CpuVcpuState => &[(P1, Ty::U32), (P2, Ty::Bool), (P3, Ty::Hash)][..],
            FaultCommandKind::CpuRegisterTransform => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U32),
                (P4, Ty::U32),
                (P5, Ty::Bytes),
                (P6, Ty::Bool),
                (P7, Ty::Bytes),
                (P8, Ty::Bytes),
            ][..],
            FaultCommandKind::CpuInstructionTransform => &[
                (P1, Ty::Bytes),
                (P2, Ty::U32),
                (P3, Ty::Hash),
                (P4, Ty::Bytes),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::CpuException => &[(P1, Ty::Bytes)][..],
            FaultCommandKind::InterruptDisposition => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::U64),
                (P5, Ty::U32),
            ][..],
            FaultCommandKind::InterruptStorm => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::U64),
                (P4, Ty::U32),
                (P5, Ty::U32),
                (P6, Ty::Bytes),
            ][..],
            FaultCommandKind::MemoryAccessTransform => &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::U32),
                (P4, Ty::Bytes),
                (P5, Ty::Bool),
                (P6, Ty::Bytes),
                (P7, Ty::Bytes),
                (P8, Ty::U32),
                (P9, Ty::Bool),
                (P10, Ty::Bool),
                (P11, Ty::Hash),
            ][..],
            FaultCommandKind::MemoryEccEvent => &[
                (P1, Ty::U32),
                (P2, Ty::U64),
                (P3, Ty::U64),
                (P4, Ty::Hash),
                (P5, Ty::Hash),
                (P6, Ty::Hash),
                (P7, Ty::Bytes),
                (P8, Ty::U32),
            ][..],
            FaultCommandKind::MemoryRegionState => {
                &[(P1, Ty::U64), (P2, Ty::U64), (P3, Ty::U32), (P4, Ty::Bytes)][..]
            }
            FaultCommandKind::MemoryService => &[
                (P1, Ty::U64),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ][..],
            FaultCommandKind::ClockTransform => &[
                (P1, Ty::Hash),
                (P2, Ty::U32),
                (P3, Ty::I64),
                (P4, Ty::Ratio),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
                (P7, Ty::U32),
                (P8, Ty::U32),
            ][..],
            FaultCommandKind::ClockSourceState => {
                &[(P1, Ty::HashSet), (P2, Ty::Bytes), (P3, Ty::Bytes)][..]
            }
            FaultCommandKind::AcceleratorLifecycle => {
                &[(P1, Ty::Hash), (P2, Ty::U32), (P3, Ty::U32), (P4, Ty::U32)][..]
            }
            FaultCommandKind::AcceleratorResultTransform => &[
                (P1, Ty::Bytes),
                (P2, Ty::Bytes),
                (P3, Ty::U64),
                (P4, Ty::Hash),
            ][..],
            FaultCommandKind::AcceleratorMemoryEvent => &[
                (P1, Ty::U64),
                (P2, Ty::U64),
                (P3, Ty::Bool),
                (P4, Ty::U32),
                (P5, Ty::Bool),
                (P6, Ty::U64),
                (P7, Ty::Bool),
                (P8, Ty::Bytes),
            ][..],
            FaultCommandKind::AcceleratorService => &[
                (P1, Ty::Ratio),
                (P2, Ty::Bool),
                (P3, Ty::U64),
                (P4, Ty::Bool),
                (P5, Ty::U64),
                (P6, Ty::Bytes),
            ][..],
            _ => return Err(NodeFaultPayloadError::CommandKind(self.command_kind as u16)),
        };
        if self.fields.len() != parameters.len() + target.len()
            || !parameters.iter().chain(target).all(|(tag, field_type)| {
                self.fields
                    .binary_search_by_key(tag, |field| field.tag)
                    .is_ok_and(|index| self.fields[index].field_type == *field_type)
            })
        {
            return Err(NodeFaultPayloadError::Schema {
                command_kind: self.command_kind as u16,
            });
        }
        self.validate_policy_fields()?;
        self.validate_discriminants()?;
        self.validate_cross_fields()?;
        Ok(())
    }

    fn validate_discriminants(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        let allowed: &[(u16, &[u32])] = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[
                (P1, &[1, 2, 3, 4, 5, 6]),
                (P4, &[1, 2, 3]),
                (P5, &[1, 2, 3]),
            ],
            FaultCommandKind::NodeHang => &[(P1, &[1, 2, 3])],
            FaultCommandKind::CpuService => &[(P4, &[1, 2])],
            FaultCommandKind::CpuVcpuState => &[(P1, &[1, 2, 3])],
            FaultCommandKind::CpuRegisterTransform => &[(P4, &[1, 2, 3])],
            FaultCommandKind::CpuInstructionTransform => &[(P2, &[1, 2, 3])],
            FaultCommandKind::InterruptDisposition => &[(P1, &[1, 2, 3, 4])],
            FaultCommandKind::MemoryAccessTransform => &[(P3, &[1, 2, 3, 4, 5])],
            FaultCommandKind::MemoryEccEvent => &[(P1, &[1, 2])],
            FaultCommandKind::MemoryRegionState => &[(P3, &[1, 2, 3])],
            FaultCommandKind::ClockTransform => &[
                (P2, &[1, 2, 3, 4, 5, 6]),
                (P7, &[1, 2, 3]),
                (P8, &[1, 2, 3]),
            ],
            FaultCommandKind::AcceleratorLifecycle => {
                &[(P2, &[1, 2, 3]), (P3, &[1, 2, 3]), (P4, &[1, 2, 3])]
            }
            _ => &[],
        };
        for (tag, values) in allowed {
            if !values.contains(&self.u32_field(*tag)?) {
                return Err(NodeFaultPayloadError::FieldValue { tag: *tag });
            }
        }
        if self.command_kind == FaultCommandKind::MemoryAccessTransform {
            let classes = self.u32_field(P8)?;
            if classes == 0 || classes & !0x3f != 0 {
                return Err(NodeFaultPayloadError::FieldValue { tag: P8 });
            }
        }
        Ok(())
    }

    fn validate_cross_fields(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        match self.command_kind {
            FaultCommandKind::CpuInstructionTransform => match self.u32_field(P2)? {
                1 if self.hash_is_zero(P3)? || self.u32_field(P5)? != 0 => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P3 })
                }
                2 if !self.hash_is_zero(P3)? || self.u32_field(P5)? != 0 => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P5 })
                }
                3 if !self.hash_is_zero(P3)? || !(1..=256).contains(&self.u32_field(P5)?) => {
                    Err(NodeFaultPayloadError::FieldValue { tag: P5 })
                }
                _ => Ok(()),
            },
            FaultCommandKind::MemoryAccessTransform => {
                if self.u64_field(P2)? == 0 {
                    return Err(NodeFaultPayloadError::FieldValue { tag: P2 });
                }
                let kind = self.u32_field(P3)?;
                let has_value = self.bool_field(P5)?;
                let violate_atomicity = self.bool_field(P9)?;
                let has_dma_device = self.bool_field(P10)?;
                let dma_device_valid = if has_dma_device {
                    !self.hash_is_zero(P11)?
                        && self.u32_field(P8)? & !0x18 == 0
                        && !self.bool_field(T3)?
                } else {
                    self.hash_is_zero(P11)?
                };
                let mask = self.field_with_tag(P4)?.value.as_slice();
                let value = self.field_with_tag(P6)?.value.as_slice();
                let mask_has_one = mask.iter().any(|byte| *byte != 0);
                let value_has_one = value.iter().any(|byte| *byte != 0);
                let valid = match kind {
                    1 => {
                        has_value && !violate_atomicity && mask_has_one && mask.len() == value.len()
                    }
                    2 => !has_value && !violate_atomicity && mask_has_one && value == [0],
                    3 => !has_value && !violate_atomicity && mask == [0] && value == [0],
                    4 => {
                        has_value
                            && mask == [0]
                            && value_has_one
                            && value.iter().any(|byte| *byte != u8::MAX)
                    }
                    5 => has_value && !violate_atomicity && mask == [0],
                    _ => false,
                };
                if valid && dma_device_valid {
                    Ok(())
                } else {
                    Err(NodeFaultPayloadError::FieldValue { tag: P3 })
                }
            }
            FaultCommandKind::ClockTransform => {
                let kind = self.u32_field(P2)?;
                let process_is_sentinel = self.field_with_tag(P6)?.value == [0];
                if matches!(kind, 4..=6) == process_is_sentinel {
                    Err(NodeFaultPayloadError::FieldValue { tag: P6 })
                } else {
                    Ok(())
                }
            }
            FaultCommandKind::AcceleratorMemoryEvent => {
                let has_ecc = self.bool_field(P3)?;
                let has_syndrome = self.bool_field(P5)?;
                let has_transform = self.bool_field(P7)?;
                let transform = self.field_with_tag(P8)?.value.as_slice();
                if (has_ecc && has_syndrome && !has_transform && transform == [0])
                    || (!has_ecc && !has_syndrome && has_transform && transform != [0])
                {
                    Ok(())
                } else {
                    Err(NodeFaultPayloadError::FieldValue { tag: P7 })
                }
            }
            _ => Ok(()),
        }
    }

    fn validate_policy_fields(&self) -> Result<(), NodeFaultPayloadError> {
        use node_fault_field::*;

        let required: &[u16] = match self.command_kind {
            FaultCommandKind::NodeLifecycle => &[P3],
            FaultCommandKind::NodeHang => &[P2, P4],
            FaultCommandKind::CpuService => &[P1],
            FaultCommandKind::CpuRegisterTransform => &[P8],
            FaultCommandKind::CpuInstructionTransform => &[P1],
            FaultCommandKind::CpuException => &[P1],
            FaultCommandKind::InterruptStorm => &[P6],
            FaultCommandKind::MemoryAccessTransform => &[P7],
            FaultCommandKind::MemoryEccEvent => &[P7],
            FaultCommandKind::MemoryRegionState => &[P4],
            FaultCommandKind::MemoryService => &[P6],
            FaultCommandKind::ClockSourceState => &[P2, P3],
            FaultCommandKind::AcceleratorResultTransform => &[P1, P2],
            FaultCommandKind::AcceleratorService => &[P6],
            _ => &[],
        };
        for tag in required {
            self.validate_policy_json(*tag)?;
        }
        if self.command_kind == FaultCommandKind::CpuInstructionTransform {
            if self.u32_field(P2)? == 1 {
                self.validate_policy_json(P4)?;
            } else {
                self.validate_sentinel(P4)?;
            }
        }
        if self.command_kind == FaultCommandKind::MemoryAccessTransform && self.u32_field(P3)? == 5
        {
            self.validate_policy_json(P6)?;
        }
        if self.command_kind == FaultCommandKind::ClockTransform {
            if matches!(self.u32_field(P2)?, 4..=6) {
                self.validate_policy_json(P6)?;
            } else {
                self.validate_sentinel(P6)?;
            }
        }
        Ok(())
    }

    fn field_with_tag(&self, tag: u16) -> Result<&NodeFaultFieldV1, NodeFaultPayloadError> {
        self.fields
            .binary_search_by_key(&tag, |field| field.tag)
            .map(|index| &self.fields[index])
            .map_err(|_| NodeFaultPayloadError::Schema {
                command_kind: self.command_kind as u16,
            })
    }

    fn u32_field(&self, tag: u16) -> Result<u32, NodeFaultPayloadError> {
        let field = self.field_with_tag(tag)?;
        field
            .value
            .as_slice()
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| NodeFaultPayloadError::FieldValue { tag })
    }

    fn u64_field(&self, tag: u16) -> Result<u64, NodeFaultPayloadError> {
        let field = self.field_with_tag(tag)?;
        field
            .value
            .as_slice()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| NodeFaultPayloadError::FieldValue { tag })
    }

    fn bool_field(&self, tag: u16) -> Result<bool, NodeFaultPayloadError> {
        match self.field_with_tag(tag)?.value.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(NodeFaultPayloadError::FieldValue { tag }),
        }
    }

    fn hash_is_zero(&self, tag: u16) -> Result<bool, NodeFaultPayloadError> {
        let value = self.field_with_tag(tag)?.value.as_slice();
        if value.len() == 32 {
            Ok(value.iter().all(|byte| *byte == 0))
        } else {
            Err(NodeFaultPayloadError::FieldValue { tag })
        }
    }

    fn validate_sentinel(&self, tag: u16) -> Result<(), NodeFaultPayloadError> {
        if self.field_with_tag(tag)?.value == [0] {
            Ok(())
        } else {
            Err(NodeFaultPayloadError::FieldValue { tag })
        }
    }

    fn validate_policy_json(&self, tag: u16) -> Result<(), NodeFaultPayloadError> {
        let bytes = &self.field_with_tag(tag)?.value;
        let Some(json) = bytes.strip_prefix(&NODE_FAULT_POLICY_JSON_MAGIC_V1) else {
            return Err(NodeFaultPayloadError::PolicyJson { tag });
        };
        let value: serde_json::Value = serde_json::from_slice(json)
            .map_err(|_source| NodeFaultPayloadError::PolicyJson { tag })?;
        if !matches!(
            value,
            serde_json::Value::Object(_)
                | serde_json::Value::Array(_)
                | serde_json::Value::String(_)
        ) || !policy_json_value_is_allowed(&value)
        {
            return Err(NodeFaultPayloadError::PolicyJson { tag });
        }
        let canonical = serde_json::to_vec(&value)
            .map_err(|_source| NodeFaultPayloadError::PolicyJson { tag })?;
        if canonical == json {
            Ok(())
        } else {
            Err(NodeFaultPayloadError::PolicyJson { tag })
        }
    }
}

fn policy_json_value_is_allowed(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => true,
        serde_json::Value::Number(number) => number.is_i64() || number.is_u64(),
        serde_json::Value::Array(values) => values.iter().all(policy_json_value_is_allowed),
        serde_json::Value::Object(values) => values.values().all(policy_json_value_is_allowed),
    }
}
