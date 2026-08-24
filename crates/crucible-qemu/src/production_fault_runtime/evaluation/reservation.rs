//! External event-owner reservation at a production evaluation boundary.

use super::*;

impl ProductionFaultRuntime {
    /// Evaluates one scheduler boundary against host devices and live QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`FaultExecutionError`] when evaluation, preparation, live
    /// application, evidence validation, or checkpointing fails.
    pub fn evaluate_boundary(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        self.evaluate_boundary_with_event_reservation(
            coordinate,
            same_coordinate_sequence,
            nodes,
            0,
            0,
        )
    }

    /// Evaluates one boundary while retaining capacity for an external event owner.
    ///
    /// The lifecycle controller durably owns records and bytes in the same
    /// authored aggregate as this runtime. Reducing the runtime's effective
    /// allowance before preview and APPLY prevents the two owners from each
    /// consuming an independent copy of that allowance. Any typed failure is
    /// translated back to the plan-authored aggregate coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the external reservation
    /// or the boundary evaluation exceeds the authored aggregate, or when
    /// evaluation, adapter execution, or evidence validation fails.
    pub fn evaluate_boundary_with_event_reservation(
        &mut self,
        coordinate: FaultCoordinate,
        same_coordinate_sequence: u64,
        nodes: &mut QemuNodeSet,
        reserved_event_records: u64,
        reserved_event_log_bytes: u64,
    ) -> Result<BindingEvaluation, ProductionFaultRuntimeError> {
        let authored = self.resource_limits;
        authored.reserve("event_records", 0, reserved_event_records)?;
        authored.reserve("event_log_bytes", 0, reserved_event_log_bytes)?;
        let mut effective = authored;
        effective.event_records = effective
            .event_records
            .checked_sub(reserved_event_records)
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_records",
                value: reserved_event_records,
            })?;
        effective.event_log_bytes = effective
            .event_log_bytes
            .checked_sub(reserved_event_log_bytes)
            .ok_or(FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: reserved_event_log_bytes,
            })?;

        self.resource_limits = effective;
        let result = self.evaluate_boundary_with_effective_limits(
            coordinate,
            same_coordinate_sequence,
            nodes,
        );
        self.resource_limits = authored;
        result.map_err(|error| {
            restore_external_event_reservation(
                error,
                authored,
                effective,
                reserved_event_records,
                reserved_event_log_bytes,
            )
        })
    }
}

fn restore_external_event_reservation(
    error: ProductionFaultRuntimeError,
    authored: FaultResourceLimits,
    effective: FaultResourceLimits,
    reserved_event_records: u64,
    reserved_event_log_bytes: u64,
) -> ProductionFaultRuntimeError {
    let ProductionFaultRuntimeError::ResourceLimit(error) = error else {
        return error;
    };
    let reservation = |field| match field {
        "event_records" => Some((
            reserved_event_records,
            effective.event_records,
            authored.event_records,
        )),
        "event_log_bytes" => Some((
            reserved_event_log_bytes,
            effective.event_log_bytes,
            authored.event_log_bytes,
        )),
        _ => None,
    };
    let restored = match error {
        FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        } => {
            let Some((reserved, effective_configured, authored_configured)) = reservation(field)
            else {
                return FaultResourceLimitError::Exceeded {
                    field,
                    current,
                    requested,
                    configured,
                    hard,
                }
                .into();
            };
            if configured != effective_configured {
                return FaultResourceLimitError::Exceeded {
                    field,
                    current,
                    requested,
                    configured,
                    hard,
                }
                .into();
            }
            FaultResourceLimitError::Exceeded {
                field,
                current: current.saturating_add(reserved),
                requested,
                configured: authored_configured,
                hard,
            }
        }
        FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        } => {
            let Some((reserved, effective_configured, authored_configured)) = reservation(field)
            else {
                return FaultResourceLimitError::UsageOverflow {
                    field,
                    current,
                    requested,
                    configured,
                    hard,
                }
                .into();
            };
            if configured != effective_configured {
                return FaultResourceLimitError::UsageOverflow {
                    field,
                    current,
                    requested,
                    configured,
                    hard,
                }
                .into();
            }
            FaultResourceLimitError::UsageOverflow {
                field,
                current: current.saturating_add(reserved),
                requested,
                configured: authored_configured,
                hard,
            }
        }
        error => error,
    };
    restored.into()
}
