//! Exhaustive scenario-owned resource limits for the fault system.
//!
//! The public plan carries every executable limit named by RFC-0013. Values
//! may be lowered but never raised above the compiled ceiling. This table is
//! also the machine-readable source for reference generation and generic
//! resource diagnostics, so adapters cannot introduce hidden semantic bounds.

use std::error::Error;
use std::fmt;

use super::*;

/// One public resource-limit field and its compiled values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultResourceLimitDescriptor {
    /// Canonical TOML field name.
    pub field: &'static str,
    /// Scenario default.
    pub default: u64,
    /// Maximum accepted authored value.
    pub hard: u64,
}

macro_rules! define_fault_resource_limits {
    ($($field:ident: $default:literal => $hard:literal,)+) => {
        /// Complete resource contract for one signal-driven fault plan.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct FaultResourceLimits {
            $(
                #[doc = concat!("Maximum admitted `", stringify!($field), "` resource usage.")]
                pub $field: u64,
            )+
        }

        impl Default for FaultResourceLimits {
            fn default() -> Self {
                Self {
                    $($field: $default,)+
                }
            }
        }

        /// Exhaustive resource-limit registry in canonical schema order.
        pub const FAULT_RESOURCE_LIMIT_DESCRIPTORS: &[FaultResourceLimitDescriptor] = &[
            $(FaultResourceLimitDescriptor {
                field: stringify!($field),
                default: $default,
                hard: $hard,
            },)+
        ];

        impl FaultResourceLimits {
            /// Validates every configured value against its compiled ceiling.
            ///
            /// # Errors
            ///
            /// Returns [`FaultResourceLimitError`] when a field is zero or is
            /// greater than its compiled hard ceiling.
            pub fn validate(self) -> Result<(), FaultResourceLimitError> {
                $(check_configured_limit(stringify!($field), self.$field, $hard)?;)+
                Ok(())
            }

            /// Returns one configured limit by its exact public field name.
            #[must_use]
            pub fn configured(self, field: &str) -> Option<u64> {
                match field {
                    $(stringify!($field) => Some(self.$field),)+
                    _ => None,
                }
            }

            /// Checks a dynamic resource reservation before state mutation.
            ///
            /// `current` is already-retained usage and `requested` is the
            /// additional atomic reservation. Both values enter the typed
            /// failure so replay observes the same terminal outcome.
            ///
            /// # Errors
            ///
            /// Returns [`FaultResourceLimitError`] for an unknown field,
            /// arithmetic overflow, or a reservation above the configured
            /// scenario limit.
            pub fn reserve(
                self,
                field: &'static str,
                current: u64,
                requested: u64,
            ) -> Result<(), FaultResourceLimitError> {
                match field {
                    $(stringify!($field) => check_dynamic_limit(
                        stringify!($field), current, requested, self.$field, $hard,
                    ),)+
                    _ => Err(FaultResourceLimitError::UnknownField { field }),
                }
            }

            /// Returns canonical identity material in schema order.
            #[must_use]
            pub fn canonical_material(self) -> String {
                let mut material = String::new();
                $(
                    material.push_str(stringify!($field));
                    material.push('=');
                    material.push_str(&self.$field.to_string());
                    material.push('\n');
                )+
                material
            }

            /// Returns a canonical JSON object in schema order.
            #[must_use]
            pub fn canonical_json_object(self) -> String {
                let mut material = String::from("{");
                let mut first = true;
                $(
                    if first {
                        first = false;
                    } else {
                        material.push(',');
                    }
                    material.push('"');
                    material.push_str(stringify!($field));
                    material.push_str("\":");
                    material.push_str(&self.$field.to_string());
                )+
                let _ = first;
                material.push('}');
                material
            }
        }
    };
}

define_fault_resource_limits! {
    signal_nodes: 16_384 => 65_536,
    signal_edges: 65_536 => 262_144,
    signal_inputs_per_node: 64 => 256,
    signal_state_bytes: 67_108_864 => 268_435_456,
    state_machine_states_per_node: 4_096 => 65_536,
    state_machine_transitions_per_node: 16_384 => 262_144,
    lookup_points_per_node: 65_536 => 1_048_576,
    bindings: 32_768 => 131_072,
    signals_per_binding: 32 => 128,
    resolved_targets_per_binding: 65_536 => 262_144,
    active_contributions_per_target: 1_024 => 4_096,
    effect_payload_bytes: 1_048_576 => 16_777_216,
    events_emitted_per_signal_transition: 256 => 4_096,
    trace_artifacts: 1_024 => 16_384,
    trace_channels_total: 16_384 => 65_536,
    trace_channels_per_artifact: 4_096 => 16_384,
    trace_entries_per_chunk: 4_096 => 4_096,
    trace_chunks_total: 4_194_304 => 16_777_216,
    trace_entries_total: 4_294_967_296 => 17_179_869_184,
    trace_normalized_bytes_total: 274_877_906_944 => 1_099_511_627_776,
    trace_single_payload_bytes: 16_777_216 => 67_108_864,
    trace_manifest_bytes: 67_108_864 => 268_435_456,
    spatial_grid_cells_total: 268_435_456 => 1_073_741_824,
    spatial_zone_vertices_total: 16_777_216 => 67_108_864,
    network_interfaces: 16_384 => 65_536,
    network_segments: 65_536 => 262_144,
    network_forwarders: 8_192 => 32_768,
    network_media: 4_096 => 16_384,
    network_queues: 65_536 => 262_144,
    network_paths: 65_536 => 262_144,
    network_path_hops: 256 => 1_024,
    network_medium_participants: 4_096 => 16_384,
    network_resources_per_medium: 4_096 => 16_384,
    network_pending_frames: 1_048_576 => 4_194_304,
    network_frame_bytes: 16_777_216 => 67_108_864,
    network_queue_frames: 262_144 => 1_048_576,
    network_queue_bytes: 1_073_741_824 => 8_589_934_592,
    network_forwarding_entries: 1_048_576 => 4_194_304,
    network_connection_entries: 1_048_576 => 4_194_304,
    network_contact_entries: 4_194_304 => 16_777_216,
    network_custody_bundles: 1_048_576 => 4_194_304,
    network_loop_hops: 256 => 1_024,
    network_retries_per_frame_per_hop: 64 => 1_024,
    network_duplicates_per_frame_per_hop: 16 => 256,
    storage_devices: 4_096 => 16_384,
    storage_pending_operations: 1_048_576 => 4_194_304,
    storage_request_bytes: 16_777_216 => 67_108_864,
    storage_queue_operations: 262_144 => 1_048_576,
    storage_cache_bytes_per_device: 17_179_869_184 => 68_719_476_736,
    storage_cache_entries_per_device: 1_048_576 => 4_194_304,
    storage_persistence_dependencies: 4_194_304 => 16_777_216,
    storage_media_intervals_per_device: 1_048_576 => 4_194_304,
    storage_retained_versions_per_interval: 64 => 1_024,
    storage_flash_blocks_per_device: 16_777_216 => 67_108_864,
    storage_array_members: 256 => 4_096,
    storage_retries_per_operation: 64 => 1_024,
    storage_completed_history_epochs: 1_048_576 => 1_048_576,
    storage_completed_history_gaps: 1_048_576 => 1_048_576,
    ninep_sessions_per_device: 65_536 => 262_144,
    ninep_fids_per_session: 65_536 => 262_144,
    ninep_object_versions: 1_048_576 => 4_194_304,
    nodes: 4_096 => 16_384,
    vcpus_per_node: 256 => 4_096,
    node_mutations_pending: 65_536 => 262_144,
    memory_mutation_bytes_per_effect: 1_048_576 => 16_777_216,
    memory_fault_intervals_per_node: 1_048_576 => 4_194_304,
    memory_access_counters_per_node: 1_048_576 => 4_194_304,
    instruction_fault_rules_per_node: 65_536 => 262_144,
    interrupt_fault_rules_per_node: 65_536 => 262_144,
    interrupt_events_pending_per_node: 262_144 => 1_048_576,
    clock_fault_rules_per_node: 4_096 => 16_384,
    accelerators_per_node: 256 => 1_024,
    accelerator_jobs_pending: 262_144 => 1_048_576,
    instruction_replay_count: 16 => 256,
    interrupt_storm_events: 1_048_576 => 4_194_304,
    event_records: 268_435_456 => 1_073_741_824,
    event_log_bytes: 68_719_476_736 => 274_877_906_944,
    event_inline_payload_bytes: 65_536 => 1_048_576,
    checkpoint_count: 65_536 => 262_144,
    fat_checkpoint_bytes: 17_179_869_184 => 68_719_476_736,
    thin_replay_events: 268_435_456 => 1_073_741_824,
    resolved_effect_records: 268_435_456 => 1_073_741_824,
    replay_first_mismatch_context_bytes: 16_777_216 => 67_108_864,
    search_states: 1_048_576 => 16_777_216,
    search_depth: 65_536 => 262_144,
    search_candidates_per_choice: 256 => 4_096,
    search_choices_per_state: 65_536 => 262_144,
    trace_mutation_windows: 65_536 => 262_144,
    mapping_mutation_points: 65_536 => 262_144,
    minimization_attempts: 1_048_576 => 16_777_216,
}

impl FaultResourceLimits {
    /// Derives the evaluator's internal graph limits from the public contract.
    ///
    /// # Errors
    ///
    /// Returns [`FaultResourceLimitError`] if any public limit is invalid or
    /// cannot be represented by the evaluator's narrower validated types.
    pub fn signal_limits(self) -> Result<SignalResourceLimits, FaultResourceLimitError> {
        self.validate()?;
        Ok(SignalResourceLimits {
            nodes: narrow_u32("signal_nodes", self.signal_nodes)?,
            edges: narrow_u32("signal_edges", self.signal_edges)?,
            inputs_per_node: narrow_u16("signal_inputs_per_node", self.signal_inputs_per_node)?,
            graph_depth: HARD_SIGNAL_GRAPH_DEPTH_LIMIT,
            state_bytes: self.signal_state_bytes,
            authored_payload_bytes: self.effect_payload_bytes,
            states_per_node: narrow_u32(
                "state_machine_states_per_node",
                self.state_machine_states_per_node,
            )?,
            transitions_per_node: narrow_u32(
                "state_machine_transitions_per_node",
                self.state_machine_transitions_per_node,
            )?,
            lookup_points_per_node: narrow_u32(
                "lookup_points_per_node",
                self.lookup_points_per_node,
            )?,
        })
    }
}

fn narrow_u32(field: &'static str, value: u64) -> Result<u32, FaultResourceLimitError> {
    u32::try_from(value).map_err(|_| FaultResourceLimitError::Representation { field, value })
}

fn narrow_u16(field: &'static str, value: u64) -> Result<u16, FaultResourceLimitError> {
    u16::try_from(value).map_err(|_| FaultResourceLimitError::Representation { field, value })
}

fn check_configured_limit(
    field: &'static str,
    configured: u64,
    hard: u64,
) -> Result<(), FaultResourceLimitError> {
    if configured == 0 {
        return Err(FaultResourceLimitError::Zero { field });
    }
    if configured > hard {
        return Err(FaultResourceLimitError::ConfiguredAboveHard {
            field,
            configured,
            hard,
        });
    }
    Ok(())
}

fn check_dynamic_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<(), FaultResourceLimitError> {
    let total = current
        .checked_add(requested)
        .ok_or(FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        })?;
    if total > configured {
        return Err(FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        });
    }
    Ok(())
}

/// Failure to validate or reserve one plan-owned resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultResourceLimitError {
    /// An authored limit was zero.
    Zero {
        /// Public field name.
        field: &'static str,
    },
    /// An authored limit exceeded the compiled ceiling.
    ConfiguredAboveHard {
        /// Public field name.
        field: &'static str,
        /// Authored value.
        configured: u64,
        /// Compiled ceiling.
        hard: u64,
    },
    /// A dynamic reservation exceeded its scenario limit.
    Exceeded {
        /// Public field name.
        field: &'static str,
        /// Already-retained usage.
        current: u64,
        /// Requested additional usage.
        requested: u64,
        /// Scenario limit.
        configured: u64,
        /// Compiled ceiling.
        hard: u64,
    },
    /// Dynamic usage addition overflowed `u64`.
    UsageOverflow {
        /// Public field name.
        field: &'static str,
        /// Already-retained usage.
        current: u64,
        /// Requested additional usage.
        requested: u64,
        /// Scenario limit.
        configured: u64,
        /// Compiled ceiling.
        hard: u64,
    },
    /// A caller requested a field absent from the closed registry.
    UnknownField {
        /// Rejected field name.
        field: &'static str,
    },
    /// A validated public value did not fit an internal narrow type.
    Representation {
        /// Public field name.
        field: &'static str,
        /// Rejected value.
        value: u64,
    },
}

impl fmt::Display for FaultResourceLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault resource limit rejected: {self:?}")
    }
}

impl Error for FaultResourceLimitError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn registry_is_exhaustive_unique_and_matches_defaults() {
        assert_eq!(FAULT_RESOURCE_LIMIT_DESCRIPTORS.len(), 90);
        let names = FAULT_RESOURCE_LIMIT_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.field)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), FAULT_RESOURCE_LIMIT_DESCRIPTORS.len());
        let limits = FaultResourceLimits::default();
        limits
            .validate()
            .unwrap_or_else(|error| panic!("validate compiled defaults: {error}"));
        for descriptor in FAULT_RESOURCE_LIMIT_DESCRIPTORS {
            assert_eq!(
                limits.configured(descriptor.field),
                Some(descriptor.default)
            );
            assert!(descriptor.default <= descriptor.hard);
            assert!(descriptor.default > 0);
        }
    }

    #[test]
    fn every_limit_is_identity_bearing_even_for_an_empty_plan() {
        let baseline = FaultSignalPlan::empty();
        let lowered = FaultResourceLimits {
            signal_nodes: FaultResourceLimits::default().signal_nodes - 1,
            ..FaultResourceLimits::default()
        };
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), lowered)
            .unwrap_or_else(|error| panic!("admit lowered empty plan: {error}"));
        assert_ne!(plan.id(), baseline.id());
        assert_ne!(plan.wire_bytes(), baseline.wire_bytes());
        assert_eq!(
            FaultSignalPlan::from_wire_bytes(plan.wire_bytes())
                .unwrap_or_else(|error| panic!("decode lowered empty plan: {error}")),
            plan,
        );
    }

    #[test]
    fn configured_and_dynamic_failures_report_complete_bounds() {
        let zero = FaultResourceLimits {
            network_paths: 0,
            ..FaultResourceLimits::default()
        };
        assert!(matches!(
            zero.validate(),
            Err(FaultResourceLimitError::Zero {
                field: "network_paths"
            })
        ));
        let above = FaultResourceLimits {
            interrupt_storm_events: 4_194_305,
            ..FaultResourceLimits::default()
        };
        assert!(matches!(
            above.validate(),
            Err(FaultResourceLimitError::ConfiguredAboveHard {
                field: "interrupt_storm_events",
                configured: 4_194_305,
                hard: 4_194_304,
            })
        ));
        assert!(matches!(
            FaultResourceLimits::default().reserve("search_depth", 65_535, 2),
            Err(FaultResourceLimitError::Exceeded {
                field: "search_depth",
                current: 65_535,
                requested: 2,
                configured: 65_536,
                hard: 262_144,
            })
        ));
    }

    #[test]
    fn authored_tables_may_lower_selected_fields_but_reject_extensions() {
        let limits = toml::from_str::<FaultResourceLimits>("bindings = 7\n")
            .unwrap_or_else(|error| panic!("partial resource table should use defaults: {error}"));
        assert_eq!(limits.bindings, 7);
        assert_eq!(
            limits.signal_nodes,
            FaultResourceLimits::default().signal_nodes
        );
        assert!(toml::from_str::<FaultResourceLimits>("unregistered_limit = 1\n").is_err());
    }
}
