//! Checked immutable role projections from the same original host model.
//!
//! The descriptor remains the admission roster. Implementations refuse absent
//! roles and never turn a clock, script or assertion model into a compute node.
//! Reading these projections neither drains native queues nor arms a world.

use super::*;
use crate::node_contract::checked_role_declaration;
use crucible_device::block::{BlockCompletionDurability, BlockDiscardSemantics};

/// Retains static source-qualified parameters independently of mutable native state.
pub(super) enum HostRoleDefinition {
    Block {
        base_hash: [u8; 32],
        length: u64,
        latency: crucible_device::BlockLatency,
        durability: crucible_device::block::BlockDurabilityConfig,
    },
    Filesystem {
        tree_hash: [u8; 32],
        latency: crucible_device::NinepLatency,
    },
    Link {
        base_latency: u64,
        floor: u64,
        faults: crucible_device::netlink::LinkFaults,
    },
    Clock,
    RateAlarm(super::super::rate_alarm_clock::RateAlarmClockDefinition),
    Unsupported,
}

impl HostRoleDefinition {
    /// Captures only constructor-qualified static parameters, never queue/frontier state.
    pub(super) fn from_model(model: &HostModel) -> Self {
        match model {
            HostModel::Io(io) => {
                if let Some(block) = io.block_device() {
                    Self::Block {
                        base_hash: block.base_hash(),
                        length: block.length(),
                        latency: *block.latency_model(),
                        durability: block.storage_fault_state().config().clone(),
                    }
                } else if let Some(filesystem) = io.ninep_device() {
                    Self::Filesystem {
                        tree_hash: filesystem.server().tree().content_hash(),
                        latency: *filesystem.latency_model(),
                    }
                } else {
                    Self::Unsupported
                }
            }
            HostModel::Link(link) => Self::Link {
                base_latency: link.base_latency_ticks(),
                floor: link.floor_ticks(),
                faults: link.faults().clone(),
            },
            HostModel::Clock(_) => Self::Clock,
            HostModel::RateAlarmClock(clock) => Self::RateAlarm(clock.definition().clone()),
            _ => Self::Unsupported,
        }
    }

    /// Checks static definition drift while allowing actual queues, fids and time to advance.
    fn matches_model(&self, model: &HostModel) -> bool {
        match (self, model) {
            (
                Self::Block {
                    base_hash,
                    length,
                    latency,
                    durability,
                },
                HostModel::Io(io),
            ) => io.block_device().is_some_and(|block| {
                block.base_hash() == *base_hash
                    && block.length() == *length
                    && block.latency_model() == latency
                    && block.storage_fault_state().config() == durability
            }),
            (Self::Filesystem { tree_hash, latency }, HostModel::Io(io)) => {
                io.ninep_device().is_some_and(|filesystem| {
                    filesystem.server().tree().content_hash() == *tree_hash
                        && filesystem.latency_model() == latency
                })
            }
            (
                Self::Link {
                    base_latency,
                    floor,
                    faults,
                },
                HostModel::Link(link),
            ) => {
                link.base_latency_ticks() == *base_latency
                    && link.floor_ticks() == *floor
                    && link.faults() == faults
            }
            (Self::Clock, HostModel::Clock(_)) => true,
            (Self::RateAlarm(definition), HostModel::RateAlarmClock(clock)) => {
                clock.definition() == definition
            }
            _ => false,
        }
    }
}

const BLOCK_OPERATIONS: &[BlockOperation] = &[
    BlockOperation::Read,
    BlockOperation::Write,
    BlockOperation::Flush,
    BlockOperation::GetLength,
    BlockOperation::Discard,
];

const FILESYSTEM_OPERATIONS: &[FilesystemOperation] = &[
    FilesystemOperation::Version,
    FilesystemOperation::Attach,
    FilesystemOperation::Walk,
    FilesystemOperation::OpenRead,
    FilesystemOperation::Read,
    FilesystemOperation::ReadDirectory,
    FilesystemOperation::GetAttributes,
    FilesystemOperation::ReadLink,
    FilesystemOperation::StatFilesystem,
    FilesystemOperation::Clunk,
    FilesystemOperation::Flush,
    FilesystemOperation::WalkExtendedAttribute,
    FilesystemOperation::Sync,
];

impl HostModelNode {
    /// Checks the original role and current model before exposing its semantics.
    fn role_declaration(&self, expected: &str) -> Result<RoleDeclaration<'_>, Refusal> {
        if self.quarantined || std::thread::current().id() != self.thread {
            return Err(role_refusal(
                "host role model is contained or on a foreign thread",
            ));
        }
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| role_refusal("host role model is released"))?;
        if model.role() != expected
            || self.route.node != self.descriptor.id
            || !self.role_definition.matches_model(model)
        {
            return Err(role_refusal(
                "requested role differs from the original actual host model",
            ));
        }

        checked_role_declaration(&self.descriptor, &self.binding, expected)
    }
}

impl BlockNode for HostModelNode {
    fn block_description(&self) -> Result<BlockDescription<'_>, Refusal> {
        let declaration = self.role_declaration("block")?;
        let Some(HostModel::Io(io)) = self.model.as_ref() else {
            return Err(role_refusal("original block model is absent"));
        };
        let block = io
            .block_device()
            .ok_or_else(|| role_refusal("original block device is absent"))?;
        let config = block.storage_fault_state().config();
        let latency = block.latency_model();
        let completion_durability = match config.completion_durability {
            BlockCompletionDurability::ControllerAccepted => {
                CompletionDurability::ControllerAccepted
            }
            BlockCompletionDurability::VolatileCacheAccepted => {
                CompletionDurability::VolatileCacheAccepted
            }
            BlockCompletionDurability::Durable => CompletionDurability::Durable,
        };
        let discard_readback = match config.discard_semantics {
            BlockDiscardSemantics::DeterministicZero => DiscardReadback::Zero,
            BlockDiscardSemantics::ReadsOldData => DiscardReadback::PreviousBytes,
            BlockDiscardSemantics::UndefinedKeyed => DiscardReadback::RequestKeyedBytes,
        };

        Ok(BlockDescription {
            declaration,
            base_hash: block.base_hash(),
            length_bytes: block.length(),
            storage_ownership: BlockStorageOwnership::PinnedBasePrivateCopyOnWrite,
            address_unit_bytes: 1,
            operations: BLOCK_OPERATIONS,
            maximum_read_reply_bytes: crucible_device::block::device::MAX_READ_BYTES,
            maximum_request_bytes: config.maximum_request_bytes,
            atomic_write_bytes: config.atomic_write_bytes,
            discard_granularity_bytes: config.discard_granularity_bytes,
            discard_readback,
            volatile_cache_bytes: config.volatile_cache_bytes,
            controller_buffer_bytes: config.controller_buffer_bytes,
            completion_durability,
            latency: BlockLatencyDescription {
                read_base_ns: latency.read_base_ns,
                write_base_ns: latency.write_base_ns,
                flush_ns: latency.flush_ns,
                get_length_ns: latency.get_length_ns,
                per_byte_ns: latency.per_byte_ns,
            },
        })
    }
}

impl FilesystemNode for HostModelNode {
    fn filesystem_description(&self) -> Result<FilesystemDescription<'_>, Refusal> {
        let declaration = self.role_declaration("filesystem")?;
        let Some(HostModel::Io(io)) = self.model.as_ref() else {
            return Err(role_refusal("original filesystem model is absent"));
        };
        let filesystem = io
            .ninep_device()
            .ok_or_else(|| role_refusal("original filesystem device is absent"))?;
        let server = filesystem.server();
        let latency = filesystem.latency_model();

        Ok(FilesystemDescription {
            declaration,
            dialect: FilesystemDialect::Ninep2000L,
            namespace_hash: match &self.role_definition {
                HostRoleDefinition::Filesystem { tree_hash, .. } => *tree_hash,
                _ => {
                    return Err(role_refusal(
                        "original pinned filesystem definition is absent",
                    ));
                }
            },
            operations: FILESYSTEM_OPERATIONS,
            read_only: true,
            permissions: FilesystemPermissions::FixedReadOnlyAttributes,
            visibility: FilesystemVisibility::OriginalSessionReplies,
            minimum_message_bytes: crucible_device::ninep::server::MIN_MSIZE,
            maximum_message_bytes: crucible_device::ninep::server::MAX_MSIZE,
            negotiated_message_bytes: server.msize(),
            version_negotiated: server.negotiated(),
            session_scoped_fids: true,
            latency: FilesystemLatencyDescription {
                control_ns: latency.control_ns,
                data_ns: latency.data_ns,
                per_byte_ns: latency.per_byte_ns,
            },
        })
    }
}

impl NetworkLinkNode for HostModelNode {
    fn link_description(&self) -> Result<NetworkLinkDescription<'_>, Refusal> {
        let declaration = self.role_declaration("network_link")?;
        let Some(HostModel::Link(link)) = self.model.as_ref() else {
            return Err(role_refusal("original network link model is absent"));
        };
        if !crucible_device::ns_to_tick(1).is_ok_and(|scale| scale == 1_000) {
            return Err(role_refusal(
                "native link ticks are not the admitted shared picoseconds",
            ));
        }
        let faults = link.faults();

        Ok(NetworkLinkDescription {
            declaration,
            input_endpoint: self.input_endpoint.as_ref(),
            output_endpoint: self.output_endpoint.as_ref(),
            base_latency_ps: link.base_latency_ticks(),
            latency_floor_ps: link.floor_ticks(),
            effective_latency_ps: link.effective_latency_ticks(),
            partitioned: faults.partitioned,
            jitter_window_ps: faults.jitter_window_ticks,
            reorder_window_ps: faults.reorder_window_ticks,
            bandwidth_bits_per_second: &faults.bandwidth_bits_per_sec,
            delivery_order: FrameDeliveryOrder::TimeSourceSequence,
        })
    }
}

impl ClockNode for HostModelNode {
    fn clock_description(&self) -> Result<ClockDescription<'_>, Refusal> {
        let (role, mapping, alarms) = match self.model.as_ref() {
            Some(HostModel::Clock(_)) => (
                "clock",
                ClockMapping::IdentityPicoseconds,
                ClockAlarms::Unsupported,
            ),
            Some(HostModel::RateAlarmClock(clock))
                if super::super::rate_alarm_clock::selected(&self.binding) =>
            {
                let definition = clock.definition();
                (
                    "rate_alarm_clock",
                    ClockMapping::RationalCounter {
                        numerator: definition.numerator.get(),
                        denominator: definition.denominator.get(),
                        epoch_ps: definition.epoch_ps.get(),
                        epoch_counter: definition.epoch_counter.get(),
                        drift_ppb: definition.drift_ppb,
                    },
                    ClockAlarms::OriginalRationalRequests {
                        maximum_requests: super::super::rate_alarm_clock::MAXIMUM_CLOCK_REQUESTS,
                    },
                )
            }
            _ => {
                return Err(role_refusal(
                    "original declared clock or selected rational extension is absent",
                ));
            }
        };
        let declaration = self.role_declaration(role)?;

        Ok(ClockDescription {
            declaration,
            mapping,
            alarms,
            refuses_overflow: true,
        })
    }
}

fn role_refusal(reason: &str) -> Refusal {
    Refusal {
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "host_roles_tests.rs"]
mod tests;
