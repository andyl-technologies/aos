//! Bounded read-only projection of current World declarations and owner custody.

use crucible_node_contract::{Direction, Id};

use crate::{BackendIoInventoryAuthority, World, WorldIoNodeKind, WorldNodeDef};

/// Reports an invalid world projection or portable participant identity.
#[derive(Debug, thiserror::Error)]
pub enum WorldInventoryError {
    /// A declared world violates its roster, ownership or resource bounds.
    #[error("{0}")]
    InvalidWorld(&'static str),
    /// A legacy identity cannot be represented by the portable contract.
    #[error(transparent)]
    InvalidIdentity(#[from] crucible_node_contract::ContractError),
}

impl From<&'static str> for WorldInventoryError {
    fn from(reason: &'static str) -> Self {
        Self::InvalidWorld(reason)
    }
}

/// Names one current-model port family before native qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentPortKind {
    /// Carries guest network frames, independent of host socket completion.
    Ethernet,
    /// Carries deterministic block requests or computed completions.
    Block,
    /// Carries bounded 9p messages and computed replies.
    Filesystem,
    /// Covers guest-clock/timer behavior inside the compute owner.
    Clock,
}

/// Describes a declared public port without claiming complete native inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentPort {
    /// Names this logical port within its public node.
    pub id: Id,
    /// Names its concrete model family.
    pub kind: CurrentPortKind,
    /// Gives the public message direction.
    pub direction: Direction,
    /// Names the public participant at the other endpoint, when declared.
    pub peer: Option<Id>,
}

/// Maps one current logical participant to its actual custody family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentWorldParticipant {
    /// Identifies the unchanged logical world node.
    pub id: Id,
    /// Names its current semantic role.
    pub role: Id,
    /// Names its indivisible execution owner in this projection.
    pub execution_owner: Id,
    /// Names its authoritative capture owner in this projection.
    pub capture_owner: Id,
    /// Lists declared public ports; physical source inventory remains separate.
    pub ports: Vec<CurrentPort>,
    /// Requires authentic native coverage before this projection can qualify.
    pub native_inventory_required: bool,
}

/// Inventories current model declarations without creating a new graph seal.
///
/// Physical QEMU block/9p servicers remain in the compute owner's source
/// inventory; scheduler-owned model devices remain independently owned. This
/// distinction prevents a duplicated authoritative snapshot of the same queue.
/// The projection never establishes IRQ, timer, device-state or queue absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentWorldInventory {
    /// Contains every declared compute, deterministic I/O and link participant.
    pub participants: Vec<CurrentWorldParticipant>,
    /// Preserves the backend's explicitly implemented queue ownership model.
    pub io_authority: BackendIoInventoryAuthority,
}

impl CurrentWorldInventory {
    /// Projects bounded current declarations into explicit owner and port rows.
    ///
    /// Links are modeled in both directions; native guest NIC/IRQ/timer coverage
    /// must still be joined by the installed QEMU adapter. No new identity is
    /// substituted for a legacy logical name that the portable API cannot carry.
    ///
    /// # Errors
    /// Rejects invalid portable identities, oversized participant/port rosters,
    /// missing compute owners or links without declared compute endpoints.
    pub fn from_world(
        world: &World,
        io_authority: BackendIoInventoryAuthority,
        maximum_participants: usize,
        maximum_ports: usize,
    ) -> Result<Self, WorldInventoryError> {
        let participant_count = world
            .nodes()
            .len()
            .checked_add(world.links().len())
            .ok_or("current World participant roster arithmetic overflow")?;
        if participant_count > maximum_participants {
            return Err("current World participant roster exceeds admitted ceiling".into());
        }
        let maximum_projected_ports = world
            .nodes()
            .len()
            .checked_mul(2)
            .and_then(|count| {
                world
                    .io_nodes()
                    .count()
                    .checked_mul(2)
                    .and_then(|io| count.checked_add(io))
            })
            .and_then(|count| {
                world
                    .links()
                    .len()
                    // Each bidirectional link contributes four link lanes
                    // and four matching guest NIC lanes across its endpoints.
                    .checked_mul(8)
                    .and_then(|links| count.checked_add(links))
            })
            .ok_or("current World port roster arithmetic overflow")?;
        if maximum_projected_ports > maximum_ports {
            return Err("current World projected ports exceed admitted ceiling".into());
        }
        let mut participants = Vec::with_capacity(participant_count);
        for definition in world.nodes() {
            let id = portable(&definition.id().name)?;
            let (role, owner, native_inventory_required, ports) = match definition {
                WorldNodeDef::Vm(_) => {
                    let owner = owner_id("compute", &id)?;
                    let ports = vec![
                        CurrentPort {
                            id: portable("clock-control")?,
                            kind: CurrentPortKind::Clock,
                            direction: Direction::Input,
                            peer: None,
                        },
                        CurrentPort {
                            id: portable("clock-observation")?,
                            kind: CurrentPortKind::Clock,
                            direction: Direction::Output,
                            peer: None,
                        },
                    ];
                    (portable("compute")?, owner, true, ports)
                }
                WorldNodeDef::Io(io) => {
                    if !world.vm_nodes().iter().any(|vm| vm.id == io.owner) {
                        return Err(
                            "I/O participant lacks its actual declared compute owner".into()
                        );
                    }
                    let peer = portable(&io.owner.name)?;
                    let physical = io_authority == BackendIoInventoryAuthority::PhysicalSource;
                    let owner = if physical {
                        owner_id("compute", &peer)?
                    } else {
                        owner_id("host-io", &id)?
                    };
                    let (role, kind) = match &io.kind {
                        WorldIoNodeKind::Block { .. } => ("block", CurrentPortKind::Block),
                        WorldIoNodeKind::NineP { .. } => {
                            ("filesystem", CurrentPortKind::Filesystem)
                        }
                    };
                    let ports = vec![
                        CurrentPort {
                            id: portable("request")?,
                            kind,
                            direction: Direction::Input,
                            peer: Some(peer.clone()),
                        },
                        CurrentPort {
                            id: portable("response")?,
                            kind,
                            direction: Direction::Output,
                            peer: Some(peer),
                        },
                    ];
                    (portable(role)?, owner, physical, ports)
                }
            };
            participants.push(CurrentWorldParticipant {
                id,
                role,
                execution_owner: owner.clone(),
                capture_owner: owner,
                ports,
                native_inventory_required,
            });
        }
        for io in world.io_nodes() {
            let peer = portable(&io.id.name)?;
            let owner = portable(&io.owner.name)?;
            let kind = match &io.kind {
                WorldIoNodeKind::Block { .. } => CurrentPortKind::Block,
                WorldIoNodeKind::NineP { .. } => CurrentPortKind::Filesystem,
            };
            let vm = participants
                .iter_mut()
                .find(|row| row.id == owner)
                .ok_or("missing compute participant for I/O peer")?;
            vm.ports.push(CurrentPort {
                id: owner_id("request", &peer)?,
                kind,
                direction: Direction::Output,
                peer: Some(peer.clone()),
            });
            vm.ports.push(CurrentPort {
                id: owner_id("response", &peer)?,
                kind,
                direction: Direction::Input,
                peer: Some(peer),
            });
        }
        for link in world.links() {
            let (a, z) = link.endpoints();
            let link_id = portable(&link.scheduler_node_id().node.name)?;
            let link_owner = owner_id("host-link", &link_id)?;
            let mut link_ports = Vec::with_capacity(4);
            if !world.vm_nodes().iter().any(|vm| vm.id == *a)
                || !world.vm_nodes().iter().any(|vm| vm.id == *z)
            {
                return Err("network link lacks its complete declared compute endpoints".into());
            }
            for (node, peer) in [(a, z), (z, a)] {
                let node = portable(&node.name)?;
                let peer = portable(&peer.name)?;
                let vm = participants
                    .iter_mut()
                    .find(|row| row.id == node)
                    .ok_or("missing link participant")?;
                vm.ports.push(CurrentPort {
                    id: owner_id("ethernet-rx", &peer)?,
                    kind: CurrentPortKind::Ethernet,
                    direction: Direction::Input,
                    peer: Some(link_id.clone()),
                });
                vm.ports.push(CurrentPort {
                    id: owner_id("ethernet-tx", &peer)?,
                    kind: CurrentPortKind::Ethernet,
                    direction: Direction::Output,
                    peer: Some(link_id.clone()),
                });
                link_ports.push(CurrentPort {
                    id: owner_id("from", &node)?,
                    kind: CurrentPortKind::Ethernet,
                    direction: Direction::Input,
                    peer: Some(node.clone()),
                });
                link_ports.push(CurrentPort {
                    id: owner_id("to", &node)?,
                    kind: CurrentPortKind::Ethernet,
                    direction: Direction::Output,
                    peer: Some(node),
                });
            }
            participants.push(CurrentWorldParticipant {
                id: link_id,
                role: portable("network_link")?,
                execution_owner: link_owner.clone(),
                capture_owner: link_owner,
                ports: link_ports,
                native_inventory_required: false,
            });
        }
        participants.sort_by(|a, b| a.id.cmp(&b.id));
        if participants.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err("derived link identity aliases a declared public World node".into());
        }
        for participant in &mut participants {
            participant.ports.sort_by(|a, b| a.id.cmp(&b.id));
        }
        Ok(Self {
            participants,
            io_authority,
        })
    }
}

fn portable(value: &str) -> Result<Id, WorldInventoryError> {
    if value.len() > 128 {
        return Err("legacy logical identity exceeds portable identifier ceiling".into());
    }
    Id::new(value).map_err(WorldInventoryError::InvalidIdentity)
}

fn owner_id(prefix: &str, node: &Id) -> Result<Id, WorldInventoryError> {
    if prefix
        .len()
        .saturating_add(node.as_str().len())
        .saturating_add(1)
        > 128
    {
        return Err("derived current-model identity exceeds portable identifier ceiling".into());
    }
    portable(&format!("{prefix}/{node}"))
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
