//! Scenario-owned typed selectable declarations and execution ceilings.
//!
//! [`ScenarioSelectables`] is an immutable component of [`ScenarioDefForm`].
//! It binds reusable campaign declarations to the scenario identity while
//! retaining the node-local ceilings needed to derive sealed QEMU launch
//! catalogs. Runtime offers may narrow these declarations but cannot replace
//! or broaden them.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use crucible_campaign::{ChoiceSource, SelectableDeclaration, SelectableId};
use crucible_protocol::SELECTABLE_PROTOCOL_VERSION;

use super::{EngineError, NodeId, World, scenario_serialization_error};

/// Maximum declarations admitted by one scenario across all producers.
pub const MAX_SCENARIO_SELECTABLE_DECLARATIONS: usize = 65_536;
/// Maximum declarations admitted for one guest node.
pub const MAX_SCENARIO_SELECTABLE_DECLARATIONS_PER_NODE: usize = 4_096;
/// Maximum canonical bytes retained by one scenario selectable component.
pub const MAX_SCENARIO_SELECTABLE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum completed requests admitted by one guest node.
pub const MAX_SCENARIO_SELECTABLE_REQUESTS: u64 = 1_000_000;

const SCENARIO_SELECTABLE_MAGIC: &[u8; 8] = b"CRUCSDS1";
const SCENARIO_SELECTABLE_VERSION: u32 = 1;
const SCENARIO_SELECTABLE_HEADER_BYTES: usize = 40;

/// Scenario-owned node and runtime ceilings for guest selectables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioSelectableLimits {
    declarations_per_node: u32,
    declarations_per_world: u32,
    requests_per_selectable: u64,
    requests_per_node: u64,
}

impl ScenarioSelectableLimits {
    /// Builds one bounded nonzero selectable ceiling profile.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a ceiling is zero,
    /// exceeds its hard maximum, or the per-selectable request ceiling exceeds
    /// the per-node ceiling.
    pub fn new(
        declarations_per_node: u32,
        declarations_per_world: u32,
        requests_per_selectable: u64,
        requests_per_node: u64,
    ) -> Result<Self, EngineError> {
        if declarations_per_node == 0
            || declarations_per_node as usize > MAX_SCENARIO_SELECTABLE_DECLARATIONS_PER_NODE
            || declarations_per_world == 0
            || declarations_per_world as usize > MAX_SCENARIO_SELECTABLE_DECLARATIONS
            || declarations_per_node > declarations_per_world
            || requests_per_selectable == 0
            || requests_per_selectable > MAX_SCENARIO_SELECTABLE_REQUESTS
            || requests_per_node == 0
            || requests_per_node > MAX_SCENARIO_SELECTABLE_REQUESTS
            || requests_per_selectable > requests_per_node
        {
            return Err(scenario_serialization_error(
                "scenario selectable limits are zero, inconsistent, or exceed hard maxima",
            ));
        }
        Ok(Self {
            declarations_per_node,
            declarations_per_world,
            requests_per_selectable,
            requests_per_node,
        })
    }

    /// Returns the declaration ceiling for one guest node.
    #[must_use]
    pub const fn declarations_per_node(self) -> u32 {
        self.declarations_per_node
    }

    /// Returns the declaration ceiling across the complete scenario.
    #[must_use]
    pub const fn declarations_per_world(self) -> u32 {
        self.declarations_per_world
    }

    /// Returns the completed-request ceiling for one selectable.
    #[must_use]
    pub const fn requests_per_selectable(self) -> u64 {
        self.requests_per_selectable
    }

    /// Returns the completed-request ceiling for one guest node.
    #[must_use]
    pub const fn requests_per_node(self) -> u64 {
        self.requests_per_node
    }
}

impl Default for ScenarioSelectableLimits {
    fn default() -> Self {
        Self {
            declarations_per_node: MAX_SCENARIO_SELECTABLE_DECLARATIONS_PER_NODE as u32,
            declarations_per_world: MAX_SCENARIO_SELECTABLE_DECLARATIONS as u32,
            requests_per_selectable: MAX_SCENARIO_SELECTABLE_REQUESTS,
            requests_per_node: MAX_SCENARIO_SELECTABLE_REQUESTS,
        }
    }
}

/// Canonical scenario declaration catalog shared by launch and runtime choice authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSelectables {
    limits: ScenarioSelectableLimits,
    declarations: BTreeMap<SelectableId, SelectableDeclaration>,
    declarations_by_name: BTreeMap<String, SelectableId>,
}

impl ScenarioSelectables {
    /// Returns an empty catalog with the hard selectable ceilings.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            limits: ScenarioSelectableLimits::default(),
            declarations: BTreeMap::new(),
            declarations_by_name: BTreeMap::new(),
        }
    }

    /// Validates and canonicalizes one scenario declaration catalog.
    ///
    /// Declaration names are scenario-wide stable identifiers. Guest sources
    /// must name an exact World VM and protocol version one; environment,
    /// scheduler, and workload declarations remain host-side producers.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when a declaration ID
    /// cannot be derived, a name or exact ID repeats, a guest node is absent,
    /// the guest protocol is unsupported, or count/byte ceilings are exceeded.
    pub fn new(
        world: &World,
        limits: ScenarioSelectableLimits,
        declarations: Vec<SelectableDeclaration>,
    ) -> Result<Self, EngineError> {
        if declarations.len() > limits.declarations_per_world as usize {
            return Err(scenario_serialization_error(
                "scenario selectable declaration count exceeds its world ceiling",
            ));
        }

        let world_nodes = world
            .vm_nodes()
            .iter()
            .map(|node| (node.id.clone(), node.white_box))
            .collect::<BTreeMap<_, _>>();
        let mut names = BTreeSet::new();
        let mut per_node = BTreeMap::<NodeId, usize>::new();
        let mut indexed = BTreeMap::new();
        let mut declarations_by_name = BTreeMap::new();
        let mut charged_bytes = SCENARIO_SELECTABLE_HEADER_BYTES;
        for declaration in declarations {
            charged_bytes = charged_bytes
                .checked_add(4)
                .and_then(|total| total.checked_add(declaration.canonical_bytes().len()))
                .ok_or_else(|| {
                    scenario_serialization_error(
                        "scenario selectable canonical byte count overflowed",
                    )
                })?;
            if charged_bytes > MAX_SCENARIO_SELECTABLE_BYTES {
                return Err(scenario_serialization_error(
                    "scenario selectable canonical bytes exceed the hard maximum",
                ));
            }
            let name = declaration.name().to_owned();
            if !names.insert(name.clone()) {
                return Err(scenario_serialization_error(
                    "scenario selectable declaration name is duplicated",
                ));
            }
            if let ChoiceSource::Guest {
                node,
                protocol_version,
            } = declaration.source()
            {
                let node = NodeId { name: node.clone() };
                let Some(white_box) = world_nodes.get(&node) else {
                    return Err(scenario_serialization_error(
                        "scenario guest selectable names an absent World VM",
                    ));
                };
                if *white_box != super::WhiteBoxPolicy::Enabled {
                    return Err(scenario_serialization_error(
                        "scenario guest selectable requires an enabled white-box channel",
                    ));
                }
                if *protocol_version != u32::from(SELECTABLE_PROTOCOL_VERSION) {
                    return Err(scenario_serialization_error(
                        "scenario guest selectable uses an unsupported protocol version",
                    ));
                }
                let count = per_node.entry(node).or_default();
                *count = count.checked_add(1).ok_or_else(|| {
                    scenario_serialization_error("scenario selectable node count overflowed")
                })?;
                if *count > limits.declarations_per_node as usize {
                    return Err(scenario_serialization_error(
                        "scenario selectable declaration count exceeds its node ceiling",
                    ));
                }
            }
            let id = declaration.id().map_err(|error| {
                scenario_serialization_error(format!(
                    "derive scenario selectable declaration identity: {error}"
                ))
            })?;
            if indexed.insert(id, declaration).is_some() {
                return Err(scenario_serialization_error(
                    "scenario selectable declaration identity is duplicated",
                ));
            }
            declarations_by_name.insert(name, id);
        }
        let value = Self {
            limits,
            declarations: indexed,
            declarations_by_name,
        };
        debug_assert_eq!(value.canonical_bytes().len(), charged_bytes);
        Ok(value)
    }

    /// Returns the scenario-owned ceilings.
    #[must_use]
    pub const fn limits(&self) -> ScenarioSelectableLimits {
        self.limits
    }

    /// Returns declarations in exact content-ID order.
    #[must_use]
    pub const fn declarations(&self) -> &BTreeMap<SelectableId, SelectableDeclaration> {
        &self.declarations
    }

    /// Resolves one declaration by its scenario-wide stable name.
    #[must_use]
    pub fn declaration(&self, name: &str) -> Option<&SelectableDeclaration> {
        self.declarations_by_name
            .get(name)
            .and_then(|id| self.declarations.get(id))
    }

    /// Returns whether this scenario declares no selectables.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// Returns guest declarations for `node` in exact content-ID order.
    pub fn guest_declarations<'a>(
        &'a self,
        node: &'a NodeId,
    ) -> impl Iterator<Item = &'a SelectableDeclaration> + 'a {
        self.declarations.values().filter(move |declaration| {
            matches!(
                declaration.source(),
                ChoiceSource::Guest { node: owner, .. } if owner == &node.name
            )
        })
    }

    /// Encodes the complete bounded declaration component.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SCENARIO_SELECTABLE_HEADER_BYTES);
        bytes.extend_from_slice(SCENARIO_SELECTABLE_MAGIC);
        bytes.extend_from_slice(&SCENARIO_SELECTABLE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.limits.declarations_per_node.to_be_bytes());
        bytes.extend_from_slice(&self.limits.declarations_per_world.to_be_bytes());
        bytes.extend_from_slice(&(self.declarations.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.limits.requests_per_selectable.to_be_bytes());
        bytes.extend_from_slice(&self.limits.requests_per_node.to_be_bytes());
        for declaration in self.declarations.values() {
            let body = declaration.canonical_bytes();
            bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&body);
        }
        bytes
    }

    /// Decodes and revalidates one canonical declaration component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed headers,
    /// bounds, declaration bodies, ordering, world references, or trailing data.
    pub fn from_canonical_bytes(world: &World, bytes: &[u8]) -> Result<Self, EngineError> {
        if bytes.len() < SCENARIO_SELECTABLE_HEADER_BYTES
            || bytes.len() > MAX_SCENARIO_SELECTABLE_BYTES
            || bytes.get(..8) != Some(SCENARIO_SELECTABLE_MAGIC)
        {
            return Err(scenario_serialization_error(
                "scenario selectable component has invalid size or magic",
            ));
        }
        let version = read_u32(bytes, 8)?;
        if version != SCENARIO_SELECTABLE_VERSION {
            return Err(scenario_serialization_error(
                "scenario selectable component has an unsupported version",
            ));
        }
        let limits = ScenarioSelectableLimits::new(
            read_u32(bytes, 12)?,
            read_u32(bytes, 16)?,
            read_u64(bytes, 24)?,
            read_u64(bytes, 32)?,
        )?;
        let count = read_u32(bytes, 20)? as usize;
        if count > limits.declarations_per_world as usize {
            return Err(scenario_serialization_error(
                "scenario selectable encoded count exceeds its world ceiling",
            ));
        }
        let mut cursor = SCENARIO_SELECTABLE_HEADER_BYTES;
        let mut declarations = Vec::new();
        declarations.try_reserve_exact(count).map_err(|_| {
            scenario_serialization_error("reserve scenario selectable declarations")
        })?;
        for _ in 0..count {
            let length = read_u32_at_cursor(bytes, &mut cursor)? as usize;
            let end = cursor.checked_add(length).ok_or_else(|| {
                scenario_serialization_error("scenario selectable length overflowed")
            })?;
            let body = bytes.get(cursor..end).ok_or_else(|| {
                scenario_serialization_error("scenario selectable body is truncated")
            })?;
            declarations.push(SelectableDeclaration::from_canonical_bytes(body).map_err(
                |error| {
                    scenario_serialization_error(format!(
                        "decode scenario selectable declaration: {error}"
                    ))
                },
            )?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(scenario_serialization_error(
                "scenario selectable component has trailing bytes",
            ));
        }
        let value = Self::new(world, limits, declarations)?;
        if value.canonical_bytes() != bytes {
            return Err(scenario_serialization_error(
                "scenario selectable component is not canonically ordered",
            ));
        }
        Ok(value)
    }
}

impl Default for ScenarioSelectables {
    fn default() -> Self {
        Self::empty()
    }
}

impl Hash for ScenarioSelectables {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_bytes().hash(state);
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EngineError> {
    let fixed: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| scenario_serialization_error("scenario selectable header is truncated"))?;
    Ok(u32::from_be_bytes(fixed))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EngineError> {
    let fixed: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| scenario_serialization_error("scenario selectable header is truncated"))?;
    Ok(u64::from_be_bytes(fixed))
}

fn read_u32_at_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u32, EngineError> {
    let value = read_u32(bytes, *cursor)?;
    *cursor = cursor
        .checked_add(4)
        .ok_or_else(|| scenario_serialization_error("scenario selectable cursor overflowed"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crucible_campaign::{
        BooleanDomain, ChoiceClassContext, ChoiceDomain, ChoiceValue, SelectableDeclaration,
    };

    use super::*;
    use crate::{
        Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioDefForm, Seed, WhiteBoxPolicy,
        WorldNode,
    };

    fn selectable_world() -> Result<World, EngineError> {
        World::from_nodes(vec![WorldNode {
            id: NodeId {
                name: String::from("router-a"),
            },
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("selectable-test"),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])
    }

    fn declaration(node: &str) -> Result<SelectableDeclaration, Box<dyn Error>> {
        Ok(SelectableDeclaration::new(
            "product.recovery",
            ChoiceSource::Guest {
                node: node.to_owned(),
                protocol_version: u32::from(SELECTABLE_PROTOCOL_VERSION),
            },
            ChoiceDomain::Boolean(BooleanDomain::new(1)?),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new())?,
            BTreeSet::new(),
            true,
        )?)
    }

    #[test]
    fn selectable_catalog_round_trips_and_changes_scenario_identity() -> Result<(), Box<dyn Error>>
    {
        let world = selectable_world()?;
        let declaration = declaration("router-a")?;
        let catalog = ScenarioSelectables::new(
            &world,
            ScenarioSelectableLimits::new(8, 16, 64, 128)?,
            vec![declaration.clone()],
        )?;
        assert_eq!(
            ScenarioSelectables::from_canonical_bytes(&world, &catalog.canonical_bytes())?,
            catalog
        );
        assert_eq!(catalog.declaration("product.recovery"), Some(&declaration));
        assert_eq!(
            catalog
                .guest_declarations(&NodeId {
                    name: String::from("router-a")
                })
                .collect::<Vec<_>>(),
            vec![&declaration]
        );

        let base = ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::default(),
        )?;
        let bounded_empty = base.with_selectables(ScenarioSelectables::new(
            &world,
            ScenarioSelectableLimits::new(8, 16, 64, 128)?,
            Vec::new(),
        )?)?;
        assert_ne!(base.id(), bounded_empty.id());
        let scenario = base.with_selectables(catalog)?;
        assert_ne!(base.id(), scenario.id());
        assert_eq!(
            ScenarioDefForm::from_compact_binary(&scenario.to_compact_binary())?,
            scenario
        );
        assert_eq!(
            ScenarioDefForm::from_canonical_toml(&scenario.to_canonical_toml()?)?,
            scenario
        );
        Ok(())
    }

    #[test]
    fn guest_selectable_must_name_an_enabled_world_node() -> Result<(), Box<dyn Error>> {
        let world = selectable_world()?;
        assert!(
            ScenarioSelectables::new(
                &world,
                ScenarioSelectableLimits::default(),
                vec![declaration("router-b")?],
            )
            .is_err()
        );
        Ok(())
    }
}
