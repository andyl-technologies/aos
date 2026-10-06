//! Finalized nonexecution ownership for an original Device Group opportunity.
//!
//! Scheduler state supplies semantic selection and input bounds. The backend
//! independently owns the actual Source and received opportunity, and must
//! reauthenticate their physical lifetime before any native publication.

use std::num::NonZeroU64;
use std::sync::Arc;

use super::*;
use crate::{BackendIoInventory, BackendIoNativeCap};
use crucible_protocol::DeviceGroupOpportunity;

/// Private-process identity of one original backend Source or received record.
///
/// This identity carries no physical permission. A concrete backend keeps its
/// original identity in its own retained holder and checks pointer identity
/// alongside the genuine Source, mapping, worker and transport predicates.
#[derive(Clone, Debug)]
pub struct BackendDeviceGroupOwner(Arc<()>);

impl BackendDeviceGroupOwner {
    /// Creates an identity for a newly enrolled backend-owned record.
    ///
    /// Creating or copying this value cannot establish Source authority.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(()))
    }

    /// Retains the concrete backend's already issued original record identity.
    ///
    /// This wraps correlation only. Physical ownership and received transport
    /// custody must still be independently checked by the concrete backend.
    #[must_use]
    pub fn from_retained(owner: Arc<()>) -> Self {
        Self(owner)
    }

    /// Compares the original retained objects, independently of descriptor bytes.
    #[must_use]
    pub fn retains_same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Default for BackendDeviceGroupOwner {
    fn default() -> Self {
        Self::new()
    }
}

/// Backend observation retained before scheduler Group selection.
///
/// The observation is factual. Its two private identities must be joined by
/// the backend to the actual original Source/input holder and tag19 receive
/// custody. Neither its constructor nor the public opportunity grants effects.
#[derive(Clone, Debug)]
pub struct BackendDeviceGroupObservation {
    input: BackendIoInventory,
    source_owner: BackendDeviceGroupOwner,
    opportunity_owner: BackendDeviceGroupOwner,
    opportunity: DeviceGroupOpportunity,
}

impl BackendDeviceGroupObservation {
    /// Retains complete observed input and an independently received opportunity.
    ///
    /// The concrete backend must authenticate both owners and all current
    /// physical facts before and after this observation enters the scheduler.
    #[must_use]
    pub fn new(
        input: BackendIoInventory,
        source_owner: BackendDeviceGroupOwner,
        opportunity_owner: BackendDeviceGroupOwner,
        opportunity: DeviceGroupOpportunity,
    ) -> Self {
        Self {
            input,
            source_owner,
            opportunity_owner,
            opportunity,
        }
    }

    /// Returns the complete original Source-backed input observation.
    #[must_use]
    pub const fn input_inventory(&self) -> &BackendIoInventory {
        &self.input
    }

    /// Returns the original Source/input holder's correlation identity.
    #[must_use]
    pub const fn source_owner(&self) -> &BackendDeviceGroupOwner {
        &self.source_owner
    }

    /// Returns the actual received record's separate correlation identity.
    #[must_use]
    pub const fn opportunity_owner(&self) -> &BackendDeviceGroupOwner {
        &self.opportunity_owner
    }

    /// Returns the exact publication, actor and ordered member bytes.
    #[must_use]
    pub const fn opportunity(&self) -> &DeviceGroupOpportunity {
        &self.opportunity
    }

    fn retains_original(&self, other: &Self) -> bool {
        self.source_owner.retains_same_owner(&other.source_owner)
            && self
                .opportunity_owner
                .retains_same_owner(&other.opportunity_owner)
            && self.input == other.input
            && self.opportunity == other.opportunity
    }
}

#[derive(Debug)]
struct DeviceGroupSelectionOwner {
    controller: Arc<()>,
    control_token: NonZeroU64,
    context: [u64; 4],
    observation: BackendDeviceGroupObservation,
    _source: Arc<SingleScheduler>,
    canonical_state: Vec<u8>,
}

/// Original scheduler-finalized Device Group selection awaiting its backend.
///
/// There is no public constructor. The selection retains the actual scheduler
/// and input enumeration, plus both original backend owner identities. It
/// supplies no CPU grant, clock payment, Source hold or native Group authority.
#[derive(Clone, Debug)]
pub struct PreparedDeviceGroupSelection {
    owner: Arc<DeviceGroupSelectionOwner>,
    input: PreparedRunInputInventory,
}

impl PreparedDeviceGroupSelection {
    pub(in crate::scheduler) fn observation(&self) -> &BackendDeviceGroupObservation {
        &self.owner.observation
    }

    /// Returns the exact logical node selected under the retained World.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.owner.observation.input.node
    }

    /// Returns the independent checked scheduler control token.
    #[must_use]
    pub fn control_token(&self) -> NonZeroU64 {
        self.owner.control_token
    }

    /// Returns the immutable semantic context of this original selection.
    #[must_use]
    pub fn context(&self) -> [u64; 4] {
        self.owner.context
    }

    /// Returns the complete original input generation and bound, including zero.
    #[must_use]
    pub const fn input_inventory(&self) -> &PreparedRunInputInventory {
        &self.input
    }

    /// Returns the original Source/input correlation object for backend current.
    #[must_use]
    pub fn source_owner(&self) -> &BackendDeviceGroupOwner {
        self.owner.observation.source_owner()
    }

    /// Returns the original received publication's correlation object.
    #[must_use]
    pub fn opportunity_owner(&self) -> &BackendDeviceGroupOwner {
        self.owner.observation.opportunity_owner()
    }

    /// Returns the exact originally selected public descriptor.
    #[must_use]
    pub fn opportunity(&self) -> &DeviceGroupOpportunity {
        self.owner.observation.opportunity()
    }

    /// Compares registered semantic owners rather than tokens or copied bytes.
    #[must_use]
    pub fn retains_same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
}

/// Actual queued publication of the original Group command.
///
/// This fact supplies no acceptance, completion, native effect or release
/// permission. The independent backend receipt owns those later milestones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceGroupSelectionPublication {
    /// The original backend queue callback returned its actual queued ACK.
    Queued,
}

#[derive(Debug)]
pub(in crate::scheduler) struct DeviceGroupSelectionController {
    identity: Arc<()>,
    revision: u64,
    selected: Option<PreparedDeviceGroupSelection>,
    // Issued before the original queue callback; its uncertainty survives a
    // physical Held-to-accepted transition. Only the actual callback0 sets ACK.
    publication_issued: bool,
    publication_queued: bool,
}

impl Default for DeviceGroupSelectionController {
    fn default() -> Self {
        Self {
            identity: Arc::new(()),
            revision: 0,
            selected: None,
            publication_issued: false,
            publication_queued: false,
        }
    }
}

impl Clone for DeviceGroupSelectionController {
    fn clone(&self) -> Self {
        // Keep the original obligation, but a new loop cannot authenticate its
        // parent's controller or silently mint another selection over it.
        Self {
            identity: Arc::new(()),
            revision: self.revision,
            selected: self.selected.clone(),
            publication_issued: self.publication_issued,
            publication_queued: self.publication_queued,
        }
    }
}

impl DeviceGroupSelectionController {
    pub(in crate::scheduler) fn is_retained(&self) -> bool {
        self.selected.is_some()
    }

    pub(in crate::scheduler) fn publication_issued(&self) -> bool {
        self.publication_issued
    }

    pub(in crate::scheduler) fn publication_queued(&self) -> bool {
        self.publication_queued
    }

    pub(in crate::scheduler) fn begin_publication(&mut self) {
        self.publication_issued = true;
    }

    pub(in crate::scheduler) fn acknowledge_publication(&mut self) {
        self.publication_queued = true;
    }

    pub(in crate::scheduler) fn current(
        &self,
        scheduler: &SingleScheduler,
        prepared: &PreparedDeviceGroupSelection,
    ) -> Result<(), SchedulerError> {
        let Some(current) = &self.selected else {
            return Err(refused("Group selection has no registered original owner"));
        };
        if !current.retains_same_owner(prepared)
            || !Arc::ptr_eq(&self.identity, &prepared.owner.controller)
            || self.revision != prepared.control_token().get()
            || canonical_state(scheduler)? != prepared.owner.canonical_state
        {
            return Err(refused(
                "Group selection changed its controller or scheduler state",
            ));
        }
        Ok(())
    }

    pub(in crate::scheduler) fn prepare(
        &mut self,
        scheduler: &SingleScheduler,
        observation: BackendDeviceGroupObservation,
    ) -> Result<PreparedDeviceGroupSelection, SchedulerError> {
        if let Some(prepared) = &self.selected {
            self.current(scheduler, prepared)?;
            if !prepared.owner.observation.retains_original(&observation) {
                return Err(refused(
                    "Group retry replaced an original Source or publication owner",
                ));
            }
            return Ok(prepared.clone());
        }
        if observation
            .source_owner
            .retains_same_owner(&observation.opportunity_owner)
        {
            return Err(refused(
                "Source and received opportunity identities are aliased",
            ));
        }
        let index = scheduler.vm_node_index(&observation.input.node)?;
        let node = &scheduler.nodes[index];
        let mut logical = [0; 8];
        logical.copy_from_slice(&observation.opportunity.actor()[72..80]);
        if node.counter != observation.input.observed
            || u64::from_le_bytes(logical) != node.counter.ticks
            || !scheduler.imported_source_matches(
                &observation.input.node,
                observation.input.observed,
                observation.input.generation,
            )
        {
            return Err(refused(
                "Group opportunity lacks this actual imported Source input",
            ));
        }
        let mut next_input = scheduler.prepared_run_next_input(node)?;
        for cap in [
            observation.input.native_caps.timer,
            observation.input.native_caps.input,
        ] {
            match cap {
                BackendIoNativeCap::Unknown => return Err(refused("Group input cap is unknown")),
                BackendIoNativeCap::ObservedAbsent => {}
                BackendIoNativeCap::Armed(at) => {
                    next_input = Some(next_input.map_or(at, |known| known.min(at)));
                }
            }
        }
        for boundary in observation
            .input
            .queues
            .iter()
            .filter_map(|queue| queue.next_pipeline_boundary)
        {
            next_input = Some(next_input.map_or(boundary, |known| known.min(boundary)));
        }
        let token = self
            .revision
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| refused("Group control token is exhausted"))?;
        let canonical_state = canonical_state(scheduler)?;
        let bytes = serde_json::to_vec(&(
            "crucible.scheduler.device-group-selection.v1",
            token.get(),
            &observation.input.node,
            observation.input.generation,
            next_input,
            ContentHash::from_bytes(&canonical_state),
            observation.opportunity.encode().as_slice(),
        ))
        .map_err(|error| refused(&format!("Group context encoding failed: {error}")))?;
        let digest = ContentHash::from_bytes(&bytes);
        let context = core::array::from_fn(|index| {
            let mut word = [0; 8];
            word.copy_from_slice(&digest.bytes[index * 8..index * 8 + 8]);
            u64::from_be_bytes(word)
        });
        let source = Arc::new(scheduler.clone());
        let input = PreparedRunInputInventory::complete_source(
            Arc::clone(&source),
            observation.input.generation,
            next_input,
        );
        let prepared = PreparedDeviceGroupSelection {
            owner: Arc::new(DeviceGroupSelectionOwner {
                controller: Arc::clone(&self.identity),
                control_token: token,
                context,
                observation,
                _source: source,
                canonical_state,
            }),
            input,
        };
        self.revision = token.get();
        self.selected = Some(prepared.clone());
        Ok(prepared)
    }
}

fn canonical_state(scheduler: &SingleScheduler) -> Result<Vec<u8>, SchedulerError> {
    scheduler
        .checkpoint()
        .map_err(|error| refused(&format!("Group scheduler checkpoint failed: {error}")))?
        .canonical_bytes()
        .map_err(|error| refused(&format!("Group scheduler state is unavailable: {error}")))
}

fn refused(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}
