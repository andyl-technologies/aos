//! Constructs a distinct ticket-backed Host17 source from a genuine code source.
//!
//! The private unprepared template already passed the compiled Host constructor.
//! Its immutable metadata may be cloned under separate construction admission;
//! its source identity, once cells, attachment and ticket are never cloned. The
//! result remains inactive and cannot issue a native mapping, context or Ready.

use super::*;
use crate::node_contract::NodeRuntime;
use crate::node_state::CompleteOriginalHostTicket;
use std::mem::size_of;

/// Prices a new Host17 source independently of native and Host node construction.
///
/// Only the actual unprepared code source and original Host17 ticket produce
/// this DATA row. The caller separately admits its complete retained holder,
/// this row and callback work before invoking the constructor. Neither this row
/// nor matching source metadata constitutes a native or activation permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRestoredSource17ConstructionData {
    process: u32,
    thread: ThreadId,
    template: *const HostSchedulingSource,
    ticket_source: *const (),
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
}

impl HostRestoredSource17ConstructionData {
    /// Returns the distinct source Rc root and independently cloned metadata.
    pub fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independently funded pure constructor copies and value headers.
    ///
    /// A failed pure metadata clone may be discarded before a completed source
    /// exists. Its temporary storage does not consume or discard the original
    /// archive ticket. No modeled operation or custody journal is copied here.
    pub fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the fixed defining quote and constructor view storage.
    pub fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked conjunction of all three independent axes.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or a sum beyond the original quote ceiling.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        sum(&[self.retained, self.transient, self.scratch], self.maximum)
    }
}

impl HostSchedulingSource {
    /// Names fixed quote views before borrowing any Host17 construction inputs.
    ///
    /// Metadata traversal uses the same defining owned-storage walk as the
    /// genuine Host source census. Source/archive, template and external holder
    /// backing remain independently counted by the enclosing admission action.
    pub fn restored_source17_construction_counter_scratch_data() -> usize {
        size_of::<HostRestoredSource17ConstructionData>()
            + size_of::<Result<HostRestoredSource17ConstructionData, RuntimeError>>()
            + size_of::<&Rc<Self>>()
            + size_of::<&CompleteOriginalHostTicket>()
            + size_of::<Result<&HostSchedulingRestoredContinuationRecord17, RuntimeError>>()
            + size_of::<&HostSchedulingSelection>()
            + size_of::<&HashRef>()
            + size_of::<[usize; 4]>()
            + size_of::<[usize; 9]>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 2]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<&mut HostSchedulingSource>>()
            + size_of::<&mut Option<HostSchedulingOwner>>()
            + size_of::<&mut Option<CompleteOriginalHostTicket>>()
            + Self::retained_original_metadata_counter_scratch_data()
    }

    /// Quotes one distinct Host17 source from this actual unprepared code source.
    ///
    /// No metadata validator, JSON serializer, hash, callback or allocation runs
    /// here. The template's compiled construction and private immutable fields
    /// provide the metadata provenance; the actual ticket supplies the archived
    /// durable selection. Fresh native custody must be established separately.
    ///
    /// # Errors
    /// Refuses a foreign, revoked, historical or already prepared template;
    /// another archive family or incompatible archived selection; or arithmetic
    /// and complete construction demand above `maximum`.
    pub fn restored_source17_construction_data(
        self: &Rc<Self>,
        ticket: &CompleteOriginalHostTicket,
        maximum: usize,
    ) -> Result<HostRestoredSource17ConstructionData, RuntimeError> {
        self.authenticate_restored_source17_template_data(ticket)?;
        let (retained, transient) = metadata_geometry(self, maximum)?;
        let row = HostRestoredSource17ConstructionData {
            process: std::process::id(),
            thread: thread::current().id(),
            template: Rc::as_ptr(self),
            ticket_source: Rc::as_ptr(&ticket.source).cast(),
            retained,
            transient,
            scratch: Self::restored_source17_construction_counter_scratch_data(),
            maximum,
        };
        row.requested_bytes_data()?;
        self.authenticate_restored_source17_template_data(ticket)?;
        Ok(row)
    }

    fn authenticate_restored_source17_template_data(
        &self,
        ticket: &CompleteOriginalHostTicket,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_report_startup_data()?;
        ticket.authenticate_birth()?;
        let record = ticket.restored_record_data()?;
        if !matching_archived_selection(
            &self.selection,
            &self.world,
            &record.source,
            &record.scheduling.world_binding_hash,
        ) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_original_report_startup_data()
    }
}

impl HostSchedulingOwner {
    /// Counts the actual target selection's independent metadata backing.
    ///
    /// The borrowed selection header is already inside its caller's Manifest
    /// root. This defining walk counts its actual strings, maps and vector
    /// capacities without cloning or granting construction permission.
    ///
    /// # Errors
    /// Refuses checked overflow in the complete typed metadata traversal.
    pub fn restored_source17_selection_storage_data(
        selected: &HostSchedulingSelection,
    ) -> Result<usize, RuntimeError> {
        NodeRuntime::capture_host_selection_storage(selected)?
            .checked_sub(size_of::<HostSchedulingSelection>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Retains a distinct Host17 source before relinquishing its original ticket.
    ///
    /// The template is the genuine compiled, unprepared code Host. All fields
    /// copied here are immutable metadata; new source identity and once state
    /// belong to a separate Rc. The caller must independently admit the quoted
    /// row and actual holder before entry. The original ticket remains in its
    /// slot until every fallible check and pure metadata construction completes.
    /// A successful result is stored before any later caller currency fence.
    ///
    /// This issues no node, scheduler attachment, native permission, context,
    /// readiness or World activation. Initial-family constructors are unchanged.
    ///
    /// # Errors
    /// Refuses an occupied output, absent or foreign ticket/template, another
    /// archived family, changed quote or insufficient admitted extent. A refusal
    /// retains the original ticket and any existing output without replacement.
    pub fn restore_complete_restored_settled_from_template_into(
        template: &Rc<HostSchedulingSource>,
        ticket: &mut Option<CompleteOriginalHostTicket>,
        row: &HostRestoredSource17ConstructionData,
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let original = ticket.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if row.process != std::process::id()
            || row.thread != thread::current().id()
            || row.template != Rc::as_ptr(template)
            || row.ticket_source != Rc::as_ptr(&original.source).cast()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let current = template.restored_source17_construction_data(original, row.maximum)?;
        if &current != row {
            return Err(RuntimeError::ForeignAuthority);
        }

        // All copied heaps are pure metadata under the separate transient row.
        // Until the final no-fail transfer, the actual archive ticket stays in
        // its caller-owned slot and retains every modeled continuation owner.
        let mut owner = Self {
            source: Rc::new(HostSchedulingSource {
                edition: preservation::Edition::CompleteOriginalLineage,
                original_ticket: None,
                archive_ticket: None,
                preservation_facet: template
                    .preservation_facet
                    .as_ref()
                    .map(complete::SelectedPreservation::cloned_metadata_data),
                selection: template.selection.clone(),
                world: template.world.clone(),
                process: std::process::id(),
                owner_thread: thread::current().id(),
                prepared_token: template.prepared_token.clone(),
                revoked: Cell::new(false),
                node_created: Cell::new(false),
                attachment_attempted: Cell::new(false),
                node: RefCell::new(Weak::new()),
                attached: RefCell::new(None),
                capture_dependencies: RefCell::new(None),
            }),
        };
        if owner
            .source
            .retained_prebirth_host_metadata_data(row.maximum)?
            > row.retained
        {
            return Err(RuntimeError::ResourceLimit);
        }
        template.authenticate_restored_source17_template_data(original)?;
        let destination = Rc::get_mut(&mut owner.source).ok_or(RuntimeError::OwnerBusy)?;

        // No fallible operation or callback follows this move into the original
        // destination. Error/unwind before it leaves the caller's ticket intact.
        destination.archive_ticket = ticket.take();
        *output = Some(owner);
        Ok(())
    }
}

fn matching_archived_selection(
    selected: &HostSchedulingSelection,
    world: &HashRef,
    archived: &HostSchedulingSelection,
    archived_world: &HashRef,
) -> bool {
    archived.descriptor == selected.descriptor
        && archived.binding.compatibility == selected.binding.compatibility
        && archived.domains == selected.domains
        && archived.operating_policy == selected.operating_policy
        && archived.guarantees == selected.guarantees
        && archived.owner == selected.owner
        && world == archived_world
}

fn metadata_geometry(
    template: &HostSchedulingSource,
    maximum: usize,
) -> Result<(usize, usize), RuntimeError> {
    let selection = NodeRuntime::capture_host_selection_storage(&template.selection)?
        .checked_sub(size_of::<HostSchedulingSelection>())
        .ok_or(RuntimeError::ResourceLimit)?;
    let children = sum(
        &[
            selection,
            NodeRuntime::capture_hash_storage(&template.world)?,
            template.prepared_token.allocated_capacity(),
            template
                .preservation_facet
                .as_ref()
                .map_or(0, |facet| facet.retained_requested_storage()),
        ],
        maximum,
    )?;
    let retained = sum(
        &[
            NodeRuntime::capture_shared_allocation_storage::<HostSchedulingSource>(),
            children,
        ],
        maximum,
    )?;

    // The future retained allowance is never lent to failed pure construction.
    // Independently fund its local Rc and child heaps until output is retained,
    // plus the actual by-value source/owner and Option/Rc return headers.
    let transient = sum(
        &[
            retained,
            size_of::<HostSchedulingSource>(),
            size_of::<HostSchedulingOwner>(),
            size_of::<Option<HostSchedulingOwner>>(),
            size_of::<Rc<HostSchedulingSource>>(),
            size_of::<HostSchedulingSelection>(),
            size_of::<HashRef>(),
            size_of::<Id>(),
            size_of::<Option<complete::SelectedPreservation>>(),
        ],
        maximum,
    )?;
    Ok((retained, transient))
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(*value)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

#[cfg(test)]
mod tests;
