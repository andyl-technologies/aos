//! Synchronizes only a genuine settled native logical publication.
//!
//! The native loan retains the actual Source, capture and Original after their
//! semantic return. Factual getters precede cache locks; acceptance promotes the
//! exact provisional view, rejection discards it, and uncertainty blocks reuse.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Status {
    schema_version: u32,
    struct_size: u32,
    plugin_id: u64,
    frame_serial: u64,
    capture_generation: u64,
    topology_generation: u64,
    dirty_generation: u64,
    operation_serial: u64,
    supervisor_origin_ns: u64,
    supervisor_capability: [u8; 32],
    operation_class: u32,
    settled: u32,
    staged: u32,
    accepted: u32,
    full_capture: u32,
    scope: u32,
    root: [u8; 32],
    logical_bytes: u64,
    cpu_replay_context: u32,
    source_claim_retained: u32,
    outer_owner_retained: u32,
    writer_owner_retained: u32,
    progress_retained: u32,
    execution_retained: u32,
    execution_return_status: c_int,
    first_status: c_int,
    post_status: c_int,
    logical_return_status: c_int,
    outer_end_status: c_int,
    writer_return_status: c_int,
    native_status: c_int,
    original_facts_status: c_int,
    retirement_borrow_retained: u32,
    retirement_first_status: c_int,
    retirement_post_status: c_int,
    retirement_rearm_status: c_int,
    retirement_end_status: c_int,
    retirement_native_status: c_int,
}

pub(super) struct Identity {
    frame_serial: u64,
    dirty_generation: u64,
    full_capture: u32,
}

pub(super) struct Returned {
    journal: Status,
}

pub(super) type Observe = extern "C" fn(u64, *mut *mut Publication, *mut Status) -> c_int;
pub(super) type Return = extern "C" fn(u64, *mut *mut Publication) -> c_int;

impl Status {
    fn validate(
        &self,
        id: u64,
        evidence: Option<&Evidence>,
        capture: Option<&CaptureHeader>,
    ) -> Result<(), RamError> {
        let flags = [
            self.settled,
            self.staged,
            self.accepted,
            self.full_capture,
            self.cpu_replay_context,
            self.source_claim_retained,
            self.outer_owner_retained,
            self.writer_owner_retained,
            self.progress_retained,
            self.execution_retained,
            self.retirement_borrow_retained,
        ];
        let causes = [
            self.execution_return_status,
            self.first_status,
            self.post_status,
            self.logical_return_status,
            self.outer_end_status,
            self.writer_return_status,
            self.native_status,
            self.original_facts_status,
            self.retirement_first_status,
            self.retirement_post_status,
            self.retirement_rearm_status,
            self.retirement_end_status,
            self.retirement_native_status,
        ];
        if self.schema_version != 1
            || self.struct_size as usize != std::mem::size_of::<Self>()
            || self.plugin_id != id
            || self.frame_serial == 0
            || self.operation_serial == 0
            || self.topology_generation == 0
            || self.dirty_generation == 0
            || !matches!(self.operation_class, 4 | 5)
            || self.scope as usize >= SCOPES.len()
            || flags.iter().any(|flag| *flag > 1)
            || causes.iter().any(|cause| *cause > 0)
            || self.settled != 1
            || self.source_claim_retained != 0
            || self.outer_owner_retained != 0
            || self.writer_owner_retained != 0
            || self.progress_retained != 0
            || self.execution_retained != 0
            || self.retirement_borrow_retained != 0
            || (self.accepted == 1
                && (self.staged != 1
                    || self.capture_generation == 0
                    || causes.iter().any(|cause| *cause != 0)))
        {
            return Err(RamError::Invariant(
                "invalid settled logical publication journal",
            ));
        }
        if let Some(evidence) = evidence {
            if self.operation_serial != evidence.serial
                || self.supervisor_origin_ns != evidence.origin_ns
                || self.supervisor_capability != evidence.capability
                || self.operation_class != evidence.class
            {
                return Err(RamError::Invariant("logical publication Original changed"));
            }
        } else {
            return Err(RamError::Invariant("logical publication Original absent"));
        }
        match capture {
            Some(capture)
                if self.capture_generation == capture.capture_generation
                    && self.topology_generation == capture.topology_generation => {}
            None if self.accepted == 0 && self.capture_generation == 0 => {}
            _ => return Err(RamError::Invariant("logical publication capture changed")),
        }
        Ok(())
    }
}

impl Owner {
    /// Observes settled facts without obtaining clocks, reads or dirty ACK.
    pub(super) fn synchronize(&self) -> Result<(), RamError> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| "publication owner busy")?;
        if state.publication.load(Ordering::Acquire).is_null() {
            if state.returned_publication.is_some() {
                return finish_cache_return(&mut state);
            }
            if state.capture.is_some() || state.staged.is_some() || state.settled.is_some() {
                return Err(RamError::Invariant(
                    "logical capture lost its publication owner",
                ));
            }
            return Ok(());
        }
        let mut observed = Status::default();
        // This narrow field mutex serializes native by-reference access. The
        // factual getter invokes no callbacks; no cache/page/controller guard
        // crosses it and no escaped field is asynchronously dereferenced.
        let result = (self.apis.publication_observe)(
            self.plugin_id,
            state.publication.get_mut(),
            &mut observed,
        );
        status(result, "observe final logical publication")?;
        observed.validate(
            self.plugin_id,
            state.evidence.as_ref(),
            state.capture.as_ref(),
        )?;
        if state.return_status.is_some_and(|returned| returned > 0)
            || (observed.accepted == 1 && state.return_status != Some(0))
        {
            return Err(RamError::Invariant(
                "logical publication view-return facts disagree",
            ));
        }
        let identity = state
            .pending_facts
            .as_ref()
            .ok_or("logical publication pending facts absent")?;
        if observed.frame_serial != identity.frame_serial
            || observed.dirty_generation != identity.dirty_generation
            || observed.full_capture != identity.full_capture
        {
            return Err(RamError::Invariant(
                "logical publication pending lineage changed",
            ));
        }
        if state.retirement.is_some()
            || state.retirement_busy
            || !state.selector.load(Ordering::Acquire).is_null()
        {
            return Err(RamError::Invariant(
                "settled publication has retained module owners",
            ));
        }
        if let Some(previous) = state.settled {
            if previous != observed {
                return Err(RamError::Invariant("settled publication journal changed"));
            }
        }
        // No native query crosses this actual cache mutation boundary.
        {
            let observer = OBSERVER.get().ok_or("logical observer absent")?;
            let mut cache = observer
                .cache
                .try_lock()
                .map_err(|_| "publication cache busy")?;
            if cache.pending.is_some()
                || cache.restore.is_some()
                || cache.held.is_some()
                || cache.held_accepted.is_some()
            {
                return Err(RamError::Invariant(
                    "logical publication cache ownership changed",
                ));
            }
            if state.settled.is_none() {
                if observed.accepted == 1 {
                    let staged = state
                        .staged
                        .as_ref()
                        .ok_or("accepted publication has no provisional view")?;
                    if staged.evidence.serial != observed.operation_serial
                        || staged.capture.capture_generation != observed.capture_generation
                        || staged.capture.topology_generation != observed.topology_generation
                    {
                        return Err(RamError::Invariant("accepted logical stage changed"));
                    }
                    let view = staged
                        .view
                        .as_ref()
                        .or(cache.view.as_ref())
                        .ok_or("accepted logical baseline absent")?;
                    let scope = observed.scope as usize;
                    if SCOPES[scope] != staged.scope {
                        return Err(RamError::Invariant("logical publication scope changed"));
                    }
                    if view.topology_generation != observed.topology_generation
                        || view.roots[scope].as_bytes() != &observed.root
                        || view.logical_bytes[scope] != observed.logical_bytes
                    {
                        return Err(RamError::Invariant("accepted logical output changed"));
                    }
                    if let Some(mut staged) = state.staged.take() {
                        if let Some(view) = staged.view.take() {
                            cache.view = Some(view);
                        }
                    }
                    if observed.cpu_replay_context == 0 {
                        cache.held_publication = None;
                    }
                } else {
                    // Genuine settled rejection keeps the prior accepted view;
                    // provisional source/snapshot reservations return here.
                    state.staged = None;
                }
                state.settled = Some(observed);
            }
            cache.ordinary_active = true;
        }
        let returned = (self.apis.publication_return)(self.plugin_id, state.publication.get_mut());
        // Pointer consumption is recorded even on a signed refusal. That alone
        // never authorizes admission: the exact settled facts above are needed.
        if returned != 0 {
            return status(returned, "return final logical publication");
        }
        if !state.publication.load(Ordering::Acquire).is_null() {
            return Err(RamError::Invariant("publication return retained custody"));
        }
        state.returned_publication = Some(Returned { journal: observed });
        finish_cache_return(&mut state)
    }
}

/// Synchronizes before actual cache locks or any cache-consuming effect.
///
/// # Errors
/// Retains pending, malformed, mismatched or physically uncertain publication.
pub(crate) fn synchronize() -> Result<(), RamError> {
    if let Some(owner) = OBSERVER.get().and_then(|observer| observer.original) {
        owner.owner().synchronize()?;
        if owner.owner().has_retained_work() {
            return Err(RamError::Invariant(
                "native logical publication still owns cache admission",
            ));
        }
    }
    Ok(())
}

fn finish_cache_return(state: &mut State) -> Result<(), RamError> {
    let returned = state
        .returned_publication
        .as_ref()
        .ok_or("publication return receipt absent")?;
    if state.settled != Some(returned.journal)
        || !state.publication.load(Ordering::Acquire).is_null()
    {
        return Err(RamError::Invariant("publication physical return changed"));
    }
    let observer = OBSERVER.get().ok_or("logical observer absent")?;
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| "publication cache return busy")?;
    if !cache.ordinary_active
        || cache.pending.is_some()
        || cache.restore.is_some()
        || cache.held.is_some()
        || cache.held_accepted.is_some()
    {
        return Err(RamError::Invariant(
            "publication cache return ownership changed",
        ));
    }
    cache.ordinary_active = false;
    state.capture = None;
    state.staged = None;
    state.evidence = None;
    state.settled = None;
    state.returned_publication = None;
    state.pending_facts = None;
    Ok(())
}

/// Synchronizes prior settlement before this genuine Root obtains its view.
pub(in crate::ram_fingerprint) fn synchronize_root() -> Result<(), RamError> {
    if let Some(owner) = OBSERVER.get().and_then(|observer| observer.original) {
        owner.owner().synchronize()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection() -> (Status, Evidence, CaptureHeader) {
        let evidence = Evidence {
            capability: [9; 32],
            origin_ns: 10,
            serial: 4,
            start_ns: 20,
            progress_ns: 21,
            bounded_ns: 1,
            class: 5,
        };
        let capture = CaptureHeader {
            schema: 1,
            region_count: 1,
            topology_generation: 3,
            capture_generation: 7,
            metadata_budget_bytes: 4096,
        };
        let status = Status {
            schema_version: 1,
            struct_size: std::mem::size_of::<Status>() as u32,
            plugin_id: 2,
            frame_serial: 8,
            capture_generation: 7,
            topology_generation: 3,
            dirty_generation: 6,
            operation_serial: 4,
            supervisor_origin_ns: 10,
            supervisor_capability: [9; 32],
            operation_class: 5,
            settled: 1,
            first_status: -libc::EIO,
            ..Status::default()
        };
        (status, evidence, capture)
    }

    #[test]
    fn pending_or_retained_owner_never_projects_settled_disposition() {
        let (status, evidence, capture) = projection();
        for changed in [
            Status {
                settled: 0,
                ..status
            },
            Status {
                outer_owner_retained: 1,
                ..status
            },
            Status {
                writer_owner_retained: 1,
                ..status
            },
            Status {
                retirement_borrow_retained: 1,
                ..status
            },
            Status {
                progress_retained: 1,
                ..status
            },
            Status {
                execution_retained: 1,
                ..status
            },
        ] {
            assert!(
                changed
                    .validate(2, Some(&evidence), Some(&capture))
                    .is_err()
            );
        }
    }

    #[test]
    fn copied_generation_or_original_never_qualifies_publication() {
        let (status, evidence, capture) = projection();
        for changed in [
            Status {
                operation_serial: 5,
                ..status
            },
            Status {
                capture_generation: 9,
                ..status
            },
            Status {
                topology_generation: 4,
                ..status
            },
            Status {
                supervisor_capability: [1; 32],
                ..status
            },
            Status {
                supervisor_origin_ns: 11,
                ..status
            },
            Status {
                operation_class: 4,
                ..status
            },
        ] {
            assert!(
                changed
                    .validate(2, Some(&evidence), Some(&capture))
                    .is_err()
            );
        }
    }

    #[test]
    fn signed_rejection_never_qualifies_as_accepted_projection() {
        let (status, evidence, capture) = projection();
        assert!(status.validate(2, Some(&evidence), Some(&capture)).is_ok());
        let changed = Status {
            staged: 1,
            accepted: 1,
            ..status
        };
        assert!(
            changed
                .validate(2, Some(&evidence), Some(&capture))
                .is_err()
        );
    }
}

/// Captures factual pending keys only from this already-issued native loan.
pub(super) fn capture_facts(owner: &Owner, state: &mut State) -> Result<(), RamError> {
    if state.publication.load(Ordering::Acquire).is_null() {
        return Err(RamError::Invariant(
            "born logical capture has no publication loan",
        ));
    }
    let mut observed = Status::default();
    let result = (owner.apis.publication_observe)(
        owner.plugin_id,
        state.publication.get_mut(),
        &mut observed,
    );
    if result != 0 && result != -libc::EAGAIN {
        return status(result, "observe pending logical publication");
    }
    let evidence = state
        .evidence
        .as_ref()
        .ok_or("logical publication Original absent")?;
    if observed.schema_version != 1
        || observed.struct_size as usize != std::mem::size_of::<Status>()
        || observed.plugin_id != owner.plugin_id
        || observed.frame_serial == 0
        || observed.settled != 0
        || observed.operation_serial != evidence.serial
        || observed.supervisor_origin_ns != evidence.origin_ns
        || observed.supervisor_capability != evidence.capability
        || observed.operation_class != evidence.class
        || observed.topology_generation == 0
        || observed.dirty_generation == 0
        || observed.full_capture > 1
    {
        return Err(RamError::Invariant(
            "invalid pending logical publication facts",
        ));
    }
    if let Some(capture) = state.capture.as_ref() {
        if observed.capture_generation != capture.capture_generation
            || observed.topology_generation != capture.topology_generation
        {
            return Err(RamError::Invariant("pending publication capture changed"));
        }
    } else if observed.capture_generation != 0 {
        return Err(RamError::Invariant("pending publication header absent"));
    }
    if state
        .pending_facts
        .as_ref()
        .is_some_and(|previous| previous.frame_serial != observed.frame_serial)
    {
        return Err(RamError::Invariant("logical restart Root frame changed"));
    }
    state.pending_facts = Some(Identity {
        frame_serial: observed.frame_serial,
        dirty_generation: observed.dirty_generation,
        full_capture: observed.full_capture,
    });
    Ok(())
}
