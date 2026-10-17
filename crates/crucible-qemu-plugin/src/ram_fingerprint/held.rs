//! Stages an incremental held view until native callback/post publication accepts it.
//!
//! The committed baseline remains intact while the same native read loan owns
//! a provisional view. Finish transfers its real claim without acknowledging
//! either dirty consumer. Only a later authentic accepted-publication journal
//! permits promotion; ordinary observers never expose staged held records.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::runtime::{CaptureLoan, HeldClaimCleanup, HeldReadContext, HeldReaderIdentity};

pub(super) struct StagedView {
    identity: HeldReaderIdentity,
    claim: usize,
    header: CaptureHeader,
    dirty_generation: u64,
    full: bool,
    value: StagedValue,
    failure: Option<RamError>,
}

// An unchanged claim retains the existing complete baseline without rebuilding
// three records or charging a second record allocation on the no-dirty path.
enum StagedValue {
    Pending,
    Unchanged,
    Updated(CachedView),
}

impl StagedView {
    fn close_no_ack(&mut self, context: &HeldReadContext) -> Result<(), RamError> {
        HeldClaimCleanup::from_reader(context)
            .close_no_ack(&mut self.claim)
            .map_err(|status| RamError::Native {
                operation: "close held fingerprint claim without acknowledgment",
                status,
            })
    }

    fn accepted(&self, context: &HeldReadContext) -> Result<(), RamError> {
        if self.identity != context.identity
            || self.claim != 0
            || self.failure.is_some()
            || matches!(self.value, StagedValue::Pending)
        {
            return Err(RamError::Invariant(
                "held staged fingerprint identity changed",
            ));
        }
        let journal = context.publication().map_err(|status| RamError::Native {
            operation: "observe held fingerprint publication",
            status,
        })?;
        if journal.capture_generation != self.header.capture_generation
            || journal.publication_capture_generation != self.header.capture_generation
            || journal.topology_generation != self.header.topology_generation
            || journal.dirty_generation != self.dirty_generation
            || journal.full != u32::from(self.full)
            || journal.claim_closed != 1
            || journal.publication_pending != 0
            || journal.publication_accepted != 1
            || journal.rearm_deferred != 1
            || journal.fingerprint_acknowledged != 0
            || journal.first_status != 0
            || journal.post_status != 0
        {
            return Err(RamError::Invariant(
                "held fingerprint publication is not accepted",
            ));
        }
        Ok(())
    }
}

impl RootCache {
    fn stage_held(
        &mut self,
        context: &HeldReadContext,
        reader: &crate::paged_ram::engine::HeldCheckpointRead,
    ) -> Result<(), RamError> {
        if self.frozen
            || self.ordinary_active
            || self.pending.is_some()
            || self.restore.is_some()
            || self.held.is_some()
            || self
                .held_accepted
                .is_some_and(|key| key != context.identity)
        {
            return Err(RamError::Invariant(
                "held fingerprint cache admission is occupied",
            ));
        }
        context.slice().map_err(|status| RamError::Native {
            operation: "held fingerprint original pre",
            status,
        })?;
        let mut claim = std::ptr::null_mut();
        let mut header = CaptureHeader::default();
        let begin = (context.api.begin)(
            context.loan(),
            u32::from(
                self.view
                    .as_ref()
                    .is_none_or(|view| view.topology_generation != context.topology_generation()),
            ),
            &mut claim,
            &mut header,
        );
        if !claim.is_null() {
            self.held = Some(StagedView {
                identity: context.identity,
                claim: claim as usize,
                header,
                dirty_generation: 0,
                full: false,
                value: StagedValue::Pending,
                failure: None,
            });
        }
        status(begin, "begin held fingerprint capture")?;
        let value = self.build_held_view(context, reader)?;
        let journal = context.publication().map_err(|status| RamError::Native {
            operation: "observe constructed held fingerprint",
            status,
        })?;
        let held = self
            .held
            .as_mut()
            .ok_or(RamError::Invariant("held claim output absent"))?;
        held.value = value;
        held.full = journal.full == 1;
        held.dirty_generation = journal.dirty_generation;
        let mut claim = held.claim as *mut CaptureLoan;
        let transfer = (context.api.finish)(&mut claim, 1);
        held.claim = claim as usize;
        status(transfer, "transfer held fingerprint publication")?;
        if held.claim != 0 {
            return Err(RamError::Invariant(
                "held publication did not move its claim",
            ));
        }
        // Finish1 is transfer only. The outer real callback and Original post
        // still own acceptance; this view remains fully provisional.
        Ok(())
    }

    fn retain_held_failure(&mut self, context: &HeldReadContext, error: RamError) {
        if let Some(held) = self.held.as_mut() {
            if held.identity == context.identity {
                held.failure = Some(error);
                // This physical close runs before the actual callback returns.
                // Its retained output survives failure for the native caller's
                // real cleanup/reap boundary; no Drop path assumes completion.
                let _retained_close = held.close_no_ack(context);
            }
        }
    }

    fn build_held_view(
        &mut self,
        context: &HeldReadContext,
        reader: &crate::paged_ram::engine::HeldCheckpointRead,
    ) -> Result<StagedValue, RamError> {
        let held = self
            .held
            .as_ref()
            .ok_or(RamError::Invariant("held fingerprint native claim absent"))?;
        let header = held.header;
        let claim = held.claim;
        if header.schema != CAPTURE_SCHEMA
            || header.region_count == 0
            || header.region_count as usize > MAX_REGIONS
            || header.topology_generation == 0
            || header.capture_generation == 0
            || header.metadata_budget_bytes == 0
        {
            return Err(RamError::Invariant("held fingerprint inventory is invalid"));
        }
        let journal = context.publication().map_err(|status| RamError::Native {
            operation: "observe held fingerprint claim",
            status,
        })?;
        if journal.capture_generation != header.capture_generation
            || journal.claim_closed != 0
            || journal.publication_pending != 0
            || journal.first_status != 0
            || journal.post_status != 0
        {
            return Err(RamError::Invariant("held fingerprint claim changed"));
        }
        let full = journal.full == 1;
        let budget = self.metadata_budget(header.metadata_budget_bytes)?;
        let inventory_reservation = budget
            .reserve_bytes(
                (header.region_count as u64)
                    .checked_mul((std::mem::size_of::<RegionDescriptor>() + 255 + 32) as u64)
                    .ok_or(RamError::Invariant(
                        "held fingerprint inventory extent overflow",
                    ))?,
            )
            .map_err(display_error)?;
        let regions = read_region_inventory(
            header.region_count,
            header.capture_generation,
            |_, index, output| {
                if let Err(status) = context.slice() {
                    return status;
                }
                let read = (context.api.region)(claim as *mut CaptureLoan, index, output);
                let post = context.slice();
                if read != 0 {
                    read
                } else {
                    post.map_or_else(|status| status, |_| 0)
                }
            },
        )?;
        let topology = Topology::new(regions.clone(), Limits::default()).map_err(display_error)?;
        let baseline = self.view.as_ref();
        if let Some(view) = baseline {
            if !budget.shares_account_with(&view.budget)
                || view.budget.limit_bytes() != header.metadata_budget_bytes
                || (!full
                    && (view.topology_generation != header.topology_generation
                        || view.snapshot.topology() != &topology))
            {
                return Err(RamError::Invariant(
                    "held fingerprint baseline or account changed",
                ));
            }
        } else if !full {
            return Err(RamError::Invariant(
                "incremental held fingerprint has no baseline",
            ));
        }
        let snapshot = if full {
            let mut trees = Vec::new();
            trees
                .try_reserve_exact(topology.regions().len())
                .map_err(display_error)?;
            for region in topology.regions() {
                trees.push(
                    RegionTree::zeroed(region.logical_length(), &budget).map_err(display_error)?,
                );
            }
            RamSnapshot::new(topology, trees, &budget).map_err(display_error)?
        } else {
            baseline
                .ok_or("held fingerprint baseline absent")?
                .snapshot
                .clone()
        };
        let source = baseline.and_then(|view| view.source.clone());
        let proof_source = source.as_deref().map(|source| HeldProofSource {
            source,
            context,
            reader,
        });
        let (snapshot, changed) = consume_pages_with(
            &regions,
            snapshot,
            full,
            proof_source
                .as_ref()
                .map(|source| source as &dyn RamProofSource),
            |cursor, page, bytes| {
                if let Err(status) = context.slice() {
                    return status;
                }
                let next = (context.api.next)(claim as *mut CaptureLoan, page);
                if next != 0 {
                    return next;
                }
                let coordinate = CapturePage {
                    region_index: page.region_index,
                    valid_length: page.valid_length,
                    page_index: page.page_index,
                    page_version: page.page_version,
                };
                let read = (context.api.page)(
                    context.loan(),
                    header.capture_generation,
                    coordinate.region_index,
                    coordinate.page_index,
                    page,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                );
                if read != 0 {
                    return read;
                }
                if page.region_index != coordinate.region_index
                    || page.page_index != coordinate.page_index
                    || page.valid_length != coordinate.valid_length
                    || page.page_version != coordinate.page_version
                {
                    return -libc::ESTALE;
                }
                if let Err(status) = context.slice() {
                    return status;
                }
                let Some(next_cursor) = cursor.checked_add(1) else {
                    return -libc::EOVERFLOW;
                };
                *cursor = next_cursor;
                0
            },
        )?;
        if !full && !changed {
            context.slice().map_err(|status| RamError::Native {
                operation: "unchanged held fingerprint original post",
                status,
            })?;
            return Ok(StagedValue::Unchanged);
        }
        let roots = [
            snapshot
                .scoped_root(Scope::Execution)
                .map_err(display_error)?,
            snapshot.scoped_root(Scope::Exact).map_err(display_error)?,
            snapshot
                .scoped_root(Scope::Lifecycle)
                .map_err(display_error)?,
        ];
        let records = encode_records(&snapshot, &budget)?;
        let mut logical_bytes = [0_u64; 3];
        for (scope, bytes) in SCOPES.iter().zip(&mut logical_bytes) {
            for region in snapshot.topology().regions() {
                if scope.includes(region.class()) {
                    *bytes = bytes
                        .checked_add(region.logical_length())
                        .ok_or("held fingerprint byte count overflow")?;
                }
            }
        }
        context.slice().map_err(|status| RamError::Native {
            operation: "held fingerprint original post",
            status,
        })?;
        Ok(StagedValue::Updated(CachedView {
            topology_generation: header.topology_generation,
            budget,
            snapshot,
            roots,
            logical_bytes,
            native_regions: regions,
            records,
            source: if full { None } else { source },
            _inventory_reservation: inventory_reservation,
        }))
    }

    fn promote_held(&mut self, context: &HeldReadContext) -> Result<(), RamError> {
        let held = self
            .held
            .as_ref()
            .ok_or(RamError::Invariant("held staged fingerprint absent"))?;
        held.accepted(context)?;
        context.slice().map_err(|status| RamError::Native {
            operation: "held fingerprint promotion post",
            status,
        })?;
        let held = self
            .held
            .as_mut()
            .ok_or("held fingerprint staging changed")?;
        let value = std::mem::replace(&mut held.value, StagedValue::Pending);
        match value {
            StagedValue::Updated(view) => self.view = Some(view),
            StagedValue::Unchanged if self.view.is_some() => {}
            StagedValue::Pending | StagedValue::Unchanged => {
                return Err(RamError::Invariant("held provisional baseline absent"));
            }
        }
        self.held_publication = Some(held.header.capture_generation);
        self.held_accepted = Some(context.identity);
        self.held = None;
        Ok(())
    }
}

struct HeldProofSource<'a> {
    source: &'a dyn RamProofSource,
    context: &'a HeldReadContext,
    reader: &'a crate::paged_ram::engine::HeldCheckpointRead,
}

impl RamProofSource for HeldProofSource<'_> {
    fn source_record(&self) -> &crucible_ram::RootRecord {
        self.source.source_record()
    }
    fn source_root(&self) -> RamRootDigest {
        self.source.source_root()
    }
    fn proof(&self, region: &str, page: u64) -> Result<crucible_ram::PageProof, RamError> {
        let mut scratch = [0; crate::paged_ram::PAGE_BYTES];
        self.context.with_page_operation(|operation| {
            self.source.proof_with_retained_operation(
                region,
                page,
                operation,
                &mut scratch,
                self.reader,
            )
        })
    }
}

/// Observes only the authentic held candidate's staged or accepted cache view.
///
/// # Errors
/// Returns missing/busy owner, invalid outputs, source/claim failures, unaccepted
/// publication or the same native Original refusal. Staging never publishes an
/// ordinary baseline or acknowledges fingerprint/checkpoint dirty obligations.
pub(crate) fn observe_held(
    context: &HeldReadContext,
    reader: &crate::paged_ram::engine::HeldCheckpointRead,
    scope: u32,
    refresh: u32,
    record: *mut u8,
    capacity: usize,
    written: *mut usize,
    root: *mut u8,
    logical_bytes: *mut u64,
) -> c_int {
    if synchronize().is_err() {
        return -libc::EBUSY;
    }
    let observer = match observer() {
        Ok(observer) => observer,
        Err(_) => return -libc::ENODEV,
    };
    let mut cache = match observer.cache.try_lock() {
        Ok(cache) => cache,
        Err(_) => return -libc::EBUSY,
    };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), RamError> {
            if refresh == 1 {
                cache.stage_held(context, reader)?;
            } else if cache.held.is_some() {
                cache.promote_held(context)?;
            } else if cache.held_accepted != Some(context.identity) {
                return Err(RamError::Invariant(
                    "held record has no same-reader accepted publication",
                ));
            }
            let view = if refresh == 1 {
                let held = cache
                    .held
                    .as_ref()
                    .filter(|held| held.identity == context.identity)
                    .ok_or("held staged identity absent")?;
                match &held.value {
                    StagedValue::Updated(view) => Some(view),
                    StagedValue::Unchanged => cache.view.as_ref(),
                    StagedValue::Pending => None,
                }
            } else {
                cache.view.as_ref()
            }
            .ok_or("held fingerprint complete view absent")?;
            let index = usize::try_from(scope).map_err(|_| "held fingerprint scope overflow")?;
            let saved = view
                .records
                .get(index)
                .ok_or("held fingerprint scope absent")?;
            if capacity != 0 && capacity < saved.bytes.len() {
                return Err(RamError::Invariant(
                    "held fingerprint record capacity is short",
                ));
            }
            context.slice().map_err(|status| RamError::Native {
                operation: "held record copy original",
                status,
            })?;
            // SAFETY: the genuine registered native callback lends these exact
            // scalar, digest and optional complete record outputs for this call.
            // Native publishes only after its separate outer Original post.
            unsafe {
                written.write(saved.bytes.len());
                logical_bytes.write(view.logical_bytes[index]);
                std::ptr::copy_nonoverlapping(view.roots[index].as_bytes().as_ptr(), root, 32);
                if capacity != 0 {
                    std::ptr::copy_nonoverlapping(saved.bytes.as_ptr(), record, saved.bytes.len());
                }
            }
            Ok(())
        }));
    let error = match result {
        Ok(Ok(())) => return 0,
        Ok(Err(error)) => error,
        Err(_) => RamError::Invariant("held fingerprint callback panicked"),
    };
    let refusal = match &error {
        RamError::Native { status, .. } if *status < 0 => *status,
        _ => -libc::EIO,
    };
    cache.retain_held_failure(context, error);
    refusal
}

/// Returns private cache custody after genuine same-provider native retirement.
///
/// # Errors
/// Refuses another retained provider or a still-issued native claim. The caller
/// must first prove actual Root/reader retirement outside State guards; this
/// method performs no native effect or inferred accepted publication.
pub(crate) fn retire_held_cache(
    matches: impl Fn(&HeldReaderIdentity) -> bool,
) -> Result<(), RamError> {
    synchronize()?;
    let Some(observer) = OBSERVER.get() else {
        return Ok(());
    };
    let mut cache = observer
        .cache
        .try_lock()
        .map_err(|_| RamError::Invariant("held cache final retirement busy"))?;
    if let Some(held) = cache.held.as_ref() {
        if !matches(&held.identity) || held.claim != 0 {
            return Err(RamError::Invariant(
                "held cache has another or issued claim",
            ));
        }
    }
    if cache
        .held_accepted
        .as_ref()
        .is_some_and(|identity| !matches(identity))
    {
        return Err(RamError::Invariant(
            "accepted held cache belongs to another provider",
        ));
    }
    // A moved/null provisional view is discarded without promotion. An already
    // accepted view stays as the committed baseline; dirty obligations remain
    // native-owned and its rearm is never inferred from cache retirement.
    cache.held = None;
    cache.held_accepted = None;
    Ok(())
}

/// Returns a module-issued claim without reading or renewing its Original.
///
/// Private snapshot/source allocations and rejection-only keys stay owned by
/// the same provider until genuine Root retirement. They expose no usable native
/// reader borrow; ordinary cache admission remains excluded throughout cleanup.
pub(crate) fn cleanup_held_claim(cleanup: &HeldClaimCleanup) -> c_int {
    let Some(observer) = OBSERVER.get() else {
        return 0;
    };
    let Ok(mut cache) = observer.cache.try_lock() else {
        return -libc::EBUSY;
    };
    if cache
        .held_accepted
        .is_some_and(|identity| identity != cleanup.identity)
    {
        return -libc::ESTALE;
    }
    let Some(held) = cache.held.as_mut() else {
        return 0;
    };
    if held.identity != cleanup.identity {
        return -libc::ESTALE;
    }
    match cleanup.close_no_ack(&mut held.claim) {
        Ok(()) => 0,
        Err(status) => {
            if held.failure.is_none() {
                held.failure = Some(RamError::Native {
                    operation: "return module-issued held fingerprint claim",
                    status,
                });
            }
            status
        }
    }
}
