//! Quotes and installs the same Source-owned import18 phase occurrence.
//!
//! The row prices this host bank alone. It is not the native initial row,
//! announced escrow or a phase admission. The actual installer retains this row
//! and independently admits its axes beside the whole live holder before entry.

use super::*;

/// Binds a host-bank constructor to the actual retained Source allocation.
///
/// The private row cannot be parsed or reconstructed from historical axes.
/// Its Weak identity prevents allocation-address reuse while the row survives.
/// The caller still owns the strong Source and every old holder throughout
/// quotation, whole-owner admission, construction and subsequent observation.
pub struct OriginalNativeImport18SourcePhaseBankConstructionData {
    source: Weak<PacketCompleteSemanticSource>,
    process: u32,
    thread: ThreadId,
    recipe: PacketNativeImport18PrebirthRecipeData,
    initial: PacketNativeImport18InitialFundingData,
    axes: [usize; 3],
}

impl OriginalNativeImport18SourcePhaseBankConstructionData {
    /// Returns this actual host bank's independent retained/transient/fixed axes.
    pub const fn requested_storage_data(&self) -> [usize; 3] {
        self.axes
    }

    fn authenticate_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source.as_ptr(), Rc::as_ptr(source))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let recipe = source.original_native_import18_recipe_data()?;
        let initial = source.original_native_import18_initial_funding_data()?;
        if recipe.identity_data() != self.recipe.identity_data()
            || recipe.lease_identity_data() != self.recipe.lease_identity_data()
            || recipe.lease_data() != self.recipe.lease_data()
            || !same_initial_data(&initial, &self.initial)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn retaining_data(&self) -> Self {
        Self {
            source: Weak::clone(&self.source),
            process: self.process,
            thread: self.thread,
            recipe: self.recipe,
            initial: self.initial,
            axes: self.axes,
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Quotes an unentered host bank from this Source's real retained birth inputs.
    ///
    /// The caller funds the defining counter before lookup, retains the returned
    /// row and then admits all axes beside every old Source/capsule/plan owner.
    /// Actual Source-born recipe/initial custody is mandatory; historical numbers,
    /// old native startup rows and caller limits cannot replace those operands.
    ///
    /// # Errors
    /// Refuses foreign origin, an entered occurrence, missing/failed birth inputs,
    /// checked layout overflow or the independently supplied requested bound.
    pub fn native_import18_phase_bank_construction_data(
        self: &Rc<Self>,
        maximum_requested_bytes: usize,
    ) -> Result<OriginalNativeImport18SourcePhaseBankConstructionData, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_phase_bank_attempted.get() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let recipe = self.original_native_import18_recipe_data()?;
        let initial = self.original_native_import18_initial_funding_data()?;
        if initial.recipe_identity_data() != recipe.identity_data() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let retained = sum_data(&[
            size_of::<NativeImport18SourcePhaseBank>(),
            size_of::<NativeImport18SourcePhaseOwner>(),
        ])?;
        // Each named by-value initializer is an independent construction view.
        // This is requested layout, not a physical stack or allocator claim.
        let transient = sum_data(&[
            size_of::<NativeImport18SourcePhaseBank>(),
            size_of::<NativeImport18SourcePhaseOwner>(),
            size_of::<OriginalNativeImport18SourcePhaseBankConstructionData>(),
            size_of::<BootstrapPartials>(),
            size_of::<PhasePartials>() * 2,
            size_of::<LiteralPartial>() * 5,
        ])?;
        let axes = [
            retained,
            transient,
            Self::native_import18_phase_bank_counter_scratch_data(),
        ];
        if sum_data(&axes)? > maximum_requested_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let row = OriginalNativeImport18SourcePhaseBankConstructionData {
            source: Rc::downgrade(self),
            process: std::process::id(),
            thread: std::thread::current().id(),
            recipe,
            initial,
            axes,
        };
        row.authenticate_data(self)?;
        Ok(row)
    }

    /// Installs one failed/spent occurrence before constructor or SDK work.
    ///
    /// The caller first retains and independently admits the exact quoted row.
    /// This method constructs only empty journals and actual bank ownership.
    /// It issues no ACK, request, capsule, native receipt or completion witness.
    /// Later genuine handlers must retain their inputs and debits in this same
    /// bank before effects; they cannot replace or renew this occurrence.
    ///
    /// # Errors
    /// Refuses a used occurrence, foreign row/birth inputs, a busy bank, capacity
    /// or requested-bound failure. The attempted flag and every initialized owner
    /// remain retained on all errors; the original row remains with the caller.
    pub fn retain_native_import18_phase_bank_data(
        self: &Rc<Self>,
        row: &OriginalNativeImport18SourcePhaseBankConstructionData,
        maximum_requested_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_phase_bank_attempted.replace(true) {
            return Err(RuntimeError::DuplicateOperation);
        }
        row.authenticate_data(self)?;
        if sum_data(&row.axes)? > maximum_requested_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut slot = self
            .native_import18_phase_bank
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *slot = Some(Box::new(NativeImport18SourcePhaseBank {
            row: row.retaining_data(),
            started: true,
            retained: false,
            failed: true,
            owners: Vec::new(),
        }));
        let bank = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        bank.owners
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        bank.owners
            .push(NativeImport18SourcePhaseOwner::retaining_data(row));
        let owner = bank
            .owners
            .last_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.retention = Retention::Retained;
        bank.retained_backing_data(row.axes[0])?;
        row.authenticate_data(self)?;
        bank.retained = true;
        bank.failed = false;
        Ok(())
    }

    /// Names genuine getter, origin, row, initializer and loan controls.
    ///
    /// Later phase/capsule construction, literal codec work, generic serializer
    /// frames and variable SDK traversal require their own defining rows.
    pub fn native_import18_phase_bank_counter_scratch_data() -> usize {
        Self::native_import18_recipe_metadata_counter_scratch_data()
            + storage::retained_counter_scratch_data()
            + PacketNativeImport18InitialFundingHistoryData::counter_scratch_data() * 2
            + size_of::<PacketNativeImport18InitialFundingHistoryData<'static>>() * 2
            + size_of::<&PacketNativeImport18InitialFundingData>() * 2
            + size_of::<&PacketNativeStartupAllocationRow>() * 2
            + size_of::<&[U64; 3]>() * 2
            + size_of::<&[u8; 32]>() * 2
            + size_of::<([u8; 32], U64)>() * 2
            + size_of::<OriginalNativeImport18SourcePhaseBankConstructionData>()
            + size_of::<Result<OriginalNativeImport18SourcePhaseBankConstructionData, RuntimeError>>(
            )
            + size_of::<&OriginalNativeImport18SourcePhaseBankConstructionData>()
            + size_of::<&Rc<Self>>()
            + size_of::<Weak<Self>>()
            + size_of::<&Weak<Self>>()
            + size_of::<*const Self>() * 2
            + size_of::<PacketNativeImport18PrebirthRecipeData>()
            + size_of::<PacketNativeImport18InitialFundingData>() * 2
            + size_of::<NativeImport18SourcePhaseBank>()
            + size_of::<NativeImport18SourcePhaseOwner>()
            + size_of::<BootstrapPartials>()
            + size_of::<PhasePartials>()
            + size_of::<LiteralPartial>()
            + size_of::<[LiteralPartial; 5]>()
            + size_of::<[Option<OriginalNativeImport18AssignmentStorageData>; 2]>()
            + size_of::<std::cell::RefMut<'static, Option<Box<NativeImport18SourcePhaseBank>>>>()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, Option<Box<NativeImport18SourcePhaseBank>>>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, Option<Box<NativeImport18SourcePhaseBank>>>,
                    RuntimeError,
                >,
            >()
            + size_of::<&mut NativeImport18SourcePhaseBank>()
            + size_of::<Option<&mut Box<NativeImport18SourcePhaseBank>>>()
            + size_of::<&mut NativeImport18SourcePhaseOwner>()
            + size_of::<Option<&mut NativeImport18SourcePhaseOwner>>()
            + size_of::<Result<&mut Box<NativeImport18SourcePhaseBank>, RuntimeError>>()
            + size_of::<Result<&mut NativeImport18SourcePhaseOwner, RuntimeError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<[usize; 2]>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 6]>()
            + size_of::<&usize>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<&ThreadId>() * 2
            + size_of::<&u32>() * 2
            + size_of::<u32>()
            + size_of::<usize>() * 8
            + size_of::<bool>() * 4
    }
}

impl NativeImport18SourcePhaseOwner {
    fn retaining_data(row: &OriginalNativeImport18SourcePhaseBankConstructionData) -> Self {
        Self {
            process: row.process,
            thread: row.thread,
            source: Weak::clone(&row.source),
            recipe: row.recipe,
            initial: row.initial,
            retention: Retention::Retaining,
            bootstrap: BootstrapPartials::new_data(),
            prepare: PhasePartials::new_data(),
            commit: PhasePartials::new_data(),
            prepare_request: None,
            commit_request: None,
            binding: None,
            sdk_rows: [None, None],
            prepare_capsule: None,
            input_upload_started: false,
            input_upload_verified: false,
            failed: false,
        }
    }
}

fn same_initial_data(
    left: &PacketNativeImport18InitialFundingData,
    right: &PacketNativeImport18InitialFundingData,
) -> bool {
    let left = left.borrowed_history_data();
    let right = right.borrowed_history_data();
    left.row.retained_requested_bytes == right.row.retained_requested_bytes
        && left.row.maximum_simultaneous_transient_bytes
            == right.row.maximum_simultaneous_transient_bytes
        && left.row.declared_counter_scratch_bytes == right.row.declared_counter_scratch_bytes
        && left.recipe_identity == right.recipe_identity
        && left.lease_identity == right.lease_identity
        && left.selected_launch_identity == right.selected_launch_identity
        && left.private_launch_identity == right.private_launch_identity
        && left.nonce == right.nonce
        && left.generation == right.generation
        && left.body_maximums == right.body_maximums
}

fn sum_data(values: &[usize]) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, amount| {
        total
            .checked_add(*amount)
            .ok_or(RuntimeError::ResourceLimit)
    })
}
