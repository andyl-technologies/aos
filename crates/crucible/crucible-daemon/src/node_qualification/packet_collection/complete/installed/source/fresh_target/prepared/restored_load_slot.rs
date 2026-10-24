//! Quotes and retains the large current17 Source-load destination lazily.
//!
//! The enclosing Prepared spends its existing prebirth flag and admits the
//! complete current owner plus each independent constructor axis before entry.
//! This private DATA row grants no Source, ticket, native state or restoration.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::RuntimeError;
use std::mem::{ManuallyDrop, MaybeUninit, size_of, size_of_val};

type Destination = Option<CompleteRestoredSettledSourceLoadAttempt>;
type Owner = Option<Box<Destination>>;

/// Retains the exact additional axes for the actual empty destination.
pub(super) struct ConstructionData {
    entered: bool,
    requested: [usize; 3],
}

impl ConstructionData {
    /// Creates an unentered runtime row from compile-time requested layouts.
    ///
    /// # Errors
    /// Refuses unsupported locked geometry or compile-time checked overflow.
    pub(super) fn new_data() -> Result<Self, RuntimeError> {
        match CONSTRUCTION_AXES {
            Some(requested) => Ok(Self {
                entered: false,
                requested,
            }),
            None => Err(RuntimeError::UnsupportedFacet),
        }
    }

    /// Returns the independent additional retained, transient and scratch axes.
    pub(super) fn requested_storage_data(&self) -> [usize; 3] {
        self.requested
    }

    /// Initializes the admitted destination while retaining its actual backing.
    ///
    /// The row is spent before every check; the enclosing prebirth flag also
    /// prevents retries after the earlier whole-owner admission. The old factory
    /// receives the same inner Option.
    /// Global allocator failure follows the existing Box allocation policy;
    /// this method does not manufacture a recoverable allocator result.
    ///
    /// # Errors
    /// Refuses an occupied destination or any independently insufficient axis
    /// before allocation. Every completed destination remains in `output`.
    pub(super) fn allocate_into_data(
        &mut self,
        admitted: [usize; 3],
        output: &mut Owner,
    ) -> Result<(), RuntimeError> {
        if self.entered {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.entered = true;
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        for (actual, needed) in admitted.into_iter().zip(self.requested) {
            if actual < needed {
                return Err(RuntimeError::ResourceLimit);
            }
        }

        // Allocate before initializing the large value. Box::write is safe;
        // the row above still pays every typed value transfer it reaches.
        let destination = Box::<Destination>::new_uninit();
        *output = Some(Box::write(destination, None));
        Ok(())
    }
}

// These are const ITEMS, not runtime calls to a const fn. All field arithmetic,
// private-envelope bounds and roster summation are evaluated by the compiler.
// None remains a refusal; no unsupported layout is interpreted as zero demand.
pub(super) const CONSTRUCTION_AXES: Option<[usize; 3]> = construction_axes_const();
pub(super) const FIXED_CALLER_SCRATCH: Option<usize> = match CONSTRUCTION_AXES {
    Some(axes) => Some(axes[2]),
    None => None,
};

const fn construction_axes_const() -> Option<[usize; 3]> {
    let allocator =
        match crucible_engine::node_contract::NodeRuntime::CAPTURE_GLOBAL_ALLOCATION_LAYOUT_DATA {
            Some(layouts) => layouts,
            None => return None,
        };
    let transient = match sum_const([
        size_of::<Destination>(),                   // actual caller None initializer
        size_of::<Destination>(),                   // Box::write owned value input
        size_of::<Destination>(),                   // MaybeUninit::write owned value input
        size_of::<Destination>(),                   // MaybeUninit::new owned value input
        size_of::<Destination>(),                   // ManuallyDrop::new owned value input
        size_of::<Destination>(),                   // MaybeDangling::new owned value input
        size_of::<Destination>(),                   // transparent MaybeDangling initializer
        size_of::<Destination>(),                   // transparent MaybeDangling return
        size_of::<ManuallyDrop<Destination>>(),     // ManuallyDrop initializer
        size_of::<ManuallyDrop<Destination>>(),     // ManuallyDrop return
        size_of::<MaybeUninit<Destination>>(),      // union initializer
        size_of::<MaybeUninit<Destination>>(),      // MaybeUninit::new return
        size_of::<MaybeUninit<Destination>>(),      // write assignment owned input
        size_of::<Box<MaybeUninit<Destination>>>(), // new_uninit transmute output
        size_of::<Box<MaybeUninit<Destination>>>(), // new_uninit return
        size_of::<Box<MaybeUninit<Destination>>>(), // Box::write owned box input
        size_of::<Box<MaybeUninit<Destination>>>(), // assume_init owned self input
        size_of::<Box<MaybeUninit<Destination>>>(), // transmute_unchecked owned input
        size_of::<Box<Destination>>(),              // transmute_unchecked output
        size_of::<Box<Destination>>(),              // assume_init return
        size_of::<Box<Destination>>(),              // Box::write return
        size_of::<Owner>(),                         // actual retained outer Some initializer
        size_of::<ConstructionData>(),              // runtime row initializer
        size_of::<ConstructionData>(),              // runtime row return
        size_of::<Result<ConstructionData, RuntimeError>>(), // new_data output
        size_of::<Result<ConstructionData, QualificationError>>(), // mapped output
        size_of::<Option<ConstructionData>>(),      // saved-row Some initializer
        size_of::<[usize; 3]>(),                    // actual const-axis read / requested return
        size_of::<[usize; 3]>(),                    // actual constructor admitted argument
        size_of::<[usize; 3]>(),                    // independent observer demand argument
        size_of::<Result<(), RuntimeError>>(),      // actual constructor outcome
    ]) {
        Some(bytes) => bytes,
        None => return None,
    };
    let runtime = match runtime_call_scratch_const() {
        Some(bytes) => bytes,
        None => return None,
    };
    let allocation = match allocation_dispatch_scratch_const(allocator) {
        Some(bytes) => bytes,
        None => return None,
    };
    let release = match release_dispatch_scratch_const() {
        Some(bytes) => bytes,
        None => return None,
    };
    match sum_const([runtime, allocation, release]) {
        Some(scratch) => Some([size_of::<Destination>(), transient, scratch]),
        None => None,
    }
}

const fn runtime_call_scratch_const() -> Option<usize> {
    sum_const([
        size_of::<Option<[usize; 3]>>(), // const DATA read before precredit
        size_of::<Option<usize>>(),      // fixed Host-counter prerequisite read
        size_of::<[usize; 3]>(),         // constant read / requested output
        size_of::<[usize; 3]>(),         // admitted independent-axis input
        size_of::<[usize; 3]>(),         // whole-Prepared demand argument
        size_of::<&ConstructionData>(),  // requested receiver
        size_of::<&mut ConstructionData>(), // actual once constructor receiver
        size_of::<&Option<ConstructionData>>(), // saved-row as_ref receiver
        size_of::<Option<&ConstructionData>>(),
        size_of::<Result<&ConstructionData, QualificationError>>(),
        size_of::<&mut Option<ConstructionData>>(), // saved-row as_mut receiver
        size_of::<Option<&mut ConstructionData>>(),
        size_of::<Result<&mut ConstructionData, QualificationError>>(),
        size_of::<std::array::IntoIter<usize, 3>>(), // admitted iterator
        size_of::<std::array::IntoIter<usize, 3>>(), // requested iterator
        size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<usize, 3>>>(),
        size_of::<Option<(usize, usize)>>(),
        size_of::<(usize, usize)>(),
        size_of::<&mut Owner>(), // retained destination output
        size_of::<&Owner>(),     // occupied check
        size_of::<&mut Box<MaybeUninit<Destination>>>(), // Box::deref_mut receiver
        size_of::<&mut MaybeUninit<Destination>>(), // Box::deref_mut return
        size_of::<&mut MaybeUninit<Destination>>(), // write receiver
        size_of::<&mut MaybeUninit<Destination>>(), // assume_init_mut receiver
        size_of::<&mut MaybeUninit<Destination>>(), // nested as_mut_ptr receiver
        size_of::<&mut Destination>(), // assume_init_mut return
        size_of::<&mut Destination>(), // write returned/discarded loan
        size_of::<*mut MaybeUninit<Destination>>(), // as_mut_ptr self cast
        size_of::<*mut Destination>(), // initialized pointer
        size_of::<&mut Box<Destination>>(), // as_deref_mut inner receiver
        size_of::<Option<&mut Destination>>(),
        size_of::<Result<&mut Destination, QualificationError>>(),
        size_of::<&PreparedCompleteRestoration>(), // observer receiver
        size_of::<HostSource17SetupBorrow<'static>>(), // actual borrowed whole owner
        size_of::<&mut Counter>(),                 // actual whole-owner charge call
        size_of::<std::array::IntoIter<usize, 3>>(), // demand-axis walk
        size_of::<Option<usize>>(),                // checked sum
        size_of::<Option<usize>>(),                // filtered sum
        size_of::<Result<usize, QualificationError>>(), // observer return
        size_of::<Result<(), RuntimeError>>(),     // constructor result
        size_of::<Result<(), QualificationError>>(), // mapped constructor result
        size_of::<Result<ConstructionData, RuntimeError>>(), // query return
        size_of::<Result<ConstructionData, QualificationError>>(), // mapped row
        size_of::<Result<std::convert::Infallible, QualificationError>>(), // residual
        size_of::<
            std::ops::ControlFlow<
                Result<std::convert::Infallible, QualificationError>,
                ConstructionData,
            >,
        >(),
        size_of::<
            std::ops::ControlFlow<
                Result<std::convert::Infallible, QualificationError>,
                &mut ConstructionData,
            >,
        >(),
        size_of::<
            std::ops::ControlFlow<
                Result<std::convert::Infallible, QualificationError>,
                &mut Destination,
            >,
        >(),
        size_of::<std::ops::ControlFlow<Result<std::convert::Infallible, QualificationError>, usize>>(
        ),
        size_of::<std::ops::ControlFlow<Result<std::convert::Infallible, QualificationError>, ()>>(
        ),
        size_of::<RuntimeError>(), // actual new_data/map_err scalar refusal
        size_of::<QualificationError>(), // original public refusal result
        size_of::<bool>(),
        size_of::<usize>(), // actual axis pair checks / observed scalar
    ])
}

// Global is fieldless. Its references are thin; Alignment is repr(usize), and
// Unique<T> is repr(transparent) over NonNull<T>. The pinned source establishes
// these exact private forms, not an arbitrary equal-size helper donation.
const fn allocation_dispatch_scratch_const(layouts: [usize; 4]) -> Option<usize> {
    let [fat, thin, residual, branch] = layouts;
    sum_const([
        size_of::<std::alloc::Layout>(), // box_new_uninit owned layout
        size_of::<&()>(),                // actual Global.allocate receiver
        size_of::<std::alloc::Layout>(), // allocate owned layout
        fat,                             // allocate return
        size_of::<&()>(),                // Global.alloc_impl receiver
        size_of::<std::alloc::Layout>(), // alloc_impl owned layout
        size_of::<bool>(),               // zeroed=false
        size_of::<(std::alloc::Layout, bool)>(), // actual argument tuple initializer
        size_of::<(std::alloc::Layout, bool)>(), // const_eval_select argument tuple
        size_of::<()>(),                 // actual const function item (not a fn pointer)
        size_of::<()>(),                 // actual runtime function item (not a fn pointer)
        fat,                             // const_eval_select / alloc_impl return
        size_of::<std::alloc::Layout>(), // runtime owned layout
        size_of::<bool>(),               // runtime zeroed argument
        size_of::<&std::alloc::Layout>(), // runtime layout.size receiver
        size_of::<usize>(),              // actual nonzero Destination size
        size_of::<std::alloc::Layout>(), // alloc(layout) owned input
        size_of::<&std::alloc::Layout>(), // allocator ABI size receiver
        size_of::<&std::alloc::Layout>(), // allocator ABI alignment receiver
        size_of::<usize>(),              // layout.size returned scalar
        size_of::<usize>(),              // layout.alignment returned repr(usize) Alignment
        size_of::<usize>(),              // __rust_alloc size argument
        size_of::<usize>(),              // actual repr(usize) Alignment argument
        size_of::<()>(),                 // __rust_no_alloc_shim_is_unstable_v2 return
        size_of::<*mut u8>(),            // allocator ABI return
        size_of::<*mut u8>(),            // alloc return / raw_ptr local
        size_of::<*mut u8>(),            // NonNull::new owned pointer input
        size_of::<bool>(),               // NonNull::new null test
        size_of::<*mut u8>(),            // actual thin new_unchecked owned pointer input
        size_of::<*mut ()>(),            // thin normal UB-check pointer cast
        size_of::<bool>(),               // thin normal nonnull precondition control
        size_of::<*mut u8>(),            // thin transmute owned pointer input
        size_of::<std::ptr::NonNull<u8>>(), // thin transmute output
        size_of::<std::ptr::NonNull<u8>>(), // thin new_unchecked return
        size_of::<Option<std::ptr::NonNull<u8>>>(), // actual Some initializer
        size_of::<Option<std::ptr::NonNull<u8>>>(), // new return
        size_of::<Option<std::ptr::NonNull<u8>>>(), // ok_or owned self
        size_of::<()>(),                 // actual fieldless AllocError input
        thin,                            // ok_or return
        thin,                            // Try::branch owned self input
        size_of::<std::ptr::NonNull<u8>>(), // branch Ok pattern
        branch,                          // ControlFlow Continue/Break initializer
        branch,                          // Try::branch return
        residual,                        // actual Err residual initializer
        residual,                        // caller residual pattern
        residual,                        // FromResidual owned input
        size_of::<()>(),                 // From<AllocError> input
        size_of::<()>(),                 // identity From return
        fat,                             // FromResidual Err initializer
        fat,                             // FromResidual return / runtime refusal output
        size_of::<std::ptr::NonNull<u8>>(), // caller success pointer pattern
        size_of::<std::ptr::NonNull<u8>>(), // cast_slice owned self
        size_of::<std::ptr::NonNull<u8>>(), // slice_from_raw_parts owned data
        size_of::<usize>(),              // slice_from_raw_parts owned length
        size_of::<std::ptr::NonNull<u8>>(), // data.as_ptr owned self
        size_of::<*mut u8>(),            // data.as_ptr return
        size_of::<usize>(),              // cast_slice length
        size_of::<*mut u8>(),            // raw slice constructor pointer
        size_of::<usize>(),              // raw slice constructor length
        size_of::<*mut [u8]>(),          // raw slice constructor return
        size_of::<*mut [u8]>(),          // NonNull::new_unchecked input
        size_of::<*mut ()>(),            // slice new_unchecked normal UB-check cast
        size_of::<bool>(),               // slice normal nonnull precondition control
        size_of::<*mut [u8]>(),          // actual fat-pointer transmute owned input
        size_of::<std::ptr::NonNull<[u8]>>(), // fat-pointer transmute output
        size_of::<std::ptr::NonNull<[u8]>>(), // slice_from_raw_parts return
        size_of::<std::ptr::NonNull<[u8]>>(), // new_unchecked return
        size_of::<std::ptr::NonNull<[u8]>>(), // cast_slice return
        fat,                             // success Ok initializer
        fat,                             // runtime return
        size_of::<std::ptr::NonNull<[u8]>>(), // box helper Ok pattern
        size_of::<std::ptr::NonNull<[u8]>>(), // as_mut_ptr owned self
        size_of::<std::ptr::NonNull<[u8]>>(), // as_non_null_ptr owned self
        size_of::<std::ptr::NonNull<[u8]>>(), // cast owned self
        size_of::<std::ptr::NonNull<[u8]>>(), // cast's nested as_ptr owned self
        size_of::<*mut [u8]>(),          // nested as_ptr returned fat pointer
        size_of::<*mut u8>(),            // actual raw cast/transmute owned input
        size_of::<std::ptr::NonNull<u8>>(), // cast transmute output
        size_of::<std::ptr::NonNull<u8>>(), // cast return
        size_of::<std::ptr::NonNull<u8>>(), // as_non_null_ptr return
        size_of::<std::ptr::NonNull<u8>>(), // as_ptr owned self
        size_of::<*mut u8>(),            // box_new_uninit return
        size_of::<*mut u8>(),            // new_uninit transmute owned input
        size_of::<std::alloc::Layout>(), // handle_alloc_error owned input
        size_of::<usize>(),              // terminal error-handler size input
        size_of::<usize>(),              // terminal error-handler Alignment input
    ])
}

const fn release_dispatch_scratch_const() -> Option<usize> {
    sum_const([
        size_of::<&mut Box<Destination>>(), // actual Box::drop receiver
        size_of::<std::ptr::NonNull<Destination>>(), // transparent Unique local
        size_of::<std::ptr::NonNull<Destination>>(), // Unique::as_ptr self
        size_of::<std::ptr::NonNull<Destination>>(), // nested NonNull::as_ptr owned self
        size_of::<*mut Destination>(),      // as_ptr return / for_value_raw input
        size_of::<*const Destination>(),    // actual for_value_raw owned argument
        size_of::<*const Destination>(),    // size_of_val_raw input
        size_of::<usize>(),                 // actual raw size output
        size_of::<*const Destination>(),    // Alignment::of_val_raw input
        size_of::<*const Destination>(),    // align_of_val_raw input
        size_of::<usize>(),                 // actual raw alignment output
        size_of::<usize>(),                 // Alignment::new_unchecked owned input
        size_of::<bool>(),                  // normal power-of-two precondition check
        size_of::<usize>(),                 // repr(usize) transmute input
        size_of::<usize>(),                 // repr(usize) Alignment output
        size_of::<usize>(),                 // Alignment::of_val_raw return
        size_of::<(usize, usize)>(),        // (size, repr(usize) Alignment) initializer
        size_of::<usize>(),                 // from_size_alignment_unchecked owned size
        size_of::<usize>(),                 // from_size_alignment_unchecked owned Alignment
        size_of::<bool>(),                  // normal size/alignment precondition branch
        size_of::<std::alloc::Layout>(),    // actual Layout initializer
        size_of::<std::alloc::Layout>(),    // from_size_alignment_unchecked return
        size_of::<std::alloc::Layout>(),    // for_value_raw return
        size_of::<std::alloc::Layout>(),    // actual layout local
        size_of::<&std::alloc::Layout>(),   // layout.size receiver
        size_of::<usize>(),                 // size test
        size_of::<bool>(),                  // nonzero allocation branch
        size_of::<std::ptr::NonNull<Destination>>(), // Unique::cast owned self
        size_of::<std::ptr::NonNull<Destination>>(), // nested NonNull::cast owned self
        size_of::<std::ptr::NonNull<Destination>>(), // cast's as_ptr owned self
        size_of::<*mut Destination>(),      // nested as_ptr return
        size_of::<*mut u8>(),               // actual raw cast/transmute owned input
        size_of::<std::ptr::NonNull<u8>>(), // actual transmute output
        size_of::<std::ptr::NonNull<u8>>(), // NonNull::cast return
        size_of::<std::ptr::NonNull<u8>>(), // transparent Unique initializer
        size_of::<std::ptr::NonNull<u8>>(), // transparent Unique<u8> cast return
        size_of::<std::ptr::NonNull<u8>>(), // From<Unique<u8>> owned input
        size_of::<std::ptr::NonNull<u8>>(), // actual Unique::as_non_null_ptr owned self
        size_of::<std::ptr::NonNull<u8>>(), // actual as_non_null_ptr return
        size_of::<std::ptr::NonNull<u8>>(), // From return
        size_of::<&()>(),                   // Global.deallocate receiver
        size_of::<std::ptr::NonNull<u8>>(), // deallocate owned pointer
        size_of::<std::alloc::Layout>(),    // deallocate owned layout
        size_of::<&()>(),                   // deallocate_impl receiver
        size_of::<std::ptr::NonNull<u8>>(), // deallocate_impl pointer
        size_of::<std::alloc::Layout>(),    // deallocate_impl layout
        size_of::<(std::ptr::NonNull<u8>, std::alloc::Layout)>(), // actual tuple initializer
        size_of::<(std::ptr::NonNull<u8>, std::alloc::Layout)>(), // select tuple
        size_of::<()>(),                    // actual const function item
        size_of::<()>(),                    // actual runtime function item
        size_of::<std::ptr::NonNull<u8>>(), // runtime owned pointer
        size_of::<std::alloc::Layout>(),    // runtime owned layout
        size_of::<&std::alloc::Layout>(),   // runtime layout.size receiver
        size_of::<usize>(),                 // nonzero size
        size_of::<bool>(),                  // runtime size branch
        size_of::<std::ptr::NonNull<u8>>(), // dealloc_nonnull pointer
        size_of::<std::alloc::Layout>(),    // dealloc_nonnull layout
        size_of::<&std::alloc::Layout>(),   // ABI size receiver
        size_of::<&std::alloc::Layout>(),   // ABI alignment receiver
        size_of::<std::ptr::NonNull<u8>>(), // __rust_dealloc pointer
        size_of::<usize>(),                 // release layout.size returned scalar
        size_of::<usize>(), // release layout.alignment returned repr(usize) Alignment
        size_of::<usize>(), // __rust_dealloc size
        size_of::<usize>(), // repr(usize) Alignment argument
        size_of::<()>(),    // actual deallocate/unit return
    ])
}

const fn sum_const<const N: usize>(terms: [usize; N]) -> Option<usize> {
    let mut bytes = 0usize;
    let mut index = 0;
    while index < N {
        bytes = match bytes.checked_add(terms[index]) {
            Some(next) => next,
            None => return None,
        };
        index += 1;
    }
    Some(bytes)
}

/// Charges the actual heap slot even while its inner destination is empty.
///
/// The enclosing Prepared already counts the outer Box pointer and saved row.
/// Failed and completed attempts keep their same inner owner and child census.
pub(super) fn charge_retained_data(
    output: &Owner,
    counter: &mut Counter,
) -> Result<(), RuntimeError> {
    if let Some(destination) = output {
        counter.add(size_of::<Destination>()).map_err(limit_data)?;
        if let Some(attempt) = destination.as_ref() {
            let children = attempt
                .retained_requested_storage_data()?
                .checked_sub(size_of_val(attempt))
                .ok_or(RuntimeError::ResourceLimit)?;
            counter.add(children).map_err(limit_data)?;
        }
    }
    Ok(())
}

/// Names only the added physical-slot census and delegation controls.
pub(super) const RETAINED_COUNTER_SCRATCH: usize = size_of::<&Owner>()
    + size_of::<&Box<Destination>>()
    + size_of::<&Destination>()
    + size_of::<&CompleteRestoredSettledSourceLoadAttempt>()
    + size_of::<&mut Counter>()
    + size_of::<&mut Counter>() // nested Counter::add receiver
    + size_of::<usize>()
    + size_of::<Option<usize>>()
    + size_of::<Result<usize, RuntimeError>>()
    + size_of::<Result<(), QualificationError>>()
    + size_of::<Result<(), RuntimeError>>()
    + size_of::<QualificationError>() // limit_data actual owned mapper input
    + size_of::<RuntimeError>() // mapper/ok_or owned scalar input and return
    + size_of::<Result<std::convert::Infallible, RuntimeError>>() // Err residual
    + size_of::<Result<std::convert::Infallible, RuntimeError>>() // FromResidual input
    + size_of::<std::ops::ControlFlow<Result<std::convert::Infallible,RuntimeError>,usize>>()
    + size_of::<std::ops::ControlFlow<Result<std::convert::Infallible,RuntimeError>,()>>()
    + size_of::<()>(); // actual mapper function item

fn limit_data(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

#[cfg(test)]
#[path = "restored_load_slot/tests.rs"]
mod tests;
