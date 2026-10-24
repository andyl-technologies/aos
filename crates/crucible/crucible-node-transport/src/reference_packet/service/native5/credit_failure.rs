//! Prices the original counting writer's concrete temporary IO error.
//!
//! Fixed geometry is evaluated by const items. The runtime API only admits
//! that independently supplied row. It changes no writer, mapping, error
//! lifetime or validator, and grants no later serializer or native phase.

use super::PacketNative5SourceLaunch;
use crate::{ProviderError, connection::SERIALIZED_CREDIT_FAILURE_MESSAGE};
use std::{
    alloc::{Layout, LayoutError},
    convert::Infallible,
    error::Error,
    io,
    mem::{align_of, size_of},
    ops::ControlFlow,
    ptr::NonNull,
};

// crucible-lint: allow erased-error -- private const-only model of pinned std::io::Error payload geometry; runtime APIs return typed ProviderError.
type DynError = dyn Error + Send + Sync;

// These helpers are used ONLY by const items below. Their loops, checked
// arithmetic and private field-layout derivation never run in the quote API.
#[derive(Clone, Copy)]
struct FieldBound {
    bytes: usize,
    alignment: usize,
}

impl FieldBound {
    const fn of<T>() -> Self {
        Self {
            bytes: size_of::<T>(),
            alignment: align_of::<T>(),
        }
    }

    const fn record(fields: &[Self]) -> Self {
        let mut bytes = 0;
        let mut alignment = 1;
        let mut index = 0;
        while index < fields.len() {
            bytes = add(bytes, fields[index].bytes);
            if fields[index].alignment > alignment {
                alignment = fields[index].alignment;
            }
            index += 1;
        }
        // Bound each possible source-field gap, plus leading and tail gaps.
        // These are source fields, not an instantiated private ABI mirror.
        bytes = add(bytes, mul(add(fields.len(), 1), alignment - 1));
        let remainder = bytes % alignment;
        if remainder != 0 {
            bytes = add(bytes, alignment - remainder);
        }
        Self { bytes, alignment }
    }

    const fn tagged(payload: Self) -> Self {
        Self::record(&[Self::of::<usize>(), payload])
    }
}

const fn add(left: usize, right: usize) -> usize {
    match left.checked_add(right) {
        Some(value) => value,
        None => panic!("fixed credit-error geometry overflow"),
    }
}

const fn mul(left: usize, right: usize) -> usize {
    match left.checked_mul(right) {
        Some(value) => value,
        None => panic!("fixed credit-error geometry overflow"),
    }
}

const fn sum(values: &[usize]) -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < values.len() {
        total = add(total, values[index]);
        index += 1;
    }
    total
}

const WORD: usize = size_of::<usize>();
const THIN: usize = size_of::<*mut ()>();
const FAT: usize = size_of::<*mut DynError>();
const GLOBAL: usize = size_of::<()>(); // actual fieldless Global / AllocError
// Layout::for_value_raw binds (usize, Alignment). Alignment's pinned source
// asserts usize size/alignment; use its actual fields rather than a fake tuple.
const SIZE_ALIGNMENT_PAIR: FieldBound =
    FieldBound::record(&[FieldBound::of::<usize>(), FieldBound::of::<usize>()]);

const RAW_INNER: FieldBound = FieldBound::record(&[
    FieldBound::of::<NonNull<u8>>(), // actual transparent Unique<u8>
    FieldBound::of::<usize>(),       // actual transparent Cap
    FieldBound::of::<()>(),          // actual Global
]);
const RAW: FieldBound =
    FieldBound::record(&[RAW_INNER, FieldBound::of::<std::marker::PhantomData<u8>>()]);
const STRING_ERROR: FieldBound = FieldBound::record(&[FieldBound::of::<String>()]);
// These signature-matched function pointer samples are layout-only: no
// callback value is created, converted or called. The selected compiler maps
// every FnPtr to the same instruction-address-space scalar without inspecting
// its safety qualifier (rustc_ty_utils/src/layout.rs). Keeping safe signatures
// therefore preserves the actual callback size/alignment, including targets
// whose instruction pointers differ from data pointers, within this safe crate.
const CUSTOM: FieldBound = FieldBound::record(&[
    FieldBound::of::<io::ErrorKind>(),
    FieldBound::of::<NonNull<DynError>>(),
    FieldBound::of::<fn(*mut DynError)>(),
    FieldBound::of::<fn(*mut ())>(), // same thin callback layout as *mut Custom
]);
const ERROR_CODE: FieldBound = FieldBound::tagged(FieldBound::of::<Box<str>>());
// This is a const initializer, not an ordinary call to a const fn. The
// defining diagnostic delegate and its private ErrorImpl field walk are CTFE.
const ERROR_IMPL_BYTES: usize = crate::reference_packet::continuation_models::serde_partials::diagnostic_error_impl_allocation_upper_bytes_data();
const ERROR_DATA: FieldBound = FieldBound::tagged(FieldBound::of::<NonNull<()>>());
const RAW_RESULT: FieldBound = FieldBound::tagged(FieldBound::record(&[
    RAW_INNER,
    FieldBound::of::<std::collections::TryReserveError>(),
]));

// AllocError is a private unstable fieldless ZST, not a ProviderError or a
// TryReserveError. Result/ControlFlow bounds below use its ACTUAL fields and
// actual NonNull payload; they do not instantiate a stand-in allocator ABI.
const ALLOC_ERROR: FieldBound = FieldBound::of::<()>();
const ALLOC_THIN_RESULT: FieldBound = FieldBound::tagged(FieldBound::record(&[
    FieldBound::of::<NonNull<u8>>(),
    ALLOC_ERROR,
]));
const ALLOC_FAT_RESULT: FieldBound = FieldBound::tagged(FieldBound::record(&[
    FieldBound::of::<NonNull<[u8]>>(),
    ALLOC_ERROR,
]));
const ALLOC_RESIDUAL: FieldBound = FieldBound::tagged(ALLOC_ERROR);
const ALLOC_FLOW: FieldBound = FieldBound::tagged(FieldBound::record(&[
    ALLOC_RESIDUAL,
    FieldBound::of::<NonNull<u8>>(),
]));

const SUPPORTED_PROFILE: bool = size_of::<usize>() == 8
    && align_of::<usize>() == 8
    && size_of::<io::Error>() == 8
    && size_of::<serde_json::Error>() == 8
    && size_of::<Box<DynError>>() == 16
    && size_of::<String>() == 24;

// Only the final constant-row load/comparison/Result boundary executes while
// quoting. No runtime field arrays, layouts, diagnostic walk, ? or arithmetic
// helper requires retroactive funding from the error-construction row.
const QUOTE_CONTROLS: usize = size_of::<usize>() * 4 // maximum, total view, two scalar returns
    + size_of::<bool>() * 3 // profile negation, restriction comparison, short-circuit
    + size_of::<(usize, usize)>() * 2 // constant row load / Ok payload
    + size_of::<Result<(usize, usize), ProviderError>>() * 2 // initializer / return
    + size_of::<ProviderError>() * 2; // static refusal initializer / Err owned input

const BACKING: usize = sum(&[
    SERIALIZED_CREDIT_FAILURE_MESSAGE.len(),
    STRING_ERROR.bytes,
    CUSTOM.bytes,
    ERROR_IMPL_BYTES,
]);

// Actual field/argument operands, distinct from their producer return and
// enclosing initializer. These are the eight transfers in the same chain.
const OWNED_FIELD_OPERANDS: usize = sum(&[
    RAW_INNER.bytes,            // RawVec.inner
    RAW.bytes,                  // Vec.buf
    size_of::<Vec<u8>>(),       // String.vec (not from_utf8_unchecked's parameter)
    size_of::<String>(),        // StringError(err)
    size_of::<Box<DynError>>(), // custom_owner_from_box's owned argument
    THIN,                       // io Error.repr
    ERROR_CODE.bytes,           // ErrorImpl.code
    THIN,                       // serde Error.err's Box<ErrorImpl>
]);

// The inline original writer owns these io::Error operands after the error
// thunk returns. Control envelopes do not donate their payload inputs.
const WRITER_OWNED_ERROR_OPERANDS: usize = size_of::<io::Error>() * 8;
// Eight roles, in order: thunk return, ok_or_else Err input, Try Err binding,
// residual Err input, FromResidual Err binding, identity From input/return,
// and enclosing Err input. Original error lifetime is unchanged.

// Actual owned initializer, argument and return windows are independent of
// the pointee backing. Sum explicitly even when individual returns are
// sequential: no optimizer, copy elision or larger unrelated slot is a donor.
const OWNED_CONSTRUCTION: usize = sum(&[
    OWNED_FIELD_OPERANDS,
    WRITER_OWNED_ERROR_OPERANDS,
    size_of::<String>() * 5, // initializer + from_utf8/to_owned/from returns + From<String> input
    size_of::<Vec<u8>>() * 8, // Vec init/return, v, ConvertVec/to_vec_in/to_vec/ToOwned returns, String input
    RAW.bytes * 2,            // RawVec initializer / with_capacity_in return
    RAW_INNER.bytes * 4,      // initializer / Ok payload / match this / with_capacity_in return
    RAW_RESULT.bytes * 2,     // actual try_allocate_in Result initializer / return
    STRING_ERROR.bytes * 3,   // initializer / Box::new input / write_via_move input
    CUSTOM.bytes * 5, // initializer / from_raw return / local / Box input / write_via_move input
    ERROR_CODE.bytes, // owning Io initializer
    ERROR_IMPL_BYTES * 3, // initializer / Box::new input / write_via_move input
    size_of::<Box<DynError>>() * 3, // From<String> / From<&str> / Into returns
    THIN * 3,         // distinct StringError / Custom / ErrorImpl Box::new returns
    THIN * 6,         // CustomOwner initializer/from_raw/from_box returns + three transfer inputs
    size_of::<io::Error>() * 5, // Error initializer/from_custom_owner/new/other returns + Io input
    THIN * 3,         // Repr initializer / local res / new_custom return
    size_of::<serde_json::Error>() * 3, // initializer / Error::io return / mapper input
    ERROR_DATA.bytes * 3, // decode_repr owning variant initializer / return / discarded temporary
    // Per allocation: runtime Ok initializer/return, const_eval_select RET,
    // alloc_impl return, allocate return and caller match temporary.
    ALLOC_FAT_RESULT.bytes * 6 * 4,
    ALLOC_FAT_RESULT.bytes * 2, // actual RawVec let result local and consuming match operand
    // Box::into_raw(dyn StringError, Custom) and mem::forget(CustomOwner):
    // caller input/local-or-temporary, ManuallyDrop::new input/initializer/
    // return and MaybeDangling::new input/initializer/return: eight each.
    FAT * 8,
    THIN * 8,
    THIN * 8,
    // Two actual callbacks reconstruct Box<Custom> and Box<dyn Error>:
    // from_raw_in initializer/return, from_raw return, mem::drop input.
    THIN * 4,
    FAT * 4,
]);

// All helpers below are evaluated only by const RUNTIME_CONTROLS. They model
// the real runtime constructor and destructor calls, not CTFE stack residency.
const fn alignment_controls() -> usize {
    sum(&[
        WORD * 2, // actual Alignment of_val_raw return / nested new_unchecked return
        WORD * 3, // align_of_val_raw input-result local / new_unchecked input / transmute result
        WORD * 2, // mem::align_of_val_raw / intrinsic return
        WORD * 2, // Alignment::as_usize / as_nonzero_usize owned inputs
        size_of::<std::num::NonZeroUsize>() * 3, // transmute/return and NonZero::get input
        WORD * 2, // NonZero::get / as_usize returns
        size_of::<bool>(), // power-of-two invariant check (valid actual alignments)
    ])
}

const fn layout_controls() -> usize {
    sum(&[
        size_of::<Layout>() * 3,   // caller layout / nested initializer / return
        size_of::<&Layout>() * 3,  // size, align, alignment receivers
        WORD * 4,                  // actual size argument/return and Alignment argument/return
        size_of::<bool>() * 3,     // nonzero size and alignment invariants
        SIZE_ALIGNMENT_PAIR.bytes, // actual usize/word-repr Alignment operand pair
        alignment_controls(),
    ])
}

// `pointer` bounds every pointer payload in this one actual instantiation.
// A sized cast from a fat input returns a thin pointer, so using the larger
// input field bound remains conservative without inventing a fat cast result.
const fn nonnull_controls(pointer: usize) -> usize {
    sum(&[
        pointer * 3,           // new_unchecked raw input / NonNull initializer / return
        pointer * 2,           // as_ptr input / raw return
        pointer * 3,           // cast input / transmute raw input / NonNull return
        pointer * 2,           // Unique source field / into NonNull return
        THIN * 2,              // actual NonNull/Unique receiver loans
        THIN,                  // actual NonNull::as_ref receiver
        pointer,               // actual NonNull::as_ref return for CustomOwner outer_drop
        pointer * 2,           // actual raw-pointer is_null/addr inputs
        WORD * 2,              // address return / zero comparison operand
        size_of::<bool>() * 2, // null predicate result / branch guard
    ])
}

// Called only for the two actual callback Box::from_raw_in paths.
const fn unique_new_unchecked_operands(pointer: usize) -> usize {
    sum(&[
        pointer, // actual raw pointer argument
        pointer, // NonNull result -> Unique.pointer field input
        pointer, // actual Unique initializer
        pointer, // actual Unique return
    ])
}

// Called only for actual Box Drop's Unique<T>::cast::<u8>. A fat input may
// become a thin target; the existing NonNull cast uses as_ptr + transmute.
const fn unique_cast_operands(pointer: usize) -> usize {
    sum(&[
        pointer, // Unique<T> self
        THIN,    // target NonNull<u8> -> Unique<u8>.pointer field input
        THIN,    // target Unique<u8> initializer
        THIN,    // target Unique<u8> return
    ])
}

// Same immediate Unique family: actual RawVec allocation constructs Unique
// from NonNull, and each release converts the real Unique back to NonNull.
const UNIQUE_FROM_NONNULL_OPERANDS: usize = THIN * 6;
// From<NonNull> input, from_non_null input, pointer field input, Unique
// initializer, from_non_null return, From return (all actual thin pointers).
const UNIQUE_TO_NONNULL_OPERANDS: usize = THIN * 4;
// From<Unique> input, as_non_null_ptr self, inner NonNull return, From return.

// The actual Global Option::ok_or/Result Try path, before each of four
// allocations returns. Private AllocError's operands are genuine zero fields.
const fn global_option_try_operands() -> usize {
    sum(&[
        size_of::<NonNull<u8>>() * 2, // ok_or Some binding / Ok constructor input
        size_of::<NonNull<u8>>() * 2, // branch Ok binding / Continue constructor input
        size_of::<NonNull<u8>>(),     // caller's ? Continue output binding, before ptr local
        GLOBAL,                       // ok_or None arm's Err owned input
        GLOBAL,                       // branch Err binding
        GLOBAL,                       // branch residual Err constructor input
        ALLOC_RESIDUAL.bytes,         // Break owned input
        ALLOC_RESIDUAL.bytes,         // caller's ? Break residual binding
        GLOBAL,                       // FromResidual Err binding
        GLOBAL,                       // actual identity From input
        GLOBAL,                       // actual identity From return
        GLOBAL,                       // enclosing Err input (no Into edge)
        ALLOC_FAT_RESULT.bytes,       // actual FromResidual Err Result initializer
    ])
}

const fn allocation_controls() -> usize {
    sum(&[
        global_option_try_operands(),
        GLOBAL * 3, // actual Global temporary + two function ITEM arguments (all ZST)
        size_of::<&()>() * 2, // Global::allocate and alloc_impl receivers
        size_of::<Layout>() * 3, // allocate / alloc_impl / runtime arguments
        size_of::<bool>() * 3, // zeroed argument chain (actual false)
        size_of::<(Layout, bool)>() * 2, // caller tuple / const_eval_select ARG
        WORD * 4,   // runtime size / allocator ABI size+alignment / layout size view
        size_of::<*mut u8>() * 2, // allocator ABI return / raw_ptr local
        size_of::<NonNull<u8>>(), // runtime ptr local
        size_of::<Option<NonNull<u8>>>() * 3, // new initializer/return + ok_or input
        ALLOC_THIN_RESULT.bytes * 3, // ok_or initializer/return + Result::branch input
        ALLOC_RESIDUAL.bytes * 2, // branch Break initializer / FromResidual input
        ALLOC_FLOW.bytes * 2, // branch initializer / ControlFlow return
        ALLOC_FAT_RESULT.bytes * 2, // FromResidual/allocator Result return controls
        GLOBAL * 3, // actual AllocError constructor, ok_or argument, conversion payload
        size_of::<NonNull<u8>>() + WORD, // actual cast_slice source pointer and len arguments
        size_of::<*mut [u8]>() * 2, // slice_from_raw_parts_mut initializer / return
        size_of::<NonNull<[u8]>>() * 3, // cast_slice unchecked input/initializer/return
        nonnull_controls(THIN),
        nonnull_controls(size_of::<NonNull<[u8]>>()),
        layout_controls(),
    ])
}

const fn deallocation_controls() -> usize {
    sum(&[
        GLOBAL * 2,                   // actual const/runtime function ITEM arguments (ZST)
        size_of::<&()>() * 2,         // Global::deallocate / deallocate_impl
        size_of::<NonNull<u8>>() * 4, // deallocate / impl / runtime / dealloc_nonnull inputs
        size_of::<Layout>() * 4,      // same four actual arguments
        size_of::<(NonNull<u8>, Layout)>() * 2, // tuple initializer / const_eval_select ARG
        WORD * 3,                     // nonzero check + __rust_dealloc size/alignment ABI
        size_of::<bool>(),
        nonnull_controls(THIN), // actual as_ptr/into raw ABI pointer
        layout_controls(),
    ])
}

const fn box_construction_controls() -> usize {
    sum(&[
        size_of::<Layout>() * 2, // SizedTypeProperties layout / box_new_uninit argument
        size_of::<*mut u8>() * 2, // box_new_uninit return / cast source
        THIN * 3, // actual *mut private T local / write_via_move pointer / transmute input
        ALLOC_FAT_RESULT.bytes, // box_new_uninit match
        size_of::<NonNull<[u8]>>(), // match Ok ptr
        size_of::<*mut u8>(), // actual NonNull<[u8]>::as_mut_ptr returns a thin pointer
        nonnull_controls(size_of::<NonNull<[u8]>>()),
    ])
}

const fn box_raw_transfer_controls(pointee_pointer: usize) -> usize {
    sum(&[
        THIN,                              // &mut ManuallyDrop<Box<T>>
        THIN,                              // &mut MaybeDangling<Box<T>>
        THIN,                              // MaybeDangling::as_mut -> &mut Box<T>
        THIN,                              // ManuallyDrop::deref_mut -> &mut Box<T>
        THIN,                              // Box::deref_mut receiver
        pointee_pointer,                   // actual &mut T result
        pointee_pointer,                   // into_raw *mut T return
        nonnull_controls(pointee_pointer), // caller's NonNull::new_unchecked
    ])
}

const fn box_release_controls(pointee_pointer: usize) -> usize {
    sum(&[
        THIN,                              // &mut Box<T> actual Drop receiver
        pointee_pointer,                   // Unique<T> local ptr
        pointee_pointer,                   // ptr.as_ptr() -> Layout::for_value_raw input
        pointee_pointer,                   // mem::size_of_val_raw input
        pointee_pointer,                   // Alignment::of_val_raw / align_of_val_raw input
        WORD * 2,                          // actual size and alignment intrinsic returns
        SIZE_ALIGNMENT_PAIR.bytes,         // actual for_value_raw pair local
        size_of::<Layout>() * 3, // initializer / from_size_alignment_unchecked / for_value_raw returns
        nonnull_controls(pointee_pointer), // Unique.as_ptr/NonNull.as_ptr
        nonnull_controls(THIN),  // Unique.cast / From<Unique<u8>> / deallocation pointer
        layout_controls(),
    ])
}

const STRING_COPY_CONTROLS: usize = sum(&[
    UNIQUE_FROM_NONNULL_OPERANDS, // actual RawVecInner allocation path
    size_of::<&str>() * 3,        // Into/From<&str>/String::from inputs
    size_of::<&str>(),            // str::to_owned receiver
    size_of::<&[u8]>() * 4,       // ToOwned/to_vec/to_vec_in/ConvertVec receivers
    size_of::<&mut Vec<u8>>(),    // v.as_mut_ptr
    size_of::<&Vec<u8>>(),        // RawVec backing view
    THIN * 4,                     // RawVec/RawVecInner/Unique receiver and as_mut_ptr return
    size_of::<*const u8>(),       // slice.as_ptr source
    size_of::<*mut u8>() * 2,     // v destination / copy_to_nonoverlapping
    WORD * 6,                     // slice len, capacity, set_len and copy count inputs
    size_of::<bool>() * 2,        // len > 0 / needs_to_grow assertion
    size_of::<std::collections::TryReserveError>(), // actual raw allocation error branch input
    RAW_RESULT.bytes,
    size_of::<Result<Layout, LayoutError>>() * 5, // from_size_alignment/repeat_packed/map_err
    size_of::<Result<Layout, std::collections::TryReserveError>>() * 3, // map_err initializer/return, caller match
    size_of::<Option<usize>>(), // actual repeat_packed checked_mul result
    nonnull_controls(THIN),
    layout_controls(),
]);

const MAXIMUM_CAPTURE: FieldBound = FieldBound::record(&[FieldBound::of::<&usize>()]);
const WRITER_CALLABLE_TRY_OPERANDS: usize = sum(&[
    size_of::<&usize>(),                 // actual read-only maximum capture loan
    MAXIMUM_CAPTURE.bytes,               // predicate closure initializer
    MAXIMUM_CAPTURE.bytes,               // Option::filter predicate owned input
    MAXIMUM_CAPTURE.bytes,               // actual FnOnce owned callable receiver
    size_of::<&usize>(),                 // predicate argument -> actual FnOnce tuple field input
    size_of::<(&usize,)>() * 2,          // call tuple initializer / FnOnce args
    size_of::<bool>(),                   // actual predicate return
    size_of::<()>(),                     // capture-free error thunk initializer
    size_of::<()>(),                     // ok_or_else owned thunk operand
    size_of::<()>(),                     // thunk FnOnce owned receiver
    size_of::<()>() * 2,                 // actual unit tuple initializer / FnOnce args
    WORD * 2,                            // Option::filter Some x binding / Some constructor input
    WORD * 2,                            // ok_or_else Some binding / Ok constructor input
    WORD * 2, // io Result::branch Ok binding / Continue constructor input
    WORD,     // caller's ? Continue output binding, before next local
    size_of::<Option<usize>>() * 2, // filter self / ok_or_else self inputs
    size_of::<Option<usize>>() * 2, // filter Some/None initializer / return
    size_of::<io::Result<usize>>() * 2, // ok_or_else Result initializer / return
    size_of::<io::Result<usize>>(), // actual local Try::branch self input
    size_of::<io::Result<Infallible>>(), // actual residual Break owned input
    size_of::<io::Result<Infallible>>(), // caller's ? Break residual binding
    size_of::<io::Result<usize>>() * 2, // FromResidual enclosing Err initializer / return
]);

const TAGGED_ERROR_CONTROLS: usize = sum(&[
    WRITER_CALLABLE_TRY_OPERANDS,
    size_of::<&mut crate::connection::SerializedCreditCounter>(),
    size_of::<&[u8]>(),
    WORD * 5,                           // bytes len/used/maximum/checked operands
    size_of::<&usize>(),                // filter's concrete candidate borrow
    size_of::<Option<usize>>() * 3,     // checked_add/filter/ok_or_else input
    size_of::<bool>(),                  // filter comparison
    size_of::<io::Result<usize>>() * 2, // ok_or_else result / write return
    size_of::<ControlFlow<io::Result<Infallible>, usize>>() * 2, // actual ? branch initializer/return
    size_of::<io::Result<Infallible>>() * 2, // residual initializer / FromResidual input
    size_of::<io::ErrorKind>(),
    size_of::<NonNull<DynError>>(),
    size_of::<fn(*mut DynError)>(),
    size_of::<fn(*mut ())>(),
    THIN * 4, // CustomOwner/from_raw/into_raw and Repr NonNull views
    THIN * 3, // *mut Custom / u8 / tagged () local
    WORD * 3, // addr/tag arithmetic
    size_of::<&io::Error>(),
    size_of::<&mut io::Error>(),
    size_of::<&serde_json::Error>(),
    size_of::<&mut serde_json::Error>(),
    size_of::<Result<(), serde_json::Error>>(),
    size_of::<Result<usize, ProviderError>>(),
    box_raw_transfer_controls(FAT), // original Box<StringError> after dyn unsizing
    box_raw_transfer_controls(THIN), // actual Box<Custom>
    nonnull_controls(THIN),         // CustomOwner raw pointer -> Repr tagged NonNull
]);

const RELEASE_CONTROLS: usize = sum(&[
    UNIQUE_TO_NONNULL_OPERANDS, // actual Box<dyn Error> deallocation conversion
    UNIQUE_TO_NONNULL_OPERANDS, // actual Box<Custom> deallocation conversion
    UNIQUE_TO_NONNULL_OPERANDS, // actual Box<ErrorImpl> deallocation conversion
    UNIQUE_TO_NONNULL_OPERANDS, // actual RawVec current_memory conversion
    THIN * 2,                   // RawVec .into(): blanket Into self input / return around From
    unique_new_unchecked_operands(THIN), // callback Box<Custom>::from_raw_in
    unique_new_unchecked_operands(FAT), // callback Box<dyn Error>::from_raw_in
    unique_cast_operands(FAT),  // actual dyn StringError Box Drop
    unique_cast_operands(THIN), // actual Custom Box Drop
    unique_cast_operands(THIN), // actual ErrorImpl Box Drop
    THIN * 2,                   // actual ErrorImpl/ErrorCode Drop glue pointer arguments
    THIN,                       // &mut Repr
    THIN,                       // &mut CustomOwner
    THIN,                       // &Custom from NonNull::as_ref for outer callback
    THIN,                       // &mut Custom
    FAT,                        // actual *mut dyn Error callback argument
    THIN,                       // actual *mut Custom callback argument
    size_of::<fn(*mut DynError)>(),
    size_of::<fn(*mut ())>(),
    THIN * 4, // decode_repr pointer/bits/tag/custom views (zero-capture closure is ZST)
    WORD * 2, // decode_repr bits / tag operations
    // Box::from_raw[_in] -> Unique::new_unchecked and the two callbacks.
    nonnull_controls(FAT),
    nonnull_controls(THIN),
    THIN * 2, // &mut StringError / &mut String
    size_of::<&mut Vec<u8>>(),
    size_of::<*mut [u8]>(), // Vec drop_in_place slice
    THIN * 2,               // RawVec/RawVecInner Drop receivers
    size_of::<(NonNull<u8>, Layout)>(),
    size_of::<Option<(NonNull<u8>, Layout)>>() * 2, // current_memory initializer / return
    size_of::<Layout>() * 2,
    WORD * 4,              // cap/element bytes/alloc_size/unchecked multiply
    WORD * 4,              // two actual Cap::as_inner inputs and scalar returns
    size_of::<bool>() * 3, // actual size/cap/nonzero predicates
    nonnull_controls(THIN),
    layout_controls(),
    box_release_controls(FAT), // actual Box<dyn Error> releases StringError allocation
    box_release_controls(THIN), // actual Box<Custom>
    box_release_controls(THIN), // actual Box<serde ErrorImpl>, independently named
]);

const RUNTIME_CONTROLS: usize = sum(&[
    STRING_COPY_CONTROLS,
    TAGGED_ERROR_CONTROLS,
    RELEASE_CONTROLS,
    // Four independent allocations and releases: byte Vec, StringError,
    // Custom, ErrorImpl. Sequential control windows are conservatively summed.
    allocation_controls(),
    allocation_controls(),
    allocation_controls(),
    allocation_controls(),
    deallocation_controls(),
    deallocation_controls(),
    deallocation_controls(),
    deallocation_controls(),
    box_construction_controls(), // StringError
    box_construction_controls(), // Custom
    box_construction_controls(), // ErrorImpl
]);

const CONSTRUCTION: (usize, usize) = (
    add(BACKING, OWNED_CONSTRUCTION),
    add(QUOTE_CONTROLS, RUNTIME_CONTROLS),
);
const TOTAL: usize = add(CONSTRUCTION.0, CONSTRUCTION.1);

/// Shares the original upper launch accounting without granting execution.
///
/// Implementations report storage DATA only; callers retain original admission
/// and parent process/thread/Source custody independently.
pub trait PacketNative5SerializedCreditFailureStorage {
    /// Quotes the original credit error's temporary backing, returns and views.
    ///
    /// The concrete static-string error and its legacy cleanup are priced
    /// independently. Original inputs, formatter/serializer/propagation work,
    /// Path errors and later validation remain the caller's separate duties.
    /// This component grants no parsing, allocation or native operation.
    ///
    /// # Errors
    /// Refuses another pinned geometry or insufficient whole-component credit.
    /// All fixed geometry arithmetic was evaluated at compile time; maximum
    /// is only a restriction and is never substituted for demand.
    fn original_import18_serialized_credit_failure_construction_data(
        maximum: usize,
    ) -> Result<(usize, usize), ProviderError>;
}

impl PacketNative5SerializedCreditFailureStorage for PacketNative5SourceLaunch {
    /// Quotes the original credit error's temporary backing, returns and views.
    ///
    /// The concrete static-string error and its legacy cleanup are priced
    /// independently. Original inputs, formatter/serializer/propagation work,
    /// Path errors and later validation remain the caller's separate duties.
    /// This component grants no parsing, allocation or native operation.
    ///
    /// # Errors
    /// Refuses another pinned geometry or insufficient whole-component credit.
    /// All fixed geometry arithmetic was evaluated at compile time; maximum
    /// is only a restriction and is never substituted for demand.
    fn original_import18_serialized_credit_failure_construction_data(
        maximum: usize,
    ) -> Result<(usize, usize), ProviderError> {
        if !SUPPORTED_PROFILE || maximum < TOTAL {
            return Err(ProviderError::ResourceExhausted(
                "original serialized-credit error construction",
            ));
        }
        Ok(CONSTRUCTION)
    }
}

/// Names this concrete component's fixed runtime admission controls.
pub const fn original_import18_serialized_credit_failure_counter_scratch_data() -> usize {
    QUOTE_CONTROLS
}
