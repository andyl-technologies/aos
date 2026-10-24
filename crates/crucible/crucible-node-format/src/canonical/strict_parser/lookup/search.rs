//! Accounts for the immutable map's actual iterative search and terminal paths.
//!
//! Private records use field-derived bounds from geometry, never layout casts.
//! Each named operation includes its distinct owned input, variant operand,
//! initializer and return. Borrowed/scalar controls live in S. The loops reuse
//! their own fixed windows; search_tree descends iteratively, and each leaf's
//! bounded key iterator is finished or discarded before the next node search.
//! No successful child Value is opened, copied, traversed or retired here.

use super::{geometry::*, total};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    iter::Enumerate,
    mem::{MaybeUninit, size_of},
    ops::{ControlFlow, Range, RangeFrom, RangeTo},
    ptr::NonNull,
    slice::Iter,
};

// Option<&Root>::as_ref -> Try::branch -> immutable reborrow; both the rootless
// early return and the eventual leaf-edge miss return actual Option<&Value>.
const GET_T: usize = total([
    REFERENCE,                       // as_ref Some owned root-reference operand
    OPTION_ROOT_REFERENCE,           // as_ref Some initializer
    OPTION_ROOT_REFERENCE,           // as_ref None initializer
    OPTION_ROOT_REFERENCE,           // as_ref return
    OPTION_ROOT_REFERENCE,           // Try::branch owned input
    REFERENCE,                       // Some root binding
    REFERENCE,                       // Continue owned root-reference operand
    ROOT_OPTION_FLOW,                // Continue initializer
    ROOT_OPTION_FLOW,                // branch return / caller match value
    size_of::<Option<Infallible>>(), // branch None residual initializer
    size_of::<Option<Infallible>>(), // Break owned residual operand
    ROOT_OPTION_FLOW,                // Break initializer
    size_of::<Option<Infallible>>(), // caller Break binding
    size_of::<Option<Infallible>>(), // FromResidual owned input
    size_of::<Option<&Value>>(),     // FromResidual None initializer
    size_of::<Option<&Value>>(),     // FromResidual return
    NODE,                            // root reborrow initializer
    NODE,                            // root reborrow return / get root_node
    SEARCH_RESULT,                   // get's search_tree return
    HANDLE,                          // get Found binding
    HANDLE,                          // into_kv owned receiver
    size_of::<(&String, &Value)>(),  // into_kv tuple initializer
    size_of::<(&String, &Value)>(),  // into_kv return / get projection
    size_of::<&Value>(),             // Some owned value-reference operand
    size_of::<Option<&Value>>(),     // found Some initializer
    size_of::<Option<&Value>>(),     // get return
    HANDLE,                          // GoDown leaf-edge match payload, including missing key
    size_of::<Option<&Value>>(),     // missing key None initializer
    size_of::<bool>(),               // Option::is_some return
    size_of::<bool>(),               // BTreeMap::contains_key return
    size_of::<bool>(),               // serde Map::contains_key return
]);

const GET_S: usize = total([
    size_of::<&Map<String, Value>>(),      // serde receiver
    size_of::<&String>(),                  // serde query loan
    size_of::<&BTreeMap<String, Value>>(), // BTreeMap contains_key receiver
    size_of::<&String>(),                  // BTreeMap contains_key query
    size_of::<&BTreeMap<String, Value>>(), // get receiver
    size_of::<&String>(),                  // get query
    REFERENCE,                             // Option<Root>::as_ref receiver
    REFERENCE,                             // as_ref's Some Root binding
    REFERENCE,                             // root NodeRef::reborrow receiver
    size_of::<&String>(),                  // search_tree query loan
    size_of::<&Option<&Value>>(),          // is_some receiver
]);

// NodeRef::search_tree -> search_node -> find_key_index, followed by force and
// descend on a real internal edge. Found and leaf-edge GoDown each retain their
// actual typed handle; the latter is not an Option and is not an empty payload.
const SEARCH_T: usize = total([
    NODE,          // search_tree owned self
    NODE,          // search_node owned self
    NODE,          // find_key_index reborrow initializer
    NODE,          // find_key_index reborrow return / node local
    INDEX_RESULT,  // KV/Edge variant initializer
    INDEX_RESULT,  // find_key_index return
    NODE,          // new_kv node owned input
    HANDLE,        // new_kv Handle initializer
    HANDLE,        // new_kv return
    HANDLE,        // search_node Found owned operand
    SEARCH_RESULT, // search_node Found initializer
    NODE,          // new_edge node owned input
    HANDLE,        // new_edge Handle initializer
    HANDLE,        // new_edge return
    HANDLE,        // search_node GoDown owned operand
    SEARCH_RESULT, // search_node GoDown initializer
    SEARCH_RESULT, // search_node return / search_tree match
    HANDLE,        // search_tree Found binding
    HANDLE,        // final Found owned operand
    SEARCH_RESULT, // final Found initializer
    HANDLE,        // search_tree GoDown binding
    HANDLE,        // Handle::force owned self
    NODE,          // NodeRef::force owned self
    NODE,          // NodeRef::force Leaf node initializer
    NODE,          // NodeRef::force Leaf owned operand
    FORCE_NODE,    // NodeRef::force Leaf initializer
    NODE,          // NodeRef::force Internal node initializer
    NODE,          // NodeRef::force Internal owned operand
    FORCE_NODE,    // NodeRef::force Internal initializer
    FORCE_NODE,    // NodeRef::force return / Handle::force match
    NODE,          // force Leaf binding
    HANDLE,        // force Leaf Handle initializer
    HANDLE,        // force Leaf owned operand
    FORCE_HANDLE,  // force Leaf variant initializer
    NODE,          // force Internal binding
    HANDLE,        // force Internal Handle initializer
    HANDLE,        // force Internal owned operand
    FORCE_HANDLE,  // force Internal variant initializer
    FORCE_HANDLE,  // Handle::force return / search_tree match
    HANDLE,        // force Leaf binding in search_tree
    HANDLE,        // terminal GoDown owned leaf-edge operand
    SEARCH_RESULT, // terminal GoDown initializer
    SEARCH_RESULT, // search_tree return
    HANDLE,        // force Internal binding in search_tree
    HANDLE,        // descend owned edge self
    POINTER,       // assume_init_read child node pointer return / binding
    NODE,          // descend NodeRef initializer
    NODE,          // descend return / loop self replacement
]);

const SEARCH_S: usize = total([
    size_of::<&String>(), // search_node key
    REFERENCE,            // find_key_index self
    size_of::<&String>(), // find_key_index key
    size_of::<usize>(),   // start_index input
    REFERENCE,            // NodeRef::reborrow self
    size_of::<usize>(),   // copied height
    POINTER,              // copied node pointer
    size_of::<usize>(),   // KV/Edge idx match binding
    size_of::<usize>(),   // new_kv idx argument
    REFERENCE,            // new_kv debug len receiver
    size_of::<usize>(),   // new_kv len / comparison
    size_of::<bool>(),    // new_kv valid-index check
    size_of::<usize>(),   // new_edge idx argument
    REFERENCE,            // new_edge debug len receiver
    size_of::<usize>(),   // new_edge len / comparison
    size_of::<bool>(),    // new_edge valid-index check
    size_of::<bool>(),    // node force height ==0
    size_of::<usize>(),   // force node copied height
    POINTER,              // force node copied pointer
    size_of::<usize>(),   // force handle copied idx
    REFERENCE,            // as_internal_ptr NodeRef receiver
    POINTER,              // as_internal_ptr NonNull::as_ptr owned receiver
    POINTER,              // NonNull::as_ptr return
    POINTER,              // cast internal pointer / parent_ptr
    POINTER,              // internal edges array loan
    POINTER,              // internal edges array coerced slice data pointer
    size_of::<usize>(),   // concrete edge array length 12 metadata
    size_of::<usize>(),   // get_unchecked edge idx
    POINTER,              // get_unchecked edge pointer
    REFERENCE,            // get_unchecked MaybeUninit<NodePtr> loan
    REFERENCE,            // assume_init_read receiver
    POINTER,              // assume_init_read cast pointer
    POINTER,              // ptr::read source pointer
    POINTER,              // ptr::read returned child NonNull value
    size_of::<usize>(),   // child height subtraction left
    size_of::<usize>(),   // child height subtraction right/one
    size_of::<usize>(),   // child height initializer
]);

// keys() and into_kv() share an immutable leaf-loan operation, but have distinct
// caller windows here. No whole LeafNode or initialized key/value array is
// copied: array references and initialized prefixes are the actual operands.
const LEAF_T: usize = total([
    NODE,                                // keys' implicit Copy receiver for into_leaf
    REFERENCE,                           // keys into_leaf return
    size_of::<&[MaybeUninit<String>]>(), // keys RangeTo selected prefix return
    size_of::<&[String]>(),              // keys assume_init_ref return
    size_of::<&[String]>(),              // keys return / find_key_index keys binding
    NODE,                                // into_kv moved node into_leaf input
    REFERENCE,                           // into_kv into_leaf return
    size_of::<&MaybeUninit<String>>(),   // key get_unchecked return
    size_of::<&String>(),                // key assume_init_ref return
    size_of::<&MaybeUninit<Value>>(),    // value get_unchecked return
    size_of::<&Value>(),                 // value assume_init_ref return
]);

const LEAF_S: usize = total([
    REFERENCE,                                 // keys NodeRef receiver
    REFERENCE,                                 // keys into_leaf as_leaf_ptr receiver
    POINTER,                                   // keys NonNull::as_ptr owned receiver
    POINTER,                                   // keys NonNull::as_ptr return
    POINTER,                                   // keys as_leaf_ptr return / local
    REFERENCE,                                 // leaf binding
    size_of::<&[MaybeUninit<String>; 11]>(),   // actual leaf keys array loan
    size_of::<&[MaybeUninit<String>]>(),       // array unsize / get_unchecked receiver
    size_of::<u16>(),                          // leaf len field
    size_of::<usize>(),                        // usize::from input conversion output
    size_of::<RangeTo<usize>>(),               // keys prefix index owned input
    size_of::<usize>(),                        // RangeTo end binding
    size_of::<*const [MaybeUninit<String>]>(), // prefix raw slice receiver
    size_of::<*const MaybeUninit<String>>(),   // prefix data pointer
    size_of::<usize>(),                        // prefix metadata length
    size_of::<*const [MaybeUninit<String>]>(), // prefix raw slice return
    size_of::<&[MaybeUninit<String>]>(),       // assume_init_ref receiver
    size_of::<*const [MaybeUninit<String>]>(), // initialization cast input
    size_of::<*const [String]>(),              // initialization cast result
    REFERENCE,                                 // into_kv node len receiver
    REFERENCE,                                 // len as_leaf_ptr receiver
    POINTER,                                   // len NonNull as_ptr input
    POINTER,                                   // len pointer return
    size_of::<u16>(),                          // len field read
    size_of::<usize>(),                        // len conversion return
    size_of::<bool>(),                         // into_kv idx < len
    REFERENCE,                                 // into_kv as_leaf_ptr receiver
    POINTER,                                   // into_kv NonNull as_ptr input
    POINTER,                                   // into_kv pointer return
    REFERENCE,                                 // into_kv leaf binding
    size_of::<&[MaybeUninit<String>; 11]>(),   // into_kv key array loan
    size_of::<&[MaybeUninit<String>]>(),       // key array unsize
    size_of::<usize>(),                        // key unchecked idx input
    size_of::<*const [MaybeUninit<String>]>(), // key raw slice input
    size_of::<*const MaybeUninit<String>>(),   // key data ptr + idx result
    size_of::<&MaybeUninit<String>>(),         // key assume_init_ref receiver
    size_of::<*const MaybeUninit<String>>(),   // key cast input
    size_of::<*const String>(),                // key cast result
    size_of::<&String>(),                      // into_kv k binding
    size_of::<&[MaybeUninit<Value>; 11]>(),    // into_kv value array loan
    size_of::<&[MaybeUninit<Value>]>(),        // value array unsize
    size_of::<usize>(),                        // value unchecked idx input
    size_of::<*const [MaybeUninit<Value>]>(),  // value raw slice input
    size_of::<*const MaybeUninit<Value>>(),    // value data ptr + idx result
    size_of::<&MaybeUninit<Value>>(),          // value assume_init_ref receiver
    size_of::<*const MaybeUninit<Value>>(),    // value cast input
    size_of::<*const Value>(),                 // value cast result
    size_of::<&Value>(),                       // into_kv v binding
]);

// Includes the final None next, Option's actual residual branch, and both
// initializer and return for the tuple/Some constructors. An actual String
// occupies 24 bytes, so the iterator's ZST-only branch is unreachable here.
const ITER_T: usize = total([
    size_of::<&[String]>(),             // RangeFrom get_unchecked return
    size_of::<Iter<'static, String>>(), // Iter::new initializer
    size_of::<Iter<'static, String>>(), // Iter::new return / iter return
    size_of::<Iter<'static, String>>(), // enumerate owned iter argument
    size_of::<Enumerate<Iter<'static, String>>>(), // Enumerate::new initializer
    size_of::<Enumerate<Iter<'static, String>>>(), // Enumerate::new return
    size_of::<Enumerate<Iter<'static, String>>>(), // into_iter owned input
    size_of::<Enumerate<Iter<'static, String>>>(), // identity into_iter return
    size_of::<&String>(),               // Iter::next Some owned operand
    size_of::<Option<&String>>(),       // Iter::next Some initializer
    size_of::<Option<&String>>(),       // Iter::next final None initializer
    size_of::<Option<&String>>(),       // Iter::next return
    size_of::<Option<&String>>(),       // enumerate Try::branch owned input
    size_of::<&String>(),               // Try Some binding
    size_of::<&String>(),               // Continue owned operand
    size_of::<ControlFlow<Option<Infallible>, &String>>(), // Continue initializer
    size_of::<Option<Infallible>>(),    // final next None residual initializer
    size_of::<Option<Infallible>>(),    // Break owned residual operand
    size_of::<ControlFlow<Option<Infallible>, &String>>(), // Break initializer
    size_of::<ControlFlow<Option<Infallible>, &String>>(), // branch return
    size_of::<Option<Infallible>>(),    // caller Break binding
    size_of::<Option<Infallible>>(),    // FromResidual input
    size_of::<Option<(usize, &String)>>(), // FromResidual None initializer
    size_of::<Option<(usize, &String)>>(), // FromResidual return
    size_of::<&String>(),               // caller Continue binding / a local
    size_of::<(usize, &String)>(),      // enumeration tuple initializer
    size_of::<(usize, &String)>(),      // Some owned tuple operand
    size_of::<Option<(usize, &String)>>(), // Some initializer
    size_of::<Option<(usize, &String)>>(), // Enumerate::next return
    size_of::<(usize, &String)>(),      // for-loop Some tuple binding
    INDEX_RESULT,                       // Equal KV variant initializer
    INDEX_RESULT,                       // Less Edge variant initializer
    INDEX_RESULT,                       // exhausted Edge variant initializer
]);

const ITER_S: usize = total([
    size_of::<RangeFrom<usize>>(),  // suffix index input
    size_of::<&[String]>(),         // suffix get_unchecked receiver
    size_of::<usize>(),             // suffix start
    size_of::<*const [String]>(),   // suffix raw slice input
    size_of::<*const String>(),     // suffix data ptr
    size_of::<usize>(),             // suffix length
    size_of::<usize>(),             // suffix new length subtraction
    size_of::<*const String>(),     // suffix data add output
    size_of::<*const [String]>(),   // suffix raw slice output
    size_of::<&[String]>(),         // slice iter receiver
    size_of::<&[String]>(),         // Iter::new receiver
    size_of::<usize>(),             // Iter::new len
    size_of::<NonNull<[String]>>(), // NonNull::from_ref return
    size_of::<NonNull<[String]>>(), // NonNull::cast owned self
    size_of::<NonNull<String>>(),   // cast return / ptr local
    size_of::<NonNull<String>>(),   // as_ptr owned input
    size_of::<*mut String>(),       // as_ptr return
    size_of::<*const String>(),     // Iter::new end pointer
    size_of::<usize>(),             // Enumerate::new initial count
    size_of::<&mut Enumerate<Iter<'static, String>>>(), // for-loop next receiver
    size_of::<&mut Iter<'static, String>>(), // inner Iter::next receiver
    size_of::<NonNull<String>>(),   // next ptr local
    size_of::<*const String>(),     // next end local
    size_of::<NonNull<String>>(),   // end transmute pointer value
    size_of::<bool>(),              // next ptr == end
    size_of::<NonNull<String>>(),   // ptr.add owned receiver
    size_of::<usize>(),             // ptr.add increment input
    size_of::<NonNull<String>>(),   // ptr.add output / updated self.ptr
    size_of::<&NonNull<String>>(),  // ptr.as_ref receiver
    size_of::<&String>(),           // ptr.as_ref return
    size_of::<usize>(),             // enumerate i binding
    size_of::<usize>(),             // enumerate count addition left
    size_of::<usize>(),             // enumerate count addition one/right
    size_of::<usize>(),             // enumerate count updated value
    size_of::<usize>(),             // offset binding
    size_of::<&String>(),           // k binding
    size_of::<bool>(),              // start_index <= keys.len
    size_of::<usize>(),             // keys.len metadata / exhausted Edge index
    size_of::<usize>(),             // start_index + offset left
    size_of::<usize>(),             // start_index + offset right
    size_of::<usize>(),             // returned KV/Edge computed index
]);

// Per concrete range helper: get_offset_len_noubcheck owns no elements.
// Both prefix MaybeUninit<String> and suffix String slices have their own row.
const fn offset_slice_s<T>() -> usize {
    total([
        size_of::<*const [T]>(), // get_offset_len_noubcheck ptr input
        size_of::<usize>(),      // offset input
        size_of::<usize>(),      // len input
        size_of::<*const T>(),   // cast data pointer / local
        size_of::<*const T>(),   // offset intrinsic pointer input
        size_of::<usize>(),      // offset intrinsic count input
        size_of::<*const T>(),   // offset intrinsic return
        size_of::<*const T>(),   // aggregate_raw_ptr pointer input
        size_of::<usize>(),      // aggregate_raw_ptr len input
        size_of::<*const [T]>(), // aggregate_raw_ptr output
        size_of::<*const [T]>(), // helper return
    ])
}

const DIRECT_T: usize = total([
    REFERENCE, // get's successful Continue root binding before reborrow
    size_of::<Iter<'static, String>>(), // slice::iter return, distinct from new
    size_of::<Iter<'static, String>>(), // Enumerate::new owned iter input
    size_of::<Enumerate<Iter<'static, String>>>(), // Iterator::enumerate return
]);

const DIRECT_S: usize = total([
    size_of::<&[String]>(),       // NonNull::from_ref slice input
    size_of::<*mut [String]>(),   // NonNull::cast inner as_ptr return
    size_of::<*mut String>(),     // NonNull::cast thin pointer cast output
    size_of::<NonNull<String>>(), // NonNull::cast transmute initializer
    size_of::<*mut String>(),     // NonNull::as_ref cast_const receiver
    size_of::<*const String>(),   // NonNull::as_ref cast_const return
]);

// Iter::next's NonNull PartialEq is a distinct helper from its later
// NonNull::as_ref. Iter::new's raw add is likewise named independently of
// NonNull::add in next; no sequential-reuse or spare-row donation is assumed.
const ITER_HELPER_S: usize = total([
    size_of::<&NonNull<String>>(),  // PartialEq::eq self receiver
    size_of::<&NonNull<String>>(),  // PartialEq::eq other receiver
    size_of::<NonNull<String>>(),   // eq self.as_ptr owned-copy input
    size_of::<*mut String>(),       // eq self.as_ptr return
    size_of::<NonNull<String>>(),   // eq other.as_ptr owned-copy input
    size_of::<*mut String>(),       // eq other.as_ptr return
    size_of::<bool>(),              // NonNull::PartialEq::eq return
    size_of::<*const [String]>(),   // from_ref reference-to-pointer cast output
    size_of::<*const [String]>(),   // from_ref transmute owned pointer input
    size_of::<NonNull<[String]>>(), // from_ref transmute output
    size_of::<*mut String>(),       // Iter::new raw pointer add owned receiver
    size_of::<usize>(),             // Iter::new raw pointer add count input
    size_of::<*mut String>(),       // Iter::new raw pointer add return
]);

// The actual raw *mut String::add used in Iter::new has a debug-only
// runtime_add_nowrap check. Its arithmetic executes even when the actual
// immutable slice proves refusal impossible. Include it without restricting
// DATA to release builds or importing the unreachable panic implementation.
const RAW_ADD_CHECK_S: usize = total([
    size_of::<*const ()>(), // self as *const () precondition argument
    size_of::<usize>(),     // precondition count argument
    size_of::<usize>(),     // precondition String size argument
    size_of::<*const ()>(), // runtime_add_nowrap this input
    size_of::<usize>(),     // runtime_add_nowrap count input
    size_of::<usize>(),     // runtime_add_nowrap size input
    size_of::<(*const (), usize, usize)>(), // const_eval_select capture initializer
    size_of::<(*const (), usize, usize)>(), // intrinsic owned capture tuple input
    0,                      // actual compiletime function item, zero-sized, no captures
    0,                      // actual runtime function item, zero-sized, tuple carries captures
    size_of::<*const ()>(), // runtime branch this binding
    size_of::<usize>(),     // runtime branch count binding
    size_of::<usize>(),     // runtime branch size binding
    size_of::<usize>(),     // checked_mul owned self
    size_of::<usize>(),     // checked_mul rhs
    size_of::<usize>(),     // overflowing_mul owned self
    size_of::<usize>(),     // overflowing_mul rhs
    size_of::<u64>(),       // mul_with_overflow self-as-ActualT cast output
    size_of::<u64>(),       // mul_with_overflow rhs-as-ActualT cast output
    size_of::<u64>(),       // mul_with_overflow x argument
    size_of::<u64>(),       // mul_with_overflow y argument
    size_of::<(u64, bool)>(), // mul_with_overflow intrinsic return
    size_of::<u64>(),       // overflowing_mul a binding
    size_of::<bool>(),      // overflowing_mul b binding
    size_of::<usize>(),     // overflowing_mul a-as-Self cast output
    size_of::<usize>(),     // overflowing_mul tuple owned numeric operand
    size_of::<bool>(),      // overflowing_mul tuple owned bool operand
    size_of::<(usize, bool)>(), // overflowing_mul tuple initializer
    size_of::<(usize, bool)>(), // overflowing_mul return
    size_of::<usize>(),     // checked_mul a binding
    size_of::<bool>(),      // checked_mul b binding
    size_of::<bool>(),      // unlikely argument
    size_of::<bool>(),      // unlikely return
    size_of::<usize>(),     // checked_mul Some owned operand
    size_of::<Option<usize>>(), // checked_mul Some initializer
    size_of::<Option<usize>>(), // checked_mul return
    size_of::<usize>(),     // runtime byte_offset Some binding
    size_of::<*const ()>(), // this.addr owned receiver
    size_of::<*const ()>(), // addr inner cast receiver
    size_of::<*const ()>(), // addr inner cast return
    size_of::<*const ()>(), // addr transmute pointer argument
    size_of::<usize>(),     // addr transmute output
    size_of::<usize>(),     // addr return
    size_of::<usize>(),     // overflowing_add owned self
    size_of::<usize>(),     // overflowing_add rhs byte_offset
    size_of::<u64>(),       // add_with_overflow self-as-ActualT cast output
    size_of::<u64>(),       // add_with_overflow rhs-as-ActualT cast output
    size_of::<u64>(),       // add_with_overflow x argument
    size_of::<u64>(),       // add_with_overflow y argument
    size_of::<(u64, bool)>(), // add_with_overflow intrinsic return
    size_of::<u64>(),       // overflowing_add a binding
    size_of::<bool>(),      // overflowing_add b binding
    size_of::<usize>(),     // overflowing_add a-as-Self cast output
    size_of::<usize>(),     // overflowing_add tuple owned numeric operand
    size_of::<bool>(),      // overflowing_add tuple owned bool operand
    size_of::<(usize, bool)>(), // overflowing_add tuple initializer
    size_of::<(usize, bool)>(), // overflowing_add return
    size_of::<bool>(),      // runtime overflow binding
    size_of::<isize>(),     // isize::MAX source value
    size_of::<usize>(),     // isize::MAX cast to usize
    size_of::<usize>(),     // <= byte_offset input
    size_of::<bool>(),      // <= result
    size_of::<bool>(),      // !overflow result
    size_of::<bool>(),      // runtime && result
    size_of::<bool>(),      // runtime function return
    size_of::<bool>(),      // const_eval_select return
    size_of::<bool>(),      // runtime_add_nowrap return
    size_of::<bool>(),      // precondition negation result
    size_of::<*mut String>(), // final offset intrinsic pointer input
    size_of::<usize>(),     // final offset intrinsic count input
    size_of::<*mut String>(), // final offset intrinsic return
]);

// check_language_ub is the same nonrecursive boolean helper for the sequential
// slice-index and raw-add preconditions. Its own row is explicitly shared;
// their distinct caller controls remain in RANGE_S and RAW_ADD_CHECK_S.
const LANGUAGE_UB_S: usize = total([
    size_of::<()>(),   // const_eval_select empty capture tuple initializer
    size_of::<()>(),   // intrinsic empty capture tuple input
    0,                 // actual compiletime function item
    0,                 // actual runtime function item
    size_of::<bool>(), // runtime !cfg!(miri) result
    size_of::<bool>(), // runtime function return
    size_of::<bool>(), // const_eval_select return
    size_of::<bool>(), // ub_checks intrinsic return
    size_of::<bool>(), // conjunction result
    size_of::<bool>(), // check_language_ub return
]);

// The RangeTo and RangeFrom SliceIndex implementations each delegate to an
// actual Range<usize> before unchecked offset/length construction. No range
// failure constructor is reached for an immutable safe map's valid prefixes.
const RANGE_S: usize = total([
    size_of::<Range<usize>>(),     // delegated prefix Range initializer
    size_of::<Range<usize>>(),     // delegated prefix Range owned input
    size_of::<Range<usize>>(),     // delegated suffix Range initializer
    size_of::<Range<usize>>(),     // delegated suffix Range owned input
    size_of::<usize>(),            // prefix precondition start
    size_of::<usize>(),            // prefix precondition end
    size_of::<usize>(),            // prefix precondition len
    size_of::<bool>(),             // prefix end >=start
    size_of::<bool>(),             // prefix end <=len
    size_of::<bool>(),             // prefix combined valid range
    size_of::<usize>(),            // prefix unchecked_sub end input
    size_of::<usize>(),            // prefix unchecked_sub start input
    size_of::<usize>(),            // prefix computed new_len
    size_of::<usize>(),            // suffix precondition start
    size_of::<usize>(),            // suffix precondition end
    size_of::<usize>(),            // suffix precondition len
    size_of::<bool>(),             // suffix end >=start
    size_of::<bool>(),             // suffix end <=len
    size_of::<bool>(),             // suffix combined valid range
    size_of::<usize>(),            // suffix unchecked_sub end input
    size_of::<usize>(),            // suffix unchecked_sub start input
    size_of::<usize>(),            // suffix computed new_len
    size_of::<bool>(),             // range check_library_ub control
    size_of::<bool>(),             // single-index check_language_ub control
    size_of::<usize>(),            // single-index precondition index
    size_of::<usize>(),            // single-index precondition len
    size_of::<bool>(),             // single-index index < len
    size_of::<bool>(),             // single-index intrinsic assume argument
    size_of::<usize>(),            // edge slice_get_unchecked index input
    POINTER,                       // edge slice_get_unchecked data pointer input
    POINTER,                       // edge slice_get_unchecked returned pointer
    size_of::<*mut String>(),      // NonNull::add internal as_ptr output
    size_of::<usize>(),            // NonNull::add offset intrinsic count
    size_of::<*mut String>(),      // NonNull::add offset intrinsic return
    size_of::<NonNull<String>>(),  // NonNull::add return initializer
    size_of::<&NonNull<String>>(), // NonNull::as_ref receiver
    size_of::<NonNull<String>>(),  // NonNull::as_ref as_ptr owned input
    size_of::<*mut String>(),      // NonNull::as_ref as_ptr output
]);

pub(super) const TRANSIENT: usize = total([GET_T, SEARCH_T, LEAF_T, ITER_T, DIRECT_T]);
pub(super) const SCRATCH: usize = total([
    GET_S,
    SEARCH_S,
    LEAF_S,
    ITER_S,
    RANGE_S,
    DIRECT_S,
    offset_slice_s::<MaybeUninit<String>>(),
    offset_slice_s::<String>(),
    ITER_HELPER_S,
    RAW_ADD_CHECK_S,
    LANGUAGE_UB_S,
]);
