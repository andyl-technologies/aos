//! Declares forward owning-map iteration and drained-only destruction controls.
//!
//! This is the actual `for (_, child) in values` path. It excludes next_back,
//! collections, recursive Value drop and dropping an iterator with unread
//! children. The caller must keep all yielded Values in its reserved workspace.

use super::{layouts::*, nodes, total};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, btree_map::IntoIter},
    mem::{ManuallyDrop, MaybeUninit, size_of},
};

type Tree = BTreeMap<String, Value>;
type TreeIter = IntoIter<String, Value>;
type JsonIter = serde_json::map::IntoIter;

// serde_json/map.rs1099-1121 -> map.rs1879-1901. The actual ManuallyDrop
// initializer uses transparent MaybeDangling and never clones the map.
const INTO_T: usize = total([
    size_of::<Map<String, Value>>(), // serde into_iter owned self
    size_of::<Tree>(),               // BTreeMap into_iter owned self
    size_of::<Tree>(),               // ManuallyDrop::new owned input
    size_of::<Tree>(),               // MaybeDangling::new owned input
    size_of::<Tree>(),               // transparent MaybeDangling return
    size_of::<ManuallyDrop<Tree>>(), // ManuallyDrop constructor return
    size_of::<ManuallyDrop<Tree>>(), // into_iter me local
    OPTIONAL_ROOT,                   // me.root.take return
    NODE,                            // Some(root) local
    NODE,
    NODE, // Root::into_dying input / return
    NODE, // dying full_range owned argument
    NODE, // full_range ptr::read duplicate root
    NODE,
    NODE, // free full_range two owned arguments
    LAZY_HANDLE,
    LAZY_HANDLE, // initialized Root endpoints
    OPTIONAL_LAZY_HANDLE,
    OPTIONAL_LAZY_HANDLE,  // initialized Some endpoints
    LAZY_RANGE,            // free full_range return
    LAZY_RANGE,            // dying full_range return
    LAZY_RANGE,            // full_range local
    LAZY_RANGE,            // none() return in empty branch
    size_of::<TreeIter>(), // BTreeMap IntoIter return
    size_of::<JsonIter>(), // serde IntoIter return
    size_of::<JsonIter>(), // for-loop owned iterator
]);
const INTO_S: usize = total([
    size_of::<&mut ManuallyDrop<Tree>>(), // deref_mut receiver
    POINTER,                              // MaybeDangling::as_mut receiver
    size_of::<&mut Tree>(),               // inner loan
    size_of::<&mut Tree>(),               // outer deref_mut return
    POINTER,                              // Option<Root>::take receiver
    OPTIONAL_ROOT,                        // mem::replace None input
    OPTIONAL_ROOT,                        // ptr::read old root envelope
    POINTER,                              // ptr::write root None destination
    POINTER,                              // full_range ptr::read root argument
    size_of::<&ManuallyDrop<Tree>>(),     // length read deref receiver
    POINTER,                              // MaybeDangling::as_ref receiver
    size_of::<&Tree>(),                   // inner as_ref return
    size_of::<&Tree>(),                   // deref return
    WORD,                                 // copied length
    POINTER,                              // ManuallyDrop::take fieldless Global receiver
    size_of::<()>(),                      // Global owned returns/PhantomData
    size_of::<bool>(),                    // root presence branch
]);

// serde delegated next -> map.rs1932-1944,1963-1965. Every Some tuple
// immediately transfers ownership to the caller; no Value destructor is run.
const NEXT_T: usize = total([
    OPTIONAL_HANDLE, // dying_next return
    HANDLE,          // deallocating_next returned dying KV
    OPTIONAL_HANDLE, // Option::map input
    HANDLE,          // map closure owned argument
    HANDLE,          // into_key_val owned self
    KEY,
    VALUE, // assume_init_read returns
    KEY,
    VALUE,                                // key/val locals
    KEY_VALUE,                            // into_key_val returned tuple
    KEY_VALUE,                            // Option::map owned payload
    size_of::<Option<(String, Value)>>(), // BTreeMap next return
    size_of::<Option<(String, Value)>>(), // serde next return
    KEY_VALUE,                            // for destructured tuple
    KEY,                                  // discarded shallow key owner
    VALUE,                                // child owner transferred to guarded workspace
]);
const NEXT_S: usize = total([
    POINTER,                    // map.rs dying_next terminal branch Global::clone receiver
    POINTER,                    // map.rs dying_next value branch Global::clone receiver
    size_of::<()>(),            // fieldless Global clone returns
    size_of::<&mut JsonIter>(), // serde next receiver
    size_of::<&mut TreeIter>(), // BTreeMap next receiver
    size_of::<&mut TreeIter>(), // dying_next receiver
    WORD,                       // length branch / decrement
    POINTER,                    // range deallocating_next/end receiver
    POINTER,                    // into_key_val as_leaf_dying receiver
    POINTER,                    // mutable leaf return/local
    size_of::<&mut [MaybeUninit<String>; 11]>(), // initialized key array loan
    size_of::<&mut MaybeUninit<String>>(), // selected key
    size_of::<*const String>(), // key ptr::read argument
    size_of::<&mut [MaybeUninit<Value>; 11]>(), // val array loan
    size_of::<&mut MaybeUninit<Value>>(), // selected value
    size_of::<*const Value>(),  // value ptr::read argument
    WORD,                       // into_key_val idx
    size_of::<bool>(),          // length/idx predicates
]);

// navigate.rs180-233: LazyRange init_front/take_front and range next/end.
const LAZY_T: usize = total([
    OPTIONAL_LAZY_HANDLE, // front.take owned return
    LAZY_HANDLE,          // take_front Some pattern
    NODE,                 // take_front Root pattern
    HANDLE,               // take_front Edge pattern
    OPTIONAL_HANDLE,      // take_front return
    NODE,                 // init_front ptr::read root
    HANDLE,               // first_leaf_edge returned edge
    LAZY_HANDLE,          // initialized Edge payload
    OPTIONAL_LAZY_HANDLE, // initialized Some edge
    HANDLE,               // range deallocating_next return
    HANDLE,               // range deallocating_end owned front argument
]);
const LAZY_S: usize = total([
    POINTER,                      // take_front mutable range receiver
    POINTER,                      // Option front.take receiver
    POINTER,                      // deallocating_next range receiver
    POINTER,                      // init_front range receiver
    POINTER,                      // borrowed front Option
    POINTER,                      // Some Root borrowed pattern
    POINTER,                      // ptr::read Root input
    POINTER,                      // mutable front Option match input
    POINTER,                      // selected edge mutable loan
    size_of::<Option<&mut ()>>(), // init_front returned Option<&mut Handle>
    POINTER,                      // unwrapped front local
    POINTER,                      // edge deallocating_next receiver
    POINTER,                      // range deallocating_end receiver
    size_of::<bool>(),            // front presence / branch predicates
]);

// navigate.rs459-476,516-525,595-603,634-644,715-728. All ascent and
// first-leaf descent loops replace one fixed handle/node, never recurse.
const NAVIGATE_T: usize = total([
    HANDLE,                 // deallocating_next owned leaf edge
    HANDLE,                 // forget_node_type return
    HANDLE,                 // mutable edge local
    HANDLE_RESULT,          // right_kv result
    HANDLE,                 // Ok kv / Err last_edge match owner
    HANDLE,                 // ptr::read kv duplicate
    HANDLE,                 // next_leaf_edge owned input
    FORCE_HANDLE,           // next_leaf_edge forced result
    HANDLE,                 // forced leaf/internal KV local
    HANDLE,                 // internal next edge local
    HANDLE,                 // next_leaf_edge return
    HANDLE_AND_KV,          // deallocating_next returned pair
    OPTIONAL_HANDLE_AND_KV, // Some returned pair envelope
    HANDLE,                 // deallocating_end owned leaf edge
    HANDLE,                 // end forget_node_type return/edge local
    HANDLE,                 // end parent_edge local
    HANDLE,                 // replace ptr::read old edge
    HANDLE,                 // replace closure owned leaf_edge argument
    OPTIONAL_HANDLE_AND_KV, // closure deallocating_next result
    HANDLE_AND_KV,          // closure unwrap return / (new_value,ret)
    HANDLE,                 // replace new_value local
    HANDLE,                 // ptr::write replacement input
    HANDLE,                 // replace ret local
    HANDLE,                 // replace/deallocating_next_unchecked return
    NODE,                   // first_leaf_edge owned self
    NODE,                   // mutable node slot
    FORCE_NODE,             // force result
    NODE,                   // forced leaf/internal local
    HANDLE,                 // first_edge return
    NODE,                   // descend replacement node
    HANDLE,                 // first_leaf_edge return
]);
const NAVIGATE_S: usize = total([
    POINTER,           // navigate.rs forward deallocating_next Global::clone receiver
    POINTER,           // navigate.rs forward deallocating_end Global::clone receiver
    size_of::<()>(),   // fieldless Global clone returns
    POINTER,           // ptr::read kv input
    POINTER,           // deallocating_next_unchecked mutable edge receiver
    POINTER,           // mem::replace mutable slot argument
    POINTER,           // ptr::read slot
    POINTER,           // ptr::write replacement slot
    WORD,              // right_kv/first-edge index
    size_of::<()>(),   // actual no-capture replace closure and PanicGuard
    size_of::<bool>(), // navigation predicates
]);

// node.rs398-419: ascend result is retained across actual node deallocation.
const FREE_T: usize = total([
    NODE,            // deallocate_and_ascend owned self
    ASCEND_RESULT,   // ascend return
    OPTIONAL_HANDLE, // Result::ok return
    OPTIONAL_HANDLE, // ret local retained over deallocate
    OPTIONAL_HANDLE, // deallocate_and_ascend return
]);
const FREE_S: usize = total([
    WORD,                            // height local
    POINTER,                         // node local
    size_of::<std::alloc::Layout>(), // branch Layout::new return
    POINTER,                         // node.cast return
    size_of::<bool>(),               // internal/leaf layout branch
    nodes::DEALLOC_S,
]);

// map.rs1904-1926. The defining caller drains every initialized child first,
// so only the terminal dying_next None branch executes in ordinary Drop.
// DropGuard and drop_key_val are deliberately NOT authorized by this row.
const DRAINED_DROP_S: usize = total([
    size_of::<&mut TreeIter>(), // IntoIter::drop receiver
    size_of::<&mut TreeIter>(), // final dying_next receiver
    OPTIONAL_HANDLE,            // final None return envelope
]);

// The actually reached forward-retirement selector subset. None of insertion's
// dormant/awaken/cast-to-leaf/into_val_mut or mutation accessors is donated.
const SELECT_T: usize = total([
    NODE,
    NODE,       // NodeRef force input / payload
    FORCE_NODE, // NodeRef forced result
    HANDLE,
    HANDLE,       // Handle force input / payload
    FORCE_HANDLE, // Handle forced result
    NODE,
    HANDLE, // first_edge owned self / return
    NODE,
    HANDLE, // new_edge owned node / return
    NODE,
    HANDLE, // new_kv owned node / return
    HANDLE,
    NODE, // into_node owned self / return
    HANDLE,
    HANDLE, // right_edge owned self / return
    HANDLE,
    HANDLE_RESULT, // right_kv owned input / result
    HANDLE,
    HANDLE, // forget_node_type owned input / return
    NODE,
    NODE, // forget_type owned input / return
    HANDLE,
    NODE, // descend owned input / return
]);
const SELECT_S: usize = total([
    POINTER,
    POINTER, // len receiver / as_leaf_ptr argument
    POINTER,
    POINTER, // as_leaf_ptr returned/local ptr
    size_of::<u16>(),
    WORD, // len field / returned usize
    POINTER,
    POINTER, // as_internal_ptr receiver / return
    WORD,    // new_edge/new_kv index
    WORD,    // right_kv idx
    WORD,    // descend index/height
    POINTER, // descend parent_ptr
    size_of::<&[MaybeUninit<std::ptr::NonNull<u8>>; 12]>(), // edges loan
    size_of::<&MaybeUninit<std::ptr::NonNull<u8>>>(), // selected edge
    POINTER,
    POINTER,
    POINTER, // assume_init_read/as_ptr/ptr::read inputs
    POINTER,
    POINTER, // read node pointer / assume_init_read return
    POINTER,
    POINTER,           // as_leaf_dying receiver / return
    size_of::<bool>(), // selectors and valid-state predicates
]);

pub(super) const TRANSIENT: usize = total([
    INTO_T,
    NEXT_T,
    LAZY_T,
    NAVIGATE_T,
    FREE_T,
    SELECT_T,
    nodes::ASCEND_T,
]);
pub(super) const SCRATCH: usize = total([
    INTO_S,
    NEXT_S,
    LAZY_S,
    NAVIGATE_S,
    FREE_S,
    DRAINED_DROP_S,
    SELECT_S,
    nodes::ASCEND_S,
]);
