//! Declares actual Map/entry/search/split insertion argument and return roles.
//!
//! Every loop in these paths replaces a fixed NodeRef/Handle/Split slot.
//! No descendant Clone or recursive insertion activation is charged here.
//! Public entry types use their actual layouts. Private views use the pinned
//! field bounds. Summing sequential groups conservatively retains every named
//! nested window without inventing simultaneous per-member copies.

use super::{layouts::*, nodes, total};
use serde_json::{Map, Value};
use std::{
    cmp::Ordering,
    collections::{
        BTreeMap,
        btree_map::{Entry, OccupiedEntry, VacantEntry},
    },
    iter::Enumerate,
    mem::{MaybeUninit, size_of},
    slice::Iter,
};

type Tree = BTreeMap<String, Value>;
const ENTRY: usize = size_of::<Entry<'static, String, Value>>();
const VACANT: usize = size_of::<VacantEntry<'static, String, Value>>();
const OCCUPIED: usize = size_of::<OccupiedEntry<'static, String, Value>>();

// serde_json/map.rs130-132; map.rs1045-1052,1501-1529;
// entry.rs426-427,450-484,604-606,627-629; borrow.rs14-57.
const ENTRY_T: usize = total([
    KEY,
    VALUE,                      // serde Map::insert owned arguments
    size_of::<Option<Value>>(), // serde insert return
    KEY,
    VALUE,                      // BTreeMap::insert owned arguments
    size_of::<Option<Value>>(), // BTreeMap insert return
    KEY,                        // BTreeMap::entry owned key argument
    MAP_AND_DORMANT,            // DormantMutRef::new tuple return
    DORMANT,                    // dormant local retained across search and entry construction
    NODE,                       // Option::insert owned root initializer
    KEY,
    VALUE,    // empty-root leaf::push_with_handle owned key/value
    HANDLE,   // empty-root push_with_handle return
    ENTRY,    // entry returned enum
    VACANT,   // vacant initializer, both empty and leaf branches
    OCCUPIED, // occupied initializer
    OCCUPIED, // occupied insert match local
    VACANT,   // vacant insert match local
    VACANT,
    VALUE, // VacantEntry::insert owned self/value
    VACANT,
    VALUE,           // VacantEntry::insert_entry owned self/value
    OPTIONAL_HANDLE, // insert_entry self.handle match input
    HANDLE,          // matched existing handle
    HANDLE,          // insert_entry resulting local
    OCCUPIED,        // insert_entry returned owner
    OCCUPIED,        // into_mut owned self
    VALUE,           // OccupiedEntry::insert owned replacement
    VALUE,           // mem::replace owned replacement
    VALUE,           // ptr::read old value / local
    VALUE,           // ptr::write replacement operand
    VALUE,           // mem::replace return
    VALUE,           // OccupiedEntry::insert return
]);
const ENTRY_S: usize = total([
    POINTER,                              // map.rs entry None: Global::clone borrowed receiver
    POINTER,                              // map.rs entry Found: Global::clone borrowed receiver
    POINTER,                              // map.rs entry GoDown: Global::clone borrowed receiver
    POINTER,                              // entry.rs empty-root new_leaf Global::clone receiver
    POINTER,                              // entry.rs insert_recursing Global::clone receiver
    POINTER,         // entry.rs split_root push_internal_level Global::clone receiver
    size_of::<()>(), // fieldless Global clone arguments/returns
    size_of::<&mut Map<String, Value>>(), // serde Map insert receiver
    size_of::<&mut Tree>(), // BTreeMap insert receiver
    size_of::<&mut Tree>(), // entry receiver
    size_of::<&mut Tree>(), // DormantMutRef::new argument
    size_of::<&mut Tree>(), // new pointer-derived return
    POINTER,         // NonNull constructor/pointer local
    size_of::<&mut Tree>(), // map pattern loan
    size_of::<Option<&mut ()>>(), // map.root.as_mut return: thin private root loan
    POINTER,         // matched root loan
    POINTER,         // split/empty dormant reborrow receiver
    size_of::<&mut Tree>(), // DormantMutRef::reborrow return
    POINTER,         // Option::insert mutable root slot
    POINTER,         // returned &mut root
    NODE,            // borrow_mut/cast returned leaf local
    POINTER,         // leaf push_with_handle receiver
    size_of::<&mut Value>(), // VacantEntry::insert returned value loan
    size_of::<&mut Value>(), // into_mut return
    POINTER,         // DormantMutRef::awaken owned pointer self field
    size_of::<&mut Tree>(), // awaken return
    size_of::<&mut OccupiedEntry<'static, String, Value>>(), // Occupied insert receiver
    size_of::<&mut Value>(), // insert's get_mut receiver output
    size_of::<&mut Value>(), // get_mut actual return
    size_of::<&mut Value>(), // mem::replace dest
    size_of::<&mut Value>(), // ptr::read/write dest view
    POINTER,         // OccupiedEntry::get_mut receiver
    POINTER,         // Handle::kv_mut receiver
    POINTER,         // kv_mut as_leaf_mut returned loan
    size_of::<&mut [MaybeUninit<String>; 11]>(), // kv_mut keys array loan
    size_of::<&mut MaybeUninit<String>>(), // selected key
    size_of::<&mut String>(), // assume_init_mut key return/local
    size_of::<&mut [MaybeUninit<Value>; 11]>(), // kv_mut vals array loan
    size_of::<&mut MaybeUninit<Value>>(), // selected val
    size_of::<&mut Value>(), // assume_init_mut value return/local
    size_of::<(&mut String, &mut Value)>(), // kv_mut actual tuple return
    SPLIT_ROOT_CLOSURE, // actual split-root closure bounded captures
    POINTER,         // split-root closure reborrow receiver
    size_of::<&mut Tree>(), // closure map local
    size_of::<Option<&mut ()>>(), // closure root.as_mut
    POINTER,         // unwrapped mutable root local
    POINTER,         // final dormant reborrow receiver
    size_of::<&mut Tree>(), // length update map loan
    WORD,            // length update scalar
    size_of::<bool>(), // Option/entry branch outcomes
]);

// search.rs55-74,195-237. String derives Ord on its Vec<u8> field;
// vec/mod.rs4286-4290 -> [u8] Ord -> slice/cmp.rs325-344 compare_bytes.
// There is no user comparison callback or character/locale allocation.
const SEARCH_T: usize = total([
    NODE,          // search_tree owned mutable self slot
    NODE,          // search_node owned input
    SEARCH_RESULT, // search_node return
    HANDLE,        // Found pattern
    HANDLE,        // GoDown pattern
    FORCE_HANDLE,  // handle.force result
    HANDLE,        // forced leaf/internal pattern
    NODE,          // descended replacement self
    SEARCH_RESULT, // search_tree return
    NODE,          // find_key_index reborrowed node local
    INDEX_RESULT,  // find_key_index return
    INDEX_RESULT,  // search_node match input
]);
const SEARCH_S: usize = total([
    size_of::<&String>(),                          // search_tree key argument
    size_of::<&String>(),                          // search_node key argument
    POINTER,                                       // find_key_index node receiver
    size_of::<&String>(),                          // find_key_index key argument
    WORD,                                          // start_index
    size_of::<&[String]>(),                        // node.keys return/local
    size_of::<&[String]>(),                        // get_unchecked suffix return
    size_of::<std::ops::RangeFrom<usize>>(),       // start_index.. argument
    size_of::<Iter<'static, String>>(),            // suffix.iter return
    size_of::<Enumerate<Iter<'static, String>>>(), // enumerate return/for owner
    size_of::<Option<(usize, &'static String)>>(), // iterator next
    size_of::<(usize, &'static String)>(),         // for tuple
    WORD,                                          // offset local
    size_of::<&String>(),                          // k local
    size_of::<&String>(),                          // Borrow<String>::borrow receiver
    size_of::<&String>(),                          // borrow return
    size_of::<&String>(),
    size_of::<&String>(), // derived String::cmp arguments
    size_of::<&Vec<u8>>(),
    size_of::<&Vec<u8>>(), // actual Vec::cmp arguments
    size_of::<&Vec<u8>>(),
    size_of::<&Vec<u8>>(), // Vec::deref receivers
    size_of::<&[u8]>(),
    size_of::<&[u8]>(), // deref returns
    size_of::<&[u8]>(),
    size_of::<&[u8]>(), // slice Ord::cmp arguments
    size_of::<&[u8]>(),
    size_of::<&[u8]>(), // SliceOrd::compare arguments
    size_of::<isize>(), // diff local
    WORD,               // len local
    size_of::<*const u8>(),
    size_of::<*const u8>(), // left/right pointer locals
    size_of::<*const u8>(),
    size_of::<*const u8>(), // compare_bytes operands
    WORD,                   // compare_bytes len operand
    size_of::<i32>(),       // actual compare_bytes return
    size_of::<isize>(),     // order local
    size_of::<&isize>(),
    size_of::<&isize>(),   // order.cmp(&0) arguments
    size_of::<Ordering>(), // primitive cmp return
    size_of::<Ordering>(), // SliceOrd return
    size_of::<Ordering>(), // slice Ord return
    size_of::<Ordering>(), // Vec Ord return
    size_of::<Ordering>(), // String Ord return and search match
    size_of::<bool>(),     // branch predicates
    // node.keys -> into_leaf -> array/slice assume_init_ref.
    POINTER,                                 // keys receiver
    NODE,                                    // into_leaf copied owned receiver
    POINTER,                                 // returned leaf loan
    size_of::<&[MaybeUninit<String>; 11]>(), // keys array loan
    size_of::<std::ops::RangeTo<usize>>(),   // ..len
    size_of::<&[MaybeUninit<String>]>(),     // prefix loan
    size_of::<&[String]>(),                  // initialized slice return
]);

// node.rs950-982 and1058-1090. Leaf split and internal split are different
// active methods: the dormant inserted handle coexists with the propagated
// SplitResult until the iterative ascent returns. These are independent roles.
const PROPAGATE_T: usize = total([
    HANDLE,
    KEY,
    VALUE, // insert_recursing owned leaf/key/value
    HANDLE,
    KEY,
    VALUE,            // leaf insert owned arguments
    SPLIT_AND_HANDLE, // leaf insert return
    OPTIONAL_SPLIT,
    HANDLE,        // returned pair destructuring windows
    SPLIT,         // Some split pattern
    SPLIT,         // forget_node_type owned split input
    SPLIT,         // forget_node_type return
    SPLIT,         // propagated split local
    HANDLE,        // dormant inserted handle local across ascent
    ASCEND_RESULT, // ascend result matched by outer loop
    HANDLE,        // Ok(parent) owner
    NODE,          // Err(root) owner
    HANDLE,
    KEY,
    VALUE,
    NODE,           // internal insert owned self/k/v/edge
    OPTIONAL_SPLIT, // internal insert return
    SPLIT,          // Some split pattern
    SPLIT,          // internal split forget_node_type input
    SPLIT,          // forgotten internal split return
    SPLIT,          // root closure owned ins argument
    SPLIT,          // closure call initializer / ownership transfer
    NODE,           // explicitly dropped ins.left (no owning destructor)
    HANDLE,         // awaken inserted handle input
    HANDLE,         // insert_recursing return
    // leaf split branch's retained direct locals
    SPLITPOINT,
    WORD,
    LEFT_OR_RIGHT, // splitpoint return + destructuring
    HANDLE,        // middle KV local
    SPLIT,         // result local
    HANDLE,        // insertion_edge local
    HANDLE,        // insert_fit result before dormant()
    // internal split branch's separate direct locals
    SPLITPOINT,
    WORD,
    LEFT_OR_RIGHT,
    HANDLE,
    SPLIT,
    HANDLE,
]);
const PROPAGATE_S: usize = total([
    POINTER,            // node.rs1065 leaf insert Global::clone borrowed receiver
    POINTER,            // node.rs1075 parent insert Global::clone borrowed receiver
    size_of::<()>(),    // fieldless Global clone returns
    SPLIT_ROOT_CLOSURE, // retained FnOnce argument
    POINTER,            // leaf insert borrowed len receiver
    WORD,               // leaf length branch input
    WORD,               // splitpoint edge_idx argument
    WORD,               // chosen middle index
    WORD,               // insertion Left/Right index
    POINTER,            // result.left reborrow_mut receiver
    POINTER,            // result.right borrow_mut receiver
    NODE,
    NODE,    // returned branch-local node views
    POINTER, // handle.dormant receiver
    POINTER, // internal insert_fit mutable receiver
    WORD,    // internal length/height operands
    WORD,    // internal splitpoint argument
    WORD,    // middle index
    WORD,    // internal insertion index
    POINTER,
    POINTER, // left/right branch receiver
    NODE,
    NODE,              // branch-local views
    POINTER,           // internal split forget_node_type pointer access
    size_of::<bool>(), // iterative match/validity predicates
]);

// node.rs929-945,1002-1016,1221-1265,1288-1308: actual owned k/v
// arguments/returns remain live beside the split constructor and copy controls.
const SPLIT_T: usize = total([
    HANDLE, KEY, VALUE,  // leaf insert_fit owned arguments
    HANDLE, // leaf insert_fit returned handle
    KEY, VALUE, NODE,      // internal insert_fit owned arguments
    HANDLE,    // leaf split owned self
    POINTER,   // leaf split new boxed node local
    KEY_VALUE, // split_leaf_data returned tuple
    KEY_VALUE, // leaf split kv local
    NODE,      // leaf split right local
    SPLIT,     // leaf split return
    HANDLE,    // internal split owned self
    POINTER,   // internal new boxed node local
    KEY_VALUE, // split_leaf_data tuple at internal call site
    KEY_VALUE, // internal kv local
    NODE,      // internal right local
    SPLIT,     // internal split return
    KEY, VALUE, // split_leaf_data k/v locals
    KEY, VALUE,     // key/value assume_init_read returns
    KEY_VALUE, // split_leaf_data returned tuple
]);
const SPLIT_S: usize = total([
    WORD, // leaf insert_fit new_len local
    WORD, // internal insert_fit new_len local
    size_of::<u16>(),
    size_of::<u16>(), // leaf/internal len write operands
    POINTER,          // split_leaf_data mutable handle receiver
    POINTER,          // split_leaf_data mutable new-node argument
    WORD,
    WORD,                                                   // old_len/new_len
    size_of::<u16>(),                                       // new node len input
    size_of::<&MaybeUninit<String>>(),                      // assume_init_read key receiver
    size_of::<*const String>(),                             // actual ptr::read argument
    size_of::<&MaybeUninit<Value>>(),                       // assume_init_read value receiver
    size_of::<*const Value>(),                              // actual ptr::read argument
    size_of::<std::ops::Range<usize>>(),                    // source split key range
    size_of::<std::ops::Range<usize>>(),                    // source split value range
    size_of::<std::ops::RangeTo<usize>>(),                  // destination prefix range
    size_of::<&mut [MaybeUninit<String>]>(),                // destination key prefix
    size_of::<&mut [MaybeUninit<Value>]>(),                 // destination value prefix
    WORD,                                                   // internal split old_len
    WORD,                                                   // internal split new_len
    size_of::<std::ops::Range<usize>>(),                    // split edge source range
    size_of::<std::ops::RangeTo<usize>>(),                  // edge destination prefix
    size_of::<&mut [MaybeUninit<std::ptr::NonNull<u8>>]>(), // edge prefix
    size_of::<std::num::NonZeroUsize>(),                    // internal split height local
    size_of::<std::num::NonZeroUsize>(),                    // from_new_internal height argument
    size_of::<bool>(),                                      // split validity predicates
]);

// entry.rs470-477 -> node.rs598-608 -> mem.rs10-39 -> node.rs238-263.
const ROOT_T: usize = total([
    NODE,          // mem::replace ptr::read old root
    NODE,          // take_mut closure's old_root argument
    NODE,          // new_internal owned child argument
    NODE,          // new_internal return
    NODE,          // forget_type owned input
    NODE,          // forget_type return
    ROOT_AND_UNIT, // replace closure returned (Root, ())
    NODE,          // replacement root local
    NODE,          // ptr::write replacement input
    NODE,          // push_internal_level returned mutable internal view
    KEY,
    VALUE,
    NODE, // internal push owned key/value/edge arguments
]);
const ROOT_S: usize = total([
    POINTER,                                 // push_internal_level mutable root receiver
    POINTER,                                 // take_mut mutable argument
    POINTER,                                 // replace mutable argument
    POINTER,                                 // ptr::read input
    POINTER,                                 // ptr::write destination
    size_of::<()>(), // take_mut/new_internal closure owns captured fieldless Global
    POINTER,         // internal push mutable receiver
    size_of::<&mut u16>(), // push len loan
    WORD,            // push idx
    POINTER,         // push edge initialized pointer
    size_of::<&mut std::ptr::NonNull<u8>>(), // write returned edge loan
    size_of::<bool>(), // internal height/capacity predicates
    size_of::<()>(), // Global, zero-capture closures, PanicGuard and unit results
]);

pub(super) const TRANSIENT: usize = total([
    ENTRY_T,
    SEARCH_T,
    PROPAGATE_T,
    SPLIT_T,
    ROOT_T,
    nodes::CONSTRUCTOR_T,
    nodes::SELECT_T,
    nodes::SLICE_T,
    nodes::ASCEND_T,
]);
pub(super) const SCRATCH: usize = total([
    ENTRY_S,
    SEARCH_S,
    PROPAGATE_S,
    SPLIT_S,
    ROOT_S,
    nodes::CONSTRUCTOR_S,
    nodes::SELECT_S,
    nodes::AREA_S,
    nodes::SLICE_S,
    nodes::ASCEND_S,
]);
