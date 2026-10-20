//! Composes actual source populations with independent constructor suppliers.
//!
//! Physical unreachable flat records are deliberately retained in this quote.
//! They conservatively enlarge named operation populations; a configured cap
//! never becomes a node, text, member, allocation, or constructor population.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use std::mem::align_of;

/// Stores independently requested axes and actual source-derived work bounds.
#[derive(Clone, Copy)]
pub(super) struct ConstructionData {
    /// Retains the complete prospective R/T/S axes beside the same input.
    pub(super) requested: [usize; 3],
    /// Bounds queued items and cumulative construction work operations.
    pub(super) work: usize,
    /// Bounds open containers and cumulative container pushes and pops.
    pub(super) frames: usize,
    /// Bounds pending retirement items, including unfinished array slots.
    pub(super) retirement: usize,
}

impl ConstructionData {
    /// Composes real physical source populations before construction effects.
    ///
    /// # Errors
    /// Refuses incomplete input, unsupported layout, overflow or total demand.
    pub(super) fn quote_data(
        source: &NativeImport18EffectiveTextAttemptData,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        ordinary_number_layout_data()?;
        source.completed_data()?;
        let mut row = [
            retained_header_and_source(source, maximum)?,
            constructor_returns_data(),
            fixed_counter_data(),
        ];
        let mut normal_nodes = 0usize;
        let mut containers = 0usize;
        let mut array_slots = 0usize;
        let mut members = 0usize;
        let mut objects = 0usize;

        for node in &source.nodes {
            // Alias targets were created fresh by the text producer. Counting
            // the ordinary node once avoids copying the alias wrapper itself.
            if !matches!(node.kind, Kind::Alias(_)) {
                normal_nodes = add(normal_nodes, 1)?;
            }
            match &node.kind {
                Kind::String(index) => {
                    let text = source.texts.get(*index).ok_or_else(invalid)?;
                    combine(
                        &mut row,
                        constructors::string_copy_data(text.len(), maximum)?,
                    )?;
                    combine(&mut row, constructors::string_drop_data(maximum)?)?;
                }
                Kind::Array { first, last: _ } => {
                    containers = add(containers, 1)?;
                    let mut next = *first;
                    let mut length = 0usize;
                    while let Some(index) = next {
                        let edge = source.edges.get(index).ok_or_else(invalid)?;
                        length = add(length, 1)?;
                        if length > source.edges.len() {
                            return Err(invalid());
                        }
                        next = edge.next;
                    }
                    array_slots = add(array_slots, length)?;
                    combine(
                        &mut row,
                        constructors::vec_reservation_data::<Value>(length, maximum)?,
                    )?;
                    combine(
                        &mut row,
                        constructors::vec_push_pop_data::<Value>(length, 0, maximum)?,
                    )?;
                    combine(
                        &mut row,
                        constructors::vec_into_iter_data::<Value>(length, maximum)?,
                    )?;
                }
                Kind::Object(values) => {
                    containers = add(containers, 1)?;
                    objects = add(objects, 1)?;
                    members = add(members, values.len())?;
                    combine(
                        &mut row,
                        constructors::map_insertion_series_data(values.len(), maximum)?,
                    )?;
                    for (key, _) in values {
                        combine(
                            &mut row,
                            constructors::string_copy_data(key.len(), maximum)?,
                        )?;
                        combine(&mut row, constructors::string_drop_data(maximum)?)?;
                    }
                }
                Kind::Number(_) => {
                    // The ordinary Number contains only private N. Its real
                    // Copy Clone return is bounded by the enclosing Number's
                    // defining field layout, separately from Number's return.
                    // This is a new concrete producer, not a Clone9 row loan.
                    row[1] = add(row[1], mul(2, size_of::<Number>())?)?;
                }
                Kind::Null | Kind::Bool(_) | Kind::Alias(_) => {}
            }
        }

        // Every actual Visit is the root or an existing array/member child;
        // every Finish belongs to one ordinary container. Raw alias traversal
        // adds no Work item and never duplicates an ordinary target subtree.
        let work = add(add(add(1, array_slots)?, members)?, containers)?;
        let frames = containers;
        // Unfinished arrays hold Null slots beside open child builders. Those
        // slots coexist with, rather than replace, their future child records.
        let retirement = add(add(normal_nodes, array_slots)?, 1)?;
        // Destructor loops call pop once more to observe None. Each disjoint
        // pending/root/frame tree has its own retirement terminal call, even
        // though all trees reuse one empty, pre-reserved bank sequentially.
        let work_pops = add(work, 1)?;
        let frame_pops = add(frames, 1)?;
        let retirement_trees = add(frames, 3)?; // root, pending, pending_old
        let retirement_pops = add(retirement, retirement_trees)?;
        combine(
            &mut row,
            constructors::vec_reservation_data::<Work>(work, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_reservation_data::<BuildFrame>(frames, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_reservation_data::<Value>(retirement, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_push_pop_data::<Work>(work, work_pops, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_push_pop_data::<BuildFrame>(frames, frame_pops, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_push_pop_data::<Value>(retirement, retirement_pops, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::map_retirement_data(objects, members, maximum)?,
        )?;
        combine(
            &mut row,
            constructors::vec_access_data::<BuildFrame>(maximum)?,
        )?;
        combine(&mut row, constructors::vec_access_data::<Value>(maximum)?)?;
        ensure_bound(row, maximum)?;

        Ok(Self {
            requested: row,
            work,
            frames,
            retirement,
        })
    }
}

/// Names the actual spent-owner initializer and the complete prewalk controls.
///
/// # Errors
/// Refuses a Number profile outside the actual ordinary producer contract.
pub(super) fn take_requested_storage_data() -> Result<[usize; 3], ProviderError> {
    ordinary_number_layout_data()?;
    let mut row = [
        size_of::<Option<NativeImport18GuardedValueAttemptData>>(),
        take_constructor_returns_data(),
        fixed_counter_data(),
    ];
    // Before the full row exists, taking can still fail or the quote can
    // refuse. These are the same typed Vec::new and empty-shell Drop families
    // defined by the empty-bank supplier, quoted at zero requested backing.
    // Its zero-reserve controls are an explicit conservative superset; they
    // are not another allocation or a donation from the later full row.
    combine(
        &mut row,
        constructors::vec_reservation_data::<Work>(0, usize::MAX)?,
    )?;
    combine(
        &mut row,
        constructors::vec_reservation_data::<BuildFrame>(0, usize::MAX)?,
    )?;
    combine(
        &mut row,
        constructors::vec_reservation_data::<Value>(0, usize::MAX)?,
    )?;
    // No deep retirement tree exists yet, but both unconditional destructor
    // loops execute their terminal None on an empty work/frame bank.
    combine(
        &mut row,
        constructors::vec_push_pop_data::<Work>(0, 1, usize::MAX)?,
    )?;
    combine(
        &mut row,
        constructors::vec_push_pop_data::<BuildFrame>(0, 1, usize::MAX)?,
    )?;
    Ok(row)
}

fn ordinary_number_layout_data() -> Result<(), ProviderError> {
    // This is the same locked ordinary-Number profile as the actual flat
    // producer. The arbitrary-precision String representation needs a
    // different concrete clone supplier; it cannot enter this allocation-free
    // Number path by changing RawValue mode or supplying a different row.
    if size_of::<Number>() != 16 || align_of::<Number>() != 8 {
        return Err(invalid());
    }
    Ok(())
}

fn retained_header_and_source(
    source: &NativeImport18EffectiveTextAttemptData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    // The enclosing inline source slot is already part of this owner header.
    // All old source backing and its history remain charged exactly once.
    let backing = source
        .retained_requested_storage_data(maximum)?
        .checked_sub(size_of::<Option<NativeImport18EffectiveTextAttemptData>>())
        .ok_or_else(invalid)?;
    add(
        size_of::<Option<NativeImport18GuardedValueAttemptData>>(),
        backing,
    )
}

/// Counts the actual initialized source, output aggregates and work capacities.
///
/// # Errors
/// Refuses source census, checked layout overflow or the supplied whole bound.
pub(super) fn retained_storage_data(
    owner: &NativeImport18GuardedValueAttemptData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut retained = match owner.source.as_ref() {
        Some(source) => retained_header_and_source(source, maximum)?,
        None => size_of::<Option<NativeImport18GuardedValueAttemptData>>(),
    };
    for backing in [
        mul(owner.work.capacity(), size_of::<Work>())?,
        mul(owner.frames.capacity(), size_of::<BuildFrame>())?,
        mul(owner.retirement.capacity(), size_of::<Value>())?,
        owner.string_bytes,
        owner.array_bytes,
        tree_storage_data(
            owner.tree_containers,
            owner.tree_members,
            size_of::<String>() + size_of::<Value>(),
            align_of::<String>().max(align_of::<Value>()),
        )?,
    ] {
        retained = add(retained, backing)?;
    }
    if retained > maximum {
        return Err(exhausted());
    }
    Ok(retained)
}

fn take_constructor_returns_data() -> usize {
    size_of::<NativeImport18GuardedValueAttemptData>()
        + size_of::<Option<NativeImport18GuardedValueAttemptData>>()
        + size_of::<Option<NativeImport18EffectiveTextAttemptData>>()
        + size_of::<ProviderError>()
        + size_of::<Result<(), ProviderError>>()
}

fn constructor_returns_data() -> usize {
    // These are independently named actual parent constructor/transfer
    // windows. Sequence, String and map internals are supplied separately.
    take_constructor_returns_data()
        + size_of::<ConstructionData>() * 2 // quote return and later copied run row
        + size_of::<Option<ConstructionData>>()
        + size_of::<Result<ConstructionData, ProviderError>>()
        + size_of::<Work>()
        + size_of::<Option<Work>>()
        + size_of::<BuildFrame>()
        + size_of::<Option<BuildFrame>>()
        + size_of::<Container>()
        + size_of::<Destination>()
        + size_of::<Option<Destination>>()
        + size_of::<Value>() * 2 // incoming constructor and displaced slot return
        + size_of::<Option<Value>>() * 2 // take and map insert returns coexist
        + size_of::<Option<String>>()
        + size_of::<Stage>()
        + size_of::<ProviderError>() // actual invalid/exhausted return, sequential
        + size_of::<NativeImport18EffectiveValueViewData<'static>>() // numeric Visit view initializer
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>() * 2 // quote helper/caller
        + size_of::<Result<(), ProviderError>>() * 4 // run/materialize/visit/attach
        + size_of::<Result<usize, ProviderError>>() * 3 // retained census/arithmetic
}

fn fixed_counter_data() -> usize {
    constructors::fixed_counter_data()
        + constructors::map_fixed_counter_data()
        // The same completed source getter, alias walk and flat census are
        // actually called. Their defining counter owns only their own roles.
        + NativeImport18EffectiveTextConstructionData::counter_scratch_data()
        + size_of::<&NativeImport18GuardedValueAttemptData>()
        + size_of::<&mut NativeImport18GuardedValueAttemptData>() * 4 // run/visit/attach/retire chain
        + size_of::<&mut Option<NativeImport18GuardedValueAttemptData>>()
        + size_of::<Option<&mut NativeImport18GuardedValueAttemptData>>()
        + size_of::<Result<&mut NativeImport18GuardedValueAttemptData, ProviderError>>()
        + size_of::<&ConstructionData>()
        + size_of::<&Option<ConstructionData>>()
        + size_of::<&NativeImport18EffectiveTextAttemptData>() * 3 // owner/quote/header helpers
        + size_of::<&mut Option<NativeImport18EffectiveTextAttemptData>>() * 2 // take caller/receiver
        + size_of::<Option<&NativeImport18EffectiveTextAttemptData>>()
        + size_of::<Result<&NativeImport18EffectiveTextAttemptData, ProviderError>>()
        + size_of::<&mut [usize; 3]>()
        + size_of::<&mut [usize]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<std::slice::Iter<'static, Node>>()
        + size_of::<std::collections::btree_map::Iter<'static, String, usize>>()
        + size_of::<(&String, &usize)>()
        + size_of::<Option<(&String, &usize)>>()
        + size_of::<&mut Vec<Work>>()
        + size_of::<&mut Vec<BuildFrame>>()
        + size_of::<&mut Vec<Value>>() * 2 // caller and nested retirement loan
        + size_of::<&mut Work>() // shallow popped Work drop glue
        + size_of::<&mut Option<Work>>()
        + size_of::<&mut Container>()
        + size_of::<&mut Destination>()
        + size_of::<&mut Option<Destination>>()
        + size_of::<&mut Option<Value>>()
        + size_of::<&mut Option<String>>()
        + size_of::<&Option<Destination>>()
        + size_of::<&Option<Value>>()
        + size_of::<&Option<String>>()
        + size_of::<&mut BuildFrame>()
        + size_of::<Option<&mut BuildFrame>>()
        + size_of::<Result<&mut BuildFrame, ProviderError>>()
        + size_of::<&BuildFrame>()
        + size_of::<Option<&BuildFrame>>()
        + size_of::<&mut Value>()
        + size_of::<Option<&mut Value>>()
        + size_of::<Result<&mut Value, ProviderError>>()
        + size_of::<&Value>()
        + size_of::<Option<&Value>>()
        + size_of::<Result<&Value, ProviderError>>()
        + size_of::<&Destination>()
        + size_of::<&Stage>() * 2 // defining PartialEq receiver and expected stage
        + size_of::<&usize>() * 2 // borrowed frame and array slot destinations
        + size_of::<Option<&Destination>>()
        + size_of::<Result<&Destination, ProviderError>>()
        + size_of::<&mut String>()
        + size_of::<Option<&mut String>>()
        + size_of::<Result<&mut String, ProviderError>>()
        + size_of::<&Number>() * 3 // pattern binding, Number Clone, private N Copy Clone
        + size_of::<&mut Map<String, Value>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>() * 3 // nested census/add/mul
        + size_of::<Result<(), ProviderError>>() * 5 // run/materialize/visit/attach/helper
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<[usize; 7]>() // actual retained-census backing initializer
        + size_of::<std::array::IntoIter<usize, 7>>()
        + size_of::<[usize; 3]>() * 2 // live aggregate and incoming supplier axes
        + size_of::<bool>() * 2 // condition return and expected discriminant
        + try_controls_data()
        // This deliberately sums named windows across sequential paths; it
        // does not claim they are concurrent. Quote: maximum, five population
        // locals, length, edge index, three reservation bounds plus four pop bounds (15). Engine: root,
        // frame, slot length, allocated bytes, attach index/members/maps (7).
        // Two census methods: two maxima, backing, retained, loop backing (5).
        // Combine axis (1), bound maximum (1), add/mul operands+returns (6).
        + size_of::<usize>() * (15 + 7 + 5 + 1 + 1 + 6)
}

fn try_controls_data() -> usize {
    // These are the actual parent's Result ? branch payload classes. Observer
    // references stay borrowed; owned Value/Frame success moves have no
    // fallible operation before their next installed guard. Supplier-internal
    // branches remain their own separately pinned producer obligations.
    type Residual = Result<std::convert::Infallible, ProviderError>;
    type Branch<T> = std::ops::ControlFlow<Residual, T>;

    size_of::<Residual>()
        + size_of::<Branch<()>>()
        + size_of::<Branch<usize>>()
        + size_of::<Branch<[usize; 3]>>()
        + size_of::<Branch<ConstructionData>>()
        + size_of::<Branch<Work>>()
        + size_of::<Branch<BuildFrame>>()
        + size_of::<Branch<Destination>>()
        + size_of::<Branch<String>>()
        + size_of::<Branch<Value>>()
        + size_of::<Branch<&'static NativeImport18EffectiveTextAttemptData>>()
        + size_of::<Branch<&'static mut NativeImport18GuardedValueAttemptData>>()
        + size_of::<Branch<NativeImport18EffectiveValueKindData<'static>>>()
        + size_of::<Branch<NativeImport18EffectiveValueViewData<'static>>>()
        + size_of::<Branch<&'static String>>()
        + size_of::<Branch<&'static Edge>>()
        + size_of::<Branch<&'static mut BuildFrame>>()
        + size_of::<Branch<&'static mut Value>>()
        + size_of::<Branch<&'static mut String>>()
        + size_of::<Branch<&'static Destination>>()
}

fn combine(row: &mut [usize; 3], next: [usize; 3]) -> Result<(), ProviderError> {
    for axis in 0..3 {
        row[axis] = add(row[axis], next[axis])?;
    }
    Ok(())
}

fn ensure_bound(row: [usize; 3], maximum: usize) -> Result<(), ProviderError> {
    if add(add(row[0], row[1])?, row[2])? > maximum {
        return Err(exhausted());
    }
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}
