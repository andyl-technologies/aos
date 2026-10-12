//! Compares physical namespace frontiers and expands logical graft changes.
//!
//! Root-local addresses retain independent source roots on both sides. Physical
//! cuts and their resynchronization snapshots are recorded separately from the
//! logical entry/property/file states, so repartitioning cannot inflate delta.

use alloc::vec::Vec;
use core::cmp::Ordering;

use super::accounting::Recorder;
use super::frontier::{Frontier, Part};
use super::{
    Address, BoundaryRegion, DataChange, Discovery, Error, FileState, Hop, InputChange,
    PreparedSource, PropertyChange, Resynchronization,
};
use super::{PhysicalEventKind, PopulationMode, StreamWork};
use crate::identity::Digest;
use crate::tree_format::{Entry, EntryKind, LeafItem, Property};

/// Compares supported immutable sources, preserving local occurrence identity.
///
/// # Errors
/// Rejects different attributes/contexts/geometry, unavailable roots or work overflow.
pub(super) fn compare<'graph, 'a>(
    old: &PreparedSource<'graph, 'a>,
    new: &PreparedSource<'graph, 'a>,
    mode: PopulationMode,
) -> Result<Discovery<'graph, 'a>, Error> {
    // The executable profile currently accepts one context and minimum. Keep
    // the two-sided binding explicit if another supported selection is added.
    if old.attribute() != new.attribute()
        || old.context != new.context
        || old.source.minimum != new.source.minimum
    {
        return Err(Error::Source);
    }
    let mut output = Discovery {
        old_lookup: old.lookup().clone(),
        new_lookup: new.lookup().clone(),
        source_lookups: super::SourceLookupWork::default(),
        inputs: Vec::new(),
        properties: Vec::new(),
        envelopes: Vec::new(),
        data: Vec::new(),
        work: super::DiscoveryWork::default(),
        boundaries: Vec::new(),
        streams: Vec::new(),
        initialization: super::InitializationWork::default(),
        logical_inputs: 0,
        sources: super::DiscoverySources {
            old: old.root,
            new: new.root,
            attribute: old.attribute().into(),
            context: old.context,
            minimum: old.source.minimum,
            mode,
        },
    };
    let sources = Sources {
        old,
        new,
        data_changes: mode == PopulationMode::Existing,
    };
    sources.pair(old.root, new.root, &[], &[], &mut output)?;
    if mode == PopulationMode::NewlyEnabled {
        initialize(new, new.root, &[], &mut output)?;
    }
    output.logical_inputs = output
        .inputs
        .len()
        .checked_add(output.properties.len())
        .ok_or(Error::Limit)?;
    Ok(output)
}

struct Sources<'s, 'graph, 'value> {
    old: &'s PreparedSource<'graph, 'value>,
    new: &'s PreparedSource<'graph, 'value>,
    data_changes: bool,
}

impl<'graph, 'a> Sources<'_, 'graph, 'a> {
    fn pair(
        &self,
        old_root: Digest,
        new_root: Digest,
        old_hops: &[Hop],
        new_hops: &[Hop],
        output: &mut Discovery<'graph, 'a>,
    ) -> Result<(), Error> {
        let old = self.old.tree(old_root, &mut output.source_lookups)?;
        let new = self.new.tree(new_root, &mut output.source_lookups)?;
        let mut local_work = Recorder::new();
        local_work.charge(
            old.root().level().min(new.root().level()),
            PhysicalEventKind::FrontierCheck,
            1,
        )?;
        if old_root == new_root {
            local_work.charge(old.root().level(), PhysicalEventKind::SkippedSubtree, 1)?;
            finish(
                local_work,
                Some(old_root),
                Some(new_root),
                Some(old_hops),
                Some(new_hops),
                output,
            )?;
            return Ok(());
        }
        if old.props().is_some() != new.props().is_some() {
            output.envelopes.push(super::RootEnvelopeChange {
                old_root,
                new_root,
                old_hops: old_hops.to_vec(),
                new_hops: new_hops.to_vec(),
                old_present: old.props().is_some(),
                new_present: new.props().is_some(),
            });
        }
        properties(
            Some(old.root().level()),
            Some(new.root().level()),
            old.props(),
            new.props(),
            Some(old_root),
            Some(new_root),
            Some(old_hops),
            Some(new_hops),
            &mut local_work,
            output,
        )?;
        let mut before = Frontier::new(old.root(), &mut local_work)?;
        let mut after = Frontier::new(new.root(), &mut local_work)?;
        // Different root heights are real geometry changes. Unequal levels
        // encountered later are merely the two cursors expanding at different
        // times and must not be mislabeled boundary divergence.
        if old.root().level() != new.root().level() {
            let index = output.boundaries.len();
            local_work.open(old.root().level(), index)?;
            local_work.open(new.root().level(), index)?;
            output.boundaries.push(BoundaryRegion {
                old_hops: old_hops.to_vec(),
                new_hops: new_hops.to_vec(),
                old: before
                    .top()
                    .and_then(|part| part.cut(old_root))
                    .ok_or(Error::Source)?,
                new: after
                    .top()
                    .and_then(|part| part.cut(new_root))
                    .ok_or(Error::Source)?,
                start: local_work.work,
                end: local_work.work,
                resynchronization: Resynchronization::Tail,
            });
        }

        loop {
            match (before.top().cloned(), after.top().cloned()) {
                (None, None) => break,
                (None, Some(_)) => {
                    if let Some(item) = after.next(&mut local_work)? {
                        self.entry(
                            None,
                            Some(item),
                            old_root,
                            new_root,
                            old_hops,
                            new_hops,
                            &mut local_work,
                            output,
                        )?;
                    }
                }
                (Some(_), None) => {
                    if let Some(item) = before.next(&mut local_work)? {
                        self.entry(
                            Some(item),
                            None,
                            old_root,
                            new_root,
                            old_hops,
                            new_hops,
                            &mut local_work,
                            output,
                        )?;
                    }
                }
                (Some(left), Some(right)) => {
                    local_work.charge(
                        left.level().min(right.level()),
                        PhysicalEventKind::FrontierCheck,
                        1,
                    )?;
                    // Align physical heights before deciding membership. An
                    // unopened taller frontier can still contain the first
                    // affected cut and must not hide it behind cursor staging.
                    match left.level().cmp(&right.level()) {
                        Ordering::Less => {
                            after.expand(&mut local_work)?;
                            continue;
                        }
                        Ordering::Greater => {
                            before.expand(&mut local_work)?;
                            continue;
                        }
                        Ordering::Equal => {}
                    }
                    if let (
                        Part::Node {
                            node: l,
                            last: old_last,
                        },
                        Part::Node {
                            node: r,
                            last: new_last,
                        },
                    ) = (&left, &right)
                    {
                        if l.identity() == r.identity() {
                            local_work.charge(l.level(), PhysicalEventKind::SkippedSubtree, 1)?;
                            let cut = left.cut(old_root).ok_or(Error::Source)?;
                            if let Some(index) = local_work.owner(cut.level)? {
                                let region = &mut output.boundaries[index];
                                if region.old.level == cut.level && region.new.level == cut.level {
                                    region.resynchronization = Resynchronization::Equal(cut);
                                    local_work.close(l.level())?;
                                    region.end = local_work.work;
                                }
                            }
                            before.pop();
                            after.pop();
                            continue;
                        }
                        if l.level() == r.level()
                            && old_last != new_last
                            && local_work.owner(l.level())?.is_none()
                        {
                            let start = local_work.work;
                            let old_cut = left.cut(old_root).ok_or(Error::Source)?;
                            let new_cut = right.cut(new_root).ok_or(Error::Source)?;
                            local_work.open(l.level(), output.boundaries.len())?;
                            output.boundaries.push(BoundaryRegion {
                                old_hops: old_hops.to_vec(),
                                new_hops: new_hops.to_vec(),
                                old: old_cut,
                                new: new_cut,
                                start,
                                end: start,
                                resynchronization: Resynchronization::Tail,
                            });
                        }
                    }
                    local_work.charge(
                        left.level().min(right.level()),
                        PhysicalEventKind::Comparison,
                        1,
                    )?;
                    let old_first = left.key(&mut local_work)?;
                    let new_first = right.key(&mut local_work)?;
                    let ordering = old_first.cmp(&new_first);
                    if let (
                        Part::Node {
                            node: l,
                            last: old_last,
                        },
                        Part::Node {
                            node: r,
                            last: new_last,
                        },
                    ) = (&left, &right)
                        && l.level() == r.level()
                        && old_last == new_last
                        && old_first == new_first
                    {
                        // An independently changed next node need not have an
                        // equal digest for its canonical boundaries to recover.
                        if let Some(index) = local_work.owner(l.level())? {
                            let region = &mut output.boundaries[index];
                            if region.old.level == l.level() && region.new.level == r.level() {
                                region.resynchronization = Resynchronization::Aligned {
                                    old: left.cut(old_root).ok_or(Error::Source)?,
                                    new: right.cut(new_root).ok_or(Error::Source)?,
                                };
                                local_work.close(l.level())?;
                                region.end = local_work.work;
                            }
                        }
                    }
                    match ordering {
                        Ordering::Less => match left {
                            Part::Node { .. } => before.expand(&mut local_work)?,
                            Part::Item(item) => {
                                before.pop();
                                self.entry(
                                    Some(item),
                                    None,
                                    old_root,
                                    new_root,
                                    old_hops,
                                    new_hops,
                                    &mut local_work,
                                    output,
                                )?;
                            }
                        },
                        Ordering::Greater => match right {
                            Part::Node { .. } => after.expand(&mut local_work)?,
                            Part::Item(item) => {
                                after.pop();
                                self.entry(
                                    None,
                                    Some(item),
                                    old_root,
                                    new_root,
                                    old_hops,
                                    new_hops,
                                    &mut local_work,
                                    output,
                                )?;
                            }
                        },
                        Ordering::Equal => match (left, right) {
                            (Part::Node { node: left, .. }, Part::Node { node: right, .. }) => {
                                match left.level().cmp(&right.level()) {
                                    Ordering::Less => after.expand(&mut local_work)?,
                                    Ordering::Greater => before.expand(&mut local_work)?,
                                    Ordering::Equal => {
                                        before.expand(&mut local_work)?;
                                        after.expand(&mut local_work)?;
                                    }
                                }
                            }
                            (Part::Node { .. }, _) => before.expand(&mut local_work)?,
                            (_, Part::Node { .. }) => after.expand(&mut local_work)?,
                            (Part::Item(old), Part::Item(new)) => {
                                before.pop();
                                after.pop();
                                local_work.charge(0, PhysicalEventKind::Comparison, 1)?;
                                if old.entry != new.entry {
                                    self.entry(
                                        Some(old),
                                        Some(new),
                                        old_root,
                                        new_root,
                                        old_hops,
                                        new_hops,
                                        &mut local_work,
                                        output,
                                    )?;
                                }
                            }
                        },
                    }
                }
            }
        }
        // Finish all charged owner checks before snapshotting any tail. A
        // root-height region can own two levels and must contain both checks.
        let mut pending = [None; crate::tree_format::MAX_TREE_LEVEL as usize + 1];
        for level in 0..=old.root().level().max(new.root().level()) {
            pending[usize::from(level)] = local_work.owner(level)?;
        }
        for index in pending.into_iter().flatten() {
            output.boundaries[index].end = local_work.work;
        }
        finish(
            local_work,
            Some(old_root),
            Some(new_root),
            Some(old_hops),
            Some(new_hops),
            output,
        )?;
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "paired local source occurrences stay explicit"
    )]
    fn entry(
        &self,
        old: Option<&LeafItem<'a>>,
        new: Option<&LeafItem<'a>>,
        old_root: Digest,
        new_root: Digest,
        old_hops: &[Hop],
        new_hops: &[Hop],
        recorder: &mut Recorder,
        output: &mut Discovery<'graph, 'a>,
    ) -> Result<(), Error> {
        let old_address = old.map(|item| address(old_hops, old_root, &item.key));
        let new_address = new.map(|item| address(new_hops, new_root, &item.key));
        let old_child = graft(old.map(|item| &item.entry));
        let new_child = graft(new.map(|item| &item.entry));

        if let (Some(before), Some(after), Some(_old_item), Some(_new_item)) =
            (old_child, new_child, old, new)
        {
            self.pair(
                before,
                after,
                old_address.as_deref().ok_or(Error::Source)?,
                new_address.as_deref().ok_or(Error::Source)?,
                output,
            )?;
        } else {
            if let Some(child) = old_child {
                self.population(
                    child,
                    old_address.as_deref().ok_or(Error::Source)?,
                    false,
                    output,
                )?;
            }
            if let Some(child) = new_child {
                self.population(
                    child,
                    new_address.as_deref().ok_or(Error::Source)?,
                    true,
                    output,
                )?;
            }
        }
        output.inputs.push(InputChange {
            old_address: old_address.clone(),
            new_address: new_address.clone(),
            old: old.map(|item| item.entry.clone()),
            new: new.map(|item| item.entry.clone()),
        });
        if !self.data_changes {
            return Ok(());
        }
        let before = state(self.old, old.map(|item| &item.entry));
        let after = state(self.new, new.map(|item| &item.entry));
        recorder.charge(0, PhysicalEventKind::Comparison, 1)?;
        if before != after {
            output.data.push(DataChange {
                old_address: before.as_ref().and(old_address),
                new_address: after.as_ref().and(new_address),
                old: before,
                new: after,
            });
        }
        Ok(())
    }

    fn population(
        &self,
        root: Digest,
        hops: &[Hop],
        added: bool,
        output: &mut Discovery<'graph, 'a>,
    ) -> Result<(), Error> {
        let source = if added { self.new } else { self.old };
        let tree = source.tree(root, &mut output.source_lookups)?;
        let mut recorder = Recorder::new();
        properties(
            (!added).then_some(tree.root().level()),
            added.then_some(tree.root().level()),
            if added { None } else { tree.props() },
            if added { tree.props() } else { None },
            (!added).then_some(root),
            added.then_some(root),
            (!added).then_some(hops),
            added.then_some(hops),
            &mut recorder,
            output,
        )?;
        let mut frontier = Frontier::new(tree.root(), &mut recorder)?;
        while let Some(item) = frontier.next(&mut recorder)? {
            self.entry(
                (!added).then_some(item),
                added.then_some(item),
                root,
                root,
                hops,
                hops,
                &mut recorder,
                output,
            )?;
        }
        finish(
            recorder,
            (!added).then_some(root),
            added.then_some(root),
            (!added).then_some(hops),
            added.then_some(hops),
            output,
        )?;
        Ok(())
    }
}

fn graft(entry: Option<&Entry<'_>>) -> Option<Digest> {
    match entry.map(|entry| &entry.kind) {
        Some(EntryKind::Tree { root, .. }) => Some(*root),
        _ => None,
    }
}

fn address(hops: &[Hop], source: Digest, key: &[u8]) -> Address {
    let mut address = hops.to_vec();
    address.push(Hop {
        source,
        key: key.to_vec(),
    });
    address
}

fn state(source: &PreparedSource<'_, '_>, entry: Option<&Entry<'_>>) -> Option<FileState> {
    match entry {
        Some(
            entry @ Entry {
                kind: EntryKind::File { content, .. },
                ..
            },
        ) => Some(FileState {
            content: *content,
            value: source.value(entry).map(<[u8]>::to_vec),
        }),
        _ => None,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "property events retain independently selected source sides"
)]
fn properties<'graph, 'a>(
    old_level: Option<u8>,
    new_level: Option<u8>,
    old: Option<&[Property<'a>]>,
    new: Option<&[Property<'a>]>,
    old_root: Option<Digest>,
    new_root: Option<Digest>,
    old_hops: Option<&[Hop]>,
    new_hops: Option<&[Hop]>,
    recorder: &mut Recorder,
    output: &mut Discovery<'graph, 'a>,
) -> Result<(), Error> {
    let old = old.unwrap_or_default();
    let new = new.unwrap_or_default();
    // Canonical CBOR text keys sort by encoded length, then bytes.
    let mut before = old.iter().peekable();
    let mut after = new.iter().peekable();
    recorder.charge(
        old_level.unwrap_or_default(),
        PhysicalEventKind::PropertyRead,
        old.len(),
    )?;
    recorder.charge(
        new_level.unwrap_or_default(),
        PhysicalEventKind::PropertyRead,
        new.len(),
    )?;
    let comparison_level = old_level
        .into_iter()
        .chain(new_level)
        .min()
        .unwrap_or_default();
    while before.peek().is_some() || after.peek().is_some() {
        let ordering = match (before.peek(), after.peek()) {
            (Some(left), Some(right)) => {
                recorder.charge(comparison_level, PhysicalEventKind::Comparison, 1)?;
                left.name
                    .len()
                    .cmp(&right.name.len())
                    .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let (previous, replacement) = match ordering {
            Ordering::Less => (before.next().copied(), None),
            Ordering::Greater => (None, after.next().copied()),
            Ordering::Equal => {
                recorder.charge(comparison_level, PhysicalEventKind::Comparison, 1)?;
                (before.next().copied(), after.next().copied())
            }
        };
        if previous != replacement {
            output.properties.push(PropertyChange {
                old_hops: old_hops.map(<[_]>::to_vec),
                new_hops: new_hops.map(<[_]>::to_vec),
                old_root,
                new_root,
                old: previous,
                new: replacement,
            });
        }
    }
    Ok(())
}

fn finish<'graph, 'a>(
    recorder: Recorder,
    old_root: Option<Digest>,
    new_root: Option<Digest>,
    old_hops: Option<&[Hop]>,
    new_hops: Option<&[Hop]>,
    output: &mut Discovery<'graph, 'a>,
) -> Result<(), Error> {
    output.work.combine(recorder.work)?;
    output.streams.push(StreamWork {
        old_root,
        new_root,
        old_hops: old_hops.map(<[_]>::to_vec),
        new_hops: new_hops.map(<[_]>::to_vec),
        work: recorder.work,
        events: recorder.events,
    });
    Ok(())
}

fn initialize<'graph, 'a>(
    source: &PreparedSource<'graph, 'a>,
    root: Digest,
    hops: &[Hop],
    output: &mut Discovery<'graph, 'a>,
) -> Result<(), Error> {
    let tree = source.tree(root, &mut output.initialization.source_lookups)?;
    let mut recorder = Recorder::new();
    let mut frontier = Frontier::new(tree.root(), &mut recorder)?;
    while let Some(item) = frontier.next(&mut recorder)? {
        let occurrence = address(hops, root, &item.key);
        match &item.entry.kind {
            EntryKind::Tree { root, .. } => initialize(source, *root, &occurrence, output)?,
            EntryKind::File { .. } => {
                output.data.push(DataChange {
                    old_address: None,
                    new_address: Some(occurrence),
                    old: None,
                    new: state(source, Some(&item.entry)),
                });
            }
            _ => {}
        }
    }
    output.initialization.work.combine(recorder.work)?;
    output.initialization.streams.push(StreamWork {
        old_root: None,
        new_root: Some(root),
        old_hops: None,
        new_hops: Some(hops.to_vec()),
        events: recorder.events,
        work: recorder.work,
    });
    Ok(())
}
