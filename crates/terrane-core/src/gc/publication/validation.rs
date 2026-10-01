//! Checks publication fields and represented cross-record relationships.
//!
//! Syntax and equality never establish resource ownership or external evidence.

use super::*;
use crate::{
    bucket::BucketKey,
    refs::{RefClass, RefName},
};

/// Checks normalized local bytes and registered remote field bounds.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn binding(binding: &BackendBinding) -> Result<(), PublicationError> {
    match binding {
        BackendBinding::Local { root, .. } => {
            if root.first() != Some(&b'/') || root.contains(&0) {
                return Err(PublicationError::Schema);
            }
            if root.len() > 1
                && root[1..]
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || part == b"." || part == b"..")
            {
                return Err(PublicationError::Schema);
            }
        }
        BackendBinding::Remote {
            endpoint,
            bucket,
            prefix,
            coordination_key,
            ..
        } => {
            if endpoint.is_empty()
                || endpoint.len() > 4096
                || bucket.is_empty()
                || bucket.len() > 4096
                || prefix.len() > 4096
                || coordination_key.is_empty()
                || coordination_key.len() > 4096
            {
                return Err(PublicationError::Schema);
            }
            // Provider-specific resource alias checks require configured evidence.
            // Exact UTF-8 and bytes here are retained without URL normalization.
        }
    }
    Ok(())
}

fn sorted<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), PublicationError> {
    let mut previous: Option<&str> = None;
    for name in names {
        if previous.is_some_and(|prior| prior.as_bytes() >= name.as_bytes()) {
            return Err(PublicationError::Schema);
        }
        previous = Some(name);
    }
    Ok(())
}

fn branch(name: &str) -> Result<(), PublicationError> {
    let name = RefName::parse(name).map_err(|_| PublicationError::Schema)?;
    if !matches!(
        name.class(),
        RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
    ) {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

/// Checks sorted unique branch names without selecting history.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn history(rows: &[HistoryEntry]) -> Result<(), PublicationError> {
    sorted(rows.iter().map(|row| row.name.as_str()))?;
    for row in rows {
        branch(&row.name)?;
    }
    Ok(())
}

/// Checks sorted unique source ref names without checking lineage.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn sources(rows: &[SourceLineage]) -> Result<(), PublicationError> {
    sorted(rows.iter().map(|row| row.name.as_str()))?;
    for row in rows {
        let name = RefName::parse(&row.name).map_err(|_| PublicationError::Schema)?;
        if name.class() == RefClass::Notes {
            return Err(PublicationError::Schema);
        }
    }
    Ok(())
}

fn decimal(value: &str) -> Result<u64, PublicationError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PublicationError::Schema);
    }
    value.parse().map_err(|_| PublicationError::Schema)
}

fn nonce(value: &str) -> Result<[u8; 32], PublicationError> {
    if value.len() != 64 {
        return Err(PublicationError::Schema);
    }
    let mut nonce = [0; 32];
    for (byte, pair) in nonce.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        fn digit(value: u8) -> Result<u8, PublicationError> {
            match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err(PublicationError::Schema),
            }
        }
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(nonce)
}

/// Parses only the registered transaction key and nonce spelling.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn transaction_key(key: &str) -> Result<[u8; 32], PublicationError> {
    nonce(
        key.strip_prefix("publication/transactions/")
            .ok_or(PublicationError::Schema)?,
    )
}

/// Parses only the registered snapshot revision and nonce spelling.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn snapshot_key(key: &str) -> Result<(u64, [u8; 32]), PublicationError> {
    let suffix = key
        .strip_prefix("publication/snapshots/")
        .ok_or(PublicationError::Schema)?;
    let (revision, operation) = suffix.split_once(':').ok_or(PublicationError::Schema)?;
    Ok((decimal(revision)?, nonce(operation)?))
}

/// Checks only the registered Fence key spelling.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn fence_key(key: &str) -> Result<(), PublicationError> {
    let mut parts = key.split('/');
    if parts.next() != Some("gc") {
        return Err(PublicationError::Schema);
    }
    decimal(parts.next().ok_or(PublicationError::Schema)?)?;
    if parts.next() != Some("fence") {
        return Err(PublicationError::Schema);
    }
    decimal(parts.next().ok_or(PublicationError::Schema)?)?;
    if parts.next().is_some() {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn logical_key(key: &str) -> Result<(), PublicationError> {
    if key == "publication/SELECTED-HISTORY" {
        return Ok(());
    }
    BucketKey::parse(key).map_err(|_| PublicationError::Schema)?;
    // Unsuffixed refs are exclusively read-only legacy names. A protected
    // deletion intent is never a selected logical payload value.
    if key.starts_with("refs/") && !key.ends_with(":record")
        || key.starts_with("gc/") && key.contains("/delete/")
    {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn projection_key(key: &str) -> Result<(), PublicationError> {
    logical_key(key)?;
    if !(key == "CAPABILITIES"
        || key == "publication/SELECTED-HISTORY"
        || key == "gc/lease"
        || key.starts_with("refs/")
        || key.starts_with("objects/index/"))
    {
        return Err(PublicationError::Schema);
    }
    Ok(())
}

fn whole_ref(key: &str, value: Option<&[u8]>) -> Result<Option<RefRecord>, PublicationError> {
    if key.starts_with("refs/") && !key.starts_with("refs/notes/") {
        return value.map(RefRecord::decode).transpose().map_err(Into::into);
    }
    Ok(None)
}

/// Checks projection shape and represented checkpoint consistency.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn snapshot(record: &PortableSnapshot) -> Result<(), PublicationError> {
    binding(&record.origin)?;
    sorted(record.projection.iter().map(|row| row.key.as_str()))?;
    if let Some(previous) = &record.predecessor {
        let (revision, _) = snapshot_key(&previous.key)?;
        if revision.checked_add(1).ok_or(PublicationError::Exhausted)? != record.revision {
            return Err(PublicationError::Contradiction);
        }
    }

    let mut selected_history = None;
    for row in &record.projection {
        projection_key(&row.key)?;
        whole_ref(&row.key, row.value.as_deref())?;
        if row.key == "gc/lease" && row.value.is_some() {
            return Err(PublicationError::Contradiction);
        }
        if row.key == "publication/SELECTED-HISTORY" {
            let history = SelectedHistory::decode(
                row.value
                    .as_deref()
                    .ok_or(PublicationError::Contradiction)?,
            )?;
            if history.origin != record.origin {
                return Err(PublicationError::Contradiction);
            }
            selected_history = Some(history);
        }
    }

    if record.predecessor.is_none() {
        if !record
            .projection
            .iter()
            .any(|row| row.key == "CAPABILITIES" && row.value.is_some())
            || !record.projection.iter().any(|row| row.key == "gc/lease")
            || selected_history.is_none()
        {
            return Err(PublicationError::Contradiction);
        }
        if let Some(history) = selected_history {
            for row in &history.branches {
                let key = alloc::format!("{}:record", row.name);
                if !record.projection.iter().any(|entry| entry.key == key) {
                    return Err(PublicationError::Contradiction);
                }
            }
            for row in &record.projection {
                if let Some(name) = row.key.strip_suffix(":record")
                    && branch(name).is_ok()
                {
                    let selection = history
                        .branches
                        .iter()
                        .find(|entry| entry.name == name)
                        .ok_or(PublicationError::Contradiction)?;
                    if let Some(current) = whole_ref(&row.key, row.value.as_deref())?
                        && selection.selection != CommittedSelection::Selected(current.into())
                    {
                        return Err(PublicationError::Contradiction);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Checks source and retained-history shape without authenticating evidence.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn state(record: &PublicationState) -> Result<(), PublicationError> {
    binding(&record.binding)?;
    history(&record.branches)?;
    sources(&record.sources)?;
    if record.guard.is_none() && !record.sources.is_empty() {
        return Err(PublicationError::Contradiction);
    }
    for source in &record.sources {
        if branch(&source.name).is_ok()
            && !record.branches.iter().any(|row| {
                row.name == source.name && matches!(row.selection, CommittedSelection::Selected(_))
            })
        {
            return Err(PublicationError::Contradiction);
        }
    }
    Ok(())
}

/// Checks proof-reference shape without granting private capabilities.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn proof(proof: &PublicationProof) -> Result<(), PublicationError> {
    if let PublicationProof::Collection {
        fence_key: key,
        removed,
        carried,
        ..
    } = proof
    {
        fence_key(key)?;
        sources(carried)?;
        let mut packs = alloc::collections::BTreeMap::new();
        for row in removed {
            if packs
                .insert(row.pack, row.index)
                .is_some_and(|prior| prior != row.index)
            {
                return Err(PublicationError::Contradiction);
            }
        }
    }
    Ok(())
}

fn next_history(
    old: &PublicationState,
    new: &PublicationState,
    changes: &[LogicalChange],
) -> Result<(), PublicationError> {
    for prior in &old.branches {
        if !new.branches.iter().any(|row| row.name == prior.name) {
            return Err(PublicationError::Contradiction);
        }
    }
    for row in &new.branches {
        let prior = old.branches.iter().find(|prior| prior.name == row.name);
        if prior.is_some_and(|prior| prior.selection == row.selection) {
            continue;
        }
        match (&row.selection, prior.map(|prior| &prior.selection)) {
            (CommittedSelection::Unknown, _) => return Err(PublicationError::Contradiction),
            (CommittedSelection::Never, Some(CommittedSelection::Selected(_))) => {
                return Err(PublicationError::Contradiction);
            }
            (CommittedSelection::Selected(next), Some(CommittedSelection::Selected(previous))) => {
                if previous
                    .seq
                    .checked_add(1)
                    .ok_or(PublicationError::Exhausted)?
                    != next.seq
                    || next.writer_epoch < previous.writer_epoch
                {
                    return Err(PublicationError::Contradiction);
                }
                // Home changes require independently checked migration authority.
            }
            (CommittedSelection::Selected(next), None | Some(CommittedSelection::Never))
                if next.seq != 1 =>
            {
                return Err(PublicationError::Contradiction);
            }
            _ => {}
        }
        if let CommittedSelection::Selected(next) = &row.selection {
            if next.candidate_id.is_none()
                && !prior
                    .is_some_and(|prior| matches!(prior.selection, CommittedSelection::Unknown))
            {
                return Err(PublicationError::Contradiction);
            }
            let key = alloc::format!("{}:record", row.name);
            let change = changes
                .iter()
                .find(|change| change.key == key)
                .ok_or(PublicationError::Contradiction)?;
            if whole_ref(&key, change.new.as_deref())? != Some(next.as_ref().clone()) {
                return Err(PublicationError::Contradiction);
            }
        }
    }
    Ok(())
}

/// Checks proposed fields and represented old/new relationships.
///
/// # Errors
/// Rejects invalid field shapes or represented contradictions.
pub(super) fn transaction(record: &PublicationTransaction) -> Result<(), PublicationError> {
    state(&record.new)?;
    proof(&record.proof)?;
    sorted(record.changes.iter().map(|row| row.key.as_str()))?;
    let (revision, operation) = snapshot_key(&record.snapshot.key)?;
    if revision != record.new.revision || operation != record.nonce {
        return Err(PublicationError::Contradiction);
    }

    match (&record.old, &record.predecessor) {
        (None, None) => {
            if record.new.revision != 0 || record.changes.iter().any(|row| row.expected.is_some()) {
                return Err(PublicationError::Contradiction);
            }
            if !record
                .changes
                .iter()
                .any(|row| row.key == "CAPABILITIES" && row.new.is_some())
                || !record.changes.iter().any(|row| row.key == "gc/lease")
                || !record
                    .changes
                    .iter()
                    .any(|row| row.key == "publication/SELECTED-HISTORY")
            {
                return Err(PublicationError::Contradiction);
            }
            for branch in &record.new.branches {
                let key = alloc::format!("{}:record", branch.name);
                if !record.changes.iter().any(|row| row.key == key) {
                    return Err(PublicationError::Contradiction);
                }
            }
        }
        (Some(old), Some(previous)) => {
            state(old)?;
            if old
                .revision
                .checked_add(1)
                .ok_or(PublicationError::Exhausted)?
                != record.new.revision
                || previous.revision != old.revision
                || old.binding != record.new.binding
                || record.new.loss_generation < old.loss_generation
            {
                return Err(PublicationError::Contradiction);
            }
            next_history(old, &record.new, &record.changes)?;
            transition_proof(old, &record.new, &record.proof, &record.changes)?;
        }
        _ => return Err(PublicationError::Contradiction),
    }

    for row in &record.changes {
        logical_key(&row.key)?;
        let current = whole_ref(&row.key, row.new.as_deref())?;
        let previous = whole_ref(&row.key, row.expected.as_deref())?;
        if let Some(name) = row.key.strip_suffix(":record")
            && branch(name).is_ok()
        {
            let retained = record
                .new
                .branches
                .iter()
                .find(|branch| branch.name == name)
                .ok_or(PublicationError::Contradiction)?;
            if let Some(current) = current
                && retained.selection != CommittedSelection::Selected(current.into())
            {
                return Err(PublicationError::Contradiction);
            }
            if let (Some(old), Some(previous)) = (&record.old, previous)
                && !old.branches.iter().any(|branch| {
                    branch.name == name
                        && branch.selection == CommittedSelection::Selected(previous.clone().into())
                })
            {
                return Err(PublicationError::Contradiction);
            }
        }
        if row.key == "publication/SELECTED-HISTORY" {
            let next = SelectedHistory::decode(
                row.new.as_deref().ok_or(PublicationError::Contradiction)?,
            )?;
            if next.origin != record.new.binding || next.branches != record.new.branches {
                return Err(PublicationError::Contradiction);
            }
            if let Some(old) = &record.old {
                let previous = SelectedHistory::decode(
                    row.expected
                        .as_deref()
                        .ok_or(PublicationError::Contradiction)?,
                )?;
                if previous.origin != old.binding || previous.branches != old.branches {
                    return Err(PublicationError::Contradiction);
                }
            }
        }
    }
    if (record
        .old
        .as_ref()
        .is_none_or(|old| old.branches != record.new.branches)
        || record.changes.iter().any(|change| {
            change
                .key
                .strip_suffix(":record")
                .is_some_and(|name| branch(name).is_ok())
        }))
        && !record
            .changes
            .iter()
            .any(|row| row.key == "publication/SELECTED-HISTORY")
    {
        return Err(PublicationError::Contradiction);
    }
    Ok(())
}

fn transition_proof(
    old: &PublicationState,
    new: &PublicationState,
    proof: &PublicationProof,
    changes: &[LogicalChange],
) -> Result<(), PublicationError> {
    if !matches!(proof, PublicationProof::Guard(_)) && old.guard != new.guard {
        return Err(PublicationError::Contradiction);
    }
    match proof {
        PublicationProof::Raw => {
            for source in &new.sources {
                if old.loss_generation != new.loss_generation
                    || !old.sources.contains(source)
                    || changes
                        .iter()
                        .any(|change| change.key == alloc::format!("{}:record", source.name))
                {
                    return Err(PublicationError::Contradiction);
                }
            }
        }
        PublicationProof::Candidate(candidate) => {
            if old.loss_generation != new.loss_generation {
                return Err(PublicationError::Contradiction);
            }
            let added: Vec<_> = new
                .sources
                .iter()
                .filter(|row| !old.sources.contains(row))
                .collect();
            if added.len() != 1 || added[0].digest != *candidate {
                return Err(PublicationError::Contradiction);
            }
            for source in new.sources.iter().filter(|row| old.sources.contains(row)) {
                if changes
                    .iter()
                    .any(|change| change.key == alloc::format!("{}:record", source.name))
                {
                    return Err(PublicationError::Contradiction);
                }
            }
        }
        PublicationProof::Collection {
            removed, carried, ..
        } => {
            if !removed.is_empty()
                && old
                    .loss_generation
                    .checked_add(1)
                    .ok_or(PublicationError::Exhausted)?
                    != new.loss_generation
            {
                return Err(PublicationError::Contradiction);
            }
            if new.sources.len() != carried.len() {
                return Err(PublicationError::Contradiction);
            }
            for (next, prior) in new.sources.iter().zip(carried) {
                if next.name != prior.name || !old.sources.contains(prior) {
                    return Err(PublicationError::Contradiction);
                }
            }
        }
        PublicationProof::Guard(guard) => {
            if new.guard != Some(*guard) || old.loss_generation != new.loss_generation {
                return Err(PublicationError::Contradiction);
            }
        }
    }
    Ok(())
}

impl BackendRegistration {
    /// Checks that recorded activation preserves binding and an existing genesis.
    ///
    /// This checks data only and cannot authenticate either registration.
    ///
    /// # Errors
    /// Rejects changed bindings or genesis, Active regression, and Active absence.
    pub fn check_successor(&self, next: &Self) -> Result<(), PublicationError> {
        self.encode()?;
        next.encode()?;
        if self.binding != next.binding
            || self.genesis.is_some() && self.genesis != next.genesis
            || self.activation == Activation::Active && next.activation != Activation::Active
        {
            return Err(PublicationError::Contradiction);
        }
        Ok(())
    }
}

impl PublicationTransaction {
    /// Checks the proposed transaction against an exact immutable key spelling.
    ///
    /// # Errors
    /// Rejects an invalid transaction key or a nonce mismatch.
    pub fn check_key(&self, key: &str) -> Result<(), PublicationError> {
        if transaction_key(key)? != self.nonce {
            return Err(PublicationError::Contradiction);
        }
        Ok(())
    }

    /// Checks the staged snapshot's bytes, origin, revision and exact digest.
    ///
    /// Predecessor-chain resolution and payload closure still require evidence.
    ///
    /// # Errors
    /// Rejects malformed snapshots, wrong selectors, contradictory projection
    /// changes in checkpoints or deltas, or disagreement with selected state.
    pub fn check_snapshot(&self, bytes: &[u8]) -> Result<(), PublicationError> {
        self.snapshot.check_snapshot(bytes)?;
        let (_, operation) = snapshot_key(&self.snapshot.key)?;
        if operation != self.nonce {
            return Err(PublicationError::Contradiction);
        }

        let snapshot = PortableSnapshot::decode(bytes)?;
        if blake3::hash(bytes).as_bytes() != &self.snapshot.digest
            || snapshot.revision != self.new.revision
            || snapshot.origin != self.new.binding
        {
            return Err(PublicationError::Contradiction);
        }
        if self.old.is_none() && snapshot.predecessor.is_some() {
            return Err(PublicationError::Contradiction);
        }
        for row in &snapshot.projection {
            if row.key == "publication/SELECTED-HISTORY" {
                let history = SelectedHistory::decode(
                    row.value
                        .as_deref()
                        .ok_or(PublicationError::Contradiction)?,
                )?;
                if history.branches != self.new.branches {
                    return Err(PublicationError::Contradiction);
                }
            }
            if snapshot.predecessor.is_some()
                && row.key != "gc/lease"
                && !self
                    .changes
                    .iter()
                    .any(|change| change.key == row.key && change.new == row.value)
            {
                return Err(PublicationError::Contradiction);
            }
            if let Some(change) = self.changes.iter().find(|change| change.key == row.key)
                && row.key != "gc/lease"
                && change.new != row.value
            {
                return Err(PublicationError::Contradiction);
            }
        }
        // Both checkpoints and deltas must include every represented payload
        // change. Checkpoints may additionally retain unchanged selected values.
        for change in &self.changes {
            if projection_key(&change.key).is_ok()
                && change.key != "gc/lease"
                && !snapshot
                    .projection
                    .iter()
                    .any(|row| row.key == change.key && row.value == change.new)
            {
                return Err(PublicationError::Contradiction);
            }
        }
        Ok(())
    }
}

impl PublicationCommit {
    /// Checks exact slot spelling and canonical transaction bytes against this slot.
    ///
    /// # Errors
    /// Rejects invalid slot names, nonce/digest/revision disagreement, and an
    /// exact predecessor digest that disagrees with the transaction.
    pub fn check_transaction(&self, key: &str, bytes: &[u8]) -> Result<(), PublicationError> {
        if decimal(
            key.strip_prefix("publication/commits/")
                .ok_or(PublicationError::Schema)?,
        )? != self.revision
        {
            return Err(PublicationError::Contradiction);
        }
        let transaction = PublicationTransaction::decode(bytes)?;
        transaction.check_key(&self.transaction_key)?;
        if blake3::hash(bytes).as_bytes() != &self.transaction_digest
            || transaction.new.revision != self.revision
            || transaction.predecessor.as_ref().map(|slot| slot.digest) != self.predecessor
        {
            return Err(PublicationError::Contradiction);
        }
        Ok(())
    }
}

impl PortableCurrent {
    /// Checks exact snapshot bytes against the portable pointer's key and digest.
    ///
    /// This checks a named record only, without selecting publication authority.
    ///
    /// # Errors
    /// Rejects malformed snapshots, revision mismatch, or raw digest disagreement.
    pub fn check_snapshot(&self, bytes: &[u8]) -> Result<(), PublicationError> {
        let (revision, _) = snapshot_key(&self.key)?;
        let snapshot = PortableSnapshot::decode(bytes)?;
        if revision != snapshot.revision || blake3::hash(bytes).as_bytes() != &self.digest {
            return Err(PublicationError::Contradiction);
        }
        Ok(())
    }
}

impl PortableSnapshot {
    /// Checks one exact represented predecessor without resolving its ancestors.
    ///
    /// The caller must independently bind this pointer to the selected preceding
    /// transaction. This equality check does not authenticate chain selection.
    ///
    /// # Errors
    /// Rejects a checkpoint, pointer mismatch, invalid predecessor bytes, origin
    /// change, or a revision that cannot advance by exactly one.
    pub fn check_predecessor(
        &self,
        pointer: &PortableCurrent,
        bytes: &[u8],
    ) -> Result<(), PublicationError> {
        if self.predecessor.as_ref() != Some(pointer) {
            return Err(PublicationError::Contradiction);
        }
        pointer.check_snapshot(bytes)?;
        let previous = PortableSnapshot::decode(bytes)?;
        if previous.origin != self.origin
            || previous
                .revision
                .checked_add(1)
                .ok_or(PublicationError::Exhausted)?
                != self.revision
        {
            return Err(PublicationError::Contradiction);
        }
        Ok(())
    }
}
