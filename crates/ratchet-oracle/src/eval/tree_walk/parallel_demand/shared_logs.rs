//! Append-only shared logs behind every parallel worker's prefix replica.
//!
//! Each log pairs an authoritative mutex-guarded store with a release-stored
//! version counter so workers can verify replica freshness with one acquire
//! load before taking the lock (see the parent module's replica
//! synchronization notes).

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::syntax::AstError;

use super::*;

/// The append-only shared symbol log behind every worker's prefix replica.
#[derive(Debug, Default)]
pub(crate) struct SharedSymbolLog {
    /// Published length of `table`; release-stored after each append batch.
    version: AtomicUsize,
    /// The authoritative global symbol table.
    table: Mutex<SymbolTable>,
}

impl SharedSymbolLog {
    /// Seeds the log with the main evaluator's initial symbol table.
    pub(super) fn seed(table: SymbolTable) -> Self {
        let version = AtomicUsize::new(table.len());
        Self {
            version,
            table: Mutex::new(table),
        }
    }

    /// Appends the log's unseen suffix to a worker's prefix replica.
    pub(super) fn sync_into(&self, local: &mut SymbolTable) {
        if self.version.load(Ordering::Acquire) <= local.len() {
            return;
        }
        let table = recover(self.table.lock());
        for bytes in &table.symbols()[local.len()..] {
            if local.intern(bytes).is_err() {
                tracing::warn!(
                    target: "aos_nix::eval::parallel",
                    "shared symbol log sync aborted: local replica is full"
                );
                return;
            }
        }
    }

    /// Interns `bytes` in the shared log and mirrors it into `local`.
    ///
    /// The local replica is first synchronized to the log tip so the new
    /// symbol receives the same dense id on every worker.
    pub(super) fn intern(&self, local: &mut SymbolTable, bytes: &[u8]) -> Result<Symbol, AstError> {
        let mut table = recover(self.table.lock());
        for text in &table.symbols()[local.len()..] {
            local.intern(text)?;
        }
        let symbol = table.intern(bytes)?;
        let local_symbol = local.intern(bytes)?;
        debug_assert_eq!(symbol, local_symbol, "prefix replica diverged from log");
        self.version.store(table.len(), Ordering::Release);
        Ok(symbol)
    }
}

/// The append-only shared registry of lowered modules.
///
/// Entry `i` is the module with [`EvalModuleId`] `i`; every worker's local
/// module vector is a prefix replica cloned from here.
#[derive(Debug, Default)]
pub(crate) struct SharedModuleRegistry {
    /// Published length of `entries`; release-stored after each append.
    version: AtomicUsize,
    entries: Mutex<Vec<TreeWalkModule>>,
}

impl SharedModuleRegistry {
    /// Seeds the registry with the main evaluator's modules (the root module).
    pub(super) fn seed(modules: &[TreeWalkModule]) -> Self {
        let entries = modules.to_vec();
        Self {
            version: AtomicUsize::new(entries.len()),
            entries: Mutex::new(entries),
        }
    }

    /// Clones the registry's unseen suffix onto a worker's local vector.
    pub(super) fn sync_into(&self, local: &mut Vec<TreeWalkModule>) {
        if self.version.load(Ordering::Acquire) <= local.len() {
            return;
        }
        let entries = recover(self.entries.lock());
        local.extend_from_slice(&entries[local.len()..]);
    }

    /// Publishes `module` under the next global id and installs it locally.
    ///
    /// The local vector is first synchronized so the freshly published module
    /// lands at the same index globally and locally. Returns the module id,
    /// or `None` if the id space is exhausted.
    pub(super) fn publish(
        &self,
        local: &mut Vec<TreeWalkModule>,
        module: TreeWalkModule,
    ) -> Option<u32> {
        let mut entries = recover(self.entries.lock());
        if entries.len() > local.len() {
            local.extend_from_slice(&entries[local.len()..]);
        }
        let raw = u32::try_from(entries.len()).ok()?;
        entries.push(module.clone());
        local.push(module);
        self.version.store(entries.len(), Ordering::Release);
        Some(raw)
    }
}

/// The append-only shared log of `.drv` surfaces recorded by any worker.
#[derive(Debug, Default)]
pub(crate) struct SharedKnownDerivationLog {
    version: AtomicUsize,
    log: Mutex<Vec<(nix_compat::store_path::StorePath<String>, KnownDerivation)>>,
}

impl SharedKnownDerivationLog {
    /// Publishes one known derivation for other workers to adopt.
    pub(super) fn publish(
        &self,
        path: &nix_compat::store_path::StorePath<String>,
        known: &KnownDerivation,
    ) {
        let mut log = recover(self.log.lock());
        log.push((path.clone(), known.clone()));
        self.version.store(log.len(), Ordering::Release);
    }

    /// Merges log entries past `cursor` into a worker's local map.
    pub(super) fn sync_into(
        &self,
        cursor: &mut usize,
        local: &mut BTreeMap<nix_compat::store_path::StorePath<String>, KnownDerivation>,
    ) {
        if self.version.load(Ordering::Acquire) <= *cursor {
            return;
        }
        let log = recover(self.log.lock());
        for (path, known) in &log[*cursor..] {
            local.entry(path.clone()).or_insert_with(|| known.clone());
        }
        *cursor = log.len();
    }
}

/// The append-only shared log of `builtins.toFile` texts.
#[derive(Debug, Default)]
pub(crate) struct SharedTextStoreLog {
    version: AtomicUsize,
    log: Mutex<Vec<(Vec<u8>, TextStoreEntry)>>,
}

impl SharedTextStoreLog {
    /// Publishes one text-store entry for other workers to adopt.
    pub(super) fn publish(&self, path: &[u8], entry: &TextStoreEntry) {
        let mut log = recover(self.log.lock());
        log.push((path.to_vec(), entry.clone()));
        self.version.store(log.len(), Ordering::Release);
    }

    /// Merges log entries past `cursor` into a worker's local map.
    pub(super) fn sync_into(
        &self,
        cursor: &mut usize,
        local: &mut BTreeMap<Vec<u8>, TextStoreEntry>,
    ) {
        if self.version.load(Ordering::Acquire) <= *cursor {
            return;
        }
        let log = recover(self.log.lock());
        for (path, entry) in &log[*cursor..] {
            local.entry(path.clone()).or_insert_with(|| entry.clone());
        }
        *cursor = log.len();
    }
}
