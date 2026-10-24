//! Orders genuine first claims and durable intent before native enrollment setters.

use super::super::{ProvisioningPhase, claims, load, retain};
use super::{capture, model::*, plan, storage};
use std::{fs, io, os::unix::fs::MetadataExt, path::Path};
use terrane_linux::host_quota::initial_enrollment::{InitialCustody, NativeInitialHostScaffold};
use terrane_linux::host_quota::{DomainProvisioningGuard, open_host_path, require_unused_project};
use terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment;

fn native_custody(custody: Custody) -> InitialCustody {
    InitialCustody {
        uid: custody.uid,
        gid: custody.gid,
        mode: custody.mode,
    }
}

/// Enrolls an entire fresh configured partition under protected explicit role intent.
///
/// Each receipt must come from the actual absent-root creator. Complete original
/// and created inode records become permanent global claims and a durable
/// provisioning ledger before the first project or custody setter. This is a
/// one-shot operation: interrupted attempts remain incomplete and require a
/// separately reviewed administrative recovery procedure.
///
/// # Errors
/// Refuses existing ledgers, incomplete or mismatched creators, unsafe role or
/// namespace configuration, reused projects, stale receipts, and native or
/// durability failures. Partial effects never produce a ready ledger.
pub fn provision(
    config_path: &Path,
    ledger_path: &Path,
    role_plan_path: &Path,
    initial: Vec<NativeInitialBucketEnrollment>,
) -> io::Result<()> {
    terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
    let config = load(config_path)?;
    let roles = plan::load(role_plan_path, &config)?;
    super::preflight::check(&config, &roles, &initial)?;
    if initial.len() != config.owners.len() {
        return Err(io::Error::other(
            "initial creator count differs from complete partition",
        ));
    }
    if config
        .owners
        .iter()
        .flat_map(|owner| &owner.roots)
        .any(|root| ledger_path.starts_with(&root.path) || role_plan_path.starts_with(&root.path))
    {
        return Err(io::Error::other(
            "administrative ledger and role plan must be outside every allocation root",
        ));
    }
    let parent = ledger_path
        .parent()
        .ok_or_else(|| io::Error::other("initial ledger has no parent"))?;
    let directory = open_host_path(parent, true)?;
    if directory.metadata()?.uid() != 0 || directory.metadata()?.mode() & 0o022 != 0 {
        return Err(io::Error::other("initial ledger parent is not protected"));
    }
    let _ledger_guard = DomainProvisioningGuard::exclusive(&directory)?;
    match fs::symlink_metadata(ledger_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(io::Error::other(
                "initial enrollment never replays an existing ledger",
            ));
        }
    }
    let mut scaffolds = Vec::new();
    for receipt in initial {
        if !config.owners.iter().any(|owner| {
            owner
                .roots
                .iter()
                .any(|root| root.role_directory == "layout-root" && root.path == receipt.root())
        }) {
            return Err(io::Error::other(
                "creator names an unconfigured original layout",
            ));
        }
        let root = open_host_path(receipt.root(), true)?;
        let guard = DomainProvisioningGuard::exclusive(&root)?;
        scaffolds.push(NativeInitialHostScaffold::create(receipt, guard)?);
    }
    let registry = claims::Registry::open(&config, ledger_path, true)?;
    let _registry_guard = DomainProvisioningGuard::exclusive(registry.directory())?;
    let mut owners = retain(&config)?;
    let mut captured = capture::capture(&config, &roles, &scaffolds)?;
    let mut ledger = InitialLedger {
        version: VERSION,
        epoch: config.epoch.clone(),
        registry: registry.identity(),
        phase: ProvisioningPhase::Provisioning,
        creators: captured.creators,
        roles: roles.owners.clone(),
        entries: captured.entries,
    };
    // Bound all serialized state before committing even the first permanent
    // claim. No caller-provided boolean or callback stands in for durability.
    storage::encode(&ledger, &config)?;
    for owner in &owners {
        require_unused_project(&owner.roots[0].directory, owner.project_id)?;
    }
    for scaffold in &scaffolds {
        scaffold.recheck()?;
    }
    for administrative in captured.administrative.iter().flatten() {
        administrative.check()?;
    }
    registry.ensure_initial(&ledger, &owners)?;
    storage::persist(ledger_path, &ledger, &config, true)?;
    registry.bind_initial(&ledger, &mut owners)?;
    for scaffold in &scaffolds {
        scaffold.recheck()?;
    }
    for administrative in captured.administrative.iter().flatten() {
        administrative.check()?;
    }

    for (owner_index, configured) in config.owners.iter().enumerate() {
        let owner = owners
            .iter()
            .find(|owner| {
                owner.owner_id == configured.owner_id && owner.domain == configured.domain
            })
            .ok_or_else(|| io::Error::other("retained initial owner is missing"))?;
        let claim = owner
            .claim
            .as_ref()
            .ok_or_else(|| io::Error::other("initial owner has no actual retained claim"))?;
        let layout = plan::root(configured, "layout-root")?;
        let scaffold = scaffolds
            .iter_mut()
            .find(|scaffold| scaffold.root() == layout)
            .ok_or_else(|| io::Error::other("retained initial scaffold is missing"))?;
        for administrative in &mut captured.administrative[owner_index] {
            administrative.assign(
                claim,
                &owner.filesystem_uuid,
                owner.project_id,
                owner.hard_limit_bytes,
            )?;
        }
        let directory_keys: Vec<_> = scaffold.directories().map(|item| item.key()).collect();
        for key in directory_keys {
            scaffold.set_directory_project(key, claim, owner.project_id, owner.hard_limit_bytes)?;
        }
        let file_keys: Vec<_> = scaffold.files().map(|item| item.key()).collect();
        for key in file_keys {
            scaffold.set_file_project(key, claim, owner.project_id, owner.hard_limit_bytes)?;
        }
        let directory_intents: Vec<_> = scaffold
            .directories()
            .map(|item| {
                ledger
                    .entries
                    .iter()
                    .find(|entry| entry.path == item.path())
                    .map(|entry| (item.key(), entry.final_custody))
                    .ok_or_else(|| {
                        io::Error::other("directory custody omitted from durable intent")
                    })
            })
            .collect::<io::Result<_>>()?;
        for (key, custody) in directory_intents {
            scaffold.set_directory_custody(
                key,
                claim,
                owner.project_id,
                owner.hard_limit_bytes,
                native_custody(custody),
            )?;
        }
        let file_intents: Vec<_> = scaffold
            .files()
            .map(|item| {
                ledger
                    .entries
                    .iter()
                    .find(|entry| entry.path == item.path())
                    .map(|entry| (item.key(), entry.final_custody))
                    .ok_or_else(|| io::Error::other("file custody omitted from durable intent"))
            })
            .collect::<io::Result<_>>()?;
        for (key, custody) in file_intents {
            scaffold.set_file_custody(
                key,
                claim,
                owner.project_id,
                owner.hard_limit_bytes,
                native_custody(custody),
            )?;
        }
        scaffold.recheck()?;
        for file in scaffold.files() {
            file.descriptor().sync_all()?;
        }
        for directory in scaffold.directories() {
            directory.descriptor().sync_all()?;
        }
        for administrative in &captured.administrative[owner_index] {
            administrative.descriptor.sync_all()?;
        }
    }
    // Retained original coordination exclusion and all host guards still cover
    // the ready publication. Dropping this function releases them only afterward.
    for scaffold in &scaffolds {
        scaffold.recheck()?;
    }
    for administrative in captured.administrative.iter().flatten() {
        administrative.check()?;
    }
    for owner in &owners {
        if terrane_linux::host_quota::NativeQuota::query(
            &owner.roots[0].directory,
            owner.project_id,
        )?
        .hard_limit_bytes
            != owner.hard_limit_bytes
        {
            return Err(io::Error::other(
                "final initial owner quota differs from finite intent",
            ));
        }
    }
    ledger.phase = ProvisioningPhase::Ready;
    storage::persist(ledger_path, &ledger, &config, false)
}
