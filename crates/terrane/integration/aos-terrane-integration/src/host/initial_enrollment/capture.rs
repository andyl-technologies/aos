//! Captures complete creator/scaffold observations before the first claim.

use super::super::{HostConfig, OwnerConfig, parse_error};
use super::model::*;
use super::plan;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::Metadata;
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Component, Path};
use terrane_format::{bucket::BucketKey, gc::publication::BackendBinding};
use terrane_linux::host_quota::initial_enrollment::NativeInitialHostScaffold;
use terrane_linux::host_quota::{
    NativeProject, directory_children, filesystem_uuid, open_host_path,
};

pub(super) use super::administrative::AdministrativeDirectory;

pub(super) struct Captured {
    pub creators: Vec<Creator>,
    pub entries: Vec<Entry>,
    pub administrative: Vec<Vec<AdministrativeDirectory>>,
}

fn attributes(metadata: &Metadata) -> Custody {
    Custody {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    }
}

/// Groups one retained inode observation with its recorded provenance and custody.
struct Observation<'a> {
    owner: &'a OwnerConfig,
    path: &'a Path,
    metadata: &'a Metadata,
    project: &'a NativeProject,
    origin: Origin,
    kind: Kind,
    expected: Vec<u8>,
    final_custody: Custody,
}

fn entry(observation: Observation<'_>) -> Entry {
    let Observation {
        owner,
        path,
        metadata,
        project,
        origin,
        kind,
        expected,
        final_custody,
    } = observation;

    Entry {
        owner_id: owner.owner_id.clone(),
        domain: owner.domain.clone(),
        path: path.to_owned(),
        kind,
        origin,
        device: metadata.dev(),
        inode: metadata.ino(),
        original: attributes(metadata),
        preimage: super::administrative::stat(metadata),
        project_preimage: ProjectPreimage {
            device: project.device,
            inode: project.inode,
            project_id: project.project_id,
            inherit: project.inherit,
        },
        final_custody,
        size: if kind == Kind::File {
            metadata.len()
        } else {
            0
        },
        expected,
    }
}

pub(super) fn administrative(
    owner: &OwnerConfig,
    control: &Path,
) -> io::Result<Vec<AdministrativeDirectory>> {
    let administrative = plan::root(owner, "administrative-root")?;
    let relative = control.strip_prefix(administrative).map_err(parse_error)?;
    if relative.components().count() > 32 {
        return Err(io::Error::other(
            "administrative ancestor depth bound exceeded",
        ));
    }
    let mut directory = open_host_path(administrative, true)?;
    let mut path = administrative.to_owned();
    let mut output = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::other(
                "protected control is not beneath its explicit administrative root",
            ));
        };
        let metadata = directory.metadata()?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || NativeProject::inspect(&directory)?.project_id != 0
        {
            return Err(io::Error::other(
                "administrative ancestor lacks original root custody",
            ));
        }
        let children = directory_children(&directory)?;
        if children.len() != 1 || children[0].name != name {
            return Err(io::Error::other(
                "administrative root contains unrecognized descendants",
            ));
        }
        output.push(AdministrativeDirectory {
            entry: entry(Observation {
                owner,
                path: &path,
                metadata: &metadata,
                project: &NativeProject::inspect(&directory)?,
                origin: Origin::Administrative,
                kind: Kind::Directory,
                expected: Vec::new(),
                final_custody: Custody {
                    uid: 0,
                    gid: 0,
                    mode: 0o700,
                },
            }),
            expected: metadata,
            project: NativeProject::inspect(&directory)?,
            child_name: name.to_os_string(),
            child_device: children[0].directory.metadata()?.dev(),
            child_inode: children[0].directory.metadata()?.ino(),
            descriptor: directory,
        });
        directory = children[0].directory.try_clone()?;
        path.push(name);
    }
    // Equality intentionally adds no second observation for the original
    // control directory: it is already covered by the genuine core receipt.
    if path != control {
        return Err(io::Error::other(
            "explicit administrative chain does not reach the original control",
        ));
    }
    Ok(output)
}

pub(super) fn capture(
    config: &HostConfig,
    roles: &RolePlan,
    scaffolds: &[NativeInitialHostScaffold],
) -> io::Result<Captured> {
    if scaffolds.len() != config.owners.len() {
        return Err(io::Error::other(
            "fresh receipts must cover the complete configured partition",
        ));
    }
    let mut creators = Vec::new();
    let mut entries = Vec::new();
    let mut administrative_sets = Vec::new();
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut total_bytes = 0usize;
    for owner in &config.owners {
        let layout = plan::root(owner, "layout-root")?;
        let scaffold = scaffolds
            .iter()
            .find(|scaffold| scaffold.root() == layout)
            .ok_or_else(|| {
                io::Error::other("fresh receipt does not match the configured original root")
            })?;
        let role = roles
            .owners
            .iter()
            .find(|role| role.owner_id == owner.owner_id && role.domain == owner.domain)
            .ok_or_else(|| io::Error::other("missing explicit owner role plan"))?;
        scaffold.recheck()?;
        if scaffold.operator_uid() != 0
            || scaffold.profile().identity != "terrane-v1"
            || scaffold.profile().algorithm != "blake3"
            || scaffold.profile().chunk != "cdc-1m"
            || scaffold.profile().seed != role.chunk_seed
        {
            return Err(io::Error::other(
                "fresh creator identity or profile differs from trusted enrollment plan",
            ));
        }
        let BackendBinding::Local {
            root,
            root_device,
            root_inode,
            coordination_device,
            coordination_inode,
        } = scaffold.binding()
        else {
            return Err(io::Error::other(
                "fresh enrollment requires an original local binding",
            ));
        };
        if root.as_slice() != layout.as_os_str().as_bytes() {
            return Err(io::Error::other(
                "creator binding names another original root",
            ));
        }
        let coordination = layout.join(
            BucketKey::parse("CAPABILITIES")
                .map_err(parse_error)?
                .lock_name(),
        );
        let control = scaffold
            .directories()
            .find(|directory| directory.path() == scaffold.control())
            .ok_or_else(|| io::Error::other("creator omits its original protected control"))?;
        let uuid = filesystem_uuid(control.descriptor())?;
        let extra = administrative(owner, scaffold.control())?;
        for directory in &extra {
            if filesystem_uuid(&directory.descriptor)? != uuid {
                return Err(io::Error::other(
                    "administrative chain crosses the original filesystem",
                ));
            }
            entries.push(directory.entry.clone());
        }
        for directory in scaffold.directories() {
            if directory.observed_project().project_id != 0
                || directory.observed_metadata().uid() != 0
                || directory.observed_metadata().mode() & 0o022 != 0
                || filesystem_uuid(directory.descriptor())? != uuid
            {
                return Err(io::Error::other(
                    "initial directory is not a quiescent unassigned original",
                ));
            }
            entries.push(entry(Observation {
                owner,
                path: directory.path(),
                metadata: directory.observed_metadata(),
                project: directory.observed_project(),
                origin: if directory.created() {
                    Origin::Scaffold
                } else {
                    Origin::Creator
                },
                kind: Kind::Directory,
                expected: Vec::new(),
                final_custody: plan::custody(
                    role,
                    layout,
                    scaffold.control(),
                    &coordination,
                    directory.path(),
                    Kind::Directory,
                )?,
            }));
        }
        for file in scaffold.files() {
            if file.observed_project().project_id != 0
                || file.observed_metadata().uid() != 0
                || file.observed_metadata().nlink() != 1
                || file.observed_metadata().mode() & 0o022 != 0
                || filesystem_uuid(file.descriptor())? != uuid
            {
                return Err(io::Error::other(
                    "initial file is not a single-link unassigned creator leaf",
                ));
            }
            total_bytes = total_bytes
                .checked_add(file.expected_bytes().len())
                .filter(|total| *total <= MAX_BYTES)
                .ok_or_else(|| io::Error::other("initial metadata aggregate bound exceeded"))?;
            entries.push(entry(Observation {
                owner,
                path: file.path(),
                metadata: file.observed_metadata(),
                project: file.observed_project(),
                origin: Origin::Creator,
                kind: Kind::File,
                expected: file.expected_bytes().to_vec(),
                final_custody: plan::custody(
                    role,
                    layout,
                    scaffold.control(),
                    &coordination,
                    file.path(),
                    Kind::File,
                )?,
            }));
        }
        let coordination_entry = entries
            .iter()
            .find(|entry| entry.path == coordination)
            .ok_or_else(|| {
                io::Error::other("initial creator coordination observation is missing")
            })?;
        if (coordination_entry.device, coordination_entry.inode)
            != (*coordination_device, *coordination_inode)
        {
            return Err(io::Error::other(
                "initial coordination inode differs from the creator binding",
            ));
        }
        creators.push(Creator {
            owner_id: owner.owner_id.clone(),
            domain: owner.domain.clone(),
            filesystem_uuid: uuid,
            project_id: owner.project_id,
            hard_limit_bytes: owner.hard_limit_bytes,
            root: layout.to_owned(),
            root_device: *root_device,
            root_inode: *root_inode,
            control: scaffold.control().to_owned(),
            control_device: control.observed_metadata().dev(),
            control_inode: control.observed_metadata().ino(),
            coordination,
            coordination_device: *coordination_device,
            coordination_inode: *coordination_inode,
            profile_identity: scaffold.profile().identity.clone(),
            profile_algorithm: scaffold.profile().algorithm.clone(),
            profile_chunk: scaffold.profile().chunk.clone(),
            profile_seed: scaffold.profile().seed,
            genesis: scaffold.genesis().encode().map_err(parse_error)?,
        });
        administrative_sets.push(extra);
    }
    if entries.len() > MAX_ENTRIES {
        return Err(io::Error::other(
            "complete initial partition exceeds its physical entry bound",
        ));
    }
    for entry in &entries {
        if !paths.insert(entry.path.clone()) || !identities.insert((entry.device, entry.inode)) {
            return Err(io::Error::other(
                "initial enrollment contains an aliased physical entry",
            ));
        }
    }
    let by_path: BTreeMap<_, _> = entries.iter().map(|entry| (&entry.path, entry)).collect();
    for owner in &config.owners {
        for root in &owner.roots {
            let entry = by_path.get(&root.path).ok_or_else(|| {
                io::Error::other("initial enrollment omits a configured query root")
            })?;
            if entry.kind != Kind::Directory
                || entry.owner_id != owner.owner_id
                || entry.domain != owner.domain
            {
                return Err(io::Error::other(
                    "initial query root belongs to another owner",
                ));
            }
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    creators.sort_by(|left, right| {
        (&left.owner_id, &left.domain).cmp(&(&right.owner_id, &right.domain))
    });
    Ok(Captured {
        creators,
        entries,
        administrative: administrative_sets,
    })
}
