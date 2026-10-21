//! Validates explicit roles and derives a fixed path-category custody policy.

use super::super::{HostConfig, OwnerConfig, parse_error, protected_text};
use super::model::*;
use std::collections::BTreeSet;
use std::io;
use std::path::Path;

pub(super) fn load(path: &Path, config: &HostConfig) -> io::Result<RolePlan> {
    let plan: RolePlan = toml::from_str(&protected_text(path)?).map_err(parse_error)?;
    validate(&plan, config)?;
    Ok(plan)
}

pub(super) fn validate(plan: &RolePlan, config: &HostConfig) -> io::Result<()> {
    if plan.version != 1 || plan.owners.len() != config.owners.len() {
        return Err(io::Error::other(
            "role plan must cover the complete configured partition",
        ));
    }
    let mut seen = BTreeSet::new();
    for role in &plan.owners {
        let owner = config
            .owners
            .iter()
            .find(|owner| owner.owner_id == role.owner_id && owner.domain == role.domain)
            .ok_or_else(|| io::Error::other("role plan names an unconfigured owner"))?;
        if !seen.insert((&role.owner_id, &role.domain))
            || [
                role.publisher_uid,
                role.publisher_gid,
                role.content_uid,
                role.content_gid,
                role.cache_state_gid,
            ]
            .contains(&0)
            || role.publisher_uid == role.content_uid
            || role.cache_state_gid == role.publisher_gid
            || role.cache_state_gid == role.content_gid
            || !owner.allowed_client_uids.contains(&role.publisher_uid)
            || !owner.allowed_client_uids.contains(&role.content_uid)
        {
            return Err(io::Error::other(
                "role plan has ambiguous or unauthorized role identities",
            ));
        }
    }
    Ok(())
}

pub(super) fn root<'a>(owner: &'a OwnerConfig, label: &str) -> io::Result<&'a Path> {
    owner
        .roots
        .iter()
        .find(|root| root.role_directory == label)
        .map(|root| root.path.as_path())
        .ok_or_else(|| {
            io::Error::other("initial enrollment requires every explicit allocation root")
        })
}

pub(super) fn custody(
    role: &RoleOwner,
    layout: &Path,
    control: &Path,
    coordination: &Path,
    path: &Path,
    kind: Kind,
) -> io::Result<Custody> {
    if path.starts_with(control) {
        return Ok(Custody {
            uid: 0,
            gid: 0,
            mode: if kind == Kind::Directory {
                0o700
            } else {
                0o600
            },
        });
    }
    let relative = path.strip_prefix(layout).map_err(parse_error)?;
    if kind == Kind::File {
        return Ok(Custody {
            uid: 0,
            gid: 0,
            mode: if path == coordination { 0o600 } else { 0o644 },
        });
    }
    let relative = relative
        .to_str()
        .ok_or_else(|| io::Error::other("host scaffold path is not UTF-8"))?;
    let (uid, gid, mode) = match relative {
        // The explicit traversal group is operator intent; allowed-client UIDs
        // never imply disclosure-domain filesystem access.
        "" if role.domain != "public" => (0, role.content_gid, 0o750),
        path if path.starts_with("objects/pack/")
            || path.starts_with("chunks/")
            || path.starts_with("quarantine/") =>
        {
            (role.content_uid, role.content_gid, 0o2770)
        }
        "chunks" | "objects" | "objects/pack" | "quarantine" => {
            (role.content_uid, role.content_gid, 0o2770)
        }
        "sealed" | "staging" | "pending-delete" | "state/publication" => {
            (role.publisher_uid, role.publisher_gid, 0o700)
        }
        "state/cache" => (role.content_uid, role.cache_state_gid, 0o2770),
        _ => (0, 0, 0o755),
    };
    Ok(Custody { uid, gid, mode })
}
