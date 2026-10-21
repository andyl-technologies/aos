//! Checks explicit administrative scopes and fixed role policy without minting native authority.

use super::{model::*, plan};
use crate::host::{HostConfig, OwnerConfig, RootConfig, validate_config};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use terrane_linux::host_quota::ROOT_LABELS;

fn config() -> HostConfig {
    let layout = PathBuf::from("/srv/terrane/private-a");
    let roots = ROOT_LABELS
        .iter()
        .map(|label| RootConfig {
            role_directory: (*label).to_owned(),
            path: if *label == "layout-root" {
                layout.clone()
            } else {
                layout.join(label)
            },
        })
        .chain(std::iter::once(RootConfig {
            role_directory: "administrative-root".to_owned(),
            path: PathBuf::from("/var/lib/terrane/private-a"),
        }))
        .collect();
    HostConfig {
        socket: PathBuf::from("/run/terrane-host/quota.sock"),
        epoch: "00000000000000000000000000000001".to_owned(),
        tier_charge_budget_bytes: 32 * 1024 * 1024,
        owners: vec![OwnerConfig {
            owner_id: "owner-a".to_owned(),
            domain: "private:a".to_owned(),
            project_id: 41001,
            hard_limit_bytes: 32 * 1024 * 1024,
            allowed_client_uids: BTreeSet::from([840, 841]),
            roots,
        }],
    }
}

fn roles() -> RolePlan {
    RolePlan {
        version: 1,
        owners: vec![RoleOwner {
            owner_id: "owner-a".to_owned(),
            domain: "private:a".to_owned(),
            publisher_uid: 841,
            publisher_gid: 841,
            content_uid: 840,
            content_gid: 845,
            cache_state_gid: 844,
            chunk_seed: [7; 32],
        }],
    }
}

#[test]
fn explicit_private_administrative_root_is_a_finite_owner_scope() {
    validate_config(&config()).expect("explicit private administrative scope is permitted");
}

#[test]
fn administrative_scope_cannot_be_a_layout_ancestor_or_descendant() {
    for unsafe_root in ["/srv/terrane", "/srv/terrane/private-a/control"] {
        let mut config = config();
        config.owners[0]
            .roots
            .iter_mut()
            .find(|root| root.role_directory == "administrative-root")
            .expect("admin root")
            .path = PathBuf::from(unsafe_root);
        assert!(validate_config(&config).is_err());
    }
}

#[test]
fn role_plan_requires_complete_explicit_authorized_identities() {
    let config = config();
    plan::validate(&roles(), &config).expect("complete role plan");
    let mut missing = roles();
    missing.owners.clear();
    assert!(plan::validate(&missing, &config).is_err());
    let mut alias = roles();
    alias.owners[0].publisher_uid = alias.owners[0].content_uid;
    assert!(plan::validate(&alias, &config).is_err());
    let mut unauthorized = roles();
    unauthorized.owners[0].publisher_uid = 999;
    assert!(plan::validate(&unauthorized, &config).is_err());
}

#[test]
fn fixed_custody_keeps_coordination_and_control_private() {
    let role = &roles().owners[0];
    let layout = Path::new("/srv/terrane/private-a");
    let control = Path::new("/var/lib/terrane/private-a/control");
    let coordination = layout.join("coordination");
    let custody = |path: &Path, kind| {
        plan::custody(role, layout, control, &coordination, path, kind).expect("fixed category")
    };
    assert_eq!(
        custody(&coordination, Kind::File),
        Custody {
            uid: 0,
            gid: 0,
            mode: 0o600
        }
    );
    assert_eq!(
        custody(&control.join("registration"), Kind::File),
        Custody {
            uid: 0,
            gid: 0,
            mode: 0o600
        }
    );
    assert_eq!(
        custody(&layout.join("sealed"), Kind::Directory),
        Custody {
            uid: 841,
            gid: 841,
            mode: 0o700
        }
    );
    assert_eq!(
        custody(&layout.join("objects/pack"), Kind::Directory),
        Custody {
            uid: 840,
            gid: 845,
            mode: 0o2770
        }
    );
    assert_eq!(
        custody(&layout.join("objects/index"), Kind::Directory),
        Custody {
            uid: 0,
            gid: 0,
            mode: 0o755
        }
    );
    assert_eq!(
        custody(&layout.join("objects/pack/01/original.pack"), Kind::File),
        Custody {
            uid: 840,
            gid: 845,
            mode: 0o640
        }
    );
    assert_eq!(
        custody(
            &layout.join("objects/index/generation/MANIFEST"),
            Kind::File
        ),
        Custody {
            uid: 0,
            gid: 0,
            mode: 0o644
        }
    );
    assert_eq!(
        custody(&layout.join("state/cache"), Kind::Directory),
        Custody {
            uid: 840,
            gid: 844,
            mode: 0o2770
        }
    );
}

#[test]
fn ready_policy_does_not_pin_catalog_generations_or_shards_forever() {
    // Decoded historical data exercises only path classification. It cannot
    // mint a creator, scaffold, retained claim or native enrollment authority.
    let creator = Creator {
        owner_id: "owner-a".to_owned(),
        domain: "private:a".to_owned(),
        filesystem_uuid: [1; 16],
        project_id: 41001,
        hard_limit_bytes: 32 * 1024 * 1024,
        root: PathBuf::from("/srv/terrane/private-a"),
        root_device: 1,
        root_inode: 1,
        control: PathBuf::from("/var/lib/terrane/private-a/control"),
        control_device: 1,
        control_inode: 2,
        coordination: PathBuf::from("/srv/terrane/private-a/.terrane-locks/original"),
        coordination_device: 1,
        coordination_inode: 3,
        profile_identity: "terrane-v1".to_owned(),
        profile_algorithm: "blake3".to_owned(),
        profile_chunk: "cdc-1m".to_owned(),
        profile_seed: [7; 32],
        genesis: Vec::new(),
    };
    let preimage = StatPreimage {
        device: 1,
        inode: 4,
        mode: 0o40755,
        uid: 0,
        gid: 0,
        nlink: 2,
        rdev: 0,
        size: 4096,
        blocks: 8,
        block_size: 4096,
        atime: 0,
        atime_nsec: 0,
        mtime: 0,
        mtime_nsec: 0,
        ctime: 0,
        ctime_nsec: 0,
    };
    let mut entry = Entry {
        owner_id: creator.owner_id.clone(),
        domain: creator.domain.clone(),
        path: creator.root.join("objects/index"),
        kind: Kind::Directory,
        origin: Origin::Creator,
        device: 1,
        inode: 4,
        original: Custody {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        preimage,
        project_preimage: ProjectPreimage {
            device: 1,
            inode: 4,
            project_id: 0,
            inherit: false,
        },
        final_custody: Custody {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        size: 0,
        expected: Vec::new(),
    };
    assert!(super::ready::stable_directory(&entry, &creator));
    entry.path = creator.root.join("objects/index/generation-0");
    assert!(!super::ready::stable_directory(&entry, &creator));
    entry.path = creator.root.join("objects/pack/ab");
    assert!(!super::ready::stable_directory(&entry, &creator));
    entry.path = creator.control.clone();
    assert!(super::ready::stable_directory(&entry, &creator));
    entry.path = creator.coordination.parent().unwrap().to_owned();
    assert!(super::ready::stable_directory(&entry, &creator));
}

#[test]
fn private_root_uses_explicit_traversal_group_while_public_root_stays_public() {
    let mut role = roles().owners.remove(0);
    let layout = Path::new("/srv/terrane/private-a");
    let control = Path::new("/var/lib/terrane/private-a/control");
    let coordination = layout.join(".terrane-locks/original");
    assert_eq!(
        plan::custody(
            &role,
            layout,
            control,
            &coordination,
            layout,
            Kind::Directory
        )
        .unwrap(),
        Custody {
            uid: 0,
            gid: 845,
            mode: 0o750
        }
    );
    role.content_gid = 912;
    assert_eq!(
        plan::custody(
            &role,
            layout,
            control,
            &coordination,
            layout,
            Kind::Directory
        )
        .unwrap(),
        Custody {
            uid: 0,
            gid: 912,
            mode: 0o750
        }
    );
    role.domain = "public".to_owned();
    assert_eq!(
        plan::custody(
            &role,
            layout,
            control,
            &coordination,
            layout,
            Kind::Directory
        )
        .unwrap(),
        Custody {
            uid: 0,
            gid: 0,
            mode: 0o755
        }
    );
}
