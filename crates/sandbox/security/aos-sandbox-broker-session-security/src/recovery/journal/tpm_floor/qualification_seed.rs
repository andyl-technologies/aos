//! Stages an offline initial floor from the actual fixed Storage journal.
//!
//! This ignored VM fixture runs while both installed owners are stopped. It
//! retains the real endpoint and protected main journal while deriving the
//! canonical initial checkpoint. A separate offline fixture can install that
//! checkpoint after the VM harness authenticates the initialized NV value.
//! Neither fixture provisions NV, changes image mode, or grants readiness.
//!
//! Its private directory contains public staging inputs and canonical outputs:
//!
//! ```text
//! salt-name:34 | deployment-epoch:16              (external inputs)
//! provision:AOSBTD01:160 | checkpoint:AOSBTF01:156
//! extend-input:32 | expected-nv:32
//! ```

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_controller_domain::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::format::FloorEndpointV1;
use super::{FloorCheckpointV1, FloorProfileV1};
use crate::endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
use crate::recovery::journal::{
    PROTECTED_SESSION_JOURNAL, ProtectedBrokerSessionFixedEndpointV1,
    ProtectedBrokerSessionJournalV1, fixed_endpoint, protected_session_journal_limits,
};

fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Retains the actual main writer while deriving its complete initial cut.
struct InstalledInitialFloor {
    directory: PathBuf,
    owner: ProtectedBrokerSessionJournalV1,
    profile: FloorProfileV1,
    checkpoint: FloorCheckpointV1,
    salt_name: [u8; 34],
}

fn installed_initial_floor() -> Result<InstalledInitialFloor, Box<dyn Error>> {
    let (endpoint, role) = match std::env::var("AOS_FLOOR_SEED_ROLE")?.as_str() {
        "client" => (
            ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            FloorEndpointV1::ControllerStorageClient,
        ),
        "broker" => (
            ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
            FloorEndpointV1::StorageBroker,
        ),
        _ => return Err("unknown offline floor role".into()),
    };
    let directory = std::env::var_os("AOS_FLOOR_SEED_DIRECTORY")
        .ok_or("offline floor output directory is absent")?;
    let directory = PathBuf::from(directory);
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("unsafe offline floor output directory".into());
    }
    let salt_name: [u8; 34] = fs::read(directory.join("salt-name"))?
        .try_into()
        .map_err(|_| "salt Name must have exactly 34 bytes")?;
    if salt_name[..2] != [0, 0x0b] || salt_name[2..] == [0; 32] {
        return Err("salt Name must identify a SHA-256 public object".into());
    }
    let epoch: [u8; 16] = fs::read(directory.join("deployment-epoch"))?
        .try_into()
        .map_err(|_| "deployment epoch must have exactly 16 bytes")?;

    let fixed = fixed_endpoint(endpoint);
    // An offline seed must consume actual retained history. The normal opener
    // remains responsible for protected ancestry, locks and complete replay.
    if !fs::symlink_metadata(Path::new(fixed.journal_root).join(PROTECTED_SESSION_JOURNAL))?
        .is_file()
    {
        return Err("installed main journal is absent".into());
    }
    let mut owner = match role {
        FloorEndpointV1::ControllerStorageClient => ProtectedBrokerSessionJournalV1::open_client(
            ProtectedBrokerSessionClientV1::load(fixed.custody_root)?,
            fixed.journal_root,
            PROTECTED_SESSION_JOURNAL,
            protected_session_journal_limits(),
        )?,
        FloorEndpointV1::StorageBroker => ProtectedBrokerSessionJournalV1::open_broker(
            ProtectedBrokerSessionBrokerV1::load(fixed.custody_root)?,
            fixed.journal_root,
            PROTECTED_SESSION_JOURNAL,
            protected_session_journal_limits(),
        )?,
    };
    let (protocol, node) = owner.endpoint.protected_protocol_and_node();
    if protocol != BrokerSessionProtocolV1::Storage {
        return Err("offline floor requires the installed Storage protocol".into());
    }
    let profile = FloorProfileV1::new(
        role,
        node,
        epoch,
        owner.stable_endpoint_identity(protocol)?,
        Sha256::digest(salt_name).into(),
    )?;
    let (cut, prospective) = owner.tpm_floor_cuts(profile, None)?;
    if prospective.is_some() || cut.sequence() <= 1 {
        return Err("offline floor requires a nonempty complete main journal cut".into());
    }
    let checkpoint = FloorCheckpointV1::new(1, profile.scope(), cut, [0; 32], [0; 32])?;

    Ok(InstalledInitialFloor {
        directory,
        owner,
        profile,
        checkpoint,
        salt_name,
    })
}

#[test]
#[ignore = "requires stopped installed Storage owners and externally prepared vTPM indices"]
fn stage_installed_initial_floor() -> Result<(), Box<dyn Error>> {
    let InstalledInitialFloor {
        directory,
        mut owner,
        profile,
        checkpoint,
        salt_name,
    } = installed_initial_floor()?;

    let mut provisioning = [0u8; 160];
    provisioning[..8].copy_from_slice(b"AOSBTD01");
    provisioning[8..10].copy_from_slice(&1u16.to_be_bytes());
    provisioning[12..124].copy_from_slice(&profile.encode());
    provisioning[124..158].copy_from_slice(&salt_name);
    write_new(&directory, "provision", &provisioning)?;
    write_new(&directory, "checkpoint", &checkpoint.encode())?;
    write_new(&directory, "extend-input", &checkpoint.extend_input())?;
    write_new(&directory, "expected-nv", &checkpoint.nv_value())?;
    File::open(&directory)?.sync_all()?;

    // All outputs describe the same protected cut, held until the final check.
    if owner.tpm_floor_cuts(profile, None)? != (checkpoint.cut(), None) {
        return Err("installed main journal changed while staging its floor".into());
    }
    Ok(())
}

#[test]
#[ignore = "requires stopped installed owners and the harness-authenticated initial NV observation"]
fn install_installed_initial_floor() -> Result<(), Box<dyn Error>> {
    let InstalledInitialFloor {
        directory,
        mut owner,
        profile,
        checkpoint,
        ..
    } = installed_initial_floor()?;
    if fs::read(directory.join("checkpoint"))? != checkpoint.encode()
        || fs::read(directory.join("extend-input"))? != checkpoint.extend_input()
        || fs::read(directory.join("expected-nv"))? != checkpoint.nv_value()
        || fs::read(directory.join("observed-nv"))? != checkpoint.nv_value()
    {
        return Err(
            "offline checkpoint does not match installed history and authenticated NV".into(),
        );
    }

    let endpoint = match profile.endpoint() {
        FloorEndpointV1::ControllerStorageClient => {
            ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
        }
        FloorEndpointV1::StorageBroker => ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
    };
    let fixed = fixed_endpoint(endpoint);
    let name = super::FLOOR_SIDECAR_NAME;
    let root = Path::new(fixed.journal_root);
    for path in [root.join(name), root.join(format!("{name}.lock"))] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("offline floor sidecar already exists".into()),
        }
    }

    // Reserve without replacement. A later failure leaves a closed partial
    // installation; repeating this fixture must never adopt or repair it.
    let reservation = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))?;
    reservation.sync_all()?;
    File::open(root)?.sync_all()?;

    let limits = crate::tpm_nv_custody::sidecar_limits(protected_session_journal_limits())?;
    let uid = rustix::process::geteuid().as_raw();
    let (mut sidecar, _) = Journal::open_protected_at_for_uid(root, name, limits, uid)?;
    if sidecar.all_records().next().is_some() {
        return Err("offline floor reservation unexpectedly contains history".into());
    }
    let transaction = JournalTransaction::new(
        [1; 16],
        vec![JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            crate::tpm_nv_custody::CHECKPOINT_KEY.to_vec(),
            checkpoint.encode().to_vec(),
        )],
    )?;
    sidecar.commit(&transaction)?;
    drop(sidecar);

    let (sidecar, _) = Journal::open_existing_protected_at_for_uid(root, name, limits, uid)?;
    if sidecar.all_records().count() != 1
        || sidecar.get(
            RecordNamespace::BrokerSessionTraffic,
            crate::tpm_nv_custody::CHECKPOINT_KEY,
        ) != Some(checkpoint.encode().as_slice())
        || owner.tpm_floor_cuts(profile, None)? != (checkpoint.cut(), None)
    {
        return Err("offline floor failed exact protected replay".into());
    }
    Ok(())
}
