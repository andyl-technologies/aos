//! Original Controller/PID1 custody of issue-only Source successor inputs.
//!
//! The selected profile, immutable unit and fresh effective PID1 delivery are
//! joined before private seed access. Original directory/file descriptions
//! and final zeroizing buffers stay in the caller's parked owner on failure.
//! No supplied path, FD, property map or signing key constructs this owner.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::Path;

use aos_sandbox_linux::inventory::{MountId, ReadOnlyDirectorySnapshot};
use aos_sandbox_linux::protected_file::{ExactReadError, open_nofollow_child, read_exact_positioned};
use aos_systemd::{OwnedValue, Value};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, openat2};
use zeroize::{Zeroize as _, Zeroizing};

use super::ProductionControllerNormalRootProfileV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::source_seed::PinnedControllerSourceTreeSeedIssuerV1;
use crate::hierarchy::source_successor::{
    BODY_BYTES, SourceSuccessorApprovalDataV2, SourceSuccessorIntentDataV2, signature_message,
};
use crate::immutable_image::RetainedImmutableFileV1;
use crate::normal_root::{NormalRootStartupErrorV1, service};
use crate::policy_compiler::SourceSuccessorSigningCutV2;
use crate::publisher_policy::PinnedPublisherProjectAuthorizationIssuerV2;
use crate::systemd_property_data;

const DIRECTORY: &str = "/run/credentials/aos-sandboxd.service";
const NAMES: [&str; 4] = [
    "controller-source-successor-admin-seed-v2",
    "controller-source-successor-intent-v2",
    "controller-source-tree-seed-issuer-v1",
    "project-authorization-issuer-v2",
];
const SOURCES: [&str; 2] = [
    "/run/credentials/@system/controller-source-successor-admin-seed-v2",
    "/run/credentials/@system/controller-source-successor-intent-v2",
];
const WIDTHS: [usize; 4] = [32, 80, 80, 80];
const CONTEXT: &[u8] = b"system_u:object_r:aos_sandbox_controller_credential_t";
const MAXIMUM_OBSERVATIONS: usize = 24;
const PROPERTIES: &[&str] = &[
    "Type", "Restart", "ExecStart", "ExecStartPre", "ExecStartPost",
    "LoadCredential", "LoadCredentialEncrypted", "SetCredential",
    "SetCredentialEncrypted", "ImportCredential", "ImportCredentialEx",
];

/// Reports fixed issue-purpose custody refusal without displaying secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum SourceSuccessorCredentialErrorV2 {
    /// The same original selected Controller/PID1 owner no longer matches.
    #[error("original Source successor Controller profile differs")]
    Profile(#[from] NormalRootStartupErrorV1),
    /// Original descriptor or protected fixed-name inspection failed.
    #[error("original Source successor credential I/O failed")]
    Io(#[from] io::Error),
    /// Required fixed delivery, schema, backing, identity or role differs.
    #[error("original Source successor credential custody differs")]
    Rejected,
    /// A final retained buffer was incomplete or had trailing bytes.
    #[error("original Source successor credential read differs: {0:?}")]
    Read(ExactReadError),
    /// Canonical DATA, signature or the borrowed original signing cut differs.
    #[error("Source successor canonical approval differs")]
    Approval(#[from] SourceGenesisErrorV1),
}

impl From<rustix::io::Errno> for SourceSuccessorCredentialErrorV2 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    mtime: (i64, u64),
    ctime: (i64, u64),
    mount: MountId,
}

impl Identity {
    fn capture(file: BorrowedFd<'_>) -> Result<Self, SourceSuccessorCredentialErrorV2> {
        let metadata = rustix::fs::fstat(file)?;
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            links: u64::from(metadata.st_nlink),
            bytes: u64::try_from(metadata.st_size).map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?,
            mtime: (i64::from(metadata.st_mtime), u64::from(metadata.st_mtime_nsec)),
            ctime: (i64::from(metadata.st_ctime), u64::from(metadata.st_ctime_nsec)),
            mount: MountId::from_fd(file).map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?,
        })
    }

    fn require(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
        kind: FileType,
        mode: u32,
    ) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if FileType::from_raw_mode(self.mode) != kind
            || self.mode & 0o7777 != mode
            || self.uid != profile.profile.identities[0]
            || self.gid != profile.profile.identities[1]
            || self.device == 0
            || self.inode == 0
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        Ok(())
    }
}

/// Retains genuine issue-only origin and original private input descriptions.
///
/// Fields remain closed. Parking is available only on the already admitted
/// original Controller profile; bytes cannot be converted into a live owner.
pub struct SourceSuccessorCredentialCustodyV2<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    directory_path: Option<File>,
    directory_reader: Option<File>,
    files: Vec<File>,
    directory_identity: Option<Identity>,
    directory_snapshot: Option<ReadOnlyDirectorySnapshot>,
    identities: Vec<Identity>,
    executable: Option<RetainedImmutableFileV1>,
    observations: Vec<(Vec<OwnedValue>, Vec<OwnedValue>)>,
    buffers: Vec<[Zeroizing<Vec<u8>>; 4]>,
    admitted: bool,
    ended: bool,
}

impl<'profile> ProductionControllerNormalRootProfileV1 {
    /// Parks issue-only original input custody before any fallible admission.
    ///
    /// # Errors
    /// Rejects a populated slot and every changed or nonissue invocation,
    /// ambiguous delivery, unsafe original descriptor, malformed input or
    /// independent public/private role mismatch. A failed slot remains owned.
    pub fn park_source_successor_credentials_v2(
        &'profile self,
        slot: &mut Option<SourceSuccessorCredentialCustodyV2<'profile>>,
    ) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if slot.is_some() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        *slot = Some(SourceSuccessorCredentialCustodyV2 {
            profile: self,
            directory_path: None,
            directory_reader: None,
            files: Vec::with_capacity(4),
            directory_identity: None,
            directory_snapshot: None,
            identities: Vec::with_capacity(4),
            executable: None,
            observations: Vec::new(),
            buffers: Vec::new(),
            admitted: false,
            ended: false,
        });
        let custody = slot.as_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let result = custody.admit();
        if result.is_err() {
            // Preserve the typed result and originals for the resident caller.
            // Its first-cause latch precedes explicit wiping and termination.
            custody.admitted = false;
            custody.ended = true;
        }
        result
    }
}

impl SourceSuccessorCredentialCustodyV2<'_> {
    fn admit(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        self.profile.recheck()?;
        let executable = self.observe_delivery(true)?;
        self.executable = Some(RetainedImmutableFileV1::retain_with_profile(
            executable.into(),
            File::open("/proc/self/exe")?,
            None,
            64 * 1024 * 1024,
            true,
        ).map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?);
        self.executable.as_ref()
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?
            .require_executed(std::process::id())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;

        self.directory_path = Some(open_directory(true)?);
        self.directory_reader = Some(open_directory(false)?);
        let path = self.directory_path.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let reader = self.directory_reader.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let identity = Identity::capture(reader.as_fd())?;
        identity.require(self.profile, FileType::Directory, 0o500)?;
        require_label_and_acl(reader.as_fd())?;
        if Identity::capture(path.as_fd())? != identity {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.directory_snapshot = Some(
            ReadOnlyDirectorySnapshot::capture(path.as_fd())
                .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?,
        );
        self.directory_identity = Some(identity);

        for (name, width) in NAMES.into_iter().zip(WIDTHS) {
            self.files.push(File::from(open_nofollow_child(path, name)?));
            let file = self.files.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
            let identity = Identity::capture(file.as_fd())?;
            identity.require(self.profile, FileType::RegularFile, 0o400)?;
            if identity.links != 1 || identity.bytes != width as u64 {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            require_read_description(file.as_fd())?;
            require_label_and_acl(file.as_fd())?;
            self.identities.push(identity);
        }

        self.capture_bytes()?;
        self.validate_roles()?;
        self.admitted = true;
        self.recheck()
    }

    /// Rechecks the same original delivery, descriptors and bounded readbacks.
    ///
    /// # Errors
    /// Rejects ended custody, changed profile/mode/invocation/delivery, replaced
    /// names or descriptions, unsafe labels/backing/ACLs, or changed bytes.
    pub fn recheck(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let result = self.recheck_inner();
        if result.is_err() {
            self.admitted = false;
            self.ended = true;
        }
        result
    }

    fn recheck_inner(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if !self.admitted || self.ended {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.profile.recheck()?;
        let executable = self.observe_delivery(true)?;
        let retained = self.executable.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if retained.path() != Path::new(&executable) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        retained.revalidate()
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        retained.require_executed(std::process::id())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        self.check_descriptors_and_names()?;
        self.capture_bytes()?;
        self.validate_roles()?;
        self.check_descriptors_and_names()?;
        self.profile.recheck().map_err(Into::into)
    }

    pub(crate) fn intent(&self) -> Result<SourceSuccessorIntentDataV2, SourceGenesisErrorV1> {
        if !self.admitted || self.ended {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        SourceSuccessorIntentDataV2::from_bytes(
            self.first_buffers()?[1].as_slice(),
        )
    }

    pub(crate) fn issuer_generation(&self) -> Result<u64, SourceGenesisErrorV1> {
        Ok(PinnedControllerSourceTreeSeedIssuerV1::decode(
            self.first_buffers()?[2].as_slice(),
        )?.generation())
    }

    pub(crate) fn verify_saved(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        let pin = PinnedControllerSourceTreeSeedIssuerV1::decode(self.first_buffers()?[2].as_slice())?;
        packet.verify_signature(pin.verifying_key())
    }

    pub(crate) fn sign_approval(
        &mut self,
        body: &[u8; BODY_BYTES],
        signing_cut: &SourceSuccessorSigningCutV2<'_, '_, '_, '_, '_>,
    ) -> Result<SourceSuccessorApprovalDataV2, SourceSuccessorCredentialErrorV2> {
        self.recheck()?;
        let intent = self.intent()?;
        let issuer_generation = self.issuer_generation()?;

        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(self.first_buffers()?[0].as_slice());
        let signer = SigningKey::from_bytes(&seed);
        let message = signature_message(body)?;

        let mut packet = [0; BODY_BYTES + 64];
        packet[..BODY_BYTES].copy_from_slice(body);

        // No fallible credential/message preparation or live-owner work may
        // intervene between this genuine current cut and the actual signature.
        signing_cut.recheck_before_signature(body, intent, issuer_generation)?;
        let signature = signer.sign(&message);
        packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&packet)?;

        self.recheck()?;
        self.verify_saved(&packet)?;
        Ok(packet)
    }

    /// Wipes private buffers while retaining the original descriptions.
    ///
    /// This irreversible negative operation grants no retry or next activation.
    pub fn end_failed(&mut self) {
        self.ended = true;
        self.admitted = false;
        wipe_private_buffers(&mut self.buffers);
    }

    fn first_buffers(&self) -> Result<&[Zeroizing<Vec<u8>>; 4], SourceGenesisErrorV1> {
        if self.ended {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        self.buffers.first().ok_or(SourceGenesisErrorV1::Stale)
    }

    fn validate_roles(&self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let buffers = self.buffers.first().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(buffers[0].as_slice());
        let signer = SigningKey::from_bytes(&seed);
        let admin = PinnedControllerSourceTreeSeedIssuerV1::decode(buffers[2].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(buffers[3].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        if signer.verifying_key() != *admin.verifying_key()
            || admin.verifying_key() == authorization.verifying_key()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        SourceSuccessorIntentDataV2::from_bytes(buffers[1].as_slice())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        Ok(())
    }

    fn capture_bytes(&mut self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if self.buffers.len() >= MAXIMUM_OBSERVATIONS || self.files.len() != 4 {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.buffers.push(WIDTHS.map(|width| Zeroizing::new(vec![0; width])));
        let received = self.buffers.last_mut().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        for (file, bytes) in self.files.iter().zip(received.iter_mut()) {
            read_exact_positioned(file, bytes.as_mut_slice())
                .map_err(SourceSuccessorCredentialErrorV2::Read)?;
        }

        let first = self.buffers.first().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let last = self.buffers.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if first != last {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        Ok(())
    }

    fn observe_delivery(&mut self, issue: bool) -> Result<String, SourceSuccessorCredentialErrorV2> {
        if self.observations.len() >= MAXIMUM_OBSERVATIONS {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.observations.push(service::read_properties(
            super::UNIT, std::process::id(), PROPERTIES,
        )?);
        let (values, unit) = self.observations.last().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        require_unit_schema(unit)?;
        let observed = service::immutable_observation(service::decode_unit(unit, super::UNIT)?)?;
        service::require_same(&self.profile.observed, &observed)?;
        self.profile.fragment.revalidate()
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;

        require_delivery(
            values.get(5..).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, issue,
        )?;
        let identities = self.profile.profile.identities[..2].try_into()
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        let path = require_issue_launch(
            values.get(..5).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, identities,
        )?;
        Ok(path.to_owned())
    }

    fn check_descriptors_and_names(&self) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let path = self.directory_path.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let reader = self.directory_reader.as_ref().ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let original_snapshot = ReadOnlyDirectorySnapshot::capture(path.as_fd())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        if Some(&Identity::capture(path.as_fd())?) != self.directory_identity.as_ref()
            || Some(&Identity::capture(reader.as_fd())?) != self.directory_identity.as_ref()
            || Some(&original_snapshot) != self.directory_snapshot.as_ref()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        require_label_and_acl(reader.as_fd())?;

        let named_directory = open_directory(true)?;
        let named_snapshot = ReadOnlyDirectorySnapshot::capture(named_directory.as_fd())
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        if Some(&Identity::capture(named_directory.as_fd())?) != self.directory_identity.as_ref()
            || Some(&named_snapshot) != self.directory_snapshot.as_ref()
        {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        for ((file, identity), name) in self.files.iter().zip(&self.identities).zip(NAMES) {
            let named = open_nofollow_child(&named_directory, name)?;
            if Identity::capture(file.as_fd())? != *identity || Identity::capture(named.as_fd())? != *identity {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            require_read_description(file.as_fd())?;
            require_label_and_acl(file.as_fd())?;
        }
        Ok(())
    }
}

fn wipe_private_buffers(buffers: &mut [[Zeroizing<Vec<u8>>; 4]]) {
    for observation in buffers {
        observation[0].zeroize();
    }
}

/// Refuses issue-purpose copies and effective delivery before ordinary effects.
///
/// # Errors
/// Rejects either unexpected fixed copy, any selected issue-purpose mapping,
/// or unavailable original PID1/profile observation. Absent legacy delivery
/// without a selected profile remains nonauthorizing and otherwise unchanged.
pub fn require_source_successor_delivery_absent_v2(
    profile: Option<&ProductionControllerNormalRootProfileV1>,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    for name in &NAMES[..2] {
        match std::fs::symlink_metadata(Path::new(DIRECTORY).join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(SourceSuccessorCredentialErrorV2::Rejected),
        }
    }
    if let Some(profile) = profile {
        profile.recheck()?;
        let (values, unit) = service::read_properties(super::UNIT, std::process::id(), PROPERTIES)?;
        require_unit_schema(&unit)?;
        let observed = service::immutable_observation(service::decode_unit(&unit, super::UNIT)?)?;
        service::require_same(&profile.observed, &observed)?;
        require_delivery(values.get(5..).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?, false)?;
        profile.recheck()?;
    }
    Ok(())
}

fn require_issue_launch(
    values: &[OwnedValue],
    identities: [u32; 2],
) -> Result<&str, SourceSuccessorCredentialErrorV2> {
    let [kind, restart, start, pre, post] = values else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    require_signature(kind, "s")?;
    require_signature(restart, "s")?;
    if <&str>::try_from(kind).ok() != Some("oneshot")
        || <&str>::try_from(restart).ok() != Some("no")
    {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    for commands in [start, pre, post] {
        require_signature(commands, "a(sasbttttuii)")?;
    }
    for commands in [pre, post] {
        if !matches!(&**commands, Value::Array(array) if array.is_empty()) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
    }

    let command = systemd_property_data::single_exec_start(start).ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
    if command.path.len() > 4096 {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    let expected = [
        command.path.to_owned(),
        identities[0].to_string(),
        identities[1].to_string(),
        "--issue-source-successor".to_owned(),
    ];
    if !command.path.starts_with("/nix/store/")
        || !command.path.ends_with("/bin/aos-sandboxd")
        || command.pid != std::process::id()
        || command.argv.len() != expected.len()
        || command.argv.iter().zip(&expected).any(|(actual, expected)| {
            !matches!(actual, Value::Str(actual) if actual.as_str() == expected)
        })
    {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(command.path)
}

fn require_signature(
    value: &OwnedValue,
    expected: &str,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    if value.value_signature().to_string() != expected {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(())
}

fn require_unit_schema(unit: &[OwnedValue]) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let [fragment, dropins, transient, invocation] = unit else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    for (value, signature) in [
        (fragment, "s"), (dropins, "as"), (transient, "b"), (invocation, "ay"),
    ] {
        require_signature(value, signature)?;
    }
    Ok(())
}

fn require_delivery(
    values: &[OwnedValue],
    issue: bool,
) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let [load, encrypted, literal, encrypted_literal, import, import_ex] = values else {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    };
    for (value, signature) in [
        (load, "a(ss)"),
        (encrypted, "a(ss)"),
        (literal, "a(say)"),
        (encrypted_literal, "a(say)"),
        (import, "as"),
        (import_ex, "a(ss)"),
    ] {
        require_signature(value, signature)?;
    }

    let mut found = [0_usize; 2];
    for (ordinary, value) in [(true, load), (false, encrypted), (false, literal), (false, encrypted_literal)] {
        let Value::Array(rows) = &**value else {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        };
        if issue && rows.len() > 64 {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        for row in rows.inner() {
            let Value::Structure(row) = row else {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            };
            let [Value::Str(id), content] = row.fields() else {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            };
            if issue && id.as_str().len() > 255 {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
            if let Some(index) = NAMES[..2].iter().position(|name| *name == id.as_str()) {
                if !issue || !ordinary || !matches!(content, Value::Str(source) if source.as_str() == SOURCES[index]) {
                    return Err(SourceSuccessorCredentialErrorV2::Rejected);
                }
                found[index] += 1;
            }
            if issue {
                match content {
                    Value::Str(value) if value.as_str().len() <= 4096 => {}
                    Value::Array(value) if value.len() <= 4096 => {}
                    _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
                }
            }
        }
    }

    for value in [import, import_ex] {
        let Value::Array(rows) = &**value else {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        };
        if issue && !rows.is_empty() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        // Absent-purpose normal mode preserves unrelated inherited imports.
        // Actual fixed copies are checked separately before ordinary effects;
        // no wildcard expansion or credential-origin authority is inferred.
        for row in rows.inner() {
            let name = match row {
                Value::Str(name) => name.as_str(),
                Value::Structure(row) => match row.fields() {
                    [Value::Str(name), Value::Str(target)] => {
                        if NAMES[..2].contains(&target.as_str()) {
                            return Err(SourceSuccessorCredentialErrorV2::Rejected);
                        }
                        name.as_str()
                    }
                    _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
                },
                _ => return Err(SourceSuccessorCredentialErrorV2::Rejected),
            };
            if NAMES[..2].contains(&name) {
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
        }
    }

    if found != [usize::from(issue); 2] {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(())
}

fn open_directory(path_only: bool) -> Result<File, SourceSuccessorCredentialErrorV2> {
    let access = if path_only { OFlags::PATH } else { OFlags::RDONLY };
    Ok(File::from(openat2(
        CWD, DIRECTORY,
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

fn require_read_description(file: BorrowedFd<'_>) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    if flags.contains(OFlags::PATH)
        || flags & OFlags::ACCMODE != OFlags::RDONLY
        || !rustix::io::fcntl_getfd(file)?.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    Ok(())
}

fn require_label_and_acl(file: BorrowedFd<'_>) -> Result<(), SourceSuccessorCredentialErrorV2> {
    let mut context = [0; 256];
    let length = rustix::fs::fgetxattr(file, "security.selinux", &mut context)?;
    let context = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
    if context != CONTEXT {
        return Err(SourceSuccessorCredentialErrorV2::Rejected);
    }
    let mut acl = [0; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(file, name, &mut acl) {
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(SourceSuccessorCredentialErrorV2::Rejected),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Command = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn delivery(issue: bool) -> Vec<OwnedValue> {
        let load = if issue {
            NAMES[..2].iter().copied().zip(SOURCES).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        vec![
            value(load),
            value(Vec::<(&str, &str)>::new()),
            value(Vec::<(&str, Vec<u8>)>::new()),
            value(Vec::<(&str, Vec<u8>)>::new()),
            value(Vec::<&str>::new()),
            value(Vec::<(&str, &str)>::new()),
        ]
    }

    fn command() -> Command {
        let path = "/nix/store/selected-controller/bin/aos-sandboxd";
        (
            path.into(),
            vec![path.into(), "1001".into(), "1002".into(), "--issue-source-successor".into()],
            false,
            0, 0, 0, 0,
            std::process::id(),
            0, 0,
        )
    }

    fn launch(command: Command) -> Vec<OwnedValue> {
        vec![
            value("oneshot"),
            value("no"),
            value(vec![command]),
            value(Vec::<Command>::new()),
            value(Vec::<Command>::new()),
        ]
    }

    #[test]
    fn exact_issue_delivery_requires_both_unique_fixed_ordinary_sources() {
        let exact = delivery(true);

        assert!(require_delivery(&exact, true).is_ok());
        assert!(require_delivery(&exact, false).is_err());
        assert!(require_delivery(&delivery(false), true).is_err());
        for rows in [
            vec![(NAMES[0], SOURCES[0])],
            vec![(NAMES[0], SOURCES[0]), (NAMES[0], SOURCES[0]), (NAMES[1], SOURCES[1])],
            vec![(NAMES[0], SOURCES[1]), (NAMES[1], SOURCES[0])],
        ] {
            let mut values = delivery(true);
            values[0] = value(rows);
            assert!(require_delivery(&values, true).is_err());
        }
        let mut encrypted = delivery(true);
        encrypted[1] = value(vec![(NAMES[0], SOURCES[0])]);
        assert!(require_delivery(&encrypted, true).is_err());
        let mut literal = delivery(true);
        literal[2] = value(vec![(NAMES[0], vec![1_u8; 32])]);
        assert!(require_delivery(&literal, true).is_err());
        let mut imported = delivery(true);
        imported[4] = value(vec!["*"]);
        assert!(require_delivery(&imported, true).is_err());
    }

    #[test]
    fn normal_absence_preserves_unrelated_imports_and_refuses_issue_names() {
        let mut values = delivery(false);
        values[0] = value(vec![("unrelated-purpose", "/run/credentials/@system/unrelated")]);
        values[4] = value(vec!["unrelated-import"]);
        values[5] = value(vec![("unrelated-import", "other")]);

        assert!(require_delivery(&values, false).is_ok());
        values[4] = value(vec![NAMES[0]]);
        assert!(require_delivery(&values, false).is_err());
        values[4] = value(Vec::<&str>::new());
        values[5] = value(vec![(NAMES[1], "other")]);
        assert!(require_delivery(&values, false).is_err());
    }

    #[test]
    fn exact_schema_precedes_empty_array_and_tuple_inspection() {
        let mut values = delivery(true);
        values[1] = value(Vec::<&str>::new());
        assert!(require_delivery(&values, true).is_err());
        values[1] = value(vec![(NAMES[0],)]);
        assert!(require_delivery(&values, true).is_err());
        let unit = vec![value("/fragment"), value(Vec::<&str>::new()), value(false), value(vec![1_u8; 16])];
        assert!(require_unit_schema(&unit).is_ok());
        let mut wrong = unit;
        wrong[3] = value(vec![1_u16; 16]);
        assert!(require_unit_schema(&wrong).is_err());
    }

    #[test]
    fn issue_launch_requires_exact_command_mode_pid_and_no_auxiliary_commands() {
        let exact = launch(command());

        assert!(require_issue_launch(&exact, [1001, 1002]).is_ok());
        assert!(require_issue_launch(&exact, [1001, 1003]).is_err());
        for index in 0..5 {
            let mut changed = launch(command());
            changed[index] = match index {
                0 => value("notify"),
                1 => value("on-failure"),
                2 => {
                    let mut altered = command();
                    altered.7 = 0;
                    value(vec![altered])
                }
                _ => value(vec![command()]),
            };
            assert!(require_issue_launch(&changed, [1001, 1002]).is_err(), "{index}");
        }
        let mut extra = command();
        extra.1.push("--public-api".into());
        assert!(require_issue_launch(&launch(extra), [1001, 1002]).is_err());
        let mut ignored = command();
        ignored.2 = true;
        assert!(require_issue_launch(&launch(ignored), [1001, 1002]).is_err());
    }

    #[test]
    fn failure_wipes_every_private_readback_but_not_public_context() {
        let mut observations = vec![
            WIDTHS.map(|width| Zeroizing::new(vec![7; width])),
            WIDTHS.map(|width| Zeroizing::new(vec![8; width])),
        ];

        wipe_private_buffers(&mut observations);

        assert!(observations.iter().all(|bytes| bytes[0].is_empty()));
        assert_eq!(observations[0][1].as_slice(), &[7; 80]);
        assert_eq!(observations[1][2].as_slice(), &[8; 80]);
    }
}
