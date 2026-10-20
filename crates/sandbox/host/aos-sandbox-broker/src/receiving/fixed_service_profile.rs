//! Retains bounded fixed-service unit bytes from original PID1 delivery.
//!
//! The parent authenticates each actual file and its strict record against the
//! same original Parent enclosure before entering this private consumer. A row,
//! digest or successful syntax check is not an image or Source authority. All
//! files stay in that parent; this owner retains their readback results and one
//! prepaid buffer, reused only after a complete positive file observation.

use std::error::Error;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use rustix::fs::{OFlags, StatFs};
use sha2::{Digest as _, Sha256};

/// Selects only fixed profile comparison DATA, without a receiving original.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FixedServiceProfileRoleV1 {
    Source,
    Ownership,
    Cache,
    Mount,
    Network,
    BootPreparation,
}

impl FixedServiceProfileRoleV1 {
    const fn unit(self) -> &'static [u8] {
        match self {
            Self::Source => b"aos-sandbox-source-signerd.service",
            Self::Ownership => b"aos-sandbox-ownershipd.service",
            Self::Cache => b"aos-sandbox-cache-signerd.service",
            Self::Mount => b"aos-sandbox-mountd.service",
            Self::Network => b"aos-netd.service",
            Self::BootPreparation => b"aos-sandbox-runtime-publisher.service",
        }
    }
}

const MAXIMUM_FILE_BYTES: usize = 64 * 1024;
const MAXIMUM_FILES: usize = 5;
const PROFILE_ROW_BYTES: usize = 1506;

#[derive(Clone, Copy)]
enum Failure {
    Order,
    Coordinates,
    Metadata(usize),
    Filesystem(usize),
    Flags(usize),
    Length(usize),
    Shape(usize),
    Read(usize),
    Digest(usize),
    Syntax(usize),
    MetadataPost(usize),
    FilesystemPost(usize),
    FlagsPost(usize),
    PhysicalPost(usize),
}

#[derive(Default)]
struct FileReadback<E> {
    metadata: Option<std::io::Result<Metadata>>,
    filesystem: Option<Result<StatFs, rustix::io::Errno>>,
    flags: Option<Result<OFlags, rustix::io::Errno>>,
    length: Option<Result<usize, std::num::TryFromIntError>>,
    shape: Option<Result<(), E>>,
    read: Option<std::io::Result<()>>,
    digest: Option<Result<(), E>>,
    syntax: Option<Result<(), E>>,
    metadata_post: Option<std::io::Result<Metadata>>,
    filesystem_post: Option<Result<StatFs, rustix::io::Errno>>,
    flags_post: Option<Result<OFlags, rustix::io::Errno>>,
    physical_post: Option<Result<(), E>>,
}

/// Retains the fixed protected Source profile's actual original-file reads.
pub(crate) struct FixedServiceProfileReadbackV1<E> {
    role: FixedServiceProfileRoleV1,
    first: Option<Failure>,
    closed: Option<E>,
    coordinates: Option<Result<(), E>>,
    row_digest: Option<[u8; 32]>,
    file_count: usize,
    next_file: usize,
    files: [FileReadback<E>; MAXIMUM_FILES],
    bytes: [u8; MAXIMUM_FILE_BYTES],
}

impl<E: Default + Copy + Error + 'static> FixedServiceProfileReadbackV1<E> {
    /// Creates inline storage without allocating, reading or adopting a file.
    pub(crate) fn new(role: FixedServiceProfileRoleV1) -> Self {
        Self {
            role,
            first: None,
            closed: None,
            coordinates: None,
            row_digest: None,
            file_count: 0,
            next_file: 0,
            files: std::array::from_fn(|_| FileReadback::default()),
            bytes: [0; MAXIMUM_FILE_BYTES],
        }
    }

    /// Reads the next parent-selected original after its fixed receiving debit.
    ///
    /// The parent retains the file and authenticates its part index, digest and
    /// subject before this call. The row must be borrowed from that same held
    /// Parent buffer; it cannot be supplied by a peer's current-cut request.
    ///
    /// # Errors
    /// Retains the first native readback, physical, digest or syntax refusal.
    /// An incomplete or failed file cannot be retried or replace its results.
    pub(crate) fn observe_next_file_once(
        &mut self,
        original: &File,
        source_row: &[u8],
    ) -> Result<(), E> {
        if self.first.is_some() || self.next_file >= MAXIMUM_FILES
            || self.file_count != 0 && self.next_file >= self.file_count
        {
            return Err(self.fail(Failure::Order));
        }

        let index = self.next_file;
        let row_digest: [u8; 32] = Sha256::digest(source_row).into();
        self.coordinates = Some(require_coordinates::<E>(source_row, index, self.role));
        if self.coordinates.as_ref().is_none_or(Result::is_err)
            || self.row_digest.is_some_and(|prior| prior != row_digest)
        {
            return Err(self.fail(Failure::Coordinates));
        }
        if self.row_digest.is_none() {
            self.row_digest = Some(row_digest);
            self.file_count = 1 + usize::from(u16::from_be_bytes([source_row[352], source_row[353]]));
        }

        self.files[index].metadata = Some(original.metadata());
        self.files[index].filesystem = Some(rustix::fs::fstatfs(original));
        self.files[index].flags = Some(rustix::fs::fcntl_getfl(original));
        if self.files[index].metadata.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Metadata(index)));
        }
        if self.files[index].filesystem.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Filesystem(index)));
        }
        if self.files[index].flags.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Flags(index)));
        }

        let metadata = self.files[index].metadata.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        self.files[index].length = Some(usize::try_from(metadata.len()));
        let length = match self.files[index].length.as_ref() {
            Some(Ok(length)) => *length,
            _ => return Err(self.fail(Failure::Length(index))),
        };
        self.files[index].shape = Some(require_physical::<E>(&self.files[index], false));
        if self.files[index].shape.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Shape(index)));
        }

        self.files[index].read = Some(original.read_exact_at(&mut self.bytes[..length], 0));
        if self.files[index].read.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Read(index)));
        }
        let digest_offset = if index == 0 { 320 } else { 354 + (index - 1) * 288 + 256 };
        self.files[index].digest = Some(if Sha256::digest(&self.bytes[..length]).as_slice()
            == &source_row[digest_offset..digest_offset + 32]
        {
            Ok(())
        } else {
            Err(E::default())
        });
        if self.files[index].digest.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Digest(index)));
        }
        self.files[index].syntax = Some(require_profile_syntax::<E>(&self.bytes[..length], index == 0, self.role));
        if self.files[index].syntax.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Syntax(index)));
        }

        self.files[index].metadata_post = Some(original.metadata());
        self.files[index].filesystem_post = Some(rustix::fs::fstatfs(original));
        self.files[index].flags_post = Some(rustix::fs::fcntl_getfl(original));
        if self.files[index].metadata_post.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::MetadataPost(index)));
        }
        if self.files[index].filesystem_post.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::FilesystemPost(index)));
        }
        if self.files[index].flags_post.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::FlagsPost(index)));
        }
        self.files[index].physical_post = Some(require_physical::<E>(&self.files[index], true));
        if self.files[index].physical_post.as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::PhysicalPost(index)));
        }

        self.next_file += 1;
        Ok(())
    }

    /// Requires every original named by the same Parent row to have completed.
    ///
    /// # Errors
    /// Rejects a missing file, an earlier failure or an incomplete observation.
    pub(crate) fn require_complete(&self) -> Result<(), E> {
        if self.first.is_none() && self.file_count != 0 && self.next_file == self.file_count {
            Ok(())
        } else {
            Err(E::default())
        }
    }

    fn fail(&mut self, site: Failure) -> E {
        self.first.get_or_insert(site);
        self.closed.get_or_insert(E::default());
        E::default()
    }

    /// Borrows the earliest retained native or closed-profile cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let site = self.first?;
        match site {
            Failure::Order => self.closed.as_ref().map(|error| error as _),
            Failure::Coordinates => failure(&self.coordinates),
            Failure::Metadata(index) => failure(&self.files[index].metadata),
            Failure::Filesystem(index) => failure(&self.files[index].filesystem),
            Failure::Flags(index) => failure(&self.files[index].flags),
            Failure::Length(index) => failure(&self.files[index].length),
            Failure::Shape(index) => failure(&self.files[index].shape),
            Failure::Read(index) => failure(&self.files[index].read),
            Failure::Digest(index) => failure(&self.files[index].digest),
            Failure::Syntax(index) => failure(&self.files[index].syntax),
            Failure::MetadataPost(index) => failure(&self.files[index].metadata_post),
            Failure::FilesystemPost(index) => failure(&self.files[index].filesystem_post),
            Failure::FlagsPost(index) => failure(&self.files[index].flags_post),
            Failure::PhysicalPost(index) => failure(&self.files[index].physical_post),
        }.or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn require_coordinates<E: Default>(row: &[u8], index: usize, role: FixedServiceProfileRoleV1) -> Result<(), E> {
    if row.len() != PROFILE_ROW_BYTES || padded_name::<E>(&row[..64])? != role.unit()
        || padded_name::<E>(&row[64..320])? != role.unit()
    {
        return Err(E::default());
    }
    let drops = usize::from(u16::from_be_bytes([row[352], row[353]]));
    if drops >= MAXIMUM_FILES || index > drops {
        return Err(E::default());
    }

    let mut prior: Option<&[u8]> = None;
    for slot in 0..MAXIMUM_FILES - 1 {
        let start = 354 + slot * 288;
        let tuple = &row[start..start + 288];
        if slot >= drops {
            if tuple.iter().any(|byte| *byte != 0) {
                return Err(E::default());
            }
            continue;
        }
        let path = padded_name::<E>(&tuple[..256])?;
        let leaf = path.strip_prefix(role.unit()).and_then(|path| path.strip_prefix(b".d/")).ok_or(E::default())?;
        if leaf.is_empty() || !leaf.ends_with(b".conf") || !leaf.is_ascii() || leaf.contains(&b'/')
            || leaf == b"." || leaf == b".." || prior.is_some_and(|prior| prior >= path)
        {
            return Err(E::default());
        }
        prior = Some(path);
    }
    Ok(())
}

fn padded_name<E: Default>(bytes: &[u8]) -> Result<&[u8], E> {
    let end = bytes.iter().position(|byte| *byte == 0).ok_or(E::default())?;
    if end == 0 || bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(E::default());
    }
    Ok(&bytes[..end])
}

fn require_physical<E: Default>(file: &FileReadback<E>, post: bool) -> Result<(), E> {
    let (metadata, filesystem, flags) = if post {
        (&file.metadata_post, &file.filesystem_post, &file.flags_post)
    } else {
        (&file.metadata, &file.filesystem, &file.flags)
    };
    let metadata = metadata.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
    let filesystem = filesystem.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
    let flags = flags.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.gid() != 0
        || metadata.mode() & 0o7222 != 0
        || metadata.len() > MAXIMUM_FILE_BYTES as u64 || filesystem.f_type as u64 != 0xe0f5_e1e2
        || flags.intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND)
    {
        return Err(E::default());
    }
    if post {
        let before = file.metadata.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        if metadata.dev() != before.dev() || metadata.ino() != before.ino()
            || metadata.len() != before.len() || metadata.mode() != before.mode()
            || metadata.uid() != before.uid() || metadata.gid() != before.gid()
            || metadata.ctime() != before.ctime() || metadata.ctime_nsec() != before.ctime_nsec()
        {
            return Err(E::default());
        }
    }
    Ok(())
}

// This finite grammar applies only to the new image-produced protected role.
// A reset in a later drop-in never excuses a forbidden earlier assignment.
pub(crate) fn require_profile_syntax<E: Default>(bytes: &[u8], base: bool, role: FixedServiceProfileRoleV1) -> Result<(), E> {
    if bytes.is_empty() {
        return if base { Err(E::default()) } else { Ok(()) };
    }
    if bytes.len() > MAXIMUM_FILE_BYTES || !bytes.is_ascii()
        || bytes.iter().any(|byte| !byte.is_ascii_graphic() && !b" \t\n".contains(byte))
        || !bytes.ends_with(b"\n")
    {
        return Err(E::default());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| E::default())?;
    let mut service = false;
    let mut section = false;
    let mut exec_start = false;
    let mut user = false;
    let mut group = false;
    let mut state_directory = false;
    let mut runtime_directory = false;
    let mut state_mode = false;
    let mut runtime_mode = false;
    for line in text.lines() {
        let line = line.trim_matches([' ', '\t']);
        if line.ends_with('\\') {
            return Err(E::default());
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('.') {
            return Err(E::default());
        }
        if line.starts_with('[') {
            if !matches!(line, "[Unit]" | "[Service]" | "[Install]") {
                return Err(E::default());
            }
            section = true;
            service = line == "[Service]";
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(E::default())?;
        let key = key.trim_matches([' ', '\t']);
        let value = value.trim_matches([' ', '\t']);
        if !section || key.is_empty()
            || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(E::default());
        }
        if service && key == "ExecStart" {
            // The final-byte image producer binds the exact selected literal;
            // PID1 also joins its actual sole parsed command to this same file.
            if !base || exec_start || value.is_empty() {
                return Err(E::default());
            }
            exec_start = true;
        }
        if service && matches!(key, "User" | "Group") {
            let seen = if key == "User" { &mut user } else { &mut group };
            let expected = match role {
                FixedServiceProfileRoleV1::Source => "aos-source-signer",
                FixedServiceProfileRoleV1::Ownership | FixedServiceProfileRoleV1::Mount
                    | FixedServiceProfileRoleV1::Network | FixedServiceProfileRoleV1::BootPreparation => "root",
                FixedServiceProfileRoleV1::Cache => "aos-cache-signer",
            };
            if !base || *seen || value != expected {
                return Err(E::default());
            }
            *seen = true;
        }
        // These new machine-role settings exclude namespace/user fallbacks
        // which could otherwise create another pre-exec descriptor table.
        let false_value = value.is_empty() || value.eq_ignore_ascii_case("no")
            || value.eq_ignore_ascii_case("false") || value == "0";
        if service && ((matches!(key, "PrivateUsers" | "PrivatePIDs" | "PrivateBPF"
            | "DynamicUser" | "RootEphemeral") && !false_value)
            || matches!(key, "UserNamespacePath" | "DelegateNamespaces") && !value.is_empty())
        {
            return Err(E::default());
        }
        let connected_tmp = value.eq_ignore_ascii_case("yes") || value.eq_ignore_ascii_case("true")
            || value == "1" || value.eq_ignore_ascii_case("connected");
        if service && matches!(key, "PrivateTmp" | "PrivateVarTmp") && !connected_tmp {
            return Err(E::default());
        }
        if service && matches!(role, FixedServiceProfileRoleV1::Ownership
            | FixedServiceProfileRoleV1::Mount | FixedServiceProfileRoleV1::Network)
        {
            let (state, runtime) = match role {
                FixedServiceProfileRoleV1::Ownership => ("aos/sandbox/multi-node", "aos/sandbox-ownership"),
                FixedServiceProfileRoleV1::Mount => ("aos/sandbox-mount", "aos/sandbox-mount-catalog"),
                FixedServiceProfileRoleV1::Network => (
                    "aos/sandbox-network/broker-state aos/sandbox-network/broker-session",
                    "aos/sandbox-pins/netns",
                ),
                _ => return Err(E::default()),
            };
            let expected = match key {
                "StateDirectory" => Some((state, &mut state_directory)),
                "RuntimeDirectory" => Some((runtime, &mut runtime_directory)),
                "StateDirectoryMode" => Some(("0700", &mut state_mode)),
                "RuntimeDirectoryMode" => Some((
                    if role == FixedServiceProfileRoleV1::Ownership { "0711" } else { "0700" },
                    &mut runtime_mode,
                )),
                _ => None,
            };
            if let Some((expected, seen)) = expected {
                if !base || *seen || value != expected {
                    return Err(E::default());
                }
                *seen = true;
                continue;
            }
        }
        if service && role == FixedServiceProfileRoleV1::Mount
            && matches!(key, "CapabilityBoundingSet" | "AmbientCapabilities")
        {
            let mut capabilities = value.split_ascii_whitespace();
            let valid = matches!((capabilities.next(), capabilities.next(), capabilities.next()),
                (Some("CAP_SYS_ADMIN"), Some("CAP_SYS_CHROOT"), None)
                | (Some("CAP_SYS_CHROOT"), Some("CAP_SYS_ADMIN"), None));
            if !base || !valid {
                return Err(E::default());
            }
            continue;
        }
        if service && matches!(key, "RootDirectory" | "RootImage" | "RootMStack"
            | "MountImages" | "ExtensionImages" | "ExtensionDirectories" | "TemporaryFileSystem"
            | "RuntimeDirectory" | "StateDirectory" | "CacheDirectory" | "LogsDirectory" | "ConfigurationDirectory")
            && !value.is_empty()
        {
            return Err(E::default());
        }
        if service && matches!(key, "PAMName" | "EnvironmentFile" | "CapabilityBoundingSet" | "AmbientCapabilities"
            | "ExecCondition" | "ExecStartPre" | "ExecStartPost" | "ExecReload"
            | "ExecReloadPost" | "ExecStop" | "ExecStopPost") && !value.is_empty()
        {
            return Err(E::default());
        }
    }
    let identity = match role {
        FixedServiceProfileRoleV1::Source | FixedServiceProfileRoleV1::Cache => user == base && group == base,
        // Optional explicit root User/Group assignments were already checked
        // above; neither can appear in a drop-in or select another identity.
        FixedServiceProfileRoleV1::Ownership | FixedServiceProfileRoleV1::Mount
            | FixedServiceProfileRoleV1::Network | FixedServiceProfileRoleV1::BootPreparation => true,
    };
    let directories = match role {
        FixedServiceProfileRoleV1::Source | FixedServiceProfileRoleV1::Cache
            | FixedServiceProfileRoleV1::BootPreparation => true,
        FixedServiceProfileRoleV1::Ownership | FixedServiceProfileRoleV1::Mount =>
            state_directory == base && runtime_directory == base
                && state_mode == base && runtime_mode == base,
        // The protected-roots variant owns the same state paths before exec.
        FixedServiceProfileRoleV1::Network => runtime_directory == base
            && runtime_mode == base && state_directory == state_mode,
    };
    if exec_start == base && identity && directories {
        Ok(())
    } else {
        Err(E::default())
    }
}

fn failure<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}


#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Default, thiserror::Error)]
    #[error("fixed profile comparison refused")]
    struct Closed;

    const OWNERSHIP: &[u8] = b"[Service]\nExecStart=/nix/store/original/bin/aos-sandbox-ownershipd 1000 1000\nStateDirectory=aos/sandbox/multi-node\nStateDirectoryMode=0700\nRuntimeDirectory=aos/sandbox-ownership\nRuntimeDirectoryMode=0711\n";

    #[test]
    fn cache_profile_requires_its_actual_identity_without_directories() {
        let cache = b"[Service]\nExecStart=/nix/store/original/bin/aos-sandbox-cache-signerd 1000 1000 813 813\nUser=aos-cache-signer\nGroup=aos-cache-signer\n";
        assert!(require_profile_syntax::<Closed>(cache, true, FixedServiceProfileRoleV1::Cache).is_ok());
        assert!(require_profile_syntax::<Closed>(cache, true, FixedServiceProfileRoleV1::Source).is_err());
        assert!(require_profile_syntax::<Closed>(OWNERSHIP, true, FixedServiceProfileRoleV1::Cache).is_err());

        let mut forbidden = cache.to_vec();
        forbidden.extend_from_slice(b"StateDirectory=private\n");
        assert!(require_profile_syntax::<Closed>(&forbidden, true, FixedServiceProfileRoleV1::Cache).is_err());
    }

    #[test]
    fn mount_and_network_keep_their_actual_private_directory_modes() {
        let mount = "[Service]\nExecStart=/nix/store/original/bin/aos-sandbox-mountd\nStateDirectory=aos/sandbox-mount\nStateDirectoryMode=0700\nRuntimeDirectory=aos/sandbox-mount-catalog\nRuntimeDirectoryMode=0700\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT\nAmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_CHROOT\n";
        let network = "[Service]\nExecStart=/nix/store/original/bin/aos-netd\nRuntimeDirectory=aos/sandbox-pins/netns\nRuntimeDirectoryMode=0700\n";

        assert!(require_profile_syntax::<Closed>(mount.as_bytes(), true, FixedServiceProfileRoleV1::Mount).is_ok());
        assert!(require_profile_syntax::<Closed>(network.as_bytes(), true, FixedServiceProfileRoleV1::Network).is_ok());
        for (body, role) in [(mount, FixedServiceProfileRoleV1::Mount),
            (network, FixedServiceProfileRoleV1::Network)] {
            let ownership_mode = body.replace("RuntimeDirectoryMode=0700", "RuntimeDirectoryMode=0711");
            assert!(require_profile_syntax::<Closed>(ownership_mode.as_bytes(), true, role).is_err());
            assert!(require_profile_syntax::<Closed>(body.as_bytes(), true, FixedServiceProfileRoleV1::Ownership).is_err());
        }
    }

    #[test]
    fn ownership_requires_its_existing_exact_directory_roster() {
        assert!(require_profile_syntax::<Closed>(OWNERSHIP, true, FixedServiceProfileRoleV1::Ownership).is_ok());
        assert!(require_profile_syntax::<Closed>(OWNERSHIP, true, FixedServiceProfileRoleV1::Source).is_err());

        let original = std::str::from_utf8(OWNERSHIP).unwrap();
        for directive in [
            "StateDirectory=aos/sandbox/multi-node\n",
            "StateDirectoryMode=0700\n",
            "RuntimeDirectory=aos/sandbox-ownership\n",
            "RuntimeDirectoryMode=0711\n",
        ] {
            let missing = original.replace(directive, "");
            assert!(require_profile_syntax::<Closed>(missing.as_bytes(), true, FixedServiceProfileRoleV1::Ownership).is_err());
        }
        for replacement in [
            original.replace("multi-node", "other"),
            original.replace("0700", "0755"),
            original.replace("StateDirectory=aos/sandbox/multi-node", "StateDirectory=aos/sandbox/multi-node:alias"),
            format!("{original}User=other\n"),
        ] {
            assert!(require_profile_syntax::<Closed>(replacement.as_bytes(), true, FixedServiceProfileRoleV1::Ownership).is_err());
        }
    }

    #[test]
    fn ownership_dropin_cannot_replace_the_fixed_root_or_directories() {
        for text in [
            b"[Service]\nUser=root\n".as_slice(),
            b"[Service]\nGroup=root\n",
            b"[Service]\nStateDirectory=aos/sandbox/multi-node\n",
            b"[Service]\nRuntimeDirectory=\n",
        ] {
            assert!(require_profile_syntax::<Closed>(text, false, FixedServiceProfileRoleV1::Ownership).is_err());
        }
        assert!(require_profile_syntax::<Closed>(b"", false, FixedServiceProfileRoleV1::Ownership).is_ok());
    }
    #[test]
    fn profile_coordinates_bind_the_complete_same_fixed_role_row() {
        for role in [FixedServiceProfileRoleV1::Source, FixedServiceProfileRoleV1::Ownership,
            FixedServiceProfileRoleV1::Cache, FixedServiceProfileRoleV1::Mount, FixedServiceProfileRoleV1::Network] {
            let unit = role.unit();
            let mut row = [0; PROFILE_ROW_BYTES];
            row[..unit.len()].copy_from_slice(unit);
            row[64..64 + unit.len()].copy_from_slice(unit);
            assert!(require_coordinates::<Closed>(&row, 0, role).is_ok());
            assert!(require_coordinates::<Closed>(&row, 1, role).is_err());

            let mut path = unit.to_vec();
            path.extend_from_slice(b".d/override.conf");
            row[353] = 1;
            row[354..354 + path.len()].copy_from_slice(&path);
            assert!(require_coordinates::<Closed>(&row, 1, role).is_ok());
            row[354] = b'x';
            assert!(require_coordinates::<Closed>(&row, 1, role).is_err());
            row[354] = path[0];
            row[354 + 288] = 1;
            assert!(require_coordinates::<Closed>(&row, 1, role).is_err());
        }
    }
}
