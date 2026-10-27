//! Keeps the actual selected daemon and fixed-file prefix before publication.
//!
//! Only the existing accepted execution and fixed installation recipe enter
//! this owner. It supplies no new process, signal, path or lifetime permission.

use super::*;
use aos_sandbox_linux::protected_file::FixedProtectedReadOriginalV3;

pub(super) fn configure_selected_command_v1(command: &mut Command) {
    command.env_clear();
    command.envs(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_ENVIRONMENT_V1);
    command.args(aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_ARGUMENTS_V1);
}

#[derive(Default)]
pub(crate) struct OpenSshDaemonStartupOriginalV1 {
    pub(super) entered: bool,
    pub(super) child: Option<std::io::Result<Child>>,
    pub(super) pidfd: aos_sandbox_linux::pidfd::PidFdOpenAttemptV1,
    pub(super) read: Option<Box<FixedProtectedReadOriginalV3>>,
    pub(super) body: Option<OpenSshGatePhysicalErrorV1>,
    pub(super) cleanup_kill: Option<std::io::Result<()>>,
    pub(super) cleanup_wait: Option<std::io::Result<Option<std::process::ExitStatus>>>,
    pub(super) identity_wait: Option<std::io::Result<Option<std::process::ExitStatus>>>,
    pub(super) identity: Option<aos_sandbox_linux::pidfd::PidFdProcessIdentityOriginalV1>,
}

impl OpenSshDaemonStartupOriginalV1 {
    pub(crate) fn read_static_login_v1(
        &mut self,
        path: &Path,
        maximum: u64,
    ) -> Result<String, OpenSshGatePhysicalErrorV1> {
        let file = self.read_fixed(path, maximum, false)?;
        if file.bytes.contains(&0) {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        String::from_utf8(file.bytes).map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)
    }

    pub(super) fn read_fixed(
        &mut self,
        path: &Path,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<ProtectedFile, OpenSshGatePhysicalErrorV1> {
        if self.read.as_ref().is_some_and(|read| !read.completed_v3()) {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        // The actual Host source invoice pays this compiled reader before the
        // selected Agent request. A preceding full-positive file phase alone
        // may release its original before this next fixed recipe.
        self.read = Some(Box::new(FixedProtectedReadOriginalV3::new()));
        check_protected_ancestors(path)?;
        let read = self
            .read
            .as_mut()
            .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        let primary = (|| {
            read.capture_once_v3(path)
                .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
            let metadata = read
                .metadata_v3()
                .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.len() == 0
                || metadata.len() > maximum_bytes
                || (executable && metadata.mode() & 0o111 == 0)
            {
                return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
            }
            let extent = metadata.len();
            if executable {
                read.hash_once_v3(extent)
                    .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)
            } else {
                let extent = usize::try_from(extent)
                    .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
                read.read_bytes_once_v3(extent)
                    .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)
            }
        })();
        // This path/name and same-descriptor post remains independent of an
        // opening, policy, hash, read or EOF refusal.
        let after = read.finish_once_v3(path);
        primary?;
        after.map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        let metadata = read
            .metadata_v3()
            .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        let (device, inode, mode) = (metadata.dev(), metadata.ino(), metadata.mode());
        let measured_digest = read.digest_v3();
        let bytes = if executable {
            Vec::new()
        } else {
            read.bytes_completed_v3()
                .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?
                .to_vec()
        };
        Ok(ProtectedFile {
            bytes,
            device,
            inode,
            mode,
            measured_digest,
        })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.child
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.read.as_ref().and_then(|read| read.failure()))
            .or_else(|| self.pidfd.failure().map(|cause| cause as _))
            .or_else(|| self.body.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.identity_wait
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.identity.as_ref()?.failure().map(|cause| cause as _))
            .or_else(|| {
                self.cleanup_kill
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.cleanup_wait
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_daemon_recipe_drops_unbound_environment_and_keeps_fixed_hooks() {
        let mut command = Command::new(SSHD_PATH);
        command.env("UNBOUND_TEST_INPUT", "must not reach daemon");

        configure_selected_command_v1(&mut command);

        let environment: Vec<_> = command.get_envs().collect();
        assert_eq!(
            environment,
            vec![
                (
                    std::ffi::OsStr::new("LANG"),
                    Some(std::ffi::OsStr::new("C"))
                ),
                (
                    std::ffi::OsStr::new("LC_ALL"),
                    Some(std::ffi::OsStr::new("C"))
                ),
            ]
        );
        assert_eq!(command.get_program(), std::ffi::OsStr::new(SSHD_PATH));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_DAEMON_ARGUMENTS_V1
                .iter()
                .map(std::ffi::OsStr::new)
                .collect::<Vec<_>>()
        );
        assert!(command.get_args().any(|argument| argument
            == std::ffi::OsStr::new("-oSshdSessionPath=/usr/libexec/sshd-session")));
    }
}
