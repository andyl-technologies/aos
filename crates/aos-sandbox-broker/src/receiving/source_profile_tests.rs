//! Retains Source's typed policy projection over common fixed-file mechanics.
//!
//! Its actual Source original still authenticates PID1, the exact Parent row,
//! Source role, profile admission and sole F ledger before these observations.
//! The common parser/readback is DATA and creates no original or key authority.

use std::error::Error;
use std::fs::File;

#[derive(Clone, Copy, Debug, Default, thiserror::Error)]
#[error("inert Source format fixture refused")]
struct SourceReceivingClosedV1;

use super::fixed_service_profile::{FixedServiceProfileReadbackV1, FixedServiceProfileRoleV1};

pub(crate) struct SourceProtectedProfileReadbackV1(FixedServiceProfileReadbackV1<SourceReceivingClosedV1>);

impl SourceProtectedProfileReadbackV1 {
    pub(crate) fn new() -> Self {
        Self(FixedServiceProfileReadbackV1::new(FixedServiceProfileRoleV1::Source))
    }

    pub(crate) fn observe_next_file_once(&mut self, original: &File, row: &[u8]) -> Result<(), SourceReceivingClosedV1> {
        self.0.observe_next_file_once(original, row)
    }

    pub(crate) fn require_complete(&self) -> Result<(), SourceReceivingClosedV1> {
        self.0.require_complete()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.0.failure()
    }
}

#[cfg(test)]
fn require_source_syntax(bytes: &[u8], base: bool) -> Result<(), SourceReceivingClosedV1> {
    super::fixed_service_profile::require_profile_syntax(bytes, base, FixedServiceProfileRoleV1::Source)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &[u8] = b"[Unit]\nDescription=Source\nX-StopIfChanged=true\n[Service]\nExecStart=/nix/store/example/bin/signer 1 2 3 4\nUser=aos-source-signer\nGroup=aos-source-signer\nEnvironment=\"STATIC=value\"\nCapabilityBoundingSet=\nAmbientCapabilities=\n";

    #[test]
    fn finite_source_profile_accepts_base_and_empty_dropin_resets() {
        assert!(require_source_syntax(BASE, true).is_ok());
        assert!(require_source_syntax(b"", false).is_ok());
        assert!(require_source_syntax(b"", true).is_err());
        assert!(require_source_syntax(
            b"# original drop-in\n[Service]\n PAMName = \t\nEnvironmentFile=\nExecStartPre=\nCapabilityBoundingSet=\nAmbientCapabilities=\n",
            false,
        ).is_ok());
    }

    #[test]
    fn finite_source_profile_refuses_meaningful_forbidden_directives() {
        for directive in [
            "PAMName", "EnvironmentFile", "ExecCondition", "ExecStartPre",
            "ExecStartPost", "ExecReload", "ExecReloadPost", "ExecStop",
            "ExecStopPost", "CapabilityBoundingSet", "AmbientCapabilities",
        ] {
            let text = format!("[Service]\n{directive}=value\n");
            assert!(require_source_syntax(text.as_bytes(), false).is_err(), "{directive}");
        }
    }

    #[test]
    fn finite_source_profile_refuses_alternate_syntax_and_exec_resets() {
        for text in [
            b"[Service]\nEnvironment=one\\\n two\n".as_slice(),
            b"# comment\\\n[Service]\n", b".include other.conf\n",
            b"[Service]\r\n", b"[Service]\n\0", b"[Service]\nKey=\x0b\n",
            b"[Socket]\nKey=value\n", b"Key=value\n", b"[Service]\nKey\n",
            b"[Service]\nExecStart=\n", b"[Service]\nExecStart=/bin/other\n",
            b"[Service]\nKey=value", b"[Service] # alternate header\n",
            b"[Service]\nUser=\n", b"[Service]\nGroup=aos-source-signer\n",
        ] {
            assert!(require_source_syntax(text, false).is_err(), "{text:?}");
        }
        assert!(require_source_syntax(b"[Service]\n", true).is_err());
        assert!(require_source_syntax(
            b"[Service]\nExecStart=one\nExecStart=two\n", true,
        ).is_err());
        let base = std::str::from_utf8(BASE).unwrap();
        for identity in ["User", "Group"] {
            let missing = base.replace(&format!("{identity}=aos-source-signer\n"), "");
            assert!(require_source_syntax(missing.as_bytes(), true).is_err());
            let different = base.replace(&format!("{identity}=aos-source-signer"), &format!("{identity}=other"));
            assert!(require_source_syntax(different.as_bytes(), true).is_err());
        }
    }

    #[test]
    fn finite_source_profile_accepts_only_false_namespace_and_user_settings() {
        assert!(require_source_syntax(BASE, true).is_ok());
        for directive in ["PrivateUsers", "PrivatePIDs", "PrivateBPF", "DynamicUser"] {
            for value in ["", "no", "NO", "false", "FaLsE", "0"] {
                let text = format!("[Service]\n{directive}={value}\n");
                assert!(require_source_syntax(text.as_bytes(), false).is_ok(), "{directive}={value}");
            }
            for value in ["yes", "true", "1", "pick", "self", "0x0", "no false"] {
                let text = format!("[Service]\n{directive}={value}\n");
                assert!(require_source_syntax(text.as_bytes(), false).is_err(), "{directive}={value}");
            }
        }
    }

    #[test]
    fn finite_source_profile_refuses_any_user_namespace_path() {
        assert!(require_source_syntax(b"[Service]\nUserNamespacePath= \t\n", false).is_ok());
        for value in ["no", "false", "0", "/proc/self/ns/user"] {
            let text = format!("[Service]\nUserNamespacePath={value}\n");
            assert!(require_source_syntax(text.as_bytes(), false).is_err());
        }
    }

    #[test]
    fn finite_source_profile_refuses_unconfigured_mount_and_root_helpers() {
        for directive in ["RootDirectory", "RootImage", "RootMStack", "MountImages",
            "ExtensionImages", "ExtensionDirectories", "TemporaryFileSystem"]
        {
            let empty = format!("[Service]\n{directive}= \t\n");
            assert!(require_source_syntax(empty.as_bytes(), false).is_ok());
            let configured = format!("[Service]\n{directive}=/image\n");
            assert!(require_source_syntax(configured.as_bytes(), false).is_err());
        }
        for value in ["", "no", "NO", "false", "FaLsE", "0"] {
            let text = format!("[Service]\nRootEphemeral={value}\n");
            assert!(require_source_syntax(text.as_bytes(), false).is_ok());
        }
        assert!(require_source_syntax(b"[Service]\nRootEphemeral=yes\n", false).is_err());
    }

    #[test]
    fn finite_source_profile_keeps_only_connected_private_tmp_assignments() {
        for directive in ["PrivateTmp", "PrivateVarTmp"] {
            for value in ["yes", "YES", "true", "TrUe", "1", "connected", "CONNECTED"] {
                let text = format!("[Service]\n{directive}={value}\n");
                assert!(require_source_syntax(text.as_bytes(), false).is_ok(), "{directive}={value}");
            }
            for value in ["", "no", "false", "0", "disconnected", "true yes"] {
                let text = format!("[Service]\n{directive}={value}\n");
                assert!(require_source_syntax(text.as_bytes(), false).is_err(), "{directive}={value}");
            }
        }
    }

    #[test]
    fn finite_source_profile_refuses_false_delegation_assignments() {
        assert!(require_source_syntax(b"[Service]\nDelegateNamespaces= \t\n", false).is_ok());
        for value in ["no", "NO", "false", "FaLsE", "0", "yes", "true", "1", "user"] {
            let text = format!("[Service]\nDelegateNamespaces={value}\n");
            assert!(require_source_syntax(text.as_bytes(), false).is_err(), "{value}");
        }
    }

    #[test]
    fn finite_source_profile_refuses_unconfigured_exec_directories() {
        assert!(require_source_syntax(BASE, true).is_ok());
        for directive in ["RuntimeDirectory", "StateDirectory", "CacheDirectory",
            "LogsDirectory", "ConfigurationDirectory"]
        {
            let empty = format!("[Service]\n{directive}= \t\n");
            assert!(require_source_syntax(empty.as_bytes(), false).is_ok());
            for value in ["source", "source:link", "source:link:ro", "../source", "/source"] {
                let configured = format!("[Service]\n{directive}={value}\n");
                assert!(require_source_syntax(configured.as_bytes(), false).is_err(), "{directive}={value}");
            }
        }
    }

}
