//! Fixed Controller process configuration and closed activation flag parsing.
//!
//! These inputs select existing consumer routes, never protected authority.
//! Identity validation and flag/error precedence retain the installed recipe;
//! only UID/GID cross to the issue-only sibling, and all other fields remain
//! inside activation.

use std::path::PathBuf;

use super::super::{ControllerRuntimeError, STATE_DIRECTORY};

const DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";

/// Holds fixed process inputs without conferring protected authority.
#[derive(Clone, Debug)]
pub(in crate::controller_service) struct RuntimeConfiguration {
    pub(in crate::controller_service) uid: u32,
    pub(in crate::controller_service) gid: u32,
    pub(super) state_directory: PathBuf,
    pub(super) diagnostic_socket: PathBuf,
    pub(super) public_api: bool,
    pub(super) publisher_ingress: bool,
    pub(super) git_upload_bootstrap: bool,
    pub(super) git_coverage: bool,
    pub(super) git_read_inspection: Option<(u32, u32)>,
    pub(super) nix_start_admission: bool,
    pub(super) nix_storage_generation_prepare: bool,
    pub(super) nix_existing_outputs: bool,
    pub(super) issue_source_successor: bool,
    pub(super) create_q04_policy_subgate: bool,
}

impl RuntimeConfiguration {
    /// Parses the installed command-line and selected online Nix disposition.
    ///
    /// # Errors
    ///
    /// Returns the original positional, flag or online-disposition error.
    pub(super) fn from_process() -> Result<Self, ControllerRuntimeError> {
        let mut configuration = Self::from_arguments(std::env::args())?;
        if configuration.nix_start_admission {
            // This fixed unit input selects a consumer disposition, not request
            // authority. The original measured owner, floor and grants are still
            // required independently at each exchange and physical readback.
            configuration.nix_existing_outputs = match std::env::var_os("AOS_NIX_EXISTING_OUTPUTS") {
                None => false,
                Some(value) if value == "1" => true,
                Some(_) => return Err(ControllerRuntimeError::InvalidArguments("online Nix mode")),
            };
        }
        Ok(configuration)
    }

    fn from_arguments(
        mut arguments: impl Iterator<Item = String>,
    ) -> Result<Self, ControllerRuntimeError> {
        let _program = arguments.next();
        let uid = parse_identity(arguments.next(), "controller UID")?;
        let gid = parse_identity(arguments.next(), "controller GID")?;
        let mut public_api = false;
        let mut publisher_ingress = false;
        let mut git_upload_bootstrap = false;
        let mut git_coverage = false;
        let mut git_read_inspection = None;
        let mut nix_start_admission = false;
        let mut nix_storage_generation_prepare = false;
        let mut issue_source_successor = false;
        let mut create_q04_policy_subgate = false;
        for argument in arguments {
            match argument.as_str() {
                "--public-api" if !public_api => public_api = true,
                "--publisher-ingress" if !publisher_ingress => publisher_ingress = true,
                "--git-upload-bootstrap" if !git_upload_bootstrap => git_upload_bootstrap = true,
                "--git-upload-coverage" if !git_coverage => git_coverage = true,
                "--nix-start-admission" if !nix_start_admission => nix_start_admission = true,
                "--nix-storage-generation-prepare" if !nix_storage_generation_prepare => {
                    nix_storage_generation_prepare = true;
                }
                "--issue-source-successor" if !issue_source_successor => {
                    issue_source_successor = true;
                }
                "--create-q04-policy-subgate" if !create_q04_policy_subgate => {
                    create_q04_policy_subgate = true;
                }
                value if value.starts_with("--git-read-inspection=")
                    && git_read_inspection.is_none() => {
                    let pair = &value["--git-read-inspection=".len()..];
                    let Some((gateway_uid, gateway_gid)) = pair.split_once(':') else {
                        return Err(ControllerRuntimeError::InvalidArguments("Git role tuple"));
                    };
                    let parse = |value: &str| -> Result<u32, ControllerRuntimeError> {
                        let parsed = value.parse::<u32>().map_err(|_| {
                            ControllerRuntimeError::InvalidArguments("Git role identity")
                        })?;
                        if parsed == 0 || parsed >= 65_536 || parsed.to_string() != value {
                            return Err(ControllerRuntimeError::InvalidArguments("Git role identity"));
                        }
                        Ok(parsed)
                    };
                    let gateway = (parse(gateway_uid)?, parse(gateway_gid)?);
                    if gateway.0 == uid || gateway.1 == gid {
                        return Err(ControllerRuntimeError::InvalidArguments("Git roles overlap"));
                    }
                    git_read_inspection = Some(gateway);
                }
                _ => {
                    return Err(ControllerRuntimeError::InvalidArguments(
                        "unknown or duplicate activation flag",
                    ));
                }
            }
        }
        if issue_source_successor
            && (public_api
                || publisher_ingress
                || nix_start_admission
                || git_upload_bootstrap
                || git_coverage
                || git_read_inspection.is_some()
                || create_q04_policy_subgate)
        {
            return Err(ControllerRuntimeError::InvalidArguments(
                "issue mode is exclusive",
            ));
        }
        if create_q04_policy_subgate && git_upload_bootstrap {
            return Err(ControllerRuntimeError::InvalidArguments(
                "original Q04 freshness is incompatible with Git Cache bootstrap",
            ));
        }
        if nix_storage_generation_prepare
            && (!cfg!(feature = "online-nix") || !nix_start_admission
                || issue_source_successor || git_coverage || git_upload_bootstrap)
        {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Nix generation Prepare requires original Nix and excludes Git/issue profiles",
            ));
        }
        if git_upload_bootstrap && !publisher_ingress {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Git bootstrap requires original publisher ingress",
            ));
        }
        if git_coverage && (!cfg!(target_os = "linux") || !git_upload_bootstrap) {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Git coverage requires the selected Linux original Cache bootstrap",
            ));
        }
        if git_read_inspection.is_some() && !(public_api && publisher_ingress && git_upload_bootstrap) {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Git inspection requires public credentials and original Cache bootstrap",
            ));
        }
        Ok(Self {
            uid,
            gid,
            state_directory: PathBuf::from(STATE_DIRECTORY),
            diagnostic_socket: PathBuf::from(DIAGNOSTIC_SOCKET),
            public_api,
            publisher_ingress,
            git_upload_bootstrap,
            git_coverage,
            git_read_inspection,
            nix_start_admission,
            nix_storage_generation_prepare,
            nix_existing_outputs: false,
            issue_source_successor,
            create_q04_policy_subgate,
        })
    }

    /// Checks the real and effective process identities against fixed inputs.
    ///
    /// # Errors
    ///
    /// Rejects zero or mismatched UID/GID values without admitting any owner.
    pub(super) fn validate_process_identity(&self) -> Result<(), ControllerRuntimeError> {
        if self.uid == 0
            || self.gid == 0
            || rustix::process::getuid().as_raw() != self.uid
            || rustix::process::geteuid().as_raw() != self.uid
            || rustix::process::getgid().as_raw() != self.gid
            || rustix::process::getegid().as_raw() != self.gid
        {
            return Err(ControllerRuntimeError::InvalidProcessIdentity);
        }
        Ok(())
    }
}

fn parse_identity(
    value: Option<String>,
    label: &'static str,
) -> Result<u32, ControllerRuntimeError> {
    value
        .ok_or(ControllerRuntimeError::InvalidArguments(label))?
        .parse()
        .map_err(|_| ControllerRuntimeError::InvalidArguments(label))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Fixture construction and regression assertions intentionally panic."
    )]

    use super::*;

    #[test]
    fn source_successor_issue_mode_is_exclusive_and_keeps_fixed_paths() {
        let configuration = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002", "--issue-source-successor"]
                .map(str::to_owned).into_iter(),
        ).unwrap();

        assert!(configuration.issue_source_successor);
        assert!(!configuration.public_api);
        assert!(!configuration.publisher_ingress);
        assert!(!configuration.nix_start_admission);
        assert_eq!(configuration.state_directory, PathBuf::from(STATE_DIRECTORY));
        assert_eq!(configuration.diagnostic_socket, PathBuf::from(DIAGNOSTIC_SOCKET));

        for other in ["--public-api", "--publisher-ingress", "--nix-start-admission"] {
            for flags in [["--issue-source-successor", other], [other, "--issue-source-successor"]] {
                let arguments = ["aos-sandboxd", "1001", "1002"]
                    .into_iter().chain(flags).map(str::to_owned);
                assert!(matches!(
                    RuntimeConfiguration::from_arguments(arguments),
                    Err(ControllerRuntimeError::InvalidArguments("issue mode is exclusive")),
                ));
            }
        }
    }

    #[test]
    fn source_successor_issue_mode_defaults_absent_and_rejects_aliases_or_duplicates() {
        let normal = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002"].map(str::to_owned).into_iter(),
        ).unwrap();

        assert!(!normal.issue_source_successor);
        for flags in [
            vec!["--issue-source-successor", "--issue-source-successor"],
            vec!["--issue-source-successor=true"],
            vec!["--source-successor"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter().chain(flags).map(str::to_owned);
            assert!(matches!(
                RuntimeConfiguration::from_arguments(arguments),
                Err(ControllerRuntimeError::InvalidArguments("unknown or duplicate activation flag")),
            ));
        }
    }

    #[test]
    fn nix_start_admission_defaults_closed_without_changing_fixed_paths() {
        let configuration = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002"].map(str::to_owned).into_iter(),
        )
        .unwrap();

        assert_eq!(configuration.uid, 1001);
        assert_eq!(configuration.gid, 1002);
        assert_eq!(
            configuration.state_directory,
            PathBuf::from(STATE_DIRECTORY)
        );
        assert_eq!(
            configuration.diagnostic_socket,
            PathBuf::from(DIAGNOSTIC_SOCKET)
        );
        assert!(!configuration.public_api);
        assert!(!configuration.publisher_ingress);
        assert!(!configuration.nix_start_admission);
    }

    #[test]
    fn legacy_activation_flags_do_not_select_nix_admission() {
        for flags in [
            vec!["--public-api"],
            vec!["--publisher-ingress"],
            vec!["--public-api", "--publisher-ingress"],
            vec!["--publisher-ingress", "--public-api"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let configuration = RuntimeConfiguration::from_arguments(arguments).unwrap();

            assert_eq!(configuration.uid, 1001);
            assert_eq!(configuration.gid, 1002);
            assert!(!configuration.nix_start_admission);
        }
    }

    #[test]
    fn nix_start_admission_flag_composes_with_each_existing_flag_order() {
        for flags in [
            ["--nix-start-admission", "--public-api", "--publisher-ingress"],
            ["--nix-start-admission", "--publisher-ingress", "--public-api"],
            ["--public-api", "--nix-start-admission", "--publisher-ingress"],
            ["--public-api", "--publisher-ingress", "--nix-start-admission"],
            ["--publisher-ingress", "--nix-start-admission", "--public-api"],
            ["--publisher-ingress", "--public-api", "--nix-start-admission"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let configuration = RuntimeConfiguration::from_arguments(arguments).unwrap();

            assert!(configuration.public_api);
            assert!(configuration.publisher_ingress);
            assert!(configuration.nix_start_admission);
        }
    }

    #[test]
    fn activation_flags_reject_duplicates_and_unknown_nix_spellings() {
        for flags in [
            vec!["--nix-start-admission", "--nix-start-admission"],
            vec!["--public-api", "--public-api"],
            vec!["--publisher-ingress", "--publisher-ingress"],
            vec!["--nix-start-admission=true"],
            vec!["--nix-build"],
            vec!["--unknown"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let error = RuntimeConfiguration::from_arguments(arguments).unwrap_err();

            assert!(matches!(
                error,
                ControllerRuntimeError::InvalidArguments("unknown or duplicate activation flag")
            ));
        }
    }

    #[test]
    fn activation_identity_errors_keep_their_original_precedence() {
        for (arguments, expected) in [
            (vec!["aos-sandboxd"], "controller UID"),
            (
                vec!["aos-sandboxd", "bad", "--nix-start-admission"],
                "controller UID",
            ),
            (vec!["aos-sandboxd", "1001"], "controller GID"),
            (
                vec!["aos-sandboxd", "1001", "bad", "--unknown"],
                "controller GID",
            ),
        ] {
            let error = RuntimeConfiguration::from_arguments(
                arguments.into_iter().map(str::to_owned),
            )
            .unwrap_err();

            assert!(matches!(
                error,
                ControllerRuntimeError::InvalidArguments(label) if label == expected
            ));
        }
    }

    #[test]
    fn git_bootstrap_is_default_off_and_requires_original_publisher_ingress() {
        let parse = |flags: &[&str]| RuntimeConfiguration::from_arguments(
            ["sandboxd", "1000", "1000"].into_iter()
                .chain(flags.iter().copied()).map(str::to_owned),
        );

        assert!(!parse(&[]).unwrap().git_upload_bootstrap);
        assert!(parse(&["--git-upload-bootstrap"]).is_err());
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap"]).unwrap().git_upload_bootstrap);
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap", "--issue-source-successor"]).is_err());
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap", "--git-upload-bootstrap"]).is_err());
    }

    #[test]
    fn q04_selection_is_default_off_and_refuses_nonfresh_git_bootstrap() {
        let parse = |flags: &[&str]| RuntimeConfiguration::from_arguments(
            ["sandboxd", "1000", "1000"].into_iter()
                .chain(flags.iter().copied()).map(str::to_owned),
        );

        assert!(!parse(&[]).unwrap().create_q04_policy_subgate);
        assert!(parse(&["--create-q04-policy-subgate"]).unwrap().create_q04_policy_subgate);
        assert!(parse(&["--create-q04-policy-subgate", "--create-q04-policy-subgate"]).is_err());
        assert!(parse(&["--create-q04-policy-subgate", "--issue-source-successor"]).is_err());
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap", "--create-q04-policy-subgate"]).is_err());
    }

    #[test]
    fn git_inspection_requires_closed_roles_and_existing_producers() {
        let parse = |flags: &[&str]| RuntimeConfiguration::from_arguments(
            ["sandboxd", "979", "979"].into_iter()
                .chain(flags.iter().copied()).map(str::to_owned),
        );
        let flags = ["--public-api", "--publisher-ingress", "--git-upload-bootstrap",
            "--git-read-inspection=980:980"];
        assert_eq!(parse(&flags).unwrap().git_read_inspection, Some((980, 980)));
        assert!(parse(&flags[3..]).is_err());
        for value in ["--git-read-inspection=979:980", "--git-read-inspection=0:980",
            "--git-read-inspection=0980:980", "--git-read-inspection=980:65536"]
        {
            assert!(parse(&[flags[0], flags[1], flags[2], value]).is_err());
        }
        assert!(parse(&[flags[0], flags[1], flags[2], flags[3], flags[3]]).is_err());
        assert!(parse(&[]).unwrap().git_read_inspection.is_none());
    }
}
