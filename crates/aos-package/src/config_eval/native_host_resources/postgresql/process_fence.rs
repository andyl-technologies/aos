//! Global PostgreSQL process discovery and adoption fences.
//!
//! The scanner pins every candidate with a pidfd, recognizes PostgreSQL's
//! supported data-directory selectors, and admits a running group only under
//! exact persisted process authority or a persisted start-adoption phase.

use std::os::fd::OwnedFd;

use super::*;

pub(super) fn authenticate_process_proof(
    proof: &ProcessProof,
    current: &PostgresqlStateDetails,
) -> Result<(), io::Error> {
    authenticate_process_proof_fields(
        proof,
        current.process.as_ref(),
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
    )?;
    require_global_target_authority(
        &current.postgres_executable,
        &current.data_path,
        &current.active_config_path,
        current.uid,
        current.gid,
        TargetProcessPolicy::Expected(proof),
    )
}

pub(super) fn recorded_process_is_absent(proof: &ProcessProof) -> Result<bool, io::Error> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if boot_id.trim() != proof.boot_id {
        return Ok(true);
    }
    let stat = match fs::read_to_string(format!("/proc/{}/stat", proof.pid)) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    let (state, _process_group, _session, start_time) = postgresql_process_stat(&stat)?;
    if start_time != proof.start_time {
        return Ok(true);
    }
    Ok(state == 'Z')
}

pub(crate) fn validate_process_fence_before_intent(
    resource: &QualifiedHostResource,
    storage: &StorageBinding,
) -> Result<(), io::Error> {
    let desired = qualification(&resource.spec.qualification)?;
    let desired_executable = artifact_executable(desired.postgresql, "bin/postgres")?;
    let desired_data_path = path_text(&Path::new(&storage.storage_path).join("data"))?;

    let Some(state) = read_state_optional(&resource.state_path)? else {
        return require_global_target_authority(
            &desired_executable,
            &desired_data_path,
            "",
            storage.uid,
            storage.gid,
            TargetProcessPolicy::Absent,
        );
    };
    let current = details(&state)?;
    validate_details_identity(&state, &current)?;
    let retained = current.prior_active.as_ref();
    let matrix = process_fence_matrix(
        current.process.is_some(),
        retained.is_some(),
        retained.is_some_and(|prior| {
            prior.postgres_executable != current.postgres_executable
                || prior.data_path != current.data_path
        }),
        desired_executable != current.postgres_executable || desired_data_path != current.data_path,
    );
    match matrix.recorded {
        RecordedProcessFence::CurrentExpected => {
            let process = current
                .process
                .as_ref()
                .ok_or_else(|| invalid("process-fence matrix lost current authority"))?;
            require_global_target_authority(
                &current.postgres_executable,
                &current.data_path,
                &current.active_config_path,
                current.uid,
                current.gid,
                TargetProcessPolicy::Expected(process),
            )?;
        }
        RecordedProcessFence::PriorExpected => {
            let prior =
                retained.ok_or_else(|| invalid("process-fence matrix lost retained authority"))?;
            require_global_target_authority(
                &prior.postgres_executable,
                &prior.data_path,
                &prior.active_config_path,
                prior.uid,
                prior.gid,
                TargetProcessPolicy::Expected(&prior.process),
            )?;
        }
        RecordedProcessFence::CurrentAbsent => {
            require_global_target_authority(
                &current.postgres_executable,
                &current.data_path,
                &current.active_config_path,
                current.uid,
                current.gid,
                TargetProcessPolicy::Absent,
            )?;
        }
    }
    if matrix.current_target_absent {
        require_global_target_authority(
            &current.postgres_executable,
            &current.data_path,
            &current.active_config_path,
            current.uid,
            current.gid,
            TargetProcessPolicy::ConfiguredTargetAbsent,
        )?;
    }
    if matrix.desired_target_absent {
        require_global_target_authority(
            &desired_executable,
            &desired_data_path,
            "",
            storage.uid,
            storage.gid,
            TargetProcessPolicy::ConfiguredTargetAbsent,
        )?;
    }
    Ok(())
}

pub(super) fn process_fence_matrix(
    has_current_process: bool,
    has_retained_process: bool,
    retained_target_differs: bool,
    desired_target_differs: bool,
) -> ProcessFenceMatrix {
    let recorded = if has_current_process {
        RecordedProcessFence::CurrentExpected
    } else if has_retained_process {
        RecordedProcessFence::PriorExpected
    } else {
        RecordedProcessFence::CurrentAbsent
    };
    ProcessFenceMatrix {
        recorded,
        current_target_absent: !has_current_process
            && has_retained_process
            && retained_target_differs,
        desired_target_absent: desired_target_differs,
    }
}

pub(super) fn start_adoption_policy(
    phase: PostgresqlPhase,
) -> Result<TargetProcessPolicy<'static>, io::Error> {
    if matches!(
        phase,
        PostgresqlPhase::QuarantineStarting | PostgresqlPhase::FinalStarting
    ) {
        Ok(TargetProcessPolicy::StartAdoption)
    } else {
        Err(invalid(
            "PostgreSQL process adoption is outside a persisted starting phase",
        ))
    }
}

pub(super) fn require_global_target_authority(
    executable: &str,
    data_path: &str,
    active_config_path: &str,
    uid: u32,
    gid: u32,
    policy: TargetProcessPolicy<'_>,
) -> Result<(), io::Error> {
    let executable = Path::new(executable);
    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(pid_handle) = rustix::process::Pid::from_raw(pid as i32) else {
            continue;
        };
        let pidfd =
            match rustix::process::pidfd_open(pid_handle, rustix::process::PidfdFlags::empty()) {
                Ok(pidfd) => pidfd,
                Err(rustix::io::Errno::NOENT | rustix::io::Errno::SRCH) => continue,
                Err(error) => return Err(error.into()),
            };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let has_slot_uid = process_status_has_uid(&status, uid)?;
        let actual_executable = match fs::canonicalize(entry.path().join("exe")) {
            Ok(actual_executable) => actual_executable,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if actual_executable != executable {
            if has_slot_uid && !matches!(policy, TargetProcessPolicy::ConfiguredTargetAbsent) {
                return Err(invalid(
                    "PostgreSQL slot principal runs an unauthenticated executable",
                ));
            }
            continue;
        }
        let command_line = match fs::read(entry.path().join("cmdline")) {
            Ok(command_line) => command_line,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let arguments = command_line
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect::<Vec<_>>();
        let environment = match fs::read(entry.path().join("environ")) {
            Ok(environment) => environment,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let selects_target = selects_postgresql_data_directory(&arguments, data_path)?
            || environment_selects_postgresql_data_directory(&environment, data_path);
        if !exact_executable_is_candidate(has_slot_uid, selects_target) {
            continue;
        }
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let (state, process_group, session, _start_time) = postgresql_process_stat(&stat)?;
        processes.push(ObservedSlotProcess {
            _pidfd: pidfd,
            pid,
            process_group,
            session,
            state,
            status,
            arguments: command_line,
            selects_target,
        });
    }

    match policy {
        TargetProcessPolicy::Absent if processes.is_empty() => Ok(()),
        TargetProcessPolicy::Absent => {
            Err(invalid("PostgreSQL slot has an unauthenticated process"))
        }
        TargetProcessPolicy::ConfiguredTargetAbsent if processes.is_empty() => Ok(()),
        TargetProcessPolicy::ConfiguredTargetAbsent => Err(invalid(
            "desired PostgreSQL executable already selects the protected data directory",
        )),
        TargetProcessPolicy::Expected(proof) => {
            let Some(leader) = processes.iter().find(|process| process.pid == proof.pid) else {
                if processes.is_empty() {
                    return Ok(());
                }
                return Err(invalid(
                    "PostgreSQL slot processes have no authenticated leader",
                ));
            };
            if !leader.selects_target {
                return Err(invalid(
                    "authenticated PostgreSQL leader does not select its data directory",
                ));
            }
            authenticate_process_proof_fields(
                proof,
                Some(proof),
                executable
                    .to_str()
                    .ok_or_else(|| invalid("PostgreSQL executable is not UTF-8"))?,
                data_path,
                active_config_path,
                uid,
                gid,
            )?;
            require_one_postgresql_process_group(&processes, proof.process_group, uid, gid)
        }
        TargetProcessPolicy::StartAdoption => {
            if processes.is_empty() {
                return Ok(());
            }
            let expected_arguments = expected_postgresql_arguments(
                executable
                    .to_str()
                    .ok_or_else(|| invalid("PostgreSQL executable is not UTF-8"))?,
                data_path,
                active_config_path,
            );
            let leaders = processes
                .iter()
                .filter(|process| {
                    process.selects_target
                        && process_arguments(&process.arguments)
                            .iter()
                            .zip(&expected_arguments)
                            .all(|(actual, expected)| *actual == expected.as_bytes())
                        && process_arguments(&process.arguments).len() == expected_arguments.len()
                })
                .collect::<Vec<_>>();
            let [leader] = leaders.as_slice() else {
                return Err(invalid(
                    "unrecorded PostgreSQL start has no unique canonical leader",
                ));
            };
            if leader.process_group != leader.pid || leader.session != leader.pid {
                return Err(invalid(
                    "unrecorded PostgreSQL leader does not own its process group and session",
                ));
            }
            require_one_postgresql_process_group(&processes, leader.process_group, uid, gid)
        }
    }
}

pub(super) fn exact_executable_is_candidate(has_slot_uid: bool, selects_target: bool) -> bool {
    has_slot_uid || selects_target
}

struct ObservedSlotProcess {
    _pidfd: OwnedFd,
    pid: u32,
    process_group: u32,
    session: u32,
    state: char,
    status: String,
    arguments: Vec<u8>,
    selects_target: bool,
}

fn require_one_postgresql_process_group(
    processes: &[ObservedSlotProcess],
    process_group: u32,
    uid: u32,
    gid: u32,
) -> Result<(), io::Error> {
    for process in processes {
        require_postgresql_process_status(&process.status, uid, gid)?;
        if process.state == 'Z' || process.process_group != process_group {
            return Err(invalid(
                "PostgreSQL slot contains a process outside the authenticated group",
            ));
        }
    }
    Ok(())
}

pub(super) fn process_status_has_uid(status: &str, uid: u32) -> Result<bool, io::Error> {
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| invalid("PostgreSQL process status has no UID set"))?;
    let values = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("PostgreSQL process status has an invalid UID set"))?;
    if values.len() != 4 {
        return Err(invalid("PostgreSQL process status has an invalid UID set"));
    }
    Ok(values.contains(&uid))
}

pub(super) fn process_arguments(command_line: &[u8]) -> Vec<&[u8]> {
    command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect()
}

pub(super) fn selects_postgresql_data_directory(
    arguments: &[&[u8]],
    data_path: &str,
) -> Result<bool, io::Error> {
    let data_path = data_path.as_bytes();
    let mut selects_target = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if argument == data_path {
            selects_target = true;
            index += 1;
            continue;
        }

        if matches!(
            argument,
            b"-D" | b"--pgdata" | b"--data-directory" | b"--data_directory"
        ) {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| invalid("PostgreSQL data-directory selector has no value"))?;
            if value.is_empty() {
                return Err(invalid("PostgreSQL data-directory selector is empty"));
            }
            selects_target |= *value == data_path;
            index += 2;
            continue;
        }

        if argument == b"-c" {
            let setting = arguments
                .get(index + 1)
                .ok_or_else(|| invalid("PostgreSQL -c selector has no value"))?;
            if let Some(value) = setting.strip_prefix(b"data_directory=") {
                if value.is_empty() {
                    return Err(invalid("PostgreSQL data_directory setting is empty"));
                }
                selects_target |= value == data_path;
            } else if setting.starts_with(b"data_directory") {
                return Err(invalid("PostgreSQL data_directory setting is malformed"));
            }
            index += 2;
            continue;
        }

        let compact = argument
            .strip_prefix(b"-D")
            .filter(|value| !value.is_empty())
            .or_else(|| argument.strip_prefix(b"--pgdata="))
            .or_else(|| argument.strip_prefix(b"--data-directory="))
            .or_else(|| argument.strip_prefix(b"--data_directory="))
            .or_else(|| argument.strip_prefix(b"-cdata_directory="));
        if let Some(value) = compact {
            if value.is_empty() {
                return Err(invalid("PostgreSQL data-directory selector is empty"));
            }
            selects_target |= value == data_path;
        } else if argument.starts_with(b"-cdata_directory") {
            return Err(invalid("PostgreSQL data_directory setting is malformed"));
        }
        index += 1;
    }
    Ok(selects_target)
}

pub(super) fn environment_selects_postgresql_data_directory(
    environment: &[u8],
    data_path: &str,
) -> bool {
    let mut expected = b"PGDATA=".to_vec();
    expected.extend_from_slice(data_path.as_bytes());
    environment
        .split(|byte| *byte == 0)
        .any(|variable| variable == expected.as_slice())
}

pub(super) fn authenticate_process_proof_fields(
    proof: &ProcessProof,
    expected: Option<&ProcessProof>,
    executable: &str,
    data_path: &str,
    active_config_path: &str,
    uid: u32,
    gid: u32,
) -> Result<(), io::Error> {
    validate_process_proof_fields(
        proof,
        expected,
        executable,
        data_path,
        active_config_path,
        uid,
        gid,
    )?;

    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if boot_id.trim() != proof.boot_id {
        return Err(invalid("PostgreSQL process proof belongs to another boot"));
    }
    if fs::canonicalize(format!("/proc/{}/exe", proof.pid))? != Path::new(executable) {
        return Err(invalid("PostgreSQL process executable changed"));
    }
    let command_line = fs::read(format!("/proc/{}/cmdline", proof.pid))?;
    let expected_arguments =
        expected_postgresql_arguments(executable, data_path, active_config_path);
    let arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    if arguments.len() != expected_arguments.len()
        || arguments
            .iter()
            .zip(&expected_arguments)
            .any(|(actual, expected)| *actual != expected.as_bytes())
    {
        return Err(invalid("PostgreSQL process arguments changed"));
    }
    let status = fs::read_to_string(format!("/proc/{}/status", proof.pid))?;
    require_postgresql_process_status(&status, uid, gid)?;
    let stat = fs::read_to_string(format!("/proc/{}/stat", proof.pid))?;
    let (state, process_group, session, start_time) = postgresql_process_stat(&stat)?;
    if state == 'Z'
        || process_group != proof.process_group
        || process_group != proof.pid
        || session != proof.pid
        || start_time != proof.start_time
    {
        return Err(invalid("PostgreSQL process incarnation changed"));
    }
    Ok(())
}

pub(super) fn validate_process_proof_fields(
    proof: &ProcessProof,
    expected: Option<&ProcessProof>,
    executable: &str,
    data_path: &str,
    active_config_path: &str,
    uid: u32,
    gid: u32,
) -> Result<(), io::Error> {
    let expected_arguments =
        expected_postgresql_arguments(executable, data_path, active_config_path);
    let zero = "0000000000000000";
    if proof.schema != "aos.postgresql.control-process/v1"
        || proof.pid <= 1
        || proof.process_group <= 1
        || proof.process_group != proof.pid
        || proof.executable != executable
        || proof.arguments != expected_arguments
        || proof.uid != uid
        || proof.gid != gid
        || !proof.groups.is_empty()
        || !proof.no_new_privileges
        || proof.capabilities.inheritable != zero
        || proof.capabilities.permitted != zero
        || proof.capabilities.effective != zero
        || proof.capabilities.bounding != zero
        || proof.capabilities.ambient != zero
        || expected.is_some_and(|expected| expected != proof)
    {
        return Err(invalid("PostgreSQL process proof has another identity"));
    }

    Ok(())
}

pub(super) fn expected_postgresql_arguments(
    executable: &str,
    data_path: &str,
    active_config_path: &str,
) -> Vec<String> {
    vec![
        executable.to_string(),
        "-D".to_string(),
        data_path.to_string(),
        "-c".to_string(),
        format!("config_file={active_config_path}"),
    ]
}

pub(super) fn postgresql_process_stat(stat: &str) -> Result<(char, u32, u32, u64), io::Error> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| invalid("PostgreSQL process stat is malformed"))?;
    let fields = stat[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| invalid("PostgreSQL process state is malformed"))?;
    let process_group = fields
        .get(2)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| invalid("PostgreSQL process group is malformed"))?;
    let session = fields
        .get(3)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| invalid("PostgreSQL process session is malformed"))?;
    let start_time = fields
        .get(19)
        .and_then(|field| field.parse::<u64>().ok())
        .ok_or_else(|| invalid("PostgreSQL process start time is malformed"))?;
    Ok((state, process_group, session, start_time))
}

pub(super) fn require_postgresql_process_status(
    status: &str,
    uid: u32,
    gid: u32,
) -> Result<(), io::Error> {
    let expected_uid = format!("{uid}\t{uid}\t{uid}\t{uid}");
    let expected_gid = format!("{gid}\t{gid}\t{gid}\t{gid}");
    let exact_uid = status
        .lines()
        .any(|line| line.strip_prefix("Uid:\t") == Some(expected_uid.as_str()));
    let exact_gid = status
        .lines()
        .any(|line| line.strip_prefix("Gid:\t") == Some(expected_gid.as_str()));
    let no_groups = status.lines().any(|line| {
        line.strip_prefix("Groups:")
            .is_some_and(|groups| groups.split_ascii_whitespace().next().is_none())
    });
    let no_new_privileges = status.lines().any(|line| {
        line.strip_prefix("NoNewPrivs:")
            .is_some_and(|value| value.trim() == "1")
    });
    let zero_capabilities = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|label| {
            status.lines().any(|line| {
                line.strip_prefix(label)
                    .is_some_and(|value| value.trim() == "0000000000000000")
            })
        });
    if !exact_uid || !exact_gid || !no_groups || !no_new_privileges || !zero_capabilities {
        return Err(invalid("PostgreSQL process confinement changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"/var/lib/aos/ability-runtime/postgresql/cluster/data";

    #[test]
    fn process_fence_matrix_covers_current_retained_and_absent_authority() {
        assert_eq!(
            process_fence_matrix(true, false, false, false),
            ProcessFenceMatrix {
                recorded: RecordedProcessFence::CurrentExpected,
                current_target_absent: false,
                desired_target_absent: false,
            }
        );
        assert_eq!(
            process_fence_matrix(false, true, true, true),
            ProcessFenceMatrix {
                recorded: RecordedProcessFence::PriorExpected,
                current_target_absent: true,
                desired_target_absent: true,
            }
        );
        assert_eq!(
            process_fence_matrix(false, false, false, true),
            ProcessFenceMatrix {
                recorded: RecordedProcessFence::CurrentAbsent,
                current_target_absent: false,
                desired_target_absent: true,
            }
        );
        assert_eq!(
            process_fence_matrix(true, true, true, false),
            ProcessFenceMatrix {
                recorded: RecordedProcessFence::CurrentExpected,
                current_target_absent: false,
                desired_target_absent: false,
            }
        );
    }

    #[test]
    fn adoption_policy_is_limited_to_persisted_starting_phases() {
        assert!(matches!(
            start_adoption_policy(PostgresqlPhase::QuarantineStarting),
            Ok(TargetProcessPolicy::StartAdoption)
        ));
        assert!(matches!(
            start_adoption_policy(PostgresqlPhase::FinalStarting),
            Ok(TargetProcessPolicy::StartAdoption)
        ));
        assert!(start_adoption_policy(PostgresqlPhase::Preparing).is_err());
        assert!(start_adoption_policy(PostgresqlPhase::Active).is_err());
        assert!(start_adoption_policy(PostgresqlPhase::Stopped).is_err());
    }

    #[test]
    fn wrong_uid_exact_executable_is_fenced_for_every_data_selector() {
        let cases = [
            vec![b"postgres".as_slice(), b"-D".as_slice(), DATA],
            vec![
                b"postgres".as_slice(),
                b"-D/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
            vec![b"postgres".as_slice(), b"--pgdata".as_slice(), DATA],
            vec![
                b"postgres".as_slice(),
                b"--pgdata=/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
            vec![b"postgres".as_slice(), b"--data-directory".as_slice(), DATA],
            vec![
                b"postgres".as_slice(),
                b"--data-directory=/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
            vec![b"postgres".as_slice(), b"--data_directory".as_slice(), DATA],
            vec![
                b"postgres".as_slice(),
                b"--data_directory=/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
            vec![
                b"postgres".as_slice(),
                b"-c".as_slice(),
                b"data_directory=/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
            vec![
                b"postgres".as_slice(),
                b"-cdata_directory=/var/lib/aos/ability-runtime/postgresql/cluster/data".as_slice(),
            ],
        ];
        for arguments in cases {
            let selects_target = selects_postgresql_data_directory(
                &arguments,
                std::str::from_utf8(DATA).expect("test data path is UTF-8"),
            )
            .expect("valid PostgreSQL selector is classified");
            assert!(selects_target);
            assert!(exact_executable_is_candidate(false, selects_target));
        }

        let mut environment = b"LANG=C\0PGDATA=".to_vec();
        environment.extend_from_slice(DATA);
        environment.push(0);
        let selects_target = environment_selects_postgresql_data_directory(
            &environment,
            std::str::from_utf8(DATA).expect("test data path is UTF-8"),
        );
        assert!(selects_target);
        assert!(exact_executable_is_candidate(false, selects_target));
    }

    #[test]
    fn malformed_data_selectors_fail_closed() {
        let cases = [
            vec![b"postgres".as_slice(), b"-D".as_slice()],
            vec![b"postgres".as_slice(), b"--pgdata=".as_slice()],
            vec![b"postgres".as_slice(), b"--data-directory".as_slice()],
            vec![b"postgres".as_slice(), b"--data_directory=".as_slice()],
            vec![b"postgres".as_slice(), b"-c".as_slice()],
            vec![
                b"postgres".as_slice(),
                b"-c".as_slice(),
                b"data_directory".as_slice(),
            ],
            vec![b"postgres".as_slice(), b"-cdata_directory".as_slice()],
        ];
        for arguments in cases {
            assert!(
                selects_postgresql_data_directory(
                    &arguments,
                    std::str::from_utf8(DATA).expect("test data path is UTF-8"),
                )
                .is_err()
            );
        }
    }
}
