//! Exercises the real pre-exec stack control and its shared selection latch.
//!
//! Descriptor-only process fixtures provide syscall storage and no authenticated
//! process, stack resource grant or Module owner.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use rustix::process::{Resource, Rlimit};

const STACK_BYTES: u64 = 2 * 1024 * 1024;

#[test]
fn main_stack_selection_is_once_only_across_actual_contract_duplicates()
-> Result<(), Box<dyn Error>> {
    let (_read, write) = pipe_pair()?;
    let contract =
        QemuChildProcessContract::for_test(write, event_fd_for_test()?, current_file_size_limit()?);
    let duplicate = contract.try_clone_for_attempt_generation()?;

    assert_eq!(contract.main_stack_limit(), None);
    for invalid in [0, libc::RLIM_INFINITY] {
        assert!(contract.configure_main_stack_limit(invalid).is_err());
        assert_eq!(duplicate.main_stack_limit(), None);
    }

    contract.configure_main_stack_limit(STACK_BYTES)?;
    assert_eq!(duplicate.main_stack_limit(), Some(STACK_BYTES));
    for repeated in [STACK_BYTES, STACK_BYTES / 2, STACK_BYTES * 2] {
        assert!(duplicate.configure_main_stack_limit(repeated).is_err());
        assert_eq!(contract.main_stack_limit(), Some(STACK_BYTES));
    }
    assert!(contract.try_clone_for_attempt_generation().is_ok());
    Ok(())
}

#[test]
fn main_stack_selection_refuses_after_launch_freeze_and_during_refinement()
-> Result<(), Box<dyn Error>> {
    let (_read, write) = pipe_pair()?;
    let contract =
        QemuChildProcessContract::for_test(write, event_fd_for_test()?, current_file_size_limit()?);
    let duplicate = contract.try_clone_for_attempt_generation()?;

    // This component cut holds the actual shared latch in its refinement state.
    contract
        .attempt_binding
        .launch_state
        .store(1, Ordering::Release);
    assert!(duplicate.configure_main_stack_limit(STACK_BYTES).is_err());
    assert_eq!(contract.main_stack_limit(), None);
    contract
        .attempt_binding
        .launch_state
        .store(0, Ordering::Release);

    contract.attempt_binding.freeze_for_launch()?;
    assert!(duplicate.configure_main_stack_limit(STACK_BYTES).is_err());
    assert_eq!(contract.main_stack_limit(), None);
    Ok(())
}

#[test]
fn guarded_pre_exec_installs_exact_main_stack_limit_without_changing_parent()
-> Result<(), Box<dyn Error>> {
    if env::var_os(PROBE_ENV).is_some() {
        assert_eq!(
            rustix::process::getrlimit(Resource::Stack),
            Rlimit {
                current: Some(STACK_BYTES),
                maximum: Some(STACK_BYTES),
            },
        );
        return Ok(());
    }

    let parent = rustix::process::getrlimit(Resource::Stack);
    assert!(parent.maximum.is_none_or(|maximum| maximum >= STACK_BYTES));
    let (read, write) = pipe_pair()?;
    let contract =
        QemuChildProcessContract::for_test(write, event_fd_for_test()?, current_file_size_limit()?);
    // Clone before selection: the real child must use the shared final choice.
    let duplicate = contract.try_clone_for_attempt_generation()?;
    contract.configure_main_stack_limit(STACK_BYTES)?;
    let (_host, resources) = create_spawn_resources(4096)?;
    let executable = env::current_exe()?.to_string_lossy().into_owned();
    let args = vec![
        String::from("--exact"),
        String::from(
            "spawn::tests::main_stack::guarded_pre_exec_installs_exact_main_stack_limit_without_changing_parent",
        ),
    ];

    let mut child = spawn_unpinned_test_process_with_resources(
        &executable,
        &args,
        resources,
        &[(PROBE_ENV, "1")],
        "spawn Main stack physical-control probe",
        Some(&duplicate),
    )?;
    assert!(child.wait()?.success());

    let mut placement = [0_u8; 2];
    std::fs::File::from(read).read_exact(&mut placement)?;
    assert_eq!(&placement, CGROUP_ATTACH_SELF);
    assert_eq!(rustix::process::getrlimit(Resource::Stack), parent);
    assert!(contract.configure_main_stack_limit(STACK_BYTES).is_err());
    Ok(())
}
