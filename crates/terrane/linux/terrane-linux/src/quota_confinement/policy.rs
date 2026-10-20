//! Defines the Linux 7.2.3 source-audited, immutable seccomp program.
//!
//! `fs/file_attr.c` exposes file_setattr in addition to ioctl setters;
//! `fs/ioctl.c` truncates command arguments and translates compat SETFLAGS.
//! x86's x32 ABI shares the audit architecture, so its syscall bit is denied
//! separately. AArch64 compat uses a different audit architecture. io_uring's
//! 7.2.3 opcode table has no ext4 setter; all ring syscalls are still excluded.

use std::io;

const LOAD: u16 = 0x20;
const EQUAL: u16 = 0x15;
const RET: u16 = 0x06;
const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
const KILL: u32 = 0x8000_0000;
const ALLOW: u32 = 0x7fff_0000;

/// Checks the source-audited native architecture and scalar ABI.
///
/// # Errors
/// Refuses targets outside little-endian Linux x86-64 and AArch64.
pub(super) fn supported() -> io::Result<()> {
    if cfg!(all(
        target_pointer_width = "64",
        target_endian = "little",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "quota confinement ABI is unsupported",
        ))
    }
}

fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn equal(value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: EQUAL,
        jt: yes,
        jf: no,
        k: value,
    }
}

fn program() -> Vec<libc::sock_filter> {
    let architecture = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    };
    let mut program = vec![
        statement(LOAD, 4),
        equal(architecture, 1, 0),
        statement(RET, KILL),
        statement(LOAD, 0),
    ];
    if cfg!(target_arch = "x86_64") {
        // BPF_JSET rejects the x32 bit before interpreting native syscall IDs.
        program.push(libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        });
        program.push(statement(RET, KILL));
    }
    let denied = [
        469, // file_setattr is common to both audited native syscall tables.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_unshare,
        libc::SYS_setns,
    ];
    for number in denied {
        program.push(equal(number as u32, 0, 1));
        program.push(statement(RET, DENY));
    }
    // seccomp_data.args[1] low word: ioctl's unsigned-int command. Unknown
    // upper argument bits cannot disguise a setter from the kernel or filter.
    program.push(equal(libc::SYS_ioctl as u32, 0, 8));
    program.push(statement(LOAD, 24));
    for command in [0x401c_5820, 0x4008_6602, 0x4004_6602] {
        program.push(equal(command, 0, 1));
        program.push(statement(RET, DENY));
    }
    program.push(statement(RET, ALLOW));
    program.push(equal(libc::SYS_prctl as u32, 0, 3));
    program.push(statement(LOAD, 16));
    program.push(equal(libc::PR_SET_DUMPABLE as u32, 0, 1));
    program.push(statement(RET, DENY));
    program.push(statement(RET, ALLOW));
    program
}

/// Installs the fixed filter with mandatory kernel thread synchronization.
///
/// # Errors
/// Refuses unrepresentable filter length, failed kernel installation or a
/// positive thread-synchronization failure; no partial installation is accepted.
pub(super) fn install() -> io::Result<()> {
    install_program(&program())
}

/// Adds fixed Unix-only socket creation to the already installed quota policy.
///
/// The base program rejects alternate ABIs, rings and cross-process descriptor
/// import. The additional policy cannot weaken those restrictions.
///
/// # Errors
/// Returns invalid program length, kernel installation or TSYNC failures.
pub(super) fn install_publisher() -> io::Result<()> {
    let instructions = [
        statement(LOAD, 0),
        equal(libc::SYS_socket as u32, 1, 0),
        equal(libc::SYS_socketpair as u32, 0, 3),
        statement(LOAD, 16),
        equal(libc::AF_UNIX as u32, 1, 0),
        statement(RET, DENY),
        statement(RET, ALLOW),
    ];
    install_program(&instructions)
}

fn install_program(instructions: &[libc::sock_filter]) -> io::Result<()> {
    let filter = libc::sock_fprog {
        len: u16::try_from(instructions.len()).map_err(io::Error::other)?,
        filter: instructions.as_ptr().cast_mut(),
    };
    // SAFETY: filter and its immutable instruction storage remain live for the
    // synchronous kernel copy. SECCOMP_SET_MODE_FILTER=1, TSYNC=1; no user
    // program, notification listener or optional success mode is accepted.
    let result = unsafe { libc::syscall(libc::SYS_seccomp, 1u32, 1u32, &filter) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if result != 0 {
        return Err(io::Error::other("seccomp thread synchronization failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Executes only the four instruction forms accepted by this fixed policy.
    fn decision(architecture: u32, syscall: u32, arguments: [u64; 2]) -> u32 {
        let instructions = program();
        let mut accumulator = 0;
        let mut cursor = 0;
        loop {
            let instruction = &instructions[cursor];
            match instruction.code {
                LOAD => {
                    accumulator = match instruction.k {
                        0 => syscall,
                        4 => architecture,
                        16 => arguments[0] as u32,
                        24 => arguments[1] as u32,
                        _ => panic!("unexpected policy data offset"),
                    }
                }
                EQUAL | 0x45 => {
                    let matches = if instruction.code == EQUAL {
                        accumulator == instruction.k
                    } else {
                        accumulator & instruction.k != 0
                    };
                    cursor += usize::from(if matches {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                RET => return instruction.k,
                _ => panic!("unexpected policy opcode"),
            }
            cursor += 1;
        }
    }

    #[test]
    fn setter_denial_survives_command_padding_and_preserves_get_and_verity() {
        let architecture = if cfg!(target_arch = "x86_64") {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        for command in [0x401c5820u64, 0x40086602, 0x40046602] {
            for padding in [0, u64::MAX << 32] {
                assert_eq!(
                    decision(architecture, libc::SYS_ioctl as u32, [0, command | padding]),
                    DENY
                );
            }
        }
        for command in [0x801c581fu64, 0x80086601, 0x40806685, 0xc0046686] {
            assert_eq!(
                decision(architecture, libc::SYS_ioctl as u32, [0, command]),
                ALLOW
            );
        }
        assert_eq!(decision(architecture, 469, [0, 0]), DENY);
        assert_eq!(
            decision(
                architecture,
                libc::SYS_prctl as u32,
                [libc::PR_SET_DUMPABLE as u64, 0]
            ),
            DENY
        );
        assert_eq!(
            decision(
                architecture,
                libc::SYS_prctl as u32,
                [libc::PR_GET_DUMPABLE as u64, 0]
            ),
            ALLOW
        );
        assert_eq!(decision(0, libc::SYS_ioctl as u32, [0, 0]), KILL);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(decision(architecture, 0x4000_0000 | 514, [0, 0]), KILL);
            assert_eq!(decision(0x4000_0003, 54, [0, 0]), KILL);
        }
    }
}
