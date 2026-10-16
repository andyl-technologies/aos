//! Cargo example used only by the explicit quota-confinement-proof VM.
//!
//! Cargo's ordinary libtest harness is intentionally not used: the actual
//! installation must execute before a test worker creates a second thread.
#![allow(clippy::expect_used, reason = "VM proof assertions must fail closed")]

use std::{
    fs::{self, File},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::Path,
    process::Command,
};

#[repr(C)]
#[derive(Default)]
struct Attributes {
    flags: u32,
    extent: u32,
    nextents: u32,
    project: u32,
    cow: u32,
    padding: [u8; 8],
}

/// Linux 7.2.3 include/uapi/linux/fs.h file_attr, version zero (24 bytes).
#[repr(C)]
#[derive(Default)]
struct FileAttributes {
    flags: u64,
    extent: u32,
    nextents: u32,
    project: u32,
    cow: u32,
}

fn file_setattr(
    file: &File,
    name: &std::ffi::CStr,
    flags: i32,
    attributes: &FileAttributes,
) -> libc::c_long {
    // SAFETY: the initialized version-zero file_attr buffer and NUL-terminated
    // path stay live; AT_EMPTY_PATH selects the retained descriptor form.
    unsafe {
        libc::syscall(
            469,
            file.as_raw_fd(),
            name.as_ptr(),
            attributes,
            24usize,
            flags,
        )
    }
}

#[repr(C)]
#[derive(Default)]
struct Quota {
    hard: u64,
    soft: u64,
    space: u64,
    inode_hard: u64,
    inode_soft: u64,
    inodes: u64,
    block_time: u64,
    inode_time: u64,
    valid: u32,
}

fn attributes(file: &File) -> Attributes {
    let mut attributes = Attributes::default();
    // SAFETY: the kernel writes the initialized Linux fsxattr ABI structure.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x801c581fu64, &mut attributes) },
        0
    );
    attributes
}

fn setter(file: &File, command: u64, value: &Attributes) -> libc::c_long {
    // SAFETY: ioctl reads a live Linux fsxattr ABI buffer; SETFLAGS reads only
    // its leading initialized flags word. syscall preserves upper command bits.
    unsafe { libc::syscall(libc::SYS_ioctl, file.as_raw_fd(), command, value) }
}

fn denied(result: libc::c_long) {
    assert_eq!(result, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
}

fn child(root: &Path, confined: bool) {
    let receipt = confined
        .then(|| terrane_linux::quota_confinement::install().expect("install real kernel policy"));
    let file = File::create(root.join("body")).expect("create charged inode");
    assert_eq!(attributes(&file).project, 41009);
    let mut changed = attributes(&file);
    changed.project = 0;
    if !confined {
        let subdirectory = root.join("escape-directory");
        fs::create_dir(&subdirectory).expect("create inheriting child");
        let directory = File::open(&subdirectory).expect("open child");
        let mut directory_attributes = attributes(&directory);
        directory_attributes.flags &= !0x200;
        assert_eq!(setter(&directory, 0x401c5820, &directory_attributes), 0);
        assert_eq!(attributes(&directory).flags & 0x200, 0);
        directory_attributes.flags |= 0x200;
        assert_eq!(setter(&directory, 0x401c5820, &directory_attributes), 0);
        let mut native_flags = 0u32;
        // SAFETY: GETFLAGS writes the initialized Linux inode flag word.
        assert_eq!(
            unsafe { libc::ioctl(directory.as_raw_fd(), 0x80086601u64, &mut native_flags) },
            0
        );
        assert_ne!(native_flags & 0x2000_0000, 0);
        native_flags &= !0x2000_0000;
        // SAFETY: SETFLAGS reads the initialized native inode flag word.
        assert_eq!(
            unsafe { libc::ioctl(directory.as_raw_fd(), 0x40086602u64, &native_flags) },
            0
        );
        assert_eq!(attributes(&directory).flags & 0x200, 0);
        fs::remove_dir(subdirectory).expect("remove inheritance escape witness");
        let alternative =
            File::create(root.join("file-setattr-body")).expect("file_setattr baseline inode");
        assert_eq!(
            file_setattr(
                &alternative,
                c"",
                libc::AT_EMPTY_PATH,
                &FileAttributes::default()
            ),
            0
        );
        assert_eq!(attributes(&alternative).project, 0);
        let reset = Attributes {
            project: 41009,
            ..Attributes::default()
        };
        assert_eq!(setter(&alternative, 0x401c5820, &reset), 0);
        let parent = File::open(root).expect("path setter parent");
        assert_eq!(
            file_setattr(&parent, c"file-setattr-body", 0, &FileAttributes::default()),
            0
        );
        assert_eq!(attributes(&alternative).project, 0);
        fs::remove_file(root.join("file-setattr-body")).expect("cleanup alternate setter witness");
        assert_eq!(setter(&file, 0x401c5820, &changed), 0);
        assert_eq!(attributes(&file).project, 0);
        (&file)
            .write_all(&vec![1; 3 * 1024 * 1024])
            .expect("unconfined project-zero escape");
        file.sync_all().expect("sync escaped allocation");
        fs::remove_file(root.join("body")).expect("cleanup escape");
        println!("unconfined owner moved charge to project zero and exceeded project hard limit");
        return;
    }
    let receipt = receipt.expect("installed receipt");
    receipt.check_current().expect("current receipt");
    for command in [0x401c5820, 0x40086602, 0x40046602] {
        denied(setter(&file, command, &changed));
        denied(setter(&file, command | (0xdead_beefu64 << 32), &changed));
    }
    let directory = File::open(root).expect("open inheriting directory");
    denied(file_setattr(
        &file,
        c"",
        libc::AT_EMPTY_PATH,
        &FileAttributes::default(),
    ));
    denied(file_setattr(
        &directory,
        c"body",
        0,
        &FileAttributes::default(),
    ));
    let mut flags = attributes(&directory);
    assert_ne!(flags.flags & 0x200, 0);
    flags.flags &= !0x200;
    denied(setter(&directory, 0x401c5820, &flags));
    // file_setattr's descriptor and path forms must be refused before argument
    // access. Invalid buffers make a missed filter return EFAULT, not EPERM.
    for empty in [false, true] {
        let name = if empty { c"" } else { c"body" };
        // SAFETY: initialized scalar syscall arguments and a deliberately null
        // userspace buffer exercise refusal before any kernel pointer access.
        denied(unsafe {
            libc::syscall(
                469,
                directory.as_raw_fd(),
                name.as_ptr(),
                std::ptr::null::<u8>(),
                24usize,
                if empty { libc::AT_EMPTY_PATH } else { 0 },
            )
        });
    }
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_pidfd_getfd,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_setuid,
    ] {
        // SAFETY: policy rejects these calls before reading any arguments.
        denied(unsafe { libc::syscall(syscall, -1i64, 0, 0, 0, 0, 0) });
    }
    // SAFETY: PR_SET_DUMPABLE has one scalar value and no pointer arguments.
    denied(unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } as libc::c_long);
    std::thread::spawn(|| {
        // SAFETY: the inherited filter rejects this scalar syscall.
        denied(unsafe { libc::syscall(469, -1i64, 0, 0, 0, 0) });
    })
    .join()
    .expect("thread inherits policy");
    // Fork only after the thread has joined; the process is single-threaded.
    // SAFETY: the child uses only raw syscalls and _exit before returning.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // SAFETY: raw scalar syscall and nonreturning child exit.
        unsafe {
            let result = libc::syscall(469, -1i64, 0, 0, 0, 0);
            libc::_exit(
                if result == -1 && *libc::__errno_location() == libc::EPERM {
                    0
                } else {
                    1
                },
            );
        }
    }
    let mut status = 0;
    // SAFETY: child is our live child and status is writable.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    assert_eq!(attributes(&file).project, 41009);
    let error = (&file)
        .write_all(&vec![2; 3 * 1024 * 1024])
        .expect_err("finite quota enforced");
    assert_eq!(error.raw_os_error(), Some(libc::EDQUOT));
    drop(file);
    fs::remove_file(root.join("body")).expect("cleanup charged file");
    // A small real verity inode is permitted after the failed excess write.
    let path = root.join("sealed-positive");
    fs::write(&path, b"verity-positive").expect("write verity body");
    let file = File::open(&path).expect("read-only verity body");
    #[repr(C)]
    struct Enable {
        version: u32,
        algorithm: u32,
        block_size: u32,
        salt_size: u32,
        salt: u64,
        signature_size: u32,
        reserved: u32,
        signature: u64,
        tail: [u64; 11],
    }
    let enable = Enable {
        version: 1,
        algorithm: 1,
        block_size: 4096,
        salt_size: 0,
        salt: 0,
        signature_size: 0,
        reserved: 0,
        signature: 0,
        tail: [0; 11],
    };
    // SAFETY: the initialized 128-byte fsverity_enable_arg ABI is read only.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x40806685u64, &enable) },
        0,
        "enable actual verity profile: {}",
        io::Error::last_os_error()
    );
    assert_ne!(attributes(&file).flags & 0x20000, 0);
    #[repr(C)]
    struct Digest {
        algorithm: u16,
        size: u16,
        bytes: [u8; 32],
    }
    // Linux 7.2.3 fsverity_digest has a four-byte header and flexible digest.
    // MEASURE uses the header size in its command, not the caller buffer size.
    let mut digest = Digest {
        algorithm: 0,
        size: 32,
        bytes: [0; 32],
    };
    // SAFETY: kernel can write the header and the advertised 32-byte capacity.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0xc0046686u64, &mut digest) },
        0
    );
    assert_eq!(digest.algorithm, 1);
    assert_eq!(digest.size, 32);
    fs::remove_file(path).expect("retire verity positive");
    receipt.check_current().expect("persistent non-dumpability");
    println!("confined setters denied; GET, EDQUOT, verity, thread and child witnesses passed");
}

fn main() {
    assert_eq!(
        std::env::var("TERRANE_QUOTA_CONFINEMENT_VM").as_deref(),
        Ok("1")
    );
    let arguments = std::env::args().collect::<Vec<_>>();
    let root = Path::new(arguments.get(2).expect("explicit VM directory"));
    match arguments.get(1).map(String::as_str) {
        Some("owner") => {
            fs::create_dir(root).expect("fixture directory");
            let file = File::open(root).expect("quota root");
            let attributes = Attributes {
                flags: 0x200,
                project: 41009,
                ..Attributes::default()
            };
            assert_eq!(setter(&file, 0x401c5820, &attributes), 0);
            let mut quota = Quota {
                hard: 2048,
                valid: 1,
                ..Quota::default()
            };
            // SAFETY: Q_SETQUOTA project ABI reads the initialized dqblk.
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_quotactl_fd,
                        file.as_raw_fd(),
                        (0x800008u32 << 8) | 2,
                        41009u32,
                        &mut quota,
                    )
                },
                0
            );
            std::os::unix::fs::chown(root, Some(840), Some(840)).expect("role ownership");
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("role-only root");
            for mode in ["escape", "confined", "startup-failure", "inherited-ring"] {
                assert!(
                    Command::new(&arguments[0])
                        .arg(mode)
                        .arg(root)
                        .uid(840)
                        .gid(840)
                        .status()
                        .expect("fresh single-thread role")
                        .success()
                );
            }
            #[cfg(target_arch = "x86_64")]
            for mode in ["x32", "compat"] {
                use std::os::unix::process::ExitStatusExt;
                let status = Command::new(&arguments[0])
                    .arg(mode)
                    .arg(root)
                    .uid(840)
                    .gid(840)
                    .status()
                    .expect("alternate ABI child");
                assert_eq!(
                    status.signal(),
                    Some(libc::SIGSYS),
                    "alternate ABI must be killed by the kernel policy"
                );
            }
            fs::remove_dir(root).expect("cleanup quota fixture");
        }
        Some("escape") => child(root, false),
        Some("confined") => child(root, true),
        Some("startup-failure") => {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let thread_barrier = barrier.clone();
            let thread = std::thread::spawn(move || {
                thread_barrier.wait();
                thread_barrier.wait();
            });
            barrier.wait();
            assert!(terrane_linux::quota_confinement::install().is_err());
            barrier.wait();
            thread.join().expect("startup rejection joins peer");
            println!("multithreaded startup rejected before mutable work");
        }
        Some("inherited-ring") => {
            let mut parameters = [0u64; 15];
            // SAFETY: the 120-byte initialized io_uring_params storage has the
            // required alignment. This creates a genuine unsubmitted ring.
            let ring =
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 2u32, parameters.as_mut_ptr()) };
            assert!(
                ring >= 0,
                "VM must permit a baseline ring: {}",
                io::Error::last_os_error()
            );
            // SAFETY: ring is our owned descriptor; removing CLOEXEC passes the
            // actual existing ring through exec into a fresh bootstrap process.
            assert_eq!(
                unsafe { libc::fcntl(ring as libc::c_int, libc::F_SETFD, 0) },
                0
            );
            assert!(
                Command::new(&arguments[0])
                    .arg("reject-inherited-ring")
                    .arg(root)
                    .status()
                    .expect("exec child with actual inherited ring")
                    .success()
            );
            // SAFETY: setup returned this owned descriptor; no other owner exists.
            assert_eq!(unsafe { libc::close(ring as libc::c_int) }, 0);
            println!("actual inherited ring refused before confinement receipt");
        }
        Some("reject-inherited-ring") => {
            assert!(terrane_linux::quota_confinement::install().is_err());
        }
        #[cfg(target_arch = "x86_64")]
        Some("x32") => {
            let _receipt = terrane_linux::quota_confinement::install()
                .expect("native install before x32 attempt");
            // SAFETY: the policy kills the alternate ABI before argument access.
            unsafe { libc::syscall(0x4000_0000i64 | 514, -1i64, 0x401c5820u64, 0) };
            panic!("x32 bypassed ABI confinement");
        }
        #[cfg(target_arch = "x86_64")]
        Some("compat") => {
            let _receipt = terrane_linux::quota_confinement::install()
                .expect("native install before compat attempt");
            // SAFETY: int80 selects the compat ABI. getpid has no pointers; the
            // kernel filter must kill the process before executing that call.
            unsafe {
                core::arch::asm!("int 0x80", inout("eax") 20u32 => _, options(nostack));
            }
            panic!("compat bypassed ABI confinement");
        }
        _ => panic!("unknown explicit fixture mode"),
    }
}
