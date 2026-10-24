/*
 * Copyright 2026 Andyl, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* The already loaded post-auth image and its forked internal relays never
 * exec. Dumpability therefore cannot reset at a new executable boundary.
 * No tenant environment, shell or RC file is loaded after this cut. The
 * inherited filter prevents the confined image from reversing that posture.
 */
#include "includes.h"
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "aos-attach-confinement.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && defined(__x86_64__)
#define AOS_ATTACH_NATIVE_PROFILE 1
#define AOS_ATTACH_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && defined(__aarch64__)
#define AOS_ATTACH_NATIVE_PROFILE 1
#define AOS_ATTACH_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#define AOS_ATTACH_NATIVE_PROFILE 0
#endif

#define AOS_DENY_SYSCALL(number) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

#define AOS_DENY_ARGUMENT_BITS(number, argument, mask) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 7), \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
	    offsetof(struct seccomp_data, args[(argument)]) + 4), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM), \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
	    offsetof(struct seccomp_data, args[(argument)])), \
	BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, (mask), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void
aos_attach_confinement_before_drop(void)
{
#if !AOS_ATTACH_NATIVE_PROFILE
	/* Ordinary OpenSSH remains available; this opt-in profile does not. */
	fatal("AOS attach native confinement profile unavailable");
#else
	struct statfs filesystem;
	char policy[3];
	int fd;
	ssize_t length;

	/* A credential drop consults this sysctl. Reject a dumpable transition
	 * rather than leave an injection window before the post-drop prctl.
	 */
	if (getuid() != 0 || geteuid() != 0 ||
	    (fd = open("/proc/sys/fs/suid_dumpable", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
		fatal("AOS attach confinement unavailable");
	length = read(fd, policy, sizeof(policy));
	if (fstatfs(fd, &filesystem) == -1 || filesystem.f_type != PROC_SUPER_MAGIC ||
	    length != 2 || memcmp(policy, "0\n", 2) != 0 ||
	    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
	    prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
		fatal("AOS attach confinement rejected");
	close(fd);
#endif
}

void
aos_attach_confinement_after_drop(void)
{
#if !AOS_ATTACH_NATIVE_PROFILE
	fatal("AOS attach native confinement profile unavailable");
#else
	static const struct sock_filter instructions[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AOS_ATTACH_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		/* In particular, x32 shares AUDIT_ARCH_X86_64 but not native numbers. */
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		AOS_DENY_SYSCALL(SYS_execve),
		AOS_DENY_SYSCALL(SYS_execveat),
		AOS_DENY_SYSCALL(SYS_ptrace),
		AOS_DENY_SYSCALL(SYS_process_vm_readv),
		AOS_DENY_SYSCALL(SYS_process_vm_writev),
		AOS_DENY_SYSCALL(SYS_pidfd_getfd),
		AOS_DENY_SYSCALL(SYS_userfaultfd),
		AOS_DENY_SYSCALL(SYS_io_uring_setup),
		AOS_DENY_SYSCALL(SYS_io_uring_enter),
		AOS_DENY_SYSCALL(SYS_io_uring_register),
		AOS_DENY_SYSCALL(SYS_bpf),
		AOS_DENY_SYSCALL(SYS_perf_event_open),
		AOS_DENY_SYSCALL(SYS_keyctl),
		AOS_DENY_SYSCALL(SYS_add_key),
		AOS_DENY_SYSCALL(SYS_request_key),
		AOS_DENY_SYSCALL(SYS_capset),
		AOS_DENY_SYSCALL(SYS_setuid),
		AOS_DENY_SYSCALL(SYS_setgid),
		AOS_DENY_SYSCALL(SYS_setreuid),
		AOS_DENY_SYSCALL(SYS_setregid),
		AOS_DENY_SYSCALL(SYS_setresuid),
		AOS_DENY_SYSCALL(SYS_setresgid),
		AOS_DENY_SYSCALL(SYS_setfsuid),
		AOS_DENY_SYSCALL(SYS_setfsgid),
		AOS_DENY_SYSCALL(SYS_setgroups),
		AOS_DENY_SYSCALL(SYS_unshare),
		AOS_DENY_SYSCALL(SYS_setns),
		AOS_DENY_SYSCALL(SYS_clone3),
#ifdef SYS_vfork
		AOS_DENY_SYSCALL(SYS_vfork),
#endif
		AOS_DENY_SYSCALL(SYS_chroot),
		AOS_DENY_SYSCALL(SYS_pivot_root),
		AOS_DENY_SYSCALL(SYS_mount),
		AOS_DENY_SYSCALL(SYS_umount2),
		AOS_DENY_SYSCALL(SYS_fsopen),
		AOS_DENY_SYSCALL(SYS_fsconfig),
		AOS_DENY_SYSCALL(SYS_fsmount),
		AOS_DENY_SYSCALL(SYS_move_mount),
		AOS_DENY_SYSCALL(SYS_mount_setattr),
		AOS_DENY_SYSCALL(SYS_open_tree),
		AOS_DENY_SYSCALL(SYS_personality),
		/* Only a private-memory, private-FD-table fork with SIGCHLD. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 10),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
		    ~(0xffU | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGCHLD, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		AOS_DENY_ARGUMENT_BITS(SYS_mmap, 2, PROT_EXEC),
		AOS_DENY_ARGUMENT_BITS(SYS_mprotect, 2, PROT_EXEC),
#ifdef SYS_pkey_mprotect
		AOS_DENY_ARGUMENT_BITS(SYS_pkey_mprotect, 2, PROT_EXEC),
#endif
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 6),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_DUMPABLE, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_NO_NEW_PRIVS, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_SECCOMP, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = {
		.len = sizeof(instructions) / sizeof(instructions[0]),
		.filter = (struct sock_filter *)instructions,
	};

	if (getuid() == 0 || geteuid() == 0 ||
	    prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
	    &program) != 0 ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER)
		fatal("AOS attach irreversible confinement rejected");
#endif
}
