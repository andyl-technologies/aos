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

/* Linux-only, opt-in custody over the existing protected Guest listener.
 * No callback result, child-supplied identity, private key or I/O descriptor
 * enters this record. The root monitor keeps its private post-auth connection,
 * the pidfd opened for its own fork, and the Guest connection until exit.
 */
#include "includes.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "servconf.h"
#include "monitor.h"
#include "aos-attach-monitor.h"

extern ServerOptions options;

#define AOS_ATTACH_SOCKET "/run/aos-sandbox-agent/exec-gate.sock"
#define AOS_ATTACH_MAXIMUM_RECORD 13312
#define AOS_ATTACH_TIMEOUT_MS 5000

static struct sshbuf *accepted_witness;
static int fully_authenticated;
static int held_child_pidfd = -1;
static int held_guest_connection = -1;

static int64_t
deadline_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		fatal("AOS attach clock unavailable");
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void
wait_ready(int fd, short events, int64_t deadline)
{
	struct pollfd pollfd = { .fd = fd, .events = events };
	int64_t remaining;
	int result;

	for (;;) {
		remaining = deadline - deadline_milliseconds();
		if (remaining <= 0)
			fatal("AOS attach registration unavailable");
		result = poll(&pollfd, 1, (int)remaining);
		if (result == -1 && errno == EINTR)
			continue;
		if (result != 1 || (pollfd.revents & events) == 0 ||
		    (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
			fatal("AOS attach registration unavailable");
		return;
	}
}

/* Capture occurs only after root key/session/signature verification. It is
 * still a candidate until the full authentication and account decisions pass.
 * Multiple distinct certificate factors do not select or overwrite custody.
 */
void
aos_attach_monitor_capture(const u_char *certificate, size_t certificate_len,
    const u_char *data, size_t data_len, const u_char *signature,
    size_t signature_len, const u_char *session, size_t session_len,
    uid_t uid, gid_t gid)
{
	struct sshbuf *candidate;
	int r;

	if (!options.aos_attach_monitor_v2)
		return;
	if (getuid() != 0 || geteuid() != 0 || uid == 0 ||
	    certificate_len == 0 || certificate_len > 4096 ||
	    data_len == 0 || data_len > 8192 ||
	    signature_len == 0 || signature_len > 128 ||
	    session_len < 32 || session_len > 64)
		fatal("AOS attach authentication profile rejected");
	if ((candidate = sshbuf_new()) == NULL)
		fatal("AOS attach allocation failed");
	if ((r = sshbuf_put(candidate, "AOSAMR02", 8)) != 0 ||
	    (r = sshbuf_put_u32(candidate, uid)) != 0 ||
	    (r = sshbuf_put_u32(candidate, gid)) != 0 ||
	    (r = sshbuf_put_string(candidate, session, session_len)) != 0 ||
	    (r = sshbuf_put_string(candidate, certificate, certificate_len)) != 0 ||
	    (r = sshbuf_put_string(candidate, data, data_len)) != 0 ||
	    (r = sshbuf_put_string(candidate, signature, signature_len)) != 0)
		fatal_fr(r, "AOS attach witness");
	if (sshbuf_len(candidate) > AOS_ATTACH_MAXIMUM_RECORD)
		fatal("AOS attach authentication profile rejected");
	if (accepted_witness != NULL) {
		if (sshbuf_len(candidate) != sshbuf_len(accepted_witness) ||
		    timingsafe_bcmp(sshbuf_ptr(candidate),
		    sshbuf_ptr(accepted_witness), sshbuf_len(candidate)) != 0)
			fatal("AOS attach ambiguous authentication factors");
		sshbuf_free(candidate);
		return;
	}
	accepted_witness = candidate;
}

void
aos_attach_monitor_complete(void)
{
	if (!options.aos_attach_monitor_v2)
		return;
	if (getuid() != 0 || geteuid() != 0 || accepted_witness == NULL)
		fatal("AOS attach requires verified certificate authentication");
	fully_authenticated = 1;
}

static void
receive_child_ready(int fd, int64_t deadline)
{
	u_char message[5];
	size_t offset = 0;
	ssize_t received;

	/* No fields can nominate a process, certificate, executable or session. */
	while (offset < sizeof(message)) {
		wait_ready(fd, POLLIN, deadline);
		received = read(fd, message + offset, sizeof(message) - offset);
		if (received == -1 && errno == EINTR)
			continue;
		if (received <= 0)
			fatal("AOS attach private monitor unavailable");
		offset += received;
	}
	if (memcmp(message, "\0\0\0\1", 4) != 0 ||
	    message[4] != AOS_ATTACH_READY_REQUEST)
		fatal("AOS attach unexpected private monitor message");
}

static int
connect_guest(void)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	struct stat metadata;
	struct ucred peer;
	socklen_t peer_len = sizeof(peer);
	int fd;

	if (lstat("/run", &metadata) == -1 || !S_ISDIR(metadata.st_mode) ||
	    metadata.st_uid != 0 || (metadata.st_mode & 022) != 0 ||
	    lstat("/run/aos-sandbox-agent", &metadata) == -1 ||
	    !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 ||
	    (metadata.st_mode & 022) != 0 ||
	    lstat(AOS_ATTACH_SOCKET, &metadata) == -1 ||
	    !S_ISSOCK(metadata.st_mode) || metadata.st_uid != 0)
		fatal("AOS attach Guest listener unavailable");
	if ((fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) == -1)
		fatal("AOS attach Guest connection unavailable");
	strlcpy(address.sun_path, AOS_ATTACH_SOCKET, sizeof(address.sun_path));
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) == -1 ||
	    peer_len != sizeof(peer) || peer.uid != 0 || peer.pid <= 0)
		fatal("AOS attach Guest connection rejected");
	return fd;
}

void
aos_attach_monitor_parent(pid_t child, int private_monitor)
{
	struct iovec iov;
	struct msghdr message = {0};
	union { struct cmsghdr alignment; u_char bytes[CMSG_SPACE(sizeof(int))]; } control;
	struct cmsghdr *header;
	u_char response[9], ancillary[1];
	struct sshbuf *empty;
	int64_t deadline;
	ssize_t sent;

	if (!options.aos_attach_monitor_v2)
		return;
	if (!fully_authenticated || accepted_witness == NULL ||
	    getuid() != 0 || geteuid() != 0 || child <= 0 || private_monitor < 0)
		fatal("AOS attach root monitor rejected");
	/* This is our exact unreaped fork, not a PID supplied in any record. */
	held_child_pidfd = syscall(SYS_pidfd_open, child, 0);
	if (held_child_pidfd == -1 ||
	    fcntl(held_child_pidfd, F_SETFD, FD_CLOEXEC) == -1)
		fatal("AOS attach child custody unavailable");
	deadline = deadline_milliseconds() + AOS_ATTACH_TIMEOUT_MS;
	receive_child_ready(private_monitor, deadline);
	held_guest_connection = connect_guest();
	if (fcntl(held_guest_connection, F_SETFL, O_NONBLOCK) == -1)
		fatal("AOS attach Guest connection unavailable");

	memset(&control, 0, sizeof(control));
	iov.iov_base = (void *)sshbuf_ptr(accepted_witness);
	iov.iov_len = sshbuf_len(accepted_witness);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(header), &held_child_pidfd, sizeof(int));
	wait_ready(held_guest_connection, POLLOUT, deadline);
	do {
		sent = sendmsg(held_guest_connection, &message, MSG_NOSIGNAL);
	} while (sent == -1 && errno == EINTR &&
	    deadline_milliseconds() < deadline);
	if (sent != (ssize_t)sshbuf_len(accepted_witness))
		fatal("AOS attach registration unavailable");

	memset(&message, 0, sizeof(message));
	iov.iov_base = response;
	iov.iov_len = sizeof(response);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary;
	message.msg_controllen = sizeof(ancillary);
	wait_ready(held_guest_connection, POLLIN, deadline);
	if (recvmsg(held_guest_connection, &message, 0) != 8 ||
	    message.msg_flags != 0 || message.msg_controllen != 0 ||
	    memcmp(response, "AOSAMB02", 8) != 0)
		fatal("AOS attach registration rejected");
	sshbuf_free(accepted_witness);
	accepted_witness = NULL;
	if ((empty = sshbuf_new()) == NULL)
		fatal("AOS attach allocation failed");
	mm_request_send(private_monitor, AOS_ATTACH_READY_ANSWER, empty);
	sshbuf_free(empty);
}

void
aos_attach_monitor_child(int private_monitor)
{
	struct sshbuf *empty;

	if (!options.aos_attach_monitor_v2)
		return;
	/* Erase the forked copy. Only the privileged owner publishes custody. */
	sshbuf_free(accepted_witness);
	accepted_witness = NULL;
	fully_authenticated = 0;
	if (getuid() == 0 || geteuid() == 0 || private_monitor < 0)
		fatal("AOS attach child privilege drop rejected");
	if ((empty = sshbuf_new()) == NULL)
		fatal("AOS attach allocation failed");
	mm_request_send(private_monitor, AOS_ATTACH_READY_REQUEST, empty);
	mm_request_receive_expect(private_monitor, AOS_ATTACH_READY_ANSWER, empty);
	if (sshbuf_len(empty) != 0)
		fatal("AOS attach unexpected monitor reply");
	sshbuf_free(empty);
}
