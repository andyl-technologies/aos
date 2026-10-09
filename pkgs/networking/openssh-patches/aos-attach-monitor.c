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
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "monitor.h"
#include "monitor_fdpass.h"
#include "aos-attach-monitor.h"
#include "aos-attach-confinement.h"

extern ServerOptions options;

#define AOS_ATTACH_MAXIMUM_RECORD 13312
#define AOS_ATTACH_TIMEOUT_MS 5000

static struct sshbuf *accepted_witness;
static int fully_authenticated;
static int held_child_pidfd = -1;
static int held_guest_connection = -1;
static uint64_t original_session_sequence = 1;

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

static void
require_original_child_live(void)
{
	struct pollfd child = { .fd = held_child_pidfd, .events = POLLIN };
	int result;

	/* The descriptor is retained from our exact unreaped fork. Polling cannot
	 * replace it with a reused PID or revive custody after child exit. */
	do {
		result = poll(&child, 1, 0);
	} while (result == -1 && errno == EINTR);
	if (held_child_pidfd == -1 || result != 0 || child.revents != 0)
		fatal("AOS attach original child unavailable");
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
	if ((r = sshbuf_put(candidate, "AOSAMR03", 8)) != 0 ||
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
	held_guest_connection = aos_attach_monitor_connect_guest();
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

/* Only the continuously confined post-auth image owns this private channel.
 * The descriptor names its still-unreaped fork. Guest's existing typed owner
 * independently joins that kernel child to the retained original witness;
 * neither this message nor its acknowledgement is an I/O grant.
 */
int
aos_attach_monitor_relay(struct ssh *ssh, int private_monitor, struct sshbuf *empty)
{
	union { struct cmsghdr alignment; u_char bytes[CMSG_SPACE(sizeof(int))]; } control;
	struct cmsghdr *header;
	struct iovec iov;
	struct msghdr message = {0};
	u_char response[9], ancillary[1];
	int relay;
	int64_t deadline;

	(void)ssh;
	if (!options.aos_attach_monitor_v2 || !fully_authenticated ||
	    held_child_pidfd == -1 || held_guest_connection == -1 ||
	    getuid() != 0 || geteuid() != 0 || sshbuf_len(empty) != 0 ||
	    (relay = mm_receive_fd(private_monitor)) == -1)
		fatal("AOS attach relay monitor rejected");
	deadline = deadline_milliseconds() + AOS_ATTACH_TIMEOUT_MS;
	memset(&control, 0, sizeof(control));
	iov = (struct iovec){ "AOSRLY03", 8 };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(header), &relay, sizeof(int));
	wait_ready(held_guest_connection, POLLOUT, deadline);
	if (sendmsg(held_guest_connection, &message, MSG_NOSIGNAL) != 8)
		fatal("AOS attach relay registration unavailable");
	close(relay);
	memset(&message, 0, sizeof(message));
	iov = (struct iovec){ response, sizeof(response) };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary;
	message.msg_controllen = sizeof(ancillary);
	wait_ready(held_guest_connection, POLLIN, deadline);
	if (recvmsg(held_guest_connection, &message, 0) != 8 ||
	    message.msg_flags != 0 || message.msg_controllen != 0 ||
	    memcmp(response, "AOSRAK03", 8) != 0)
		fatal("AOS attach relay registration rejected");
	mm_request_send(private_monitor, AOS_ATTACH_RELAY_ANSWER, empty);
	return 0;
}

/* The fixed empty MM operation reads data only from the original retained
 * Guest connection. Neither a relay status nor a child-nominated PID/status
 * can become the original execution result. No expiry or IO grant is renewed.
 */
int
aos_attach_monitor_terminal(struct ssh *ssh, int private_monitor, struct sshbuf *empty)
{
	struct msghdr message = {0};
	struct iovec iov;
	u_char request[32] = {0}, response[33], ancillary[1];
	uint32_t raw;
	int64_t deadline;
	int r;
	size_t index;

	(void)ssh;
	if (!options.aos_attach_monitor_v2 || !fully_authenticated ||
	    getuid() != 0 || geteuid() != 0 || held_child_pidfd == -1 ||
	    held_guest_connection == -1 || sshbuf_len(empty) != 0 ||
	    original_session_sequence == 0 || original_session_sequence == UINT64_MAX)
		fatal("AOS attach original terminal unavailable");
	require_original_child_live();
	memcpy(request, "AOSMCT04", 8);
	for (index = 0; index < 8; index++)
		request[8 + index] = original_session_sequence >> (56 - index * 8);
	request[16] = 3;
	deadline = deadline_milliseconds() + AOS_ATTACH_TIMEOUT_MS;
	wait_ready(held_guest_connection, POLLOUT, deadline);
	if (send(held_guest_connection, request, sizeof(request), MSG_NOSIGNAL) != (ssize_t)sizeof(request))
		fatal("AOS attach original terminal request ambiguous");
	iov = (struct iovec){ response, sizeof(response) };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary;
	message.msg_controllen = sizeof(ancillary);
	wait_ready(held_guest_connection, POLLIN, deadline);
	if (recvmsg(held_guest_connection, &message, 0) != 32 ||
	    message.msg_flags != 0 || message.msg_controllen != 0 ||
	    memcmp(response, "AOSMCA04", 8) != 0 ||
	    memcmp(response + 8, request + 8, 8) != 0 || response[16] != 1)
		fatal("AOS attach original terminal reply rejected");
	for (index = 17; index < 24; index++) {
		if (response[index] != 0)
			fatal("AOS attach original terminal reply rejected");
	}
	for (index = 28; index < 32; index++) {
		if (response[index] != 0)
			fatal("AOS attach original terminal reply rejected");
	}
	raw = ((uint32_t)response[24] << 24) | ((uint32_t)response[25] << 16) |
	    ((uint32_t)response[26] << 8) | response[27];
	if ((raw & ~0xffffU) != 0 ||
	    (WIFEXITED(raw) ? (raw & 0xff) != 0 :
	    !WIFSIGNALED(raw) || WTERMSIG(raw) > 64 || (raw & ~0xffU) != 0))
		fatal("AOS attach original terminal status rejected");
	if (deadline_milliseconds() >= deadline)
		fatal("AOS attach original terminal reply expired");
	require_original_child_live();
	original_session_sequence++;
	if ((r = sshbuf_put_u32(empty, raw)) != 0)
		fatal_fr(r, "AOS attach original terminal result");
	mm_request_send(private_monitor, AOS_ATTACH_TERMINAL_ANSWER, empty);
	return 0;
}

/* The confined child nominates only bounded control data, never a target,
 * ticket, expiry, sequence or authorization. Current Controller/Host policy
 * must still authorize this exact queue through the existing forward channel.
 */
int
aos_attach_monitor_control(struct ssh *ssh, int private_monitor, struct sshbuf *data)
{
	struct msghdr message = {0};
	struct iovec iov;
	u_char request[1192] = {0}, response[25], ancillary[1], action;
	const u_char *payload;
	size_t length, index;
	int64_t deadline;
	int r;

	(void)ssh;
	if (!options.aos_attach_monitor_v2 || !fully_authenticated ||
	    getuid() != 0 || geteuid() != 0 || held_child_pidfd == -1 ||
	    held_guest_connection == -1 || original_session_sequence == 0 ||
	    original_session_sequence == UINT64_MAX ||
	    sshbuf_len(data) > 1169 || (r = sshbuf_get_u8(data, &action)) != 0 ||
	    (r = sshbuf_get_string_direct(data, &payload, &length)) != 0 ||
	    sshbuf_len(data) != 0 || length > sizeof(request) - 28 ||
	    action < 1 || action > 3 || (action == 1 && length != 1) ||
	    (action == 2 && length != 8) || (action == 3 && length < 12))
		fatal("AOS attach original control rejected");
	require_original_child_live();
	memcpy(request, "AOSMCQ05", 8);
	for (index = 0; index < 8; index++)
		request[8 + index] = original_session_sequence >> (56 - index * 8);
	request[16] = action;
	for (index = 0; index < 4; index++)
		request[24 + index] = length >> (24 - index * 8);
	memcpy(request + 28, payload, length);
	deadline = deadline_milliseconds() + AOS_ATTACH_TIMEOUT_MS;
	wait_ready(held_guest_connection, POLLOUT, deadline);
	if (send(held_guest_connection, request, 28 + length, MSG_NOSIGNAL) != (ssize_t)(28 + length))
		fatal("AOS attach original control ambiguous");
	iov = (struct iovec){ response, sizeof(response) };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = ancillary;
	message.msg_controllen = sizeof(ancillary);
	wait_ready(held_guest_connection, POLLIN, deadline);
	if (recvmsg(held_guest_connection, &message, 0) != 24 ||
	    message.msg_flags != 0 || message.msg_controllen != 0 ||
	    memcmp(response, "AOSMCA05", 8) != 0 ||
	    memcmp(response + 8, request + 8, 8) != 0)
		fatal("AOS attach original control acknowledgement rejected");
	for (index = 16; index < 24; index++) {
		if (response[index] != 0)
			fatal("AOS attach original control acknowledgement rejected");
	}
	if (deadline_milliseconds() >= deadline)
		fatal("AOS attach original control expired");
	require_original_child_live();
	original_session_sequence++;
	sshbuf_reset(data);
	mm_request_send(private_monitor, AOS_ATTACH_CONTROL_ANSWER, data);
	return 0;
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
	aos_attach_confinement_after_drop();
	if ((empty = sshbuf_new()) == NULL)
		fatal("AOS attach allocation failed");
	mm_request_send(private_monitor, AOS_ATTACH_READY_REQUEST, empty);
	mm_request_receive_expect(private_monitor, AOS_ATTACH_READY_ANSWER, empty);
	if (sshbuf_len(empty) != 0)
		fatal("AOS attach unexpected monitor reply");
	sshbuf_free(empty);
}
