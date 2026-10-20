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

/* A selected foreground daemon publishes its actual complete wildcard TCP
 * listener set before the ordinary accept/fork engine can run. Stdin is the
 * same private socket installed by its owning Guest parent; no environment,
 * PID lookup, filesystem discovery or public descriptor adopter is used.
 */
#include "includes.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aos-attach-bootstrap.h"
#include "log.h"

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

struct aos_bootstrap_original_v1 {
	unsigned char request[192];
	unsigned char receipt[88];
	unsigned char acknowledgement[40];
	struct timespec boottime, wall;
	struct rlimit nofile;
	struct pollfd acknowledgement_poll;
	struct timespec acknowledgement_timeout;
	struct ucred peer;
	struct sockaddr_storage addresses[2];
	uint64_t cookies[2];
	uint64_t original_boot;
	time_t original_wall;
	int listeners[2];
	ssize_t received, sent, acknowledged;
	int nofile_result;
	int poll_result, poll_error;
	int enabled, prepared, finished;
};

static struct aos_bootstrap_original_v1 original;

static uint64_t
aos_load64(const unsigned char *bytes)
{
	uint64_t value = 0;
	unsigned int i;

	for (i = 0; i < 8; i++)
		value = (value << 8) | bytes[i];
	return value;
}

static void
aos_store64(unsigned char *bytes, uint64_t value)
{
	unsigned int i;

	for (i = 0; i < 8; i++) {
		bytes[7 - i] = value & 255;
		value >>= 8;
	}
}

static uint32_t
aos_load32(const unsigned char *bytes)
{
	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
	    ((uint32_t)bytes[2] << 8) | bytes[3];
}

int
aos_attach_bootstrap_request_is_canonical_v1(const unsigned char *bytes,
    size_t length)
{
	unsigned int i, nonzero;

	if (length != sizeof(original.request) ||
	    memcmp(bytes, "AOSSLB01", 8) ||
	    memcmp(bytes + 8, "AOSSSH01", 8) ||
	    aos_load64(bytes + 128) == 0 ||
	    aos_load32(bytes + 136) != 4 ||
	    aos_load32(bytes + 140) < 3 ||
	    aos_load32(bytes + 144) == 0 ||
	    aos_load32(bytes + 148) < 2 ||
	    aos_load64(bytes + 152) == 0 ||
	    aos_load64(bytes + 160) == 0 ||
	    aos_load64(bytes + 160) > INT64_MAX ||
	    (bytes[168] | bytes[169]) == 0)
		return 0;
	for (i = 170; i < 176; i++) {
		if (bytes[i] != 0)
			return 0;
	}
	/* Runtime/session/execution/request and nonce are distinct original
	 * coordinates, not optional zero sentinels or authority by themselves. */
	for (i = 0; i < 5; i++) {
		static const unsigned int offsets[] = { 16, 48, 80, 96, 176 };
		static const unsigned int widths[] = { 32, 32, 16, 32, 16 };
		unsigned int j;

		for (j = nonzero = 0; j < widths[i]; j++)
			nonzero |= bytes[offsets[i] + j];
		if (nonzero == 0)
			return 0;
	}
	return 1;
}

static void
aos_bootstrap_current(void)
{
	uint64_t boot, deadline;

	if (clock_gettime(CLOCK_BOOTTIME, &original.boottime) == -1 ||
	    clock_gettime(CLOCK_REALTIME, &original.wall) == -1)
		fatal("AOS listener bootstrap clock: %s", strerror(errno));
	if (original.boottime.tv_sec < 0 || original.wall.tv_sec < 0 ||
	    (uint64_t)original.boottime.tv_sec > UINT64_MAX / 1000000000)
		fatal("AOS listener bootstrap clock range");
	boot = (uint64_t)original.boottime.tv_sec * 1000000000;
	if ((uint64_t)original.boottime.tv_nsec > UINT64_MAX - boot)
		fatal("AOS listener bootstrap clock overflow");
	boot += original.boottime.tv_nsec;
	if (original.original_boot == 0) {
		original.original_boot = boot;
		original.original_wall = original.wall.tv_sec;
	}
	deadline = aos_load64(original.request + 152);
	if (deadline == 0 || boot < original.original_boot ||
	    original.wall.tv_sec < original.original_wall || boot >= deadline ||
	    aos_load64(original.request + 160) == 0 ||
	    (uint64_t)original.wall.tv_sec >= aos_load64(original.request + 160))
		fatal("AOS listener bootstrap original horizon expired");
}

static void
aos_bootstrap_wait_for_ack(void)
{
	uint64_t boot, boot_remaining, wall_seconds, wall_remaining, remaining;

	/* This is one native wait under the unchanged original endpoints. The
	 * child's original Process supervisor owns this entire scope and can
	 * kill/reap it independently. EINTR/backpressure never starts a retry. */
	aos_bootstrap_current();
	boot = (uint64_t)original.boottime.tv_sec * 1000000000 +
	    original.boottime.tv_nsec;
	boot_remaining = aos_load64(original.request + 152) - boot;
	wall_seconds = aos_load64(original.request + 160) - original.wall.tv_sec;
	if (wall_seconds > UINT64_MAX / 1000000000)
		wall_remaining = UINT64_MAX;
	else
		wall_remaining = wall_seconds * 1000000000 - original.wall.tv_nsec;
	remaining = boot_remaining < wall_remaining ? boot_remaining : wall_remaining;
	original.acknowledgement_timeout.tv_sec = remaining / 1000000000;
	original.acknowledgement_timeout.tv_nsec = remaining % 1000000000;
	original.acknowledgement_poll.fd = STDIN_FILENO;
	original.acknowledgement_poll.events = POLLIN;
	original.poll_result = ppoll(&original.acknowledgement_poll, 1,
	    &original.acknowledgement_timeout, NULL);
	original.poll_error = original.poll_result == -1 ? errno : 0;
	/* The after clock is owed after every actual native wait result. */
	aos_bootstrap_current();
	if (original.poll_result != 1 ||
	    original.acknowledgement_poll.revents != POLLIN)
		fatal("AOS listener bootstrap original ACK wait refused: %s",
		    original.poll_error == 0 ? "incomplete readiness" :
		    strerror(original.poll_error));
}

void
aos_attach_bootstrap_current_v1(void)
{
	if (!original.enabled)
		return;
	if (!original.prepared || original.finished)
		fatal("AOS listener bootstrap native phase unavailable");
	aos_bootstrap_current();
}

void
aos_attach_bootstrap_prepare_v1(int enabled, int monitor, int foreground,
    int inetd)
{
	struct iovec vector;
	struct msghdr message;
	socklen_t size;
	int type, flags;

	/* This entrance precedes fill_default_server_options: an unspecified
	 * option is still -1 and must remain the ordinary no-op branch. */
	if (enabled != 1)
		return;
	if (original.enabled || monitor != 1 || !foreground || inetd ||
	    getuid() != 0 || geteuid() != 0)
		fatal("AOS listener bootstrap fixed foreground recipe required");
	original.enabled = 1;
	size = sizeof(type);
	if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_TYPE, &type, &size) == -1 ||
	    size != sizeof(type) || type != SOCK_SEQPACKET)
		fatal("AOS listener bootstrap requires owned seqpacket stdin");
	size = sizeof(original.peer);
	if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &original.peer,
	    &size) == -1 || size != sizeof(original.peer) ||
	    original.peer.uid != 0 || original.peer.gid != 0 ||
	    original.peer.pid != getppid())
		fatal("AOS listener bootstrap original parent mismatch");
	if ((flags = fcntl(STDIN_FILENO, F_GETFD)) == -1 ||
	    fcntl(STDIN_FILENO, F_SETFD, flags | FD_CLOEXEC) == -1)
		fatal("AOS listener bootstrap descriptor flags: %s", strerror(errno));
	if ((flags = fcntl(STDIN_FILENO, F_GETFL)) == -1 ||
	    !(flags & O_NONBLOCK))
		fatal("AOS listener bootstrap requires the original nonblocking endpoint");

	/* The owning parent queues this exact fixed record before spawning. No
	 * descriptors are accepted here; the native kernel closes truncated rights.
	 * Interrupted/partial transfers fail once and cannot restart the phase.
	 */
	memset(&message, 0, sizeof(message));
	vector.iov_base = original.request;
	vector.iov_len = sizeof(original.request);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	original.received = recvmsg(STDIN_FILENO, &message, MSG_CMSG_CLOEXEC);
	if (original.received != sizeof(original.request) ||
	    message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
	    !aos_attach_bootstrap_request_is_canonical_v1(original.request,
	    sizeof(original.request)))
		fatal("AOS listener bootstrap original request refused");

	/* The same child helper installs this hard limit before execing sshd.
	 * A late READY cannot replace cgroup-at-birth or a limit that already
	 * covers dynamic sshd setup and every later fork/helper.
	 */
	original.nofile_result = getrlimit(RLIMIT_NOFILE, &original.nofile);
	if (original.nofile_result == -1 ||
	    original.nofile.rlim_cur != aos_load32(original.request + 140) ||
	    original.nofile.rlim_max != aos_load32(original.request + 140))
		fatal("AOS listener bootstrap original hard nofile limit differs");

	aos_bootstrap_current();
	original.prepared = 1;
}

void
aos_attach_bootstrap_listeners_v1(const int *listeners, int count)
{
	struct msghdr message;
	struct iovec vector;
	struct cmsghdr *header;
	union {
		struct cmsghdr align;
		unsigned char bytes[CMSG_SPACE(2 * sizeof(int))];
	} control;
	unsigned int seen = 0, family;
	socklen_t size;
	uint16_t port;
	int i, accepting, type;

	if (!original.enabled)
		return;
	if (!original.prepared || original.finished || count < 1 || count > 2)
		fatal("AOS listener bootstrap incomplete fixed listener table");
	port = ((uint16_t)original.request[168] << 8) | original.request[169];
	for (i = 0; i < count; i++) {
		original.listeners[i] = listeners[i];
		size = sizeof(original.addresses[i]);
		if (getsockname(listeners[i], (struct sockaddr *)&original.addresses[i],
		    &size) == -1)
			fatal("AOS listener bootstrap local endpoint: %s", strerror(errno));
		family = original.addresses[i].ss_family;
		if (family == AF_INET) {
			struct sockaddr_in *address = (void *)&original.addresses[i];
			if (size != sizeof(*address) || ntohs(address->sin_port) != port ||
			    address->sin_addr.s_addr != htonl(INADDR_ANY) || seen & 1)
				fatal("AOS listener bootstrap IPv4 fixed endpoint mismatch");
			seen |= 1;
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *address = (void *)&original.addresses[i];
			if (size != sizeof(*address) || ntohs(address->sin6_port) != port ||
			    memcmp(&address->sin6_addr, &in6addr_any, sizeof(in6addr_any)) ||
			    address->sin6_scope_id != 0 || seen & 2)
				fatal("AOS listener bootstrap IPv6 fixed endpoint mismatch");
			seen |= 2;
		} else {
			fatal("AOS listener bootstrap unsupported fixed listener family");
		}
		size = sizeof(accepting);
		if (getsockopt(listeners[i], SOL_SOCKET, SO_ACCEPTCONN, &accepting,
		    &size) == -1 || size != sizeof(accepting) || accepting != 1)
			fatal("AOS listener bootstrap listener is not accepting");
		size = sizeof(type);
		if (getsockopt(listeners[i], SOL_SOCKET, SO_TYPE, &type, &size) == -1 ||
		    size != sizeof(type) || type != SOCK_STREAM)
			fatal("AOS listener bootstrap listener is not TCP");
		size = sizeof(original.cookies[i]);
		if (getsockopt(listeners[i], SOL_SOCKET, SO_COOKIE, &original.cookies[i],
		    &size) == -1 || size != sizeof(original.cookies[i]) ||
		    original.cookies[i] == 0)
			fatal("AOS listener bootstrap cookie unavailable");
	}

	memcpy(original.receipt, "AOSSLR01", 8);
	memcpy(original.receipt + 8, original.request + 80, 16);
	memcpy(original.receipt + 24, original.request + 176, 16);
	original.receipt[40] = count;
	for (i = 0; i < 2; i++)
		aos_store64(original.receipt + 48 + 8 * i, original.cookies[i]);
	original.receipt[64] = ((uint32_t)getpid() >> 24) & 255;
	original.receipt[65] = ((uint32_t)getpid() >> 16) & 255;
	original.receipt[66] = ((uint32_t)getpid() >> 8) & 255;
	original.receipt[67] = (uint32_t)getpid() & 255;
	memcpy(original.receipt + 72, original.request + 128, 8);
	memcpy(original.receipt + 80, original.request + 140, 4);
	memcpy(original.receipt + 84, original.request + 136, 4);
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	vector.iov_base = original.receipt;
	vector.iov_len = sizeof(original.receipt);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = &control;
	message.msg_controllen = CMSG_SPACE(count * sizeof(int));
	header = CMSG_FIRSTHDR(&message);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(count * sizeof(int));
	memcpy(CMSG_DATA(header), original.listeners, count * sizeof(int));
	aos_bootstrap_current();
	original.sent = sendmsg(STDIN_FILENO, &message, MSG_NOSIGNAL);
	if (original.sent != sizeof(original.receipt))
		fatal("AOS listener bootstrap transfer did not complete");
	aos_bootstrap_current();

	aos_bootstrap_wait_for_ack();
	memset(&message, 0, sizeof(message));
	vector.iov_base = original.acknowledgement;
	vector.iov_len = sizeof(original.acknowledgement);
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	original.acknowledged = recvmsg(STDIN_FILENO, &message, MSG_CMSG_CLOEXEC);
	if (original.acknowledged != sizeof(original.acknowledgement) ||
	    message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
	    memcmp(original.acknowledgement, "AOSSLA01", 8) ||
	    memcmp(original.acknowledgement + 8, original.request + 80, 16) ||
	    memcmp(original.acknowledgement + 24, original.request + 176, 16))
		fatal("AOS listener bootstrap original acceptance unavailable");
	aos_bootstrap_current();
	if (close(STDIN_FILENO) == -1)
		fatal("AOS listener bootstrap close: %s", strerror(errno));
	original.finished = 1;
}
