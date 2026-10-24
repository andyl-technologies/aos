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

/* The fixed internal relay never parses a certificate, invents a claim, execs
 * a helper, or reads a tenant environment. The existing typed Guest owner
 * joins this kernel-identified descendant to the root-held original witness.
 */
#include "includes.h"
#include <sys/socket.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "sshbuf.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "monitor.h"
#include "monitor_fdpass.h"
#include "aos-attach-monitor.h"
#include "aos-attach-relay.h"

extern ServerOptions options;
extern struct monitor *pmonitor;

static int relay_barrier[2] = { -1, -1 };

void
aos_attach_relay_before_fork(void)
{
	if (!options.aos_attach_monitor_v2)
		return;
	if (getuid() == 0 || geteuid() == 0 ||
	    relay_barrier[0] != -1 || relay_barrier[1] != -1 ||
	    pipe2(relay_barrier, O_CLOEXEC) == -1)
		fatal("AOS attach relay fork rejected");
}

void
aos_attach_relay_parent(pid_t child)
{
	struct sshbuf *empty;
	int descriptor;
	u_char ready = 3;

	if (!options.aos_attach_monitor_v2)
		return;
	close(relay_barrier[0]);
	relay_barrier[0] = -1;
	/* This exact, still-unreaped fork inherits irreversible confinement. */
	if (child <= 0 || (descriptor = syscall(SYS_pidfd_open, child, 0)) == -1 ||
	    (empty = sshbuf_new()) == NULL)
		fatal("AOS attach relay child unavailable");
	mm_request_send(pmonitor->m_recvfd, AOS_ATTACH_RELAY_REQUEST, empty);
	if (mm_send_fd(pmonitor->m_recvfd, descriptor) == -1)
		fatal("AOS attach relay monitor unavailable");
	close(descriptor);
	mm_request_receive_expect(pmonitor->m_recvfd, AOS_ATTACH_RELAY_ANSWER, empty);
	if (sshbuf_len(empty) != 0 || write(relay_barrier[1], &ready, 1) != 1)
		fatal("AOS attach relay registration rejected");
	close(relay_barrier[1]);
	relay_barrier[1] = -1;
	sshbuf_free(empty);
}

void
aos_attach_relay_child(void)
{
	struct pollfd wait;
	u_char ready[2];
	ssize_t length;

	close(relay_barrier[1]);
	relay_barrier[1] = -1;
	wait.fd = relay_barrier[0];
	wait.events = POLLIN;
	wait.revents = 0;
	if (poll(&wait, 1, 5000) != 1 || (wait.revents & POLLIN) == 0)
		fatal("AOS attach relay readiness unavailable");
	length = read(relay_barrier[0], ready, sizeof(ready));
	close(relay_barrier[0]);
	relay_barrier[0] = -1;
	if (length != 1 || ready[0] != 3)
		fatal("AOS attach relay readiness rejected");
}

static void
require_nonblocking(int descriptor)
{
	int flags = fcntl(descriptor, F_GETFL);

	if (flags == -1 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == -1)
		_exit(1);
}

static void
relay_descriptors(int *descriptors, size_t count, int original_connection)
{
	struct relay_buffer {
		int source, target;
		u_char bytes[8192];
		size_t offset, length;
		int closed;
	} buffers[3] = {
		{ .source = STDIN_FILENO, .target = descriptors[0] },
		{ .source = count == 1 ? descriptors[0] : descriptors[1], .target = STDOUT_FILENO },
		{ .source = count == 1 ? -1 : descriptors[2], .target = STDERR_FILENO,
		  .closed = count == 1 },
	};
	struct pollfd watches[7];
	struct msghdr message;
	struct iovec iov;
	u_char terminal[13], ancillary[1];
	int terminal_received = 0;
	size_t index;
	ssize_t length;
	int result;

	for (index = 0; index < 3; index++) {
		if (buffers[index].source != -1)
			require_nonblocking(buffers[index].source);
		require_nonblocking(buffers[index].target);
	}
	for (;;) {
		for (index = 0; index < 3; index++) {
			watches[index * 2] = (struct pollfd){
			    buffers[index].closed || buffers[index].length != 0 ? -1 : buffers[index].source,
			    POLLIN, 0 };
			watches[index * 2 + 1] = (struct pollfd){
			    buffers[index].length == 0 ? -1 : buffers[index].target, POLLOUT, 0 };
		}
		watches[6] = (struct pollfd){ terminal_received ? -1 : original_connection, POLLIN, 0 };
		result = poll(watches, 7, -1);
		if (result == -1 && errno == EINTR)
			continue;
		if (result <= 0)
			_exit(1);
		if ((watches[6].revents & POLLIN) != 0) {
			memset(&message, 0, sizeof(message));
			iov = (struct iovec){ terminal, sizeof(terminal) };
			message.msg_iov = &iov;
			message.msg_iovlen = 1;
			message.msg_control = ancillary;
			message.msg_controllen = sizeof(ancillary);
			if (recvmsg(original_connection, &message, 0) != 12 ||
			    message.msg_flags != 0 || message.msg_controllen != 0 ||
			    memcmp(terminal, "AOSIOE04", 8) != 0)
				_exit(1);
			/* Data only. The root monitor independently reads the original
			 * Guest waitstatus; the relay cannot nominate an exit result. */
			terminal_received = 1;
		} else if ((watches[6].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			_exit(1);
		}
		for (index = 0; index < 3; index++) {
			if (watches[index * 2].fd != -1 &&
			    (watches[index * 2].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
				length = read(buffers[index].source, buffers[index].bytes,
				    sizeof(buffers[index].bytes));
				if (length > 0) {
					buffers[index].offset = 0;
					buffers[index].length = length;
				} else if (length == 0 ||
				    (length == -1 && errno == EIO && count == 1)) {
					buffers[index].closed = 1;
					if (index == 0 && count == 3)
						close(buffers[index].target);
				} else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
					_exit(1);
				}
			}
			if (watches[index * 2 + 1].fd != -1 &&
			    (watches[index * 2 + 1].revents & POLLOUT) != 0) {
				length = write(buffers[index].target,
				    buffers[index].bytes + buffers[index].offset,
				    buffers[index].length - buffers[index].offset);
				if (length > 0) {
					buffers[index].offset += length;
					if (buffers[index].offset == buffers[index].length)
						buffers[index].length = buffers[index].offset = 0;
				} else if (length == 0 ||
				    (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
					_exit(1);
				}
			}
			if ((watches[index * 2 + 1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
				_exit(1);
		}
		if (terminal_received && buffers[1].closed && buffers[2].closed &&
		    buffers[1].length == 0 && buffers[2].length == 0)
			_exit(0);
	}
}

void
aos_attach_internal_relay(void)
{
	union { struct cmsghdr alignment; u_char bytes[CMSG_SPACE(3 * sizeof(int))]; } control;
	struct cmsghdr *header;
	struct pollfd wait;
	struct iovec iov;
	struct msghdr message = {0};
	u_char reply[9];
	int connection, descriptors[3];
	size_t count;

	if (getuid() == 0 || geteuid() == 0)
		fatal("AOS attach relay credentials rejected");
	connection = aos_attach_monitor_connect_guest();
	if (send(connection, "AOSRIO03", 8, MSG_NOSIGNAL) != 8)
		fatal("AOS attach relay request unavailable");
	wait = (struct pollfd){ connection, POLLIN, 0 };
	if (poll(&wait, 1, 5000) != 1 || (wait.revents & POLLIN) == 0 ||
	    (wait.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
		fatal("AOS attach relay consume unavailable");
	iov = (struct iovec){ reply, sizeof(reply) };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	/* Linux preserves the requested CLOEXEC bit in the returned flags. */
	if (recvmsg(connection, &message, MSG_CMSG_CLOEXEC) != 8 ||
	    (message.msg_flags & ~MSG_CMSG_CLOEXEC) != 0)
		fatal("AOS attach relay handoff rejected");
	count = memcmp(reply, "AOSGOK03", 8) == 0 ? 1 :
	    memcmp(reply, "AOSGOS03", 8) == 0 ? 3 : 0;
	header = CMSG_FIRSTHDR(&message);
	if (count == 0 || header == NULL || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(count * sizeof(int)) ||
	    CMSG_NXTHDR(&message, header) != NULL)
		fatal("AOS attach relay descriptor shape rejected");
	memcpy(descriptors, CMSG_DATA(header), count * sizeof(int));
	if (send(connection, "AOSRID03", 8, MSG_NOSIGNAL) != 8)
		fatal("AOS attach relay handoff ambiguous");
	/* This exact channel remains connected for the lifetime of the relay.
	 * AOSRID03 is a transfer receipt, not an SSH disconnect event. */
	relay_descriptors(descriptors, count, connection);
	_exit(1);
}
