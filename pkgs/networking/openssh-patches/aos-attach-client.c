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

/* Shared fixed MM clients and protected Guest connector for session.o.
 * Both pinned server binaries own session.o. This object contains no root
 * authentication candidate, retained monitor/child/Guest custody or dispatcher.
 * Linking it into sshd-auth does not run a post-auth entry or confer authority.
 */
#include "includes.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "monitor.h"
#include "aos-attach-monitor.h"

extern ServerOptions options;
extern struct monitor *pmonitor;

#define AOS_ATTACH_SOCKET "/run/aos-sandbox-agent/exec-gate.sock"

int
aos_attach_monitor_connect_guest(void)
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

int
aos_attach_original_waitstatus(void)
{
	struct sshbuf *empty;
	uint32_t raw;
	int r;

	if (!options.aos_attach_monitor_v2 || getuid() == 0 || geteuid() == 0 ||
	    (empty = sshbuf_new()) == NULL)
		fatal("AOS attach original terminal custody rejected");
	mm_request_send(pmonitor->m_recvfd, AOS_ATTACH_TERMINAL_REQUEST, empty);
	mm_request_receive_expect(pmonitor->m_recvfd, AOS_ATTACH_TERMINAL_ANSWER, empty);
	if ((r = sshbuf_get_u32(empty, &raw)) != 0 || sshbuf_len(empty) != 0 || raw > 0xffff)
		fatal("AOS attach original terminal answer rejected");
	sshbuf_free(empty);
	return (int)raw;
}

static int
original_control(u_char action, struct sshbuf *payload)
{
	struct sshbuf *data;
	int r;

	if (!options.aos_attach_monitor_v2 || getuid() == 0 || geteuid() == 0 ||
	    (data = sshbuf_new()) == NULL)
		fatal("AOS attach original control custody rejected");
	if ((r = sshbuf_put_u8(data, action)) != 0 ||
	    (r = sshbuf_put_stringb(data, payload)) != 0)
		fatal_fr(r, "AOS attach original control encoding");
	mm_request_send(pmonitor->m_recvfd, AOS_ATTACH_CONTROL_REQUEST, data);
	mm_request_receive_expect(pmonitor->m_recvfd, AOS_ATTACH_CONTROL_ANSWER, data);
	if (sshbuf_len(data) != 0)
		fatal("AOS attach original control answer rejected");
	sshbuf_free(data);
	return 1;
}

static struct sshbuf *
original_geometry(unsigned int rows, unsigned int columns,
    unsigned int xpixel, unsigned int ypixel)
{
	struct sshbuf *data;
	int r;

	if (rows > UINT16_MAX || columns > UINT16_MAX || xpixel > UINT16_MAX ||
	    ypixel > UINT16_MAX || (data = sshbuf_new()) == NULL)
		return NULL;
	if ((r = sshbuf_put_u16(data, rows)) != 0 ||
	    (r = sshbuf_put_u16(data, columns)) != 0 ||
	    (r = sshbuf_put_u16(data, xpixel)) != 0 ||
	    (r = sshbuf_put_u16(data, ypixel)) != 0)
		fatal_fr(r, "AOS attach original geometry encoding");
	return data;
}

int
aos_attach_original_signal(int signal)
{
	struct sshbuf *payload;
	int result, r;

	if (signal != 1 && signal != 2 && signal != 3 && signal != 9 &&
	    signal != 10 && signal != 12 && signal != 15)
		return 0;
	if ((payload = sshbuf_new()) == NULL)
		fatal("AOS attach original control allocation failed");
	if ((r = sshbuf_put_u8(payload, signal)) != 0)
		fatal_fr(r, "AOS attach original signal encoding");
	result = original_control(1, payload);
	sshbuf_free(payload);
	return result;
}

int
aos_attach_original_resize(unsigned int rows, unsigned int columns,
    unsigned int xpixel, unsigned int ypixel)
{
	struct sshbuf *payload;
	int result;

	if (rows == 0 || columns == 0 ||
	    (payload = original_geometry(rows, columns, xpixel, ypixel)) == NULL)
		return 0;
	result = original_control(2, payload);
	sshbuf_free(payload);
	return result;
}

int
aos_attach_original_pty(const char *terminal, unsigned int rows,
    unsigned int columns, unsigned int xpixel, unsigned int ypixel,
    const unsigned char *modes, size_t modes_length)
{
	struct sshbuf *payload;
	size_t terminal_length = strlen(terminal);
	int result, r;

	if (terminal_length > 128 || modes_length > 1024 ||
	    (payload = original_geometry(rows, columns, xpixel, ypixel)) == NULL)
		return 0;
	if ((r = sshbuf_put_u16(payload, terminal_length)) != 0 ||
	    (r = sshbuf_put(payload, terminal, terminal_length)) != 0 ||
	    (r = sshbuf_put_u16(payload, modes_length)) != 0 ||
	    (r = sshbuf_put(payload, modes, modes_length)) != 0)
		fatal_fr(r, "AOS attach original PTY encoding");
	result = original_control(3, payload);
	sshbuf_free(payload);
	return result;
}
