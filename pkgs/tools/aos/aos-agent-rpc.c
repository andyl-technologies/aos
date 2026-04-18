/*
 * aos-agent-rpc — Single-shot RPC client for the AOS VM test agent.
 *
 * Connects to a Unix domain socket, optionally performs the Firecracker
 * vsock CONNECT handshake, sends a command, reads one line of JSON
 * response, and prints it to stdout.
 *
 * Replaces the shell pipeline { printf cmd; sleep 30 } | socat | head -1
 * which always blocks for the full sleep duration because sleep is immune
 * to SIGPIPE.  A single process owns both sides of the socket — it reads
 * the response before closing, so no sleep hack is needed.
 */

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum driver {
	DRIVER_QEMU,
	DRIVER_FIRECRACKER,
};

#define RESPONSE_BUFSZ  65536
#define HANDSHAKE_BUFSZ 256

/* Forward declarations — helpers defined after main (call-graph order). */
static void    usage(const char *progname);
static int     write_all(int fd, const char *buf, size_t len);
static ssize_t read_line(int fd, char *buf, size_t bufsz, int timeout_ms);

int main(int argc, char *argv[])
{
	enum driver driver = DRIVER_QEMU;
	int driver_set = 0;
	int timeout_secs = 30;

	static struct option long_options[] = {
		{"driver",  required_argument, NULL, 'd'},
		{"timeout", required_argument, NULL, 't'},
		{NULL, 0, NULL, 0},
	};

	signal(SIGPIPE, SIG_IGN);

	int opt;
	while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			if (strcmp(optarg, "qemu") == 0) {
				driver = DRIVER_QEMU;
			} else if (strcmp(optarg, "firecracker") == 0) {
				driver = DRIVER_FIRECRACKER;
			} else {
				fprintf(stderr,
					"aos-agent-rpc: unknown driver '%s'"
					" (expected 'qemu' or 'firecracker')\n",
					optarg);
				return 2;
			}
			driver_set = 1;
			break;
		case 't':
			timeout_secs = atoi(optarg);
			if (timeout_secs <= 0) {
				fprintf(stderr,
					"aos-agent-rpc: --timeout must be a"
					" positive integer, got '%s'\n",
					optarg);
				return 2;
			}
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!driver_set) {
		fprintf(stderr, "aos-agent-rpc: --driver is required\n");
		usage(argv[0]);
	}

	if (argc - optind != 2) {
		fprintf(stderr,
			"aos-agent-rpc: expected 2 positional arguments"
			" (socket command), got %d\n",
			argc - optind);
		usage(argv[0]);
	}

	const char *socket_path = argv[optind];
	const char *command = argv[optind + 1];

	/* Connect to the Unix domain socket. */
	int fd = socket(AF_UNIX, SOCK_STREAM, /*protocol=*/0);
	if (fd < 0) {
		fprintf(stderr, "aos-agent-rpc: socket: %s\n",
			strerror(errno));
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	if (strlen(socket_path) >= sizeof(addr.sun_path)) {
		fprintf(stderr,
			"aos-agent-rpc: socket path too long"
			" (%zu bytes, max %zu): %s\n",
			strlen(socket_path), sizeof(addr.sun_path) - 1,
			socket_path);
		close(fd);
		return 1;
	}
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "aos-agent-rpc: connect(%s): %s\n",
			socket_path, strerror(errno));
		close(fd);
		return 1;
	}

	int timeout_ms = timeout_secs * 1000;

	/* Firecracker vsock handshake: send CONNECT <port>, read OK <port>. */
	if (driver == DRIVER_FIRECRACKER) {
		const char *handshake = "CONNECT 52\n";
		if (write_all(fd, handshake, strlen(handshake)) < 0) {
			close(fd);
			return 1;
		}

		char hbuf[HANDSHAKE_BUFSZ];
		ssize_t n = read_line(fd, hbuf, sizeof(hbuf), timeout_ms);
		if (n < 0) {
			fprintf(stderr,
				"aos-agent-rpc: vsock handshake failed"
				" (no OK response from %s)\n",
				socket_path);
			close(fd);
			return 1;
		}
		/* hbuf contains "OK <port>" — discard. */
	}

	/* Send the command. */
	if (write_all(fd, command, strlen(command)) < 0 ||
	    write_all(fd, "\n", /*len=*/1) < 0) {
		close(fd);
		return 1;
	}

	/* Read the JSON response line. */
	char response[RESPONSE_BUFSZ];
	ssize_t rlen = read_line(fd, response, sizeof(response), timeout_ms);
	if (rlen < 0) {
		fprintf(stderr,
			"aos-agent-rpc: no response from guest agent"
			" (timeout %ds, socket %s)\n",
			timeout_secs, socket_path);
		close(fd);
		return 1;
	}

	printf("%s\n", response);

	close(fd);
	return 0;
}

/* -------------------------------------------------------------------------- */

static void usage(const char *progname)
{
	fprintf(stderr,
		"usage: %s --driver qemu|firecracker"
		" [--timeout SECS] <socket> <command>\n",
		progname);
	exit(2);
}

static int write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static ssize_t read_line(int fd, char *buf, size_t bufsz, int timeout_ms)
{
	size_t pos = 0;
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
	};

	while (pos < bufsz - 1) {
		int ret = poll(&pfd, /*nfds=*/1, timeout_ms);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			return -1; /* timeout */

		ssize_t n = read(fd, &buf[pos], /*count=*/1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			/* EOF before newline — return what we have. */
			buf[pos] = '\0';
			return (ssize_t)pos;
		}
		if (buf[pos] == '\n') {
			buf[pos] = '\0';
			return (ssize_t)pos;
		}
		pos++;
	}

	fprintf(stderr, "aos-agent-rpc: response line exceeds %zu bytes\n",
		bufsz - 1);
	return -1;
}
