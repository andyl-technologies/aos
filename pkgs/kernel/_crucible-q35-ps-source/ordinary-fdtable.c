/* SPDX-License-Identifier: GPL-2.0-only */
/* Ordinary syscall controls for a future boot of the composed kernel.
 * These exercise real files/fdtable operations, not selected KVM authority.
 * Authored only: never compiled or executed for this source candidate.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 4
#define OWNED_PER_WORKER 32

static int failure(const char *operation)
{
	perror(operation);
	return 1;
}

static int wait_success(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) != child)
		return failure("waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "child control did not complete successfully\n");
		return 1;
	}
	return 0;
}

static int growth_and_reuse(int source)
{
	int high, reused, flags;

	high = fcntl(source, F_DUPFD_CLOEXEC, 256);
	if (high < 0)
		return failure("growth F_DUPFD_CLOEXEC");
	flags = fcntl(high, F_GETFD);
	if (flags < 0 || !(flags & FD_CLOEXEC)) {
		close(high);
		return failure("grown close-on-exec bit");
	}
	if (close(high))
		return failure("close grown slot");

	reused = fcntl(source, F_DUPFD_CLOEXEC, 256);
	if (reused < 0)
		return failure("reserve released grown slot");
	if (reused != high) {
		fprintf(stderr, "released lowest slot was not reused\n");
		close(reused);
		return 1;
	}
	if (close(reused))
		return failure("close reused slot");
	return 0;
}

static int exhausted_child(int source)
{
	struct rlimit original, limited;
	int descriptors[64];
	int count = 0, result, released;

	if (getrlimit(RLIMIT_NOFILE, &original))
		return failure("getrlimit");
	limited = original;
	if (limited.rlim_cur > 64)
		limited.rlim_cur = 64;
	if (limited.rlim_cur <= (rlim_t)source + 1) {
		fprintf(stderr, "ordinary control lacks a usable descriptor limit\n");
		return 1;
	}
	if (setrlimit(RLIMIT_NOFILE, &limited))
		return failure("child-only descriptor limit");

	for (;;) {
		result = fcntl(source, F_DUPFD_CLOEXEC, 0);
		if (result < 0)
			break;
		if (count == 64) {
			close(result);
			fprintf(stderr, "descriptor exhaustion bound was exceeded\n");
			return 1;
		}
		descriptors[count++] = result;
	}
	if (errno != EMFILE || !count)
		return failure("actual EMFILE before another slot reservation");

	released = descriptors[--count];
	if (close(released))
		return failure("release exhausted slot");
	result = fcntl(source, F_DUPFD_CLOEXEC, 0);
	if (result != released) {
		if (result >= 0)
			close(result);
		fprintf(stderr, "failed allocation disturbed the next free slot\n");
		return 1;
	}
	close(result);
	while (count)
		close(descriptors[--count]);
	return 0;
}

struct shared_worker {
	pthread_barrier_t *barrier;
	int source;
	int descriptors[OWNED_PER_WORKER];
	int error;
};

static void *shared_files_worker(void *opaque)
{
	struct shared_worker *worker = opaque;
	int index;

	for (index = 0; index < OWNED_PER_WORKER; index++) {
		worker->descriptors[index] = fcntl(worker->source, F_DUPFD_CLOEXEC, 0);
		if (worker->descriptors[index] < 0) {
			worker->error = errno;
			break;
		}
	}
	/* All callers reach the rendezvous even after their first failure. */
	pthread_barrier_wait(worker->barrier);
	pthread_barrier_wait(worker->barrier);
	for (index = 0; index < OWNED_PER_WORKER; index++)
		if (worker->descriptors[index] >= 0)
			close(worker->descriptors[index]);
	return NULL;
}

static int concurrent_shared_files(int source)
{
	pthread_barrier_t barrier;
	pthread_t threads[WORKERS];
	struct shared_worker workers[WORKERS];
	int worker, index, other, slot;
	int failed = 0;

	if (pthread_barrier_init(&barrier, NULL, WORKERS + 1)) {
		fprintf(stderr, "pthread barrier initialization failed\n");
		return 1;
	}
	for (worker = 0; worker < WORKERS; worker++) {
		workers[worker].barrier = &barrier;
		workers[worker].source = source;
		workers[worker].error = 0;
		for (index = 0; index < OWNED_PER_WORKER; index++)
			workers[worker].descriptors[index] = -1;
		if (pthread_create(&threads[worker], NULL, shared_files_worker, &workers[worker])) {
			/* Exiting the test process contains any earlier waiting worker. */
			fprintf(stderr, "pthread_create failed\n");
			exit(1);
		}
	}

	pthread_barrier_wait(&barrier);
	for (worker = 0; worker < WORKERS; worker++) {
		if (workers[worker].error)
			failed = 1;
		for (index = 0; index < OWNED_PER_WORKER; index++) {
			int descriptor = workers[worker].descriptors[index];

			int flags = descriptor < 0 ? -1 : fcntl(descriptor, F_GETFD);

			if (flags < 0 || !(flags & FD_CLOEXEC))
				failed = 1;
			for (other = 0; other <= worker; other++)
				for (slot = 0; slot < OWNED_PER_WORKER; slot++) {
					if (other == worker && slot >= index)
						break;
					if (descriptor >= 0 && descriptor == workers[other].descriptors[slot])
						failed = 1;
				}
		}
	}
	pthread_barrier_wait(&barrier);
	for (worker = 0; worker < WORKERS; worker++)
		if (pthread_join(threads[worker], NULL))
			failed = 1;
	pthread_barrier_destroy(&barrier);
	if (failed)
		fprintf(stderr, "shared-files allocation, bitmap or uniqueness control failed\n");
	return failed;
}

static int exec_check(int closed, int retained)
{
	int result;

	errno = 0;
	result = fcntl(closed, F_GETFD);
	if (result != -1 || errno != EBADF)
		return 1;
	result = fcntl(retained, F_GETFD);
	return result < 0 || (result & FD_CLOEXEC);
}

static int exec_and_parent_isolation(int source)
{
	char closed_text[32], retained_text[32];
	int closed, retained;
	pid_t child;
	int result;

	closed = fcntl(source, F_DUPFD_CLOEXEC, 0);
	if (closed < 0)
		return failure("duplicate close-on-exec control");
	retained = fcntl(source, F_DUPFD, 0);
	if (retained < 0) {
		close(closed);
		return failure("duplicate retained-exec control");
	}
	snprintf(closed_text, sizeof(closed_text), "%d", closed);
	snprintf(retained_text, sizeof(retained_text), "%d", retained);
	child = fork();
	if (child < 0) {
		close(closed);
		close(retained);
		return failure("fork exec control");
	}
	if (!child) {
		execl("/proc/self/exe", "ordinary-fdtable", "--exec-check",
		      closed_text, retained_text, (char *)NULL);
		_exit(1);
	}
	result = wait_success(child);
	if (fcntl(closed, F_GETFD) < 0 || fcntl(retained, F_GETFD) < 0)
		result = 1;
	close(closed);
	close(retained);
	return result;
}

int main(int argc, char **argv)
{
	int pipe_descriptors[2];
	pid_t child;
	int result;

	if (argc == 4 && !strcmp(argv[1], "--exec-check"))
		return exec_check(atoi(argv[2]), atoi(argv[3]));
	if (argc != 1) {
		fprintf(stderr, "unexpected control arguments\n");
		return 1;
	}
	if (pipe2(pipe_descriptors, O_CLOEXEC))
		return failure("pipe2");
	result = growth_and_reuse(pipe_descriptors[0]);
	if (!result) {
		child = fork();
		if (!child)
			_exit(exhausted_child(pipe_descriptors[0]));
		result = child < 0 ? failure("fork exhaustion control") : wait_success(child);
	}
	if (!result)
		result = concurrent_shared_files(pipe_descriptors[0]);
	if (!result)
		result = exec_and_parent_isolation(pipe_descriptors[0]);
	close(pipe_descriptors[0]);
	close(pipe_descriptors[1]);
	return result;
}
