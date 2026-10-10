// SPDX-License-Identifier: Apache-2.0
/* Executes the guest's pipe relay locally; no doorbells, mounts or VM authority. */
#define RAM_WRITER_LOCAL_CONTROL
#include "ram-writer-boot-init.c"

static unsigned observed_boundaries;
static int denied_stage;

static int local_boundary(unsigned stage) {
  observed_boundaries++;
  if ((int)stage == denied_stage) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "--reply") == 0) {
    unsigned char reply[128];
    FILE *stream = fopen(argv[2], "rb");
    if (stream == NULL) {
      return 2;
    }
    int full = fread(reply, sizeof(reply), 1, stream) == 1 && fgetc(stream) == EOF;
    int closed = fclose(stream) == 0;
    return full && closed && validate_reply(reply, (unsigned)atoi(argv[3])) == 0 ? 0 : 1;
  }
  if (argc == 3 && strcmp(argv[1], "--wire") == 0) {
    FILE *stream = fopen(argv[2], "wb");
    if (stream == NULL) {
      return 2;
    }
    unsigned char registration[81], request[128];
    prepare_registration(registration);
    if (fwrite(registration, sizeof(registration), 1, stream) != 1) {
      fclose(stream);
      return 2;
    }
    for (unsigned stage = 0; stage < 3; ++stage) {
      prepare_request(request, stage);
      if (fwrite(request, sizeof(request), 1, stream) != 1) {
        fclose(stream);
        return 2;
      }
    }
    return fclose(stream) == 0 ? 0 : 2;
  }
  if (argc != 5) {
    return 2;
  }
  denied_stage = atoi(argv[3]);
  if (strcmp(argv[4], "closed-stdin") == 0) {
    close(STDIN_FILENO);
  }
  signal(SIGPIPE, SIG_IGN);
  int outcome = run_writer(argv[1], argv[2], strcmp(argv[2], "dma-virtio") == 0, local_boundary);
  int cause = outcome == 0 ? 0 : errno;
  int child_status;
  errno = 0;
  pid_t extra = waitpid(-1, &child_status, WNOHANG);
  if (extra != -1 || errno != ECHILD) {
    return 3;
  }
  printf("LOCAL_RELAY_RESULT_V1 outcome=%d cause=%d boundaries=%u children=none\n",
         outcome, cause, observed_boundaries);
  return outcome == 0 ? 0 : 1;
}
