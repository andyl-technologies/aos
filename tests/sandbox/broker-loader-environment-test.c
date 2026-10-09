/* SPDX-License-Identifier: Apache-2.0 */
/* Test the helper's fail-closed environment-name classification. */
#define main broker_query_program_main
#include "broker-query.c"
#undef main

int main(void)
{
  static const char *const forbidden[] = {
      "LD_PRELOAD=/tmp/inject.so",
      "LD_LIBRARY_PATH=/tmp",
      "LD_FUTURE_OVERRIDE=1",
      "GLIBC_TUNABLES=glibc.rtld.nns=1",
      "GCONV_PATH=/tmp",
      "LIBC_FATAL_STDERR_=1",
      "MALLOC_TRACE=/tmp/trace",
      "BROKEN",
      "=empty-name",
  };
  static const char *const allowed[] = {
      "PATH=/nix/store/bin",
      "CREDENTIALS_DIRECTORY=/run/credentials/service",
      "LANG=C.UTF-8",
  };

  for (size_t index = 0; index < sizeof(forbidden) / sizeof(forbidden[0]);
       index++) {
    if (!loader_environment_name(forbidden[index]))
      return 1;
  }
  for (size_t index = 0; index < sizeof(allowed) / sizeof(allowed[0]);
       index++) {
    if (loader_environment_name(allowed[index]))
      return 1;
  }
  return 0;
}
