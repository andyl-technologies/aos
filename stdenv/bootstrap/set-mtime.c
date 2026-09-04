/* SPDX-License-Identifier: Apache-2.0 */

/* Set bootstrap source paths to one timestamp without relying on touch(1).
 *
 * The stage-4 touch is linked against Mes libc, whose incomplete timestamp
 * handling makes both reference and explicit times behave like "now".  This
 * helper is compiled only after the bootstrap reaches glibc.
 */

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

int
main(int argc, char **argv)
{
  struct utimbuf timestamp;
  struct stat status;
  int argument;

  if (argc < 2)
    {
      fputs("usage: set-mtime PATH...\n", stderr);
      return 1;
    }

  timestamp.actime = 946684800;
  timestamp.modtime = 946684800;

  for (argument = 1; argument < argc; ++argument)
    {
      if (lstat(argv[argument], &status) != 0)
        {
          perror(argv[argument]);
          return 1;
        }
      if (S_ISLNK(status.st_mode))
        {
          fprintf(stderr, "%s: refusing to follow symbolic link\n", argv[argument]);
          return 1;
        }
      if (utime(argv[argument], &timestamp) != 0)
        {
          perror(argv[argument]);
          return 1;
        }
    }

  return 0;
}
