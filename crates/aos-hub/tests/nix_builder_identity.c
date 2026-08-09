#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static char user_name[] = "aos-test";
static char user_gecos[] = "AOS test identity";
static char user_home[] = "/build";
static char user_shell[] = "/bin/sh";
static char group_name[] = "aos-test";
static char *group_members[] = {user_name, NULL};
static struct passwd user_entry;
static struct group group_entry;

static void fill_user(struct passwd *entry, uid_t uid) {
  entry->pw_name = user_name;
  entry->pw_passwd = (char *)"x";
  entry->pw_uid = uid;
  entry->pw_gid = getgid();
  entry->pw_gecos = user_gecos;
  entry->pw_dir = user_home;
  entry->pw_shell = user_shell;
}

struct passwd *getpwuid(uid_t uid) {
  fill_user(&user_entry, uid);
  return &user_entry;
}

int getpwuid_r(uid_t uid, struct passwd *entry, char *buffer,
               size_t buffer_length, struct passwd **result) {
  const char *values[] = {user_name, "x", user_gecos, user_home, user_shell};
  size_t lengths[5];
  size_t required = 0;
  for (size_t index = 0; index < 5; ++index) {
    lengths[index] = strlen(values[index]) + 1;
    required += lengths[index];
  }
  if (buffer_length < required) {
    *result = NULL;
    return ERANGE;
  }

  char *cursor = buffer;
  char *copied[5];
  for (size_t index = 0; index < 5; ++index) {
    copied[index] = cursor;
    memcpy(cursor, values[index], lengths[index]);
    cursor += lengths[index];
  }
  entry->pw_name = copied[0];
  entry->pw_passwd = copied[1];
  entry->pw_uid = uid;
  entry->pw_gid = getgid();
  entry->pw_gecos = copied[2];
  entry->pw_dir = copied[3];
  entry->pw_shell = copied[4];
  *result = entry;
  return 0;
}

static void fill_group(struct group *entry, gid_t gid) {
  entry->gr_name = group_name;
  entry->gr_passwd = (char *)"x";
  entry->gr_gid = gid;
  entry->gr_mem = group_members;
}

struct group *getgrgid(gid_t gid) {
  fill_group(&group_entry, gid);
  return &group_entry;
}

int getgrgid_r(gid_t gid, struct group *entry, char *buffer,
               size_t buffer_length, struct group **result) {
  size_t name_length = strlen(group_name) + 1;
  size_t user_length = strlen(user_name) + 1;
  size_t pointer_bytes = 2 * sizeof(char *);
  uintptr_t raw = (uintptr_t)buffer;
  uintptr_t aligned = (raw + sizeof(char *) - 1) & ~(sizeof(char *) - 1);
  size_t padding = (size_t)(aligned - raw);
  size_t required = padding + pointer_bytes + name_length + 2 + user_length;
  if (buffer_length < required) {
    *result = NULL;
    return ERANGE;
  }

  char **members = (char **)(buffer + padding);
  char *cursor = buffer + padding + pointer_bytes;
  entry->gr_name = cursor;
  memcpy(cursor, group_name, name_length);
  cursor += name_length;
  entry->gr_passwd = cursor;
  memcpy(cursor, "x", 2);
  cursor += 2;
  members[0] = cursor;
  memcpy(cursor, user_name, user_length);
  members[1] = NULL;
  entry->gr_gid = gid;
  entry->gr_mem = members;
  *result = entry;
  return 0;
}
