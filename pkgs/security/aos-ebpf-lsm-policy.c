#define _GNU_SOURCE

#include <errno.h>
#include <json-c/json.h>
#include <json-c/json_util.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#define MAX_PROGRAMS 32
#define BPF_FS_ROOT "/sys/fs/bpf"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

struct program_list {
  char *items[MAX_PROGRAMS];
  size_t len;
};

struct policy {
  char *name;
  struct program_list programs;
};

static void usage(FILE *out)
{
  fprintf(out,
          "usage: aos-ebpf-lsm-policy validate --policy PATH --object PATH\n"
          "       aos-ebpf-lsm-policy load --policy PATH --object PATH --pin-dir PATH\n");
}

static bool is_safe_name(const char *text)
{
  if (text == NULL || text[0] == '\0')
    return false;

  for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
    if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
        (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')
      continue;
    return false;
  }
  return true;
}

static bool path_is_under_bpffs(const char *path)
{
  size_t root_len = strlen(BPF_FS_ROOT);

  return path != NULL &&
         (strcmp(path, BPF_FS_ROOT) == 0 ||
          (strncmp(path, BPF_FS_ROOT, root_len) == 0 && path[root_len] == '/'));
}

static bool path_has_parent_component(const char *path)
{
  const char *p = path;

  while (*p != '\0') {
    while (*p == '/')
      p++;
    const char *start = p;
    while (*p != '\0' && *p != '/')
      p++;
    if (p - start == 2 && start[0] == '.' && start[1] == '.')
      return true;
  }

  return false;
}

static int ensure_directory(const char *path)
{
  struct stat st;

  if (mkdir(path, 0755) == 0)
    return 0;
  if (errno != EEXIST) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to create directory %s: %s\n",
            path, strerror(errno));
    return -1;
  }
  if (stat(path, &st) != 0) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to stat directory %s: %s\n",
            path, strerror(errno));
    return -1;
  }
  if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: %s exists but is not a directory\n",
            path);
    return -1;
  }

  return 0;
}

static int mkdir_p(const char *path)
{
  char tmp[PATH_MAX];
  size_t len = 0;

  if (path == NULL || path[0] != '/') {
    fprintf(stderr, "aos-ebpf-lsm-policy: pin directory must be absolute\n");
    return -1;
  }

  len = strlen(path);
  if (len == 0 || len >= sizeof(tmp)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: pin directory path is too long\n");
    return -1;
  }

  memcpy(tmp, path, len + 1);
  if (len > 1 && tmp[len - 1] == '/')
    tmp[len - 1] = '\0';

  for (char *p = tmp + 1; *p != '\0'; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (ensure_directory(tmp) != 0)
      return -1;
    *p = '/';
  }

  return ensure_directory(tmp);
}

static int ensure_bpffs_pin_dir(const char *pin_dir)
{
  struct statfs fs;

  if (!path_is_under_bpffs(pin_dir) || path_has_parent_component(pin_dir)) {
    fprintf(stderr,
            "aos-ebpf-lsm-policy: pin directory must be under " BPF_FS_ROOT "\n");
    return -1;
  }

  if (ensure_directory(BPF_FS_ROOT) != 0)
    return -1;

  if (statfs(BPF_FS_ROOT, &fs) != 0) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to statfs " BPF_FS_ROOT ": %s\n",
            strerror(errno));
    return -1;
  }

  if ((unsigned long)fs.f_type != (unsigned long)BPF_FS_MAGIC) {
    if (mount("bpf", BPF_FS_ROOT, "bpf", 0, NULL) != 0 && errno != EBUSY) {
      fprintf(stderr, "aos-ebpf-lsm-policy: failed to mount bpffs: %s\n",
              strerror(errno));
      return -1;
    }
    if (statfs(BPF_FS_ROOT, &fs) != 0) {
      fprintf(stderr,
              "aos-ebpf-lsm-policy: failed to statfs " BPF_FS_ROOT " after mount: %s\n",
              strerror(errno));
      return -1;
    }
    if ((unsigned long)fs.f_type != (unsigned long)BPF_FS_MAGIC) {
      fprintf(stderr, "aos-ebpf-lsm-policy: " BPF_FS_ROOT " is not bpffs\n");
      return -1;
    }
  }

  return mkdir_p(pin_dir);
}

static int json_get_int(struct json_object *parent, const char *key, int *out)
{
  struct json_object *value = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_int)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: missing integer '%s'\n", key);
    return -1;
  }

  *out = json_object_get_int(value);
  return 0;
}

static int json_get_string_dup(struct json_object *parent, const char *key,
                               char **out)
{
  struct json_object *value = NULL;
  const char *text = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_string)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: missing string '%s'\n", key);
    return -1;
  }

  text = json_object_get_string(value);
  if (!is_safe_name(text)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: unsafe string '%s'\n", key);
    return -1;
  }

  *out = strdup(text);
  if (*out == NULL) {
    perror("aos-ebpf-lsm-policy: strdup");
    return -1;
  }

  return 0;
}

static int json_get_array(struct json_object *parent, const char *key,
                          struct json_object **out)
{
  struct json_object *value = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_array)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: missing array '%s'\n", key);
    return -1;
  }

  *out = value;
  return 0;
}

static void free_policy(struct policy *policy)
{
  free(policy->name);
  for (size_t i = 0; i < policy->programs.len; i++)
    free(policy->programs.items[i]);
  memset(policy, 0, sizeof(*policy));
}

static int read_policy(const char *path, struct policy *policy)
{
  struct json_object *root = NULL;
  struct json_object *programs = NULL;
  int version = 0;
  int ret = -1;

  memset(policy, 0, sizeof(*policy));
  root = json_object_from_file(path);
  if (root == NULL) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to parse %s\n", path);
    return -1;
  }
  if (!json_object_is_type(root, json_type_object)) {
    fprintf(stderr, "aos-ebpf-lsm-policy: policy root is not an object\n");
    goto out;
  }

  if (json_get_int(root, "version", &version) != 0 || version != 1) {
    fprintf(stderr, "aos-ebpf-lsm-policy: unsupported policy version %d\n",
            version);
    goto out;
  }
  if (json_get_string_dup(root, "name", &policy->name) != 0 ||
      json_get_array(root, "programs", &programs) != 0) {
    goto out;
  }

  policy->programs.len = json_object_array_length(programs);
  if (policy->programs.len == 0 || policy->programs.len > MAX_PROGRAMS) {
    fprintf(stderr, "aos-ebpf-lsm-policy: programs must contain 1..%d entries\n",
            MAX_PROGRAMS);
    goto out;
  }

  for (size_t i = 0; i < policy->programs.len; i++) {
    struct json_object *item = json_object_array_get_idx(programs, i);
    const char *program = NULL;

    if (!json_object_is_type(item, json_type_string)) {
      fprintf(stderr, "aos-ebpf-lsm-policy: programs[%zu] is not a string\n",
              i);
      goto out;
    }
    program = json_object_get_string(item);
    if (!is_safe_name(program)) {
      fprintf(stderr, "aos-ebpf-lsm-policy: unsafe program name '%s'\n",
              program);
      goto out;
    }
    policy->programs.items[i] = strdup(program);
    if (policy->programs.items[i] == NULL) {
      perror("aos-ebpf-lsm-policy: strdup");
      goto out;
    }
  }

  ret = 0;

out:
  json_object_put(root);
  if (ret != 0)
    free_policy(policy);
  return ret;
}

static int raise_memlock_limit(void)
{
  struct rlimit limit = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
    perror("aos-ebpf-lsm-policy: setrlimit(RLIMIT_MEMLOCK)");
    return -1;
  }

  return 0;
}

static int validate_bpf_object(const char *object_path, const struct policy *policy)
{
  struct bpf_object *obj = NULL;
  int err = 0;

  obj = bpf_object__open_file(object_path, NULL);
  err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to open BPF object %s: %s\n",
            object_path, strerror(-err));
    return -1;
  }

  for (size_t i = 0; i < policy->programs.len; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(obj, policy->programs.items[i]);
    if (program == NULL) {
      fprintf(stderr, "aos-ebpf-lsm-policy: BPF object is missing program %s\n",
              policy->programs.items[i]);
      bpf_object__close(obj);
      return -1;
    }
    if (bpf_program__type(program) != BPF_PROG_TYPE_LSM) {
      fprintf(stderr, "aos-ebpf-lsm-policy: program %s is not a BPF-LSM program\n",
              policy->programs.items[i]);
      bpf_object__close(obj);
      return -1;
    }
  }

  bpf_object__close(obj);
  return 0;
}

enum pin_set_state {
  PIN_SET_ABSENT,
  PIN_SET_PRESENT,
  PIN_SET_PARTIAL,
};

static int build_pin_path(char *path, size_t path_len, const char *pin_dir,
                          const struct policy *policy, const char *program)
{
  if (snprintf(path, path_len, "%s/%s-%s", pin_dir, policy->name, program) >=
      (int)path_len) {
    fprintf(stderr, "aos-ebpf-lsm-policy: pin path is too long\n");
    return -1;
  }

  return 0;
}

static int policy_pin_state(const char *pin_dir, const struct policy *policy,
                            enum pin_set_state *state)
{
  size_t present = 0;

  for (size_t i = 0; i < policy->programs.len; i++) {
    char path[PATH_MAX];

    if (build_pin_path(path, sizeof(path), pin_dir, policy,
                       policy->programs.items[i]) != 0)
      return -1;
    if (access(path, F_OK) == 0) {
      present++;
      continue;
    }
    if (errno != ENOENT) {
      fprintf(stderr, "aos-ebpf-lsm-policy: failed to inspect pin %s: %s\n",
              path, strerror(errno));
      return -1;
    }
  }

  if (present == 0) {
    *state = PIN_SET_ABSENT;
  } else if (present == policy->programs.len) {
    *state = PIN_SET_PRESENT;
  } else {
    *state = PIN_SET_PARTIAL;
  }

  return 0;
}

static int pin_link(struct bpf_link *link, const char *path)
{
  int err = bpf_link__pin(link, path);

  if (err != 0) {
    if (err < 0)
      err = -err;
    else
      err = errno;
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to pin %s: %s\n", path,
            strerror(err));
    return -1;
  }

  return 0;
}

static void cleanup_created_pins(const char *pin_dir, const struct policy *policy,
                                 const bool *pins_created)
{
  for (size_t i = 0; i < policy->programs.len; i++) {
    char path[PATH_MAX];

    if (!pins_created[i])
      continue;
    if (build_pin_path(path, sizeof(path), pin_dir, policy,
                       policy->programs.items[i]) != 0)
      continue;
    if (unlink(path) != 0 && errno != ENOENT) {
      fprintf(stderr, "aos-ebpf-lsm-policy: failed to clean up pin %s: %s\n",
              path, strerror(errno));
    }
  }
}

static int load_policy(const char *policy_path, const char *object_path,
                       const char *pin_dir)
{
  struct policy policy;
  struct bpf_object *obj = NULL;
  struct bpf_link *links[MAX_PROGRAMS];
  bool pins_created[MAX_PROGRAMS];
  enum pin_set_state pin_state = PIN_SET_ABSENT;
  int err = 0;
  int ret = -1;

  memset(links, 0, sizeof(links));
  memset(pins_created, 0, sizeof(pins_created));
  if (read_policy(policy_path, &policy) != 0)
    return -1;

  if (validate_bpf_object(object_path, &policy) != 0 ||
      raise_memlock_limit() != 0 || ensure_bpffs_pin_dir(pin_dir) != 0 ||
      policy_pin_state(pin_dir, &policy, &pin_state) != 0) {
    goto out;
  }
  if (pin_state == PIN_SET_PRESENT) {
    printf("aos-ebpf-lsm-policy: loaded policy %s (already pinned)\n",
           policy.name);
    ret = 0;
    goto out;
  }
  if (pin_state == PIN_SET_PARTIAL) {
    fprintf(stderr,
            "aos-ebpf-lsm-policy: policy %s has a partial pinned link set\n",
            policy.name);
    goto out;
  }

  obj = bpf_object__open_file(object_path, NULL);
  err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to open BPF object %s: %s\n",
            object_path, strerror(-err));
    goto out;
  }

  err = bpf_object__load(obj);
  if (err != 0) {
    fprintf(stderr, "aos-ebpf-lsm-policy: failed to load BPF object %s: %s\n",
            object_path, strerror(-err));
    goto out;
  }

  for (size_t i = 0; i < policy.programs.len; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(obj, policy.programs.items[i]);
    links[i] = bpf_program__attach_lsm(program);
    err = libbpf_get_error(links[i]);
    if (err) {
      fprintf(stderr, "aos-ebpf-lsm-policy: failed to attach %s: %s\n",
              policy.programs.items[i], strerror(-err));
      links[i] = NULL;
      goto out;
    }
  }

  for (size_t i = 0; i < policy.programs.len; i++) {
    char path[PATH_MAX];

    if (build_pin_path(path, sizeof(path), pin_dir, &policy,
                       policy.programs.items[i]) != 0)
      goto out;
    if (pin_link(links[i], path) != 0)
      goto out;
    pins_created[i] = true;
  }

  printf("aos-ebpf-lsm-policy: loaded policy %s\n", policy.name);
  ret = 0;

out:
  if (ret != 0)
    cleanup_created_pins(pin_dir, &policy, pins_created);
  for (size_t i = 0; i < MAX_PROGRAMS; i++) {
    if (links[i] != NULL)
      bpf_link__destroy(links[i]);
  }
  if (obj != NULL)
    bpf_object__close(obj);
  free_policy(&policy);
  return ret;
}

static int validate_policy(const char *policy_path, const char *object_path)
{
  struct policy policy;
  int ret = -1;

  if (read_policy(policy_path, &policy) != 0)
    return -1;

  ret = validate_bpf_object(object_path, &policy);
  free_policy(&policy);
  return ret;
}

int main(int argc, char **argv)
{
  const char *mode = NULL;
  const char *policy_path = NULL;
  const char *object_path = NULL;
  const char *pin_dir = NULL;

  if (argc < 2) {
    usage(stderr);
    return 2;
  }

  mode = argv[1];
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
      policy_path = argv[++i];
    } else if (strcmp(argv[i], "--object") == 0 && i + 1 < argc) {
      object_path = argv[++i];
    } else if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
      pin_dir = argv[++i];
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(stdout);
      return 0;
    } else {
      fprintf(stderr, "aos-ebpf-lsm-policy: unknown argument '%s'\n", argv[i]);
      usage(stderr);
      return 2;
    }
  }

  if (policy_path == NULL || object_path == NULL) {
    usage(stderr);
    return 2;
  }

  if (strcmp(mode, "validate") == 0)
    return validate_policy(policy_path, object_path) == 0 ? 0 : 1;

  if (strcmp(mode, "load") != 0) {
    fprintf(stderr, "aos-ebpf-lsm-policy: unknown mode '%s'\n", mode);
    usage(stderr);
    return 2;
  }
  if (pin_dir == NULL) {
    usage(stderr);
    return 2;
  }

  return load_policy(policy_path, object_path, pin_dir) == 0 ? 0 : 1;
}
