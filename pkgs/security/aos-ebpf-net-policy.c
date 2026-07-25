#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <json-c/json_util.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_TCP_PORTS 65535

struct port_set {
  uint16_t ports[MAX_TCP_PORTS];
  size_t len;
};

struct policy {
  char *package;
  char *security_label;
  struct port_set bind;
  struct port_set connect;
};

struct link_set {
  struct bpf_link *bind4;
  struct bpf_link *bind6;
  struct bpf_link *connect4;
  struct bpf_link *connect6;
};

static volatile sig_atomic_t stop_requested;

static void usage(FILE *out)
{
  fprintf(out,
          "usage: aos-ebpf-net-policy validate --policy PATH --object PATH\n"
          "       aos-ebpf-net-policy run --policy PATH --cgroup PATH --object PATH\n");
}

static void request_stop(int signo)
{
  (void)signo;
  stop_requested = 1;
}

static int json_get_object(struct json_object *parent, const char *key,
                           struct json_object **out)
{
  struct json_object *value = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_object)) {
    fprintf(stderr, "aos-ebpf-net-policy: missing object '%s'\n", key);
    return -1;
  }

  *out = value;
  return 0;
}

static int json_get_array(struct json_object *parent, const char *key,
                          struct json_object **out)
{
  struct json_object *value = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_array)) {
    fprintf(stderr, "aos-ebpf-net-policy: missing array '%s'\n", key);
    return -1;
  }

  *out = value;
  return 0;
}

static int json_get_string_dup(struct json_object *parent, const char *key,
                               char **out)
{
  struct json_object *value = NULL;
  const char *text = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_string)) {
    fprintf(stderr, "aos-ebpf-net-policy: missing string '%s'\n", key);
    return -1;
  }

  text = json_object_get_string(value);
  *out = strdup(text);
  if (*out == NULL) {
    perror("aos-ebpf-net-policy: strdup");
    return -1;
  }

  return 0;
}

static int json_get_int(struct json_object *parent, const char *key, int *out)
{
  struct json_object *value = NULL;

  if (!json_object_object_get_ex(parent, key, &value) ||
      !json_object_is_type(value, json_type_int)) {
    fprintf(stderr, "aos-ebpf-net-policy: missing integer '%s'\n", key);
    return -1;
  }

  *out = json_object_get_int(value);
  return 0;
}

static int parse_ports(struct json_object *array, const char *field,
                       struct port_set *ports)
{
  bool *seen = NULL;
  size_t len = json_object_array_length(array);

  if (len > MAX_TCP_PORTS) {
    fprintf(stderr, "aos-ebpf-net-policy: too many ports in %s\n", field);
    return -1;
  }

  seen = calloc(MAX_TCP_PORTS + 1, sizeof(*seen));
  if (seen == NULL) {
    perror("aos-ebpf-net-policy: calloc");
    return -1;
  }

  ports->len = 0;
  for (size_t i = 0; i < len; i++) {
    struct json_object *item = json_object_array_get_idx(array, i);
    int port = 0;

    if (!json_object_is_type(item, json_type_int)) {
      fprintf(stderr, "aos-ebpf-net-policy: %s[%zu] is not an integer\n", field,
              i);
      free(seen);
      return -1;
    }

    port = json_object_get_int(item);
    if (port < 1 || port > 65535) {
      fprintf(stderr, "aos-ebpf-net-policy: %s[%zu] has invalid TCP port %d\n",
              field, i, port);
      free(seen);
      return -1;
    }
    if (seen[port]) {
      fprintf(stderr, "aos-ebpf-net-policy: %s contains duplicate TCP port %d\n",
              field, port);
      free(seen);
      return -1;
    }

    seen[port] = true;
    ports->ports[ports->len++] = (uint16_t)port;
  }

  free(seen);
  return 0;
}

static bool port_sets_equal(const struct port_set *left,
                            const struct port_set *right)
{
  if (left->len != right->len)
    return false;

  for (size_t i = 0; i < left->len; i++) {
    if (left->ports[i] != right->ports[i])
      return false;
  }

  return true;
}

static int parse_hook_names(struct json_object *hooks)
{
  const char *expected[] = {"socket_bind", "socket_connect"};

  if (json_object_array_length(hooks) != 2) {
    fprintf(stderr, "aos-ebpf-net-policy: ebpf.hooks must contain two entries\n");
    return -1;
  }

  for (size_t i = 0; i < 2; i++) {
    struct json_object *item = json_object_array_get_idx(hooks, i);
    const char *hook = NULL;

    if (!json_object_is_type(item, json_type_string)) {
      fprintf(stderr, "aos-ebpf-net-policy: ebpf.hooks[%zu] is not a string\n",
              i);
      return -1;
    }

    hook = json_object_get_string(item);
    if (strcmp(hook, expected[i]) != 0) {
      fprintf(stderr,
              "aos-ebpf-net-policy: ebpf.hooks[%zu] must be '%s', got '%s'\n",
              i, expected[i], hook);
      return -1;
    }
  }

  return 0;
}

static int read_policy(const char *path, struct policy *policy)
{
  struct json_object *root = NULL;
  struct json_object *tcp = NULL;
  struct json_object *ebpf = NULL;
  struct json_object *ebpf_tcp = NULL;
  struct json_object *bind = NULL;
  struct json_object *connect = NULL;
  struct json_object *hooks = NULL;
  struct port_set top_bind;
  struct port_set top_connect;
  int version = 0;
  int ret = -1;

  memset(&top_bind, 0, sizeof(top_bind));
  memset(&top_connect, 0, sizeof(top_connect));
  memset(policy, 0, sizeof(*policy));
  root = json_object_from_file(path);
  if (root == NULL) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to parse %s\n", path);
    return -1;
  }
  if (!json_object_is_type(root, json_type_object)) {
    fprintf(stderr, "aos-ebpf-net-policy: policy root is not an object\n");
    goto out;
  }

  if (json_get_int(root, "version", &version) != 0 || version != 1) {
    fprintf(stderr, "aos-ebpf-net-policy: unsupported policy version %d\n",
            version);
    goto out;
  }
  if (json_get_string_dup(root, "package", &policy->package) != 0 ||
      json_get_string_dup(root, "securityLabel", &policy->security_label) != 0 ||
      json_get_object(root, "tcp", &tcp) != 0 ||
      json_get_object(root, "ebpf", &ebpf) != 0 ||
      json_get_array(ebpf, "hooks", &hooks) != 0 ||
      parse_hook_names(hooks) != 0 ||
      json_get_object(ebpf, "tcp", &ebpf_tcp) != 0 ||
      json_get_array(ebpf_tcp, "bind", &bind) != 0 ||
      parse_ports(bind, "ebpf.tcp.bind", &policy->bind) != 0 ||
      json_get_array(ebpf_tcp, "connect", &connect) != 0 ||
      parse_ports(connect, "ebpf.tcp.connect", &policy->connect) != 0) {
    goto out;
  }

  if (json_get_array(tcp, "bind", &bind) != 0 ||
      json_get_array(tcp, "connect", &connect) != 0 ||
      parse_ports(bind, "tcp.bind", &top_bind) != 0 ||
      parse_ports(connect, "tcp.connect", &top_connect) != 0 ||
      !port_sets_equal(&top_bind, &policy->bind) ||
      !port_sets_equal(&top_connect, &policy->connect)) {
    fprintf(stderr,
            "aos-ebpf-net-policy: top-level TCP grants differ from ebpf grants\n");
    goto out;
  }

  ret = 0;

out:
  json_object_put(root);
  if (ret != 0) {
    free(policy->package);
    free(policy->security_label);
    memset(policy, 0, sizeof(*policy));
  }
  return ret;
}

static void free_policy(struct policy *policy)
{
  free(policy->package);
  free(policy->security_label);
  memset(policy, 0, sizeof(*policy));
}

static int validate_bpf_object(const char *object_path)
{
  struct bpf_object *obj = NULL;
  const char *programs[] = {"aos_bind4", "aos_bind6", "aos_connect4",
                            "aos_connect6"};
  const char *maps[] = {"bind_ports", "connect_ports"};
  int err = 0;

  obj = bpf_object__open_file(object_path, NULL);
  err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to open BPF object %s: %s\n",
            object_path, strerror(-err));
    return -1;
  }

  for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
    if (bpf_object__find_program_by_name(obj, programs[i]) == NULL) {
      fprintf(stderr, "aos-ebpf-net-policy: BPF object is missing program %s\n",
              programs[i]);
      bpf_object__close(obj);
      return -1;
    }
  }
  for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
    if (bpf_object__find_map_by_name(obj, maps[i]) == NULL) {
      fprintf(stderr, "aos-ebpf-net-policy: BPF object is missing map %s\n",
              maps[i]);
      bpf_object__close(obj);
      return -1;
    }
  }

  bpf_object__close(obj);
  return 0;
}

static int raise_memlock_limit(void)
{
  struct rlimit limit = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
    perror("aos-ebpf-net-policy: setrlimit(RLIMIT_MEMLOCK)");
    return -1;
  }

  return 0;
}

static int populate_port_map(int map_fd, const struct port_set *ports)
{
  __u8 value = 1;

  for (size_t i = 0; i < ports->len; i++) {
    __u32 key = htons(ports->ports[i]);

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      fprintf(stderr, "aos-ebpf-net-policy: failed to add TCP port %u: %s\n",
              ports->ports[i], strerror(errno));
      return -1;
    }
  }

  return 0;
}

static struct bpf_link *attach_cgroup_program(struct bpf_object *obj,
                                              const char *program_name,
                                              int cgroup_fd)
{
  struct bpf_program *program = NULL;
  struct bpf_link *link = NULL;
  int err = 0;

  program = bpf_object__find_program_by_name(obj, program_name);
  if (program == NULL) {
    fprintf(stderr, "aos-ebpf-net-policy: BPF object is missing program %s\n",
            program_name);
    return NULL;
  }

  link = bpf_program__attach_cgroup(program, cgroup_fd);
  err = libbpf_get_error(link);
  if (err) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to attach %s: %s\n",
            program_name, strerror(-err));
    return NULL;
  }

  return link;
}

static void destroy_links(struct link_set *links)
{
  if (links->connect6 != NULL)
    bpf_link__destroy(links->connect6);
  if (links->connect4 != NULL)
    bpf_link__destroy(links->connect4);
  if (links->bind6 != NULL)
    bpf_link__destroy(links->bind6);
  if (links->bind4 != NULL)
    bpf_link__destroy(links->bind4);
  memset(links, 0, sizeof(*links));
}

static int notify_ready(void)
{
  const char *socket_path = getenv("NOTIFY_SOCKET");
  struct sockaddr_un addr;
  size_t path_len = 0;
  socklen_t addr_len = 0;
  int fd = -1;
  int ret = 0;
  const char ready[] = "READY=1";

  if (socket_path == NULL || socket_path[0] == '\0') {
    return 0;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (socket_path[0] == '@') {
    path_len = strlen(socket_path + 1);
    if (path_len + 1 >= sizeof(addr.sun_path)) {
      fprintf(stderr, "aos-ebpf-net-policy: NOTIFY_SOCKET is too long\n");
      return -1;
    }
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, socket_path + 1, path_len);
    addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + path_len);
  } else {
    path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
      fprintf(stderr, "aos-ebpf-net-policy: NOTIFY_SOCKET is too long\n");
      return -1;
    }
    memcpy(addr.sun_path, socket_path, path_len + 1);
    addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len + 1);
  }

  fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("aos-ebpf-net-policy: socket(AF_UNIX)");
    return -1;
  }

  if (sendto(fd, ready, sizeof(ready) - 1, MSG_NOSIGNAL,
             (const struct sockaddr *)&addr, addr_len) < 0) {
    perror("aos-ebpf-net-policy: sendto(NOTIFY_SOCKET)");
    ret = -1;
  }

  close(fd);
  return ret;
}

static int run_policy(const char *policy_path, const char *cgroup_path,
                      const char *object_path)
{
  struct policy policy;
  struct bpf_object *obj = NULL;
  struct link_set links;
  int cgroup_fd = -1;
  int bind_map_fd = -1;
  int connect_map_fd = -1;
  int err = 0;
  int ret = -1;

  memset(&links, 0, sizeof(links));
  if (read_policy(policy_path, &policy) != 0 ||
      validate_bpf_object(object_path) != 0 ||
      raise_memlock_limit() != 0) {
    return -1;
  }

  cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cgroup_fd < 0) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to open cgroup %s: %s\n",
            cgroup_path, strerror(errno));
    goto out_policy;
  }

  obj = bpf_object__open_file(object_path, NULL);
  err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to open BPF object %s: %s\n",
            object_path, strerror(-err));
    goto out_policy;
  }

  err = bpf_object__load(obj);
  if (err != 0) {
    fprintf(stderr, "aos-ebpf-net-policy: failed to load BPF object %s: %s\n",
            object_path, strerror(-err));
    goto out_policy;
  }

  bind_map_fd = bpf_object__find_map_fd_by_name(obj, "bind_ports");
  connect_map_fd = bpf_object__find_map_fd_by_name(obj, "connect_ports");
  if (bind_map_fd < 0 || connect_map_fd < 0) {
    fprintf(stderr, "aos-ebpf-net-policy: BPF object is missing port maps\n");
    goto out_policy;
  }
  if (populate_port_map(bind_map_fd, &policy.bind) != 0 ||
      populate_port_map(connect_map_fd, &policy.connect) != 0) {
    goto out_policy;
  }

  links.bind4 = attach_cgroup_program(obj, "aos_bind4", cgroup_fd);
  links.bind6 = attach_cgroup_program(obj, "aos_bind6", cgroup_fd);
  links.connect4 = attach_cgroup_program(obj, "aos_connect4", cgroup_fd);
  links.connect6 = attach_cgroup_program(obj, "aos_connect6", cgroup_fd);
  if (links.bind4 == NULL || links.bind6 == NULL || links.connect4 == NULL ||
      links.connect6 == NULL) {
    goto out_policy;
  }

  printf("aos-ebpf-net-policy: attached policy for %s (%s)\n", policy.package,
         policy.security_label);
  fflush(stdout);
  if (notify_ready() != 0) {
    goto out_policy;
  }

  ret = 0;
  while (!stop_requested) {
    pause();
  }

out_policy:
  destroy_links(&links);
  if (obj != NULL) {
    bpf_object__close(obj);
  }
  if (cgroup_fd >= 0) {
    close(cgroup_fd);
  }
  free_policy(&policy);
  return ret;
}

static int validate_policy(const char *policy_path, const char *object_path)
{
  struct policy policy;
  int ret = -1;

  if (read_policy(policy_path, &policy) != 0) {
    return -1;
  }
  ret = validate_bpf_object(object_path);
  free_policy(&policy);
  return ret;
}

int main(int argc, char **argv)
{
  const char *mode = NULL;
  const char *policy_path = NULL;
  const char *cgroup_path = NULL;
  const char *object_path = NULL;
  struct sigaction action;

  if (argc < 2) {
    usage(stderr);
    return 2;
  }

  mode = argv[1];
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
      policy_path = argv[++i];
    } else if (strcmp(argv[i], "--cgroup") == 0 && i + 1 < argc) {
      cgroup_path = argv[++i];
    } else if (strcmp(argv[i], "--object") == 0 && i + 1 < argc) {
      object_path = argv[++i];
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(stdout);
      return 0;
    } else {
      fprintf(stderr, "aos-ebpf-net-policy: unknown argument '%s'\n", argv[i]);
      usage(stderr);
      return 2;
    }
  }

  if (policy_path == NULL || object_path == NULL) {
    usage(stderr);
    return 2;
  }

  if (strcmp(mode, "validate") == 0) {
    return validate_policy(policy_path, object_path) == 0 ? 0 : 1;
  }

  if (strcmp(mode, "run") != 0) {
    fprintf(stderr, "aos-ebpf-net-policy: unknown mode '%s'\n", mode);
    usage(stderr);
    return 2;
  }
  if (cgroup_path == NULL) {
    usage(stderr);
    return 2;
  }

  memset(&action, 0, sizeof(action));
  action.sa_handler = request_stop;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0) {
    perror("aos-ebpf-net-policy: sigaction");
    return 1;
  }

  return run_policy(policy_path, cgroup_path, object_path) == 0 ? 0 : 1;
}
