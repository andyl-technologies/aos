# The host directory has one stable sandbox name so derivations never embed a
# developer-specific home path. Trusted-user mode mounts it per build command.
aos_dev_cache_dir=${AOS_DEV_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/aos-dev}

aos_dev_cache_check_nix() {
  # sandbox-paths is restricted by the daemon. A client setting from an
  # untrusted user is silently ignored, so check the configured local policy
  # before asking the daemon to build. The daemon remains the final authority.
  local configuration trusted paths username group
  configuration=$(nix config show 2>/dev/null) || \
    configuration=$(nix show-config 2>/dev/null) || \
    aos_dev_error 'cannot read Nix daemon configuration'
  trusted=$(printf '%s\n' "$configuration" | sed -n 's/^trusted-users = //p')
  paths=$(printf '%s\n' "$configuration" | sed -n 's/^sandbox-paths = //p')
  username=$(id -un)
  aos_dev_cache_nix_options=()

  # Trusted users can request the mount per invocation. This keeps release
  # and qualification sandboxes free of the cache path.
  if [[ $(id -u) == 0 || " $trusted " == *" $username "* || " $trusted " == *" * "* ]]; then
    aos_dev_cache_nix_options=(--option extra-sandbox-paths "/aos-build-cache=$aos_dev_cache_dir")
    return
  fi

  for group in $(id -Gn); do
    if [[ " $trusted " == *" @$group "* ]]; then
      aos_dev_cache_nix_options=(--option extra-sandbox-paths "/aos-build-cache=$aos_dev_cache_dir")
      return
    fi
  done

  # A static daemon mount is a fallback for developers who cannot be trusted
  # users. It is visible in every sandbox on that daemon.
  if [[ " $paths " == *" /aos-build-cache=$aos_dev_cache_dir "* ]]; then
    return
  fi

  aos_dev_error "Nix daemon rejected client sandbox paths for '$username'; ask an administrator to trust this user or add '/aos-build-cache=$aos_dev_cache_dir' to daemon sandbox-paths"
}

aos_dev_cache_prepare() {
  # Validate before mkdir/chmod so an accidental broad path or symlink cannot
  # turn cache initialization into a host filesystem permission change.
  [[ $aos_dev_cache_dir == /* ]] || aos_dev_error 'AOS_DEV_CACHE_DIR must be an absolute path'
  [[ $aos_dev_cache_dir != *' '* ]] || aos_dev_error 'cache path cannot contain spaces'

  local path
  for path in "$aos_dev_cache_dir" "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" \
      "$aos_dev_cache_dir/sccache" "$aos_dev_cache_dir/sccache/store"; do
    [[ ! -L $path ]] || aos_dev_error "cache setup refuses symlink: $path"
  done

  mkdir -p "$aos_dev_cache_dir"/{go,bazel,sccache/store}
  # Nix builds run under different nixbld UIDs. Only Go/Bazel artifact trees
  # are shared for writes; the host sccache server owns its private store.
  chmod 0755 "$aos_dev_cache_dir" "$aos_dev_cache_dir/sccache"
  chmod 0777 "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel"
  chmod 0700 "$aos_dev_cache_dir/sccache/store"

  # The shared compiler cache is a host-side server. nixbld users only need
  # its socket; they never write to its private storage directory directly.
  local sccache
  sccache=$(aos_dev_cache_sccache)
  if [[ ! -S $aos_dev_cache_dir/sccache/server.sock ]] || \
      ! SCCACHE_SERVER_UDS="$aos_dev_cache_dir/sccache/server.sock" \
        SCCACHE_DIR="$aos_dev_cache_dir/sccache/store" \
        SCCACHE_CACHE_SIZE="${AOS_DEV_SCCACHE_SIZE:-50G}" \
        "$sccache" --show-stats >/dev/null 2>&1; then
    rm -f -- "$aos_dev_cache_dir/sccache/server.sock"
    aos_dev_cache_start_sccache
  fi
  chmod 666 "$aos_dev_cache_dir/sccache/server.sock"
}

aos_dev_cache_sccache() {
  # Always build the server from the cache-free package set. The Rust and LLVM
  # builders may themselves use sccache after this initial bootstrap.
  local tool
  tool=$(nix-build "$aos_dev_root/default.nix" -A pkgs.sccache --no-out-link)
  printf '%s/bin/sccache' "$tool"
}

aos_dev_cache_start_sccache() {
  aos_dev_require_command nix-build
  local sccache
  sccache=$(aos_dev_cache_sccache)

  SCCACHE_SERVER_UDS="$aos_dev_cache_dir/sccache/server.sock" \
    SCCACHE_DIR="$aos_dev_cache_dir/sccache/store" \
    SCCACHE_CACHE_SIZE="${AOS_DEV_SCCACHE_SIZE:-50G}" \
    SCCACHE_IDLE_TIMEOUT=0 \
    "$sccache" --start-server >&2

  # New sandboxes use different nixbld UIDs, so the Unix socket must accept
  # connections from each of them.
  [[ -S $aos_dev_cache_dir/sccache/server.sock ]] || aos_dev_error 'sccache server did not create its socket'
  chmod 666 "$aos_dev_cache_dir/sccache/server.sock"
}

aos_dev_cache_command() {
  # Init and doctor check daemon mount policy; local maintenance can still run
  # when a developer has stopped sccache or the Nix daemon is unavailable.
  local action=${1:-doctor}
  case $action in
    init)
      aos_dev_cache_check_nix
      aos_dev_cache_prepare
      printf 'Shared caches ready in %s\n' "$aos_dev_cache_dir"
      ;;
    doctor)
      aos_dev_cache_check_nix
      printf 'Cache directory: %s\n' "$aos_dev_cache_dir"
      [[ -d $aos_dev_cache_dir ]] || aos_dev_error 'run cache init first'
      [[ -w $aos_dev_cache_dir ]] || aos_dev_error 'cache directory is not writable'
      [[ -S $aos_dev_cache_dir/sccache/server.sock ]] || aos_dev_error 'sccache socket is absent; run cache init'
      printf 'Cache directories and sccache socket are present.\n'
      ;;
    status)
      aos_dev_cache_usage
      if [[ ! -S $aos_dev_cache_dir/sccache/server.sock ]]; then
        printf 'sccache server: stopped\n'
        return
      fi
      local sccache
      sccache=$(aos_dev_cache_sccache)
      SCCACHE_SERVER_UDS="$aos_dev_cache_dir/sccache/server.sock" "$sccache" --show-stats
      ;;
    stop)
      [[ -S $aos_dev_cache_dir/sccache/server.sock ]] || return 0
      local sccache
      sccache=$(aos_dev_cache_sccache)
      SCCACHE_SERVER_UDS="$aos_dev_cache_dir/sccache/server.sock" "$sccache" --stop-server
      ;;
    usage) aos_dev_cache_usage ;;
    prune) shift; aos_dev_cache_prune "$@" ;;
    clear) shift; aos_dev_cache_clear "$@" ;;
    *) aos_dev_error "unknown cache command '$action'" ;;
  esac
}
