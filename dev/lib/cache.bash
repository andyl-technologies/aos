# The host directory has one stable sandbox name so derivations never embed a
# developer-specific path. /var/tmp remains accessible to nixbld users even
# when a developer's home directory is private, and survives normal reboots.
aos_dev_cache_dir=${AOS_DEV_CACHE_DIR:-/var/tmp/aos-dev-cache-$(id -u)}

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
    # /var/tmp is shared. Refuse a path pre-created by another user instead
    # of changing its mode or placing a server socket inside it.
    [[ ! -e $path || -O $path ]] || aos_dev_error "cache setup refuses path owned by another user: $path"
  done

  aos_dev_require_command setfacl
  aos_dev_require_command getfacl
  mkdir -p "$aos_dev_cache_dir"/{go,bazel,sccache/store}
  # Nix builds run under different nixbld UIDs. Only Go/Bazel artifact trees
  # are shared for writes; the host sccache server owns its private store.
  # Default ACLs make new cache entries writable across UIDs without changing
  # the build's umask. A permissive build umask also changes test fixtures and
  # can invalidate tests that check private credential directories.
  chmod 0755 "$aos_dev_cache_dir" "$aos_dev_cache_dir/sccache"
  chmod 0777 "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel"
  chmod 0700 "$aos_dev_cache_dir/sccache/store"
  for path in "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel"; do
    if ! aos_dev_cache_has_default_acl "$path" && \
        [[ -n $(find "$path" -mindepth 1 -print -quit) ]]; then
      aos_dev_error "existing cache entries under '$path' lack inherited permissions; run cache clear ${path##*/}, then cache init"
    fi
    setfacl -m d:u::rwx,d:g::rwx,d:o::rwx "$path" || \
      aos_dev_error "cannot set default ACL on '$path'; shared builds need filesystem ACL support"
  done

  # Remember a chosen AOS-built tool across invocations. The compiler wrapper
  # and host server must use the same executable, so load this before the
  # shared Nix arguments are assembled by aos_dev_nix_build.
  aos_dev_cache_select_sccache_tool

  # The shared compiler cache is a host-side server. nixbld users only need
  # its socket; they never write to its private storage directory directly.
  local sccache
  sccache=$(aos_dev_cache_sccache)
  # --show-stats succeeds with zeroes even when the socket is stale. The
  # status RPC connects to a live server, or starts one if none is reachable.
  if [[ ! -S $aos_dev_cache_dir/sccache/server.sock ]] || \
      ! aos_dev_cache_sccache_call "$sccache" --dist-status >/dev/null 2>&1; then
    rm -f -- "$aos_dev_cache_dir/sccache/server.sock"
    aos_dev_cache_start_sccache "$sccache"
  fi
  chmod 666 "$aos_dev_cache_dir/sccache/server.sock"
}

aos_dev_cache_has_default_acl() {
  local acl
  acl=$(getfacl -cp -- "$1" 2>/dev/null) || return 1
  [[ $acl == *'default:user::rwx'* && \
     $acl == *'default:group::rwx'* && \
     $acl == *'default:other::rwx'* ]]
}

aos_dev_cache_verify_mount() {
  aos_dev_require_command nix-build

  # This checks the mount from a real nixbld user, but its AOS-built shell and
  # coreutils can require a full source bootstrap on a new machine. Keep it
  # explicit instead of making cache init and doctor trigger that build.
  local status
  nix-build "$aos_dev_root/dev/cache-mount-smoke.nix" \
    --no-out-link "${aos_dev_cache_nix_options[@]}" >/dev/null || {
    status=$?
    aos_dev_cache_probe_error "$status"
    return "$status"
  }

  # A realized output alone can hide a mount that has since become inaccessible.
  nix-build "$aos_dev_root/dev/cache-mount-smoke.nix" \
    --check --no-out-link "${aos_dev_cache_nix_options[@]}" >/dev/null || {
    status=$?
    aos_dev_cache_probe_error "$status"
    return "$status"
  }
}

aos_dev_cache_probe_error() {
  local status=$1
  if (( status == 130 || status == 143 )); then
    printf 'aos-dev: sandbox probe interrupted (nix-build exit status %s)\n' "$status" >&2
  else
    printf 'aos-dev: sandbox probe failed (nix-build exit status %s); inspect the Nix error above\n' "$status" >&2
  fi
}

aos_dev_cache_validate_sccache_tool() {
  [[ $AOS_DEV_SCCACHE_TOOL =~ ^/nix/store/[0-9a-z]{32}-[^/]+$ ]] || \
    aos_dev_error 'AOS_DEV_SCCACHE_TOOL must name an AOS-built Nix store output'
  [[ -x $AOS_DEV_SCCACHE_TOOL/bin/sccache ]] || \
    aos_dev_error "sccache is absent from '$AOS_DEV_SCCACHE_TOOL'"
}

aos_dev_cache_select_sccache_tool() {
  local selection=$aos_dev_cache_dir/sccache/tool-path
  [[ ! -L $selection ]] || aos_dev_error "cache setup refuses symlink: $selection"
  [[ ! -e $selection || -O $selection ]] || \
    aos_dev_error "cache setup refuses path owned by another user: $selection"

  if [[ -z ${AOS_DEV_SCCACHE_TOOL:-} && -f $selection ]]; then
    IFS= read -r AOS_DEV_SCCACHE_TOOL < "$selection" || \
      aos_dev_error "cannot read sccache tool selection from '$selection'"
  fi

  if [[ -n ${AOS_DEV_SCCACHE_TOOL:-} ]]; then
    aos_dev_cache_validate_sccache_tool
    # The selection file is not a GC root. Retain the already-built tool so
    # ordinary store collection cannot silently make the cache unusable.
    nix-store --realise "$AOS_DEV_SCCACHE_TOOL" \
      --add-root "$aos_dev_cache_dir/sccache/tool-root" >/dev/null || \
      aos_dev_error 'cannot root the selected sccache output'
    printf '%s\n' "$AOS_DEV_SCCACHE_TOOL" > "$selection"
    chmod 0600 "$selection"
  fi
}

aos_dev_cache_sccache() {
  # Reuse the pinned executable even when current package derivations change.
  if [[ -n ${AOS_DEV_SCCACHE_TOOL:-} || -f $aos_dev_cache_dir/sccache/tool-path ]]; then
    aos_dev_cache_sccache_existing
    return
  fi

  # The default tool is always built from the cache-free package set.
  local tool
  tool=$(nix-build "$aos_dev_root/default.nix" -A pkgs.sccache --no-out-link)
  AOS_DEV_SCCACHE_TOOL=$tool
  aos_dev_cache_select_sccache_tool
  aos_dev_cache_sccache_existing
}

aos_dev_cache_sccache_existing() {
  # Inspection commands must never bootstrap a changed sccache derivation.
  if [[ -z ${AOS_DEV_SCCACHE_TOOL:-} && -f $aos_dev_cache_dir/sccache/tool-path ]]; then
    IFS= read -r AOS_DEV_SCCACHE_TOOL < "$aos_dev_cache_dir/sccache/tool-path" || \
      aos_dev_error 'cannot read sccache tool selection'
  fi
  [[ -n ${AOS_DEV_SCCACHE_TOOL:-} ]] || \
    aos_dev_error 'no pinned sccache tool; run cache init'
  aos_dev_cache_validate_sccache_tool
  printf '%s/bin/sccache' "$AOS_DEV_SCCACHE_TOOL"
}

aos_dev_cache_sccache_call() {
  # Keep the server's storage configuration identical for every subcommand.
  # In particular, --show-stats otherwise reports the host's default cache.
  local sccache=$1
  shift
  SCCACHE_SERVER_UDS="$aos_dev_cache_dir/sccache/server.sock" \
    SCCACHE_DIR="$aos_dev_cache_dir/sccache/store" \
    SCCACHE_CACHE_SIZE="${AOS_DEV_SCCACHE_SIZE:-50G}" \
    SCCACHE_IDLE_TIMEOUT=0 \
    "$sccache" "$@"
}

aos_dev_cache_start_sccache() {
  local sccache=$1

  aos_dev_cache_sccache_call "$sccache" --start-server >&2

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
      aos_dev_require_command getfacl
      for path in "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel"; do
        aos_dev_cache_has_default_acl "$path" || \
          aos_dev_error "shared cache permissions are incomplete at '$path'; run cache init"
      done
      local sccache
      sccache=$(aos_dev_cache_sccache_existing)
      aos_dev_cache_sccache_call "$sccache" --dist-status >/dev/null || \
        aos_dev_error 'sccache server is unavailable; run cache init'
      chmod 666 "$aos_dev_cache_dir/sccache/server.sock"
      printf 'Cache directories, ACLs, and sccache server are ready.\n'
      printf 'Run cache verify-mount for an optional Nix sandbox probe.\n'
      ;;
    verify-mount)
      aos_dev_cache_check_nix
      aos_dev_cache_verify_mount
      printf 'Nix build users can write the shared cache.\n'
      ;;
    status)
      aos_dev_cache_usage
      if [[ ! -S $aos_dev_cache_dir/sccache/server.sock ]]; then
        printf 'sccache server: stopped\n'
        return
      fi
      local sccache
      sccache=$(aos_dev_cache_sccache_existing)
      aos_dev_cache_sccache_call "$sccache" --dist-status >/dev/null || \
        aos_dev_error 'sccache server is unavailable; run cache init'
      chmod 666 "$aos_dev_cache_dir/sccache/server.sock"
      aos_dev_cache_sccache_call "$sccache" --show-stats
      ;;
    stop)
      [[ -S $aos_dev_cache_dir/sccache/server.sock ]] || return 0
      local sccache
      sccache=$(aos_dev_cache_sccache_existing)
      aos_dev_cache_sccache_call "$sccache" --stop-server
      ;;
    usage) aos_dev_cache_usage ;;
    prune) shift; aos_dev_cache_prune "$@" ;;
    clear) shift; aos_dev_cache_clear "$@" ;;
    *) aos_dev_error "unknown cache command '$action'" ;;
  esac
}
