# Derivations see stable backend paths inside the sandbox, independent of the
# host cache root. /var/tmp is traversable by nixbld users even when a
# developer's home directory is private, and survives normal reboots.
aos_dev_cache_dir=${AOS_DEV_CACHE_DIR:-/var/tmp/aos-dev-cache-$(id -u)}
aos_dev_go_cache_path=${AOS_DEV_GO_CACHE_DIR:-/aos-build-cache/go}
aos_dev_bazel_cache_path=${AOS_DEV_BAZEL_CACHE_DIR:-/aos-build-cache/bazel}
aos_dev_rust_cache_path=${AOS_DEV_RUST_TARGET_DIR:-/aos-build-cache/rust}

aos_dev_cache_validate_sandbox_paths() {
  # Each backend is mounted separately. A developer may choose the exact path
  # that the corresponding language builder sees inside the Nix sandbox.
  local path
  for path in "$aos_dev_go_cache_path" "$aos_dev_bazel_cache_path" "$aos_dev_rust_cache_path"; do
    [[ $path == /* && $path != / && $path != /nix && $path != /nix/* && \
       ! $path =~ [[:space:]] && $path != *'/../'* && $path != *'/./'* ]] || \
      aos_dev_error "sandbox cache path must be an absolute path without spaces or dot segments: $path"
  done
  [[ $aos_dev_go_cache_path != "$aos_dev_bazel_cache_path" && \
     $aos_dev_go_cache_path != "$aos_dev_rust_cache_path" && \
     $aos_dev_bazel_cache_path != "$aos_dev_rust_cache_path" ]] || \
    aos_dev_error 'sandbox cache paths must be distinct'
}

aos_dev_cache_check_nix() {
  # sandbox-paths is restricted by the daemon. A client setting from an
  # untrusted user is silently ignored, so check the configured local policy
  # before asking the daemon to build. The daemon remains the final authority.
  local configuration trusted paths username group mapping backend sandbox_path
  local -a mappings=()
  aos_dev_cache_validate_sandbox_paths
  for backend in go bazel rust; do
    case $backend in
      go) sandbox_path=$aos_dev_go_cache_path; [[ ${1:-} == all || $aos_dev_go_cache == true ]] || continue ;;
      bazel) sandbox_path=$aos_dev_bazel_cache_path; [[ ${1:-} == all || $aos_dev_bazel_cache == true ]] || continue ;;
      rust) sandbox_path=$aos_dev_rust_cache_path; [[ ${1:-} == all || $aos_dev_rust_target_cache == true ]] || continue ;;
    esac
    mappings+=("$sandbox_path=$aos_dev_cache_dir/$backend")
  done
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
    aos_dev_cache_nix_options=(--option extra-sandbox-paths "${mappings[*]}")
    return
  fi

  for group in $(id -Gn); do
    if [[ " $trusted " == *" @$group "* ]]; then
      aos_dev_cache_nix_options=(--option extra-sandbox-paths "${mappings[*]}")
      return
    fi
  done

  # A static daemon mount is a fallback for developers who cannot be trusted
  # users. Accept the earlier single-root mount for its default child paths,
  # so existing daemon configuration continues to work during migration.
  if [[ $aos_dev_go_cache_path == /aos-build-cache/go && \
     $aos_dev_bazel_cache_path == /aos-build-cache/bazel && \
     $aos_dev_rust_cache_path == /aos-build-cache/rust && \
     " $paths " == *" /aos-build-cache=$aos_dev_cache_dir "* ]]; then
    return
  fi

  # Per-backend static mounts are visible in every sandbox on that daemon.
  for mapping in "${mappings[@]}"; do
    [[ " $paths " == *" $mapping "* ]] || \
      aos_dev_error "Nix daemon rejected client sandbox paths for '$username'; ask an administrator to trust this user or add '$mapping' to daemon sandbox-paths"
  done
}

aos_dev_cache_prepare() {
  # Validate before mkdir/chmod so an accidental broad path or symlink cannot
  # turn cache initialization into a host filesystem permission change.
  [[ $aos_dev_cache_dir == /* ]] || aos_dev_error 'AOS_DEV_CACHE_DIR must be an absolute path'
  [[ $aos_dev_cache_dir != *' '* ]] || aos_dev_error 'cache path cannot contain spaces'
  [[ $aos_dev_cache_dir != / && $aos_dev_cache_dir != /tmp && \
     $aos_dev_cache_dir != /var/tmp && $aos_dev_cache_dir != "$HOME" && \
     $aos_dev_cache_dir != "$HOME/.cache" ]] || \
    aos_dev_error 'AOS_DEV_CACHE_DIR is too broad for cache setup'

  local path
  for path in "$aos_dev_cache_dir" "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" \
      "$aos_dev_cache_dir/rust"; do
    [[ ! -L $path ]] || aos_dev_error "cache setup refuses symlink: $path"
    # /var/tmp is shared. Refuse a path pre-created by another user instead
    # of changing its mode.
    [[ ! -e $path || -O $path ]] || aos_dev_error "cache setup refuses path owned by another user: $path"
  done

  aos_dev_require_command setfacl
  aos_dev_require_command getfacl
  mkdir -p "$aos_dev_cache_dir"/{go,bazel,rust}
  # Nix builds run under different nixbld UIDs. All artifact trees must
  # support writers from all of those users.
  # Default ACLs make new cache entries writable across UIDs without changing
  # the build's umask. A permissive build umask also changes test fixtures and
  # can invalidate tests that check private credential directories.
  chmod 0755 "$aos_dev_cache_dir"
  chmod 0777 "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" "$aos_dev_cache_dir/rust"
  for path in "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" "$aos_dev_cache_dir/rust"; do
    if ! aos_dev_cache_has_default_acl "$path" && \
        [[ -n $(find "$path" -mindepth 1 ! -name '.aos-cache.lock' -print -quit) ]]; then
      aos_dev_error "existing cache entries under '$path' lack inherited permissions; run cache clear ${path##*/}, then cache init"
    fi
    setfacl -m d:u::rwx,d:g::rwx,d:o::rwx "$path" || \
      aos_dev_error "cannot set default ACL on '$path'; shared builds need filesystem ACL support"
  done
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

  # Use the source bootstrap shell and coreutils, whose closure is much
  # smaller than the current AOS toolchain.
  aos_dev_cache_probe_once
  # A realized output alone can hide a mount that has since become inaccessible.
  aos_dev_cache_probe_once --check
}

aos_dev_cache_probe_once() {
  local log status interrupted=false
  log=$(mktemp)

  # Nix may report a user interruption with exit status 1 instead of 130.
  # Keep its diagnostics live and inspect the message before reporting the
  # failure. Redirect stdout after duplicating stderr into the pipe.
  if nix-build "$aos_dev_root/dev/cache-mount-smoke.nix" \
      --argstr goCacheDir "$aos_dev_go_cache_path" \
      --argstr bazelCacheDir "$aos_dev_bazel_cache_path" \
      --argstr rustCacheDir "$aos_dev_rust_cache_path" \
      "$@" --no-out-link "${aos_dev_cache_nix_options[@]}" \
      2>&1 >/dev/null | tee "$log" >&2; then
    rm -f -- "$log"
    return 0
  else
    status=$?
  fi

  if grep -Fq 'interrupted by the user' "$log"; then
    interrupted=true
  fi
  rm -f -- "$log"
  aos_dev_cache_probe_error "$status" "$interrupted"
  return "$status"
}

aos_dev_cache_probe_error() {
  local status=$1 interrupted=${2:-false}
  if [[ $interrupted == true ]] || (( status == 130 || status == 143 )); then
    printf 'aos-dev: sandbox probe interrupted (nix-build exit status %s)\n' "$status" >&2
  else
    printf 'aos-dev: sandbox probe failed (nix-build exit status %s); inspect the Nix error above\n' "$status" >&2
  fi
}

aos_dev_cache_command() {
  # Init and doctor check daemon mount policy; local maintenance can still run
  # when the Nix daemon is unavailable.
  local action=${1:-doctor}
  case $action in
    init)
      aos_dev_cache_check_nix all
      aos_dev_cache_prepare
      printf 'Shared caches ready in %s\n' "$aos_dev_cache_dir"
      ;;
    doctor)
      aos_dev_cache_check_nix all
      printf 'Cache directory: %s\n' "$aos_dev_cache_dir"
      [[ -d $aos_dev_cache_dir ]] || aos_dev_error 'run cache init first'
      [[ -w $aos_dev_cache_dir ]] || aos_dev_error 'cache directory is not writable'
      aos_dev_require_command getfacl
      for path in "$aos_dev_cache_dir/go" "$aos_dev_cache_dir/bazel" "$aos_dev_cache_dir/rust"; do
        aos_dev_cache_has_default_acl "$path" || \
          aos_dev_error "shared cache permissions are incomplete at '$path'; run cache init"
      done
      printf 'Go, Bazel, and Rust cache directories and ACLs are ready.\n'
      printf 'Run cache verify-mount for an optional Nix sandbox probe.\n'
      ;;
    verify-mount)
      [[ $# == 1 ]] || aos_dev_error 'cache verify-mount accepts no arguments'
      aos_dev_cache_check_nix all
      aos_dev_cache_verify_mount
      printf 'Nix build users can write the shared cache.\n'
      ;;
    status)
      aos_dev_cache_usage
      ;;
    usage) aos_dev_cache_usage ;;
    prune) shift; aos_dev_cache_prune "$@" ;;
    clear) shift; aos_dev_cache_clear "$@" ;;
    go|bazel|rust) aos_dev_cache_backend_command "$action" "${@:2}" ;;
    *) aos_dev_error "unknown cache command '$action'" ;;
  esac
}
