aos_dev_error() {
  printf 'aos-dev: %s\n' "$*" >&2
  exit 2
}

aos_dev_usage() {
  cat <<'HELP'
Usage: bash ./aos-dev [--release|--no-cache] <command> [arguments]

Commands:
  list [packages|images|containers|checks|builds|evals] [filter]
  build <package|image|container|check|build|eval> <name> [Nix flags]
  run <package|image|container> <name> [arguments]
  all <packages|checks|builds|format|ci> [Nix flags]
  fmt [nix|rust|all] [--check]
  release <arguments>       Run the existing release CLI without shared caches
  cache usage               Show disk use by backend
  cache prune [--days N] [--max-gib N] [--dry-run]
  cache clear [go|bazel|sccache|all]
  cache <init|doctor|verify-mount|status|stop>
  completion bash           Print Bash completion setup
  help

Development builds use shared sccache, Go and Bazel caches. --release disables
the shared cache and preserves the ordinary Nix derivation identities.
Set AOS_DEV_CACHE_DIR to move the cache (default: /var/tmp/aos-dev-cache-UID).
Set AOS_DEV_SCCACHE_TOOL to an existing AOS-built sccache store output to
avoid a cold Rust bootstrap when initializing the cache.
The optional cache verify-mount command builds an AOS shell and coreutils to
probe a real Nix sandbox; it can bootstrap many dependencies on a fresh host.
HELP
}

aos_dev_require_command() {
  command -v "$1" >/dev/null 2>&1 || aos_dev_error "required command '$1' is unavailable"
}

# All build and run commands eventually pass through this wrapper. Keeping the
# mode decision here prevents a new command from forgetting release isolation.
aos_dev_nix_build() {
  local -a command=(nix-build "$aos_dev_root/default.nix")

  if [[ $aos_dev_mode == development ]]; then
    # A single command may build several targets. Initialize the server and
    # sandbox mount once, then reuse the same Nix options for every target.
    if [[ ${aos_dev_cache_ready:-0} != 1 ]]; then
      aos_dev_cache_check_nix
      aos_dev_cache_prepare
      aos_dev_cache_ready=1
    fi
    command+=(--arg sharedBuildCache true)
    if [[ -n ${AOS_DEV_SCCACHE_TOOL:-} ]]; then
      command+=(--argstr sharedBuildCacheTool "$AOS_DEV_SCCACHE_TOOL")
    fi
    command+=("${aos_dev_cache_nix_options[@]}")
  fi

  "${command[@]}" "$@"
}
