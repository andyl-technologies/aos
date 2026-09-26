aos_dev_error() {
  printf 'aos-dev: %s\n' "$*" >&2
  exit 2
}

aos_dev_usage() {
  cat <<'HELP'
Usage: bash ./aos-dev [cache flags] <command> [arguments]

Commands:
  list [packages|images|containers|checks|builds|evals] [filter]
  build <package|image|container|check|build|eval> <name> [Nix flags]
  run <package|image|container> <name> [arguments]
  all <packages|checks|builds|format|ci> [Nix flags]
  fmt [nix|rust|all] [--check]
  release <arguments>       Run the existing release CLI without shared caches
  cache usage               Show disk use by backend
  cache prune [--before TIME|--days N] [--max-gib N] [--dry-run] [--compact]
  cache clear [go|bazel|rust|accache|all]
  cache <init|doctor|verify-mount|status>
  cache <go|bazel|rust|accache> <status|entries|builds|prune|compact|clear|help>
  cache rust intermediates [--limit N]
  completion bash           Print Bash completion setup
  help

Target names come from 'list'; a filter narrows the output by name. 'build'
accepts ordinary nix-build flags after the target, such as --no-out-link or
--dry-run. 'all packages' builds the package aggregate; 'all builds' also
includes images, containers, and system roots. 'all ci' runs formatting,
evaluation, broad builds, and checks, and can take a long time.

Development builds enable all four options by default:
  --[no-]go-cache           Share Go compilation artifacts
  --[no-]bazel-cache        Share Bazel disk action artifacts
  --[no-]rust-target-cache  Persist Cargo's target directory
  --[no-]rust-incremental   Enable rustc incremental compilation
  --[no-]accache            Share compiler action artifacts (default on)
  --cache-dir PATH          Host cache root (or set AOS_DEV_CACHE_DIR)
  --release, --no-cache     Disable all shared caches and use ordinary builds
The default host cache root is \${XDG_CACHE_HOME:-\$HOME/.cache}/aos-dev.
Private/nontraversable parents fall back to /var/tmp/aos-dev-cache-UID.
The paths inside Nix sandboxes default to /aos-build-cache/{go,bazel,rust}; set
AOS_DEV_GO_CACHE_DIR, AOS_DEV_BAZEL_CACHE_DIR, or AOS_DEV_RUST_TARGET_DIR
to choose each path. aos-dev maps them to the corresponding host directory.
These variables name sandbox paths, not host paths. Initialize the host root
with 'cache init' before building; it configures ACLs for concurrent Nix
build users but does not build tools or start a server. Every parent of the
host root must be traversable by Nix build users. The Nix daemon must trust
the invoking user to request extra-sandbox-paths, or have matching static
sandbox-paths mounts. 'cache doctor' checks local setup without building;
'cache verify-mount' checks write access in a real Nix sandbox. It uses the
source-built bootstrap Bash and coreutils, so ordinary compiler and dev-shell
changes do not make the probe rebuild the current toolchain.

Accache defaults on for supported nonincremental mkCargoPackage actions.
Incremental actions pass through unchanged; use --no-rust-incremental to cache
application Rust actions as well as dependencies. AOS_DEV_ACCACHE_DIR and
AOS_DEV_ACCACHE_STATE_DIR select separate sandbox data and metadata paths.
Stats, explanations, provenance, C/C++ opt-in, and coverage are documented in
tools/accache/README.md. No daemon starts. Release mode disables this too.

Only mkGoPackage, mkBazelPackage, and mkCargoPackage use these cache settings.
Generic C/C++ builds and language toolchains keep ordinary identities. Cargo
target trees are keyed by build contract and shared across source revisions;
rustc incremental compilation is a separate option. Go and Bazel cache keys
are opaque. 'cache <backend> entries' lists stored records; 'builds' lists
direct aos-dev outputs and their Nix derivers from a local journal. It cannot
map every individual hashed record to its producing derivation. Run
'cache <backend> help' for entry formats and age/size cleanup options.

Use --release or --no-cache for ordinary derivations and no requested cache
mounts. A daemon-wide static mount remains visible in release sandboxes; use
a separate builder if release qualification requires a cache-free sandbox.
Examples:
  bash ./aos-dev --no-bazel-cache build package aos --no-out-link
  bash ./aos-dev cache rust intermediates --limit 50
  bash ./aos-dev cache go prune --before 2026-09-01 --compact
  bash ./aos-dev --release build package aos --no-out-link
  source <(bash ./aos-dev completion bash)
The optional sandbox probe may build the source bootstrap tools if they are
absent on a fresh host.
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
    # Only directory caches need a sandbox mount. The Rust incremental flag
    # also works with Cargo's ordinary per-build target directory.
    if [[ $aos_dev_go_cache == true || $aos_dev_bazel_cache == true || \
          $aos_dev_rust_target_cache == true || ${aos_dev_accache:-false} == true ]]; then
      if [[ ${aos_dev_cache_ready:-0} != 1 ]]; then
        aos_dev_cache_check_nix
        aos_dev_cache_prepare
        aos_dev_cache_ready=1
      fi
      command+=("${aos_dev_cache_nix_options[@]}")
    fi
    if [[ ${aos_dev_accache:-false} == true ]]; then
      command+=(--argstr sharedAccacheDir "$aos_dev_accache_path")
      command+=(--argstr sharedAccacheStateDir "$aos_dev_accache_state_path")
    fi
    [[ $aos_dev_go_cache == true ]] && \
      command+=(--argstr sharedGoCacheDir "$aos_dev_go_cache_path")
    [[ $aos_dev_bazel_cache == true ]] && \
      command+=(--argstr sharedBazelCacheDir "$aos_dev_bazel_cache_path")
    [[ $aos_dev_rust_target_cache == true ]] && \
      command+=(--argstr sharedRustTargetDir "$aos_dev_rust_cache_path")
    [[ $aos_dev_rust_incremental == true ]] && \
      command+=(--arg sharedRustIncremental true)
  fi

  if [[ $aos_dev_mode == release ]]; then
    "${command[@]}" "$@"
    return
  fi

  # Capture only Nix's output paths while forwarding them unchanged to the
  # caller. The journal records the direct result's deriver after success.
  local attr='' prior='' argument capture status dry_run=false
  for argument in "$@"; do
    [[ $prior != -A ]] || attr=$argument
    [[ $argument != --dry-run ]] || dry_run=true
    prior=$argument
  done
  capture=$(mktemp)
  if "${command[@]}" "$@" | tee "$capture"; then
    if [[ $dry_run == false ]]; then
      aos_dev_cache_record_builds "$capture" "$attr"
    fi
    rm -f -- "$capture"
  else
    status=$?
    rm -f -- "$capture"
    return "$status"
  fi
}
